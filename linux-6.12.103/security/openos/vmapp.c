// SPDX-License-Identifier: GPL-2.0-only
/*
 * vmapp — OPENOS 轻量软件隔离机制 (内核实现)
 *
 * 用途: 让用户调用包管理工具 (如 opt) 时自动获得独立文件系统视图。
 *   - 在 /vmapp/<app_name> 下为每个软件提供独立根目录视图 (chroot +
 *     新挂载命名空间), 避免配置/缓存/依赖相互干扰
 *   - 保持网络命名空间与 PID 命名空间不变 (仅隔离文件系统视图)
 *   - 普通进程默认无法访问 /vmapp 内容 (目录 0700 root + 需要
 *     CAP_SYS_ADMIN 才能用本设备); 应用抽屉经本设备列出子目录
 *
 * 实现: 字符设备 /dev/vmapp + ioctl (避免新增系统调用号带来的
 *       四内核 x 四架构 syscall 表改动), 用户态 libvmapp 提供
 *       vmappapi() 同名 API 封装。
 *
 * ioctl 命令:
 *   VMAPP_IOC_CMD (struct vmapp_req):
 *     app_name : 软件名 (字母数字_-, 禁止 / 和 ..)
 *     enable   : 1=进入虚拟化视图, 0=仅读取 sub_path 列表
 *     sub_path : 可选子路径 (如 "usr/share/applications"), 空则无
 *     out_buf  : 目录列表 (换行分隔, NULL 结尾), 由内核填充
 *
 * 说明 (enable=1):
 *   - 递归创建 /vmapp/<app>/{etc,var,usr}
 *   - ksys_unshare(CLONE_NEWNS) 新挂载命名空间
 *   - set_fs_root + set_fs_pwd 切换到 /vmapp/<app> 视图
 *   - "退出虚拟化视图"= 进程退出 (mount 命名空间单向; enable=0
 *     无 sub_path 时返回 0, 进程结束自动回到宿主机)
 *
 * 跨版本:
 *   - vfs_mkdir idmap: 5.15 用 &init_user_ns, 6.12+ 用 &nop_mnt_idmap
 *   - kern_path_create / set_fs_root / ksys_unshare / iterate_dir 跨版本稳定
 */

#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#include <linux/mnt_idmapping.h>
#endif

/* ---- 外部函数原型 (供 oak_lsm.c 调用) ---- */
int openos_vmapp_init(void);
void openos_vmapp_exit(void);

#define VMAPP_ROOT      "/vmapp"
#define VMAPP_NAME_MAX  63
#define VMAPP_PATH_MAX  512
#define VMAPP_OUT_MAX   4096
#define VMAPP_SUBDIRS   {"etc", "var", "usr", "opt", "home"}

/* ---- 用户态请求结构 (ioctl) ---- */
struct vmapp_req {
	char app_name[64];
	int enable;
	char sub_path[256];
	char out_buf[VMAPP_OUT_MAX];
	int out_len;
};

#define VMAPP_MAGIC 0x6f
#define VMAPP_IOC_CMD _IOWR(VMAPP_MAGIC, 1, struct vmapp_req)

/* ---- 校验 app_name: 仅字母数字 _ - (防路径遍历) ---- */
static int vmapp_check_name(const char *name)
{
	const char *p;

	if (!name || !name[0] || strlen(name) > VMAPP_NAME_MAX)
		return -EINVAL;
	for (p = name; *p; p++) {
		if (!isalnum(*p) && *p != '_' && *p != '-')
			return -EINVAL;
	}
	return 0;
}

/* ---- 校验 sub_path: 禁止 / 开头, .. 与绝对路径 ---- */
static int vmapp_check_subpath(const char *sub)
{
	const char *p = sub;

	if (!sub[0])
		return 0;
	if (sub[0] == '/' || strstr(sub, ".."))
		return -EINVAL;
	for (; *p; p++) {
		if (*p < 0x20 || *p == 0x7f)
			return -EINVAL;
	}
	return 0;
}

/* ---- 创建目录 (跨版本 vfs_mkdir) ---- */
static int vmapp_mkdir_path(const char *path, umode_t mode)
{
	struct path parent;
	struct dentry *d;
	int rc;

	d = kern_path_create(AT_FDCWD, path, &parent, LOOKUP_DIRECTORY);
	if (IS_ERR(d))
		return PTR_ERR(d);

	if (d->d_inode) {	/* 已存在 */
		rc = 0;
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
		rc = vfs_mkdir(&init_user_ns, parent.dentry->d_inode, d, mode);
#else
		rc = vfs_mkdir(&nop_mnt_idmap, parent.dentry->d_inode, d, mode);
#endif
	}
	done_path_create(&parent, d);
	return rc;
}

/* ---- 递归创建 /vmapp/<app> 骨架 ---- */
static int vmapp_ensure_root(const char *app)
{
	static const char *subdirs[] = VMAPP_SUBDIRS;
	char path[VMAPP_PATH_MAX];
	int i, rc;

	snprintf(path, sizeof path, "%s/%s", VMAPP_ROOT, app);
	rc = vmapp_mkdir_path(path, 0700);
	if (rc != 0)
		return rc;
	/* /vmapp 本身 0700, 普通进程不可见 */
	vmapp_mkdir_path(VMAPP_ROOT, 0700);

	for (i = 0; i < ARRAY_SIZE(subdirs); i++) {
		snprintf(path, sizeof path, "%s/%s/%s",
			 VMAPP_ROOT, app, subdirs[i]);
		rc = vmapp_mkdir_path(path, 0755);
		if (rc != 0)
			return rc;
	}
	return 0;
}

/* ---- 目录列表上下文 ---- */
struct vmapp_dir_ctx {
	struct dir_context ctx;
	char __user *out;
	size_t left;
	size_t used;
};

static bool vmapp_emit(struct dir_context *c, const char *name, int namlen,
		       loff_t off, u64 ino, unsigned int d_type)
{
	struct vmapp_dir_ctx *vc =
		container_of(c, struct vmapp_dir_ctx, ctx);
	size_t n = (size_t)namlen;

	/* 过滤隐藏文件 */
	if (n > 0 && name[0] == '.')
		return true;

	if (vc->used + n + 1 > vc->left)
		return false;	/* 缓冲满 */

	if (copy_to_user(vc->out + vc->used, name, n) != 0)
		return false;
	if (copy_to_user(vc->out + vc->used + n, "\n", 1) != 0)
		return false;
	vc->used += n + 1;
	return true;
}

/* ---- 读取 /vmapp/<app>/<sub_path> 目录列表 ---- */
static int vmapp_list(const char *app, const char *sub, struct vmapp_req *req)
{
	char path[VMAPP_PATH_MAX];
	struct vmapp_dir_ctx vc;
	struct file *f;
	int rc;

	snprintf(path, sizeof path, "%s/%s/%s", VMAPP_ROOT, app, sub);
	f = filp_open(path, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);

	memset(&vc, 0, sizeof vc);
	vc.ctx.actor = vmapp_emit;
	vc.out = req->out_buf;
	vc.left = sizeof req->out_buf;
	vc.used = 0;

	rc = iterate_dir(f, &vc.ctx);
	filp_close(f, NULL);
	if (rc < 0)
		return rc;
	/* NULL 结尾 */
	if (vc.used < sizeof req->out_buf)
		if (copy_to_user(req->out_buf + vc.used, "", 1) == 0)
			vc.used++;
	req->out_len = (int)vc.used;
	return 0;
}

/* ---- ioctl: 进入虚拟化 / 读取列表 ---- */
static long vmapp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct vmapp_req *req;
	long rc;

	if (cmd != VMAPP_IOC_CMD)
		return -ENOTTY;

	/* 需要 CAP_SYS_ADMIN (隔离视图 + 目录可见性控制) */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	if (copy_from_user(req, (void __user *)arg, sizeof(*req))) {
		rc = -EFAULT;
		goto out_free;
	}

	rc = vmapp_check_name(req->app_name);
	if (rc != 0)
		goto out_free;
	if (vmapp_check_subpath(req->sub_path) != 0) {
		rc = -EINVAL;
		goto out_free;
	}

	if (req->enable) {
		/* 1. 创建骨架 */
		rc = vmapp_ensure_root(req->app_name);
		if (rc != 0)
			goto out_free;
		/* 2. 新挂载命名空间 (保持 net/pid ns 不变) */
		rc = ksys_unshare(CLONE_NEWNS);
		if (rc != 0)
			goto out_free;
		/* 3. 切换到 /vmapp/<app> 视图 */
		{
			struct path p;
			char root[VMAPP_PATH_MAX];

			snprintf(root, sizeof root, "%s/%s",
				 VMAPP_ROOT, req->app_name);
			rc = kern_path(root, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				       &p);
			if (rc != 0)
				goto out_free;
			set_fs_root(current->fs, &p);
			set_fs_pwd(current->fs, &p);
			path_put(&p);
		}
		req->out_len = 0;
	} else if (req->sub_path[0]) {
		/* 读取指定子目录列表 (应用抽屉场景) */
		rc = vmapp_list(req->app_name, req->sub_path, req);
		if (rc != 0)
			goto out_free;
	} else {
		/* enable=0 无 sub_path: 进程退出即恢复宿主机视图 */
		req->out_len = 0;
	}

	if (copy_to_user((void __user *)arg, req, sizeof(*req)) != 0) {
		rc = -EFAULT;
		goto out_free;
	}
	rc = 0;

out_free:
	kfree(req);
	return rc;
}

static const struct file_operations vmapp_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = vmapp_ioctl,
	.compat_ioctl = vmapp_ioctl,
};

static struct miscdevice vmapp_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vmapp",
	.fops = &vmapp_fops,
	.mode = 0600,	/* root: 普通进程不可用 */
};

static int __init vmapp_init(void)
{
	int rc;

	rc = misc_register(&vmapp_dev);
	if (rc != 0)
		return rc;
	/* /vmapp 根目录 0700 (root only) */
	vmapp_mkdir_path(VMAPP_ROOT, 0700);
	pr_info("vmapp: 轻量软件隔离已启用 (/dev/vmapp, /vmapp 0700)\n");
	return 0;
}

/* 由 OPENOS Security 模块统一 init (经 oak_lsm.o 的 oak_init 调用) */
int openos_vmapp_init(void) { return vmapp_init(); }
void openos_vmapp_exit(void) { misc_deregister(&vmapp_dev); }
