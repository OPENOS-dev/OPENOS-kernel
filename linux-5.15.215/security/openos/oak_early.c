// SPDX-License-Identifier: GPL-2.0-only
/*
 * OPENOS Security — OAK-Seal 启动完整性校验 (早期启动)
 *
 * 由 init/main.c 的 start_kernel() 调用 openos_oak_early_init():
 *   1. 从硬盘头部偏移 0x1000 读取 OAK-Seal 封印数据块
 *   2. 用内核 crypto 框架 (crypto_shash) 计算当前内核镜像 (_text.._end)
 *     的 SHA-256 哈希, 与封印中的期望哈希比对
 *   3. 校验失败 -> 尝试凭据解锁 (用户名+密码); 解锁失败 -> machine_halt()
 *      锁死系统 (防篡改/防未授权启动)
 *
 * 依赖 (按需求): 仅 blkdev_get_by_path / bdev_file_open_by_path +
 *                crypto_shash。
 *
 * 跨版本 (LINUX_VERSION_CODE):
 *   - < 6.0 : blkdev_get_by_path(path, fmode_t, holder) -> read_mapping_page
 *   - >= 6.0: bdev_file_open_by_path(path, blk_mode_t, holder, hops) -> kernel_read
 *
 * 工程说明:
 *   - start_kernel 阶段块设备/crypto 子系统可能尚未初始化: 设备或 crypto
 *     不可用时, 若 oak.strict=1 则停机, 否则警告降级 (保证不误锁正常启动)。
 *   - 交互式"用户名+密码"输入在 start_kernel 阶段无 tty/input 子系统,
 *     由引导加载器/initramfs 询问用户后以内核参数传递:
 *         oak.user=<username>  oak.pass=<sha256hex(password)>
 *     生产部署: 交互提示建议放到 initramfs, 解锁凭据经 cmdline 或
 *     /proc/oak/unlock 传入 (本文件提供内核侧比对)。
 */

#include <linux/blkdev.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/reboot.h>
#include <linux/string.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#include <linux/hex.h>	/* hex_to_bin (6.x 自 kernel.h 拆分) */
#endif

#define OAK_SEAL_OFFSET		0x1000	/* 封印块在设备上的偏移 */
#define OAK_SEAL_MAGIC		"OAKS"	/* 封印魔数 */
#define OAK_SHA256_LEN		32
#define OAK_SEAL_BLOCK_SZ	512

/* OAK-Seal 封印数据块布局 (固定, 由封印工具生成) */
struct oak_seal_block {
	u8 magic[4];			/* "OAKS" */
	u32 version;			/* 格式版本 */
	u32 kernel_len;			/* 被测量内核范围长度 (字节) */
	u8 kernel_hash[OAK_SHA256_LEN];	/* 期望的内核 SHA-256 */
	u8 user_hash[OAK_SHA256_LEN];	/* 解锁用户名 SHA-256 */
	u8 pass_hash[OAK_SHA256_LEN];	/* 解锁密码 SHA-256 */
	u8 reserved[OAK_SEAL_BLOCK_SZ - (4 + 4 + 4 + 32 * 3)];
};

/* 启动参数 */
static char oak_seal_dev[64] = "/dev/sda";
static char oak_user[64];
static char oak_pass_sha[OAK_SHA256_LEN * 2 + 1];
static bool oak_strict;

static int __init oak_param_seal_dev(char *str)
{
	strscpy(oak_seal_dev, str, sizeof(oak_seal_dev));
	return 0;
}
early_param("oak.seal_dev", oak_param_seal_dev);

static int __init oak_param_user(char *str)
{
	strscpy(oak_user, str, sizeof(oak_user));
	return 0;
}
early_param("oak.user", oak_param_user);

static int __init oak_param_pass(char *str)
{
	strscpy(oak_pass_sha, str, sizeof(oak_pass_sha));
	return 0;
}
early_param("oak.pass", oak_param_pass);

static int __init oak_param_strict(char *str)
{
	return kstrtobool(str, &oak_strict);
}
early_param("oak.strict", oak_param_strict);

/* ---- SHA-256 (内核 crypto 框架) ---- */
static int oak_sha256(const void *data, unsigned int len, u8 out[OAK_SHA256_LEN])
{
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(desc, tfm);
	int rc;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc->tfm = tfm;
	rc = crypto_shash_digest(desc, data, len, out);

	shash_desc_zero(desc);
	crypto_free_shash(tfm);
	return rc;
}

/* ---- hex -> bytes (解锁凭据转换) ---- */
static int oak_hex2bin(const char *hex, u8 *out, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		int hi, lo;

		hi = hex_to_bin(hex[i * 2]);
		lo = hex_to_bin(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[i] = (u8)((hi << 4) | lo);
	}
	return 0;
}

/* ---- 读取封印块 (跨版本块设备打开) ---- */
static int oak_read_seal(void *buf, size_t len)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
	/* 5.15: blkdev_get_by_path + 页缓存读取 */
	struct block_device *bdev;
	struct page *page;
	loff_t pos = OAK_SEAL_OFFSET;
	void *kaddr;
	int rc;

	bdev = blkdev_get_by_path(oak_seal_dev, FMODE_READ, NULL);
	if (IS_ERR(bdev))
		return PTR_ERR(bdev);

	page = read_mapping_page(bdev->bd_inode->i_mapping,
				 pos >> PAGE_SHIFT, NULL);
	if (IS_ERR(page)) {
		rc = PTR_ERR(page);
		goto out_put;
	}
	kaddr = kmap_local_page(page);
	memcpy(buf, kaddr + offset_in_page(pos), len);
	kunmap_local(kaddr);
	put_page(page);
	rc = 0;

out_put:
	blkdev_put(bdev, NULL);
	return rc;
#else
	/* 6.12 / 7.x: bdev_file_open_by_path + kernel_read */
	struct file *bfile;
	loff_t pos = OAK_SEAL_OFFSET;
	ssize_t rc;

	bfile = bdev_file_open_by_path(oak_seal_dev, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(bfile))
		return PTR_ERR(bfile);

	rc = kernel_read(bfile, buf, len, &pos);
	fput(bfile);
	return rc == (ssize_t)len ? 0 : -EIO;
#endif
}

/* ---- 凭据解锁 (用户名+密码 比对封印中的哈希) ---- */
static int oak_try_unlock(const struct oak_seal_block *seal)
{
	u8 user_h[OAK_SHA256_LEN];
	u8 pass_h[OAK_SHA256_LEN];
	int rc;

	if (!oak_user[0] || !oak_pass_sha[0])
		return -EACCES;
	if (strlen(oak_pass_sha) != OAK_SHA256_LEN * 2)
		return -EINVAL;

	rc = oak_sha256(oak_user, strlen(oak_user), user_h);
	if (rc != 0)
		return rc;
	rc = oak_hex2bin(oak_pass_sha, pass_h, OAK_SHA256_LEN);
	if (rc != 0)
		return rc;

	if (memcmp(user_h, seal->user_hash, OAK_SHA256_LEN) == 0 &&
	    memcmp(pass_h, seal->pass_hash, OAK_SHA256_LEN) == 0)
		return 0;	/* 解锁成功 */
	return -EACCES;
}

/* ---- 失败处理: 严格模式停机 (锁死) ---- */
static void oak_fail_and_halt(const char *reason)
{
	pr_emerg("OAK-Seal: %s\n", reason);
	pr_emerg("OAK-Seal: 系统已锁定 (完整性校验失败)\n");
	machine_halt();
}

/* =====================================================================
 * 入口: 由 init/main.c start_kernel() 调用
 * ===================================================================== */
void __init openos_oak_early_init(void)
{
	struct oak_seal_block seal;
	u8 hash[OAK_SHA256_LEN];
	extern char _text[], _end[];
	size_t klen;
	int rc;

	pr_info("OPENOS Security: OAK-Seal 启动完整性校验 (设备=%s)\n",
		oak_seal_dev);

	rc = oak_read_seal(&seal, sizeof(seal));
	if (rc != 0) {
		/* 早期块设备未就绪属正常; strict 时才锁死 */
		pr_warn("OAK-Seal: 无法读取封印设备 %s (rc=%d)%s\n",
			oak_seal_dev, rc,
			oak_strict ? " - strict 模式, 停机" : " - 降级跳过");
		if (oak_strict)
			oak_fail_and_halt("封印设备不可用且 strict=1");
		return;
	}
	if (memcmp(seal.magic, OAK_SEAL_MAGIC, 4) != 0) {
		pr_warn("OAK-Seal: 偏移 0x%x 处无有效封印 (魔数不符)%s\n",
			OAK_SEAL_OFFSET, oak_strict ? " - 停机" : " - 降级跳过");
		if (oak_strict)
			oak_fail_and_halt("封印魔数不符且 strict=1");
		return;
	}

	/* 计算当前内核镜像哈希 */
	klen = (size_t)(_end - _text);
	rc = oak_sha256(_text, klen, hash);
	if (rc != 0) {
		pr_warn("OAK-Seal: crypto 子系统不可用 (rc=%d)%s\n", rc,
			oak_strict ? " - 停机" : " - 降级跳过");
		if (oak_strict)
			oak_fail_and_halt("crypto 不可用且 strict=1");
		return;
	}

	if (memcmp(hash, seal.kernel_hash, OAK_SHA256_LEN) == 0) {
		pr_info("OAK-Seal: 校验通过, 内核未被篡改 (len=%zu)\n", klen);
		return;
	}

	pr_emerg("OAK-Seal: 内核哈希不匹配! 可能被篡改\n");
	rc = oak_try_unlock(&seal);
	if (rc == 0) {
		pr_warn("OAK-Seal: 已通过用户凭据解锁, 继续启动 (降级可信状态)\n");
		return;
	}
	oak_fail_and_halt("内核校验失败且解锁无效");
}
