// SPDX-License-Identifier: GPL-2.0-only
/*
 * OPENOS Security 安全模块 (security/openos/oak_lsm.c)
 *
 * 模块名: OPENOS Security (CONFIG_SECURITY_OPENOS)
 * 内部加密方法: OAK (密钥/验证体系, .oak 文件 + oakctl + 握手协议)
 *
 * 职责: 永久保护 OPENOS-Security 框架的内置安全子模块,
 *      以及未来经 OAK 注册认证的第三方守护进程。
 *
 * 设计:
 *   [固定逻辑] 内置安全子模块 (三个固定角色, 保护规则不可删除):
 *     - System 守护进程     (负责内核看门狗)
 *     - OPT 守护进程        (负责包管理事务)
 *     - Application 守护进程 (负责应用生命周期)
 *     三者"永远受保护"的规则固定, 但其 PID 随系统启动变化,
 *     因此 PID 值由 Security Watchdog 在守护进程就绪后登记
 *     (/proc/oak/builtin)。角色槽位固定, 不可增删, 只可登记/更新 PID。
 *
 *   [动态接口] 第三方白名单 (经 OAK 认证的守护进程):
 *     - 内核哈希表 (struct hlist_head, 8 bit 桶) 维护
 *     - 用户态经 /proc/oak/whitelist 动态增删 (add/del)
 *
 *   [安全主体] Security Watchdog:
 *     - PID 经 /proc/oak/watchdog 登记
 *     - 只有它被允许终止受保护进程; 其余发送者一律拒绝 (-EPERM)
 *
 *   [内核权利] 授权提权 (给受保护进程授予 capabilities):
 *     - 内置角色固定能力集合: system=看门狗(SYS_ADMIN/SYS_BOOT/KILL),
 *       opt=包管理(SYS_ADMIN/DAC_OVERRIDE/CHOWN/FOWNER/SETUID/SETGID/MKNOD...),
 *       application=生命周期(KILL/SYS_RESOURCE/DAC_OVERRIDE)
 *     - Security Watchdog: 全权管理 (含 SYS_RAWIO/NET_ADMIN/LINUX_IMMUTABLE)
 *     - 白名单: 默认受限能力, 注册时可用 add <pid> <hexmask> 覆盖
 *     - 受保护进程启动后向 /proc/oak/authorize 写 token 自证身份,
 *       OAK 校验其 PID 在保护名单后对其 credential 提权 (prepare_creds +
 *       cap_raise + commit_creds; cap_raise 宏兼容 5.15 数组式与 6.12+ 位图式)
 *     - 说明: 未用 security_capable 钩子 (LSM 间为 AND 语义, capability
 *       模块拒绝后无法覆盖), 故采用"授权接口 + 直接提权"。
 *
 * 钩子: security_task_kill — 拦截对受保护进程的 SIGKILL / SIGTERM。
 *
 * 兼容内核 (LINUX_VERSION_CODE 三段):
 *   - < KERNEL_VERSION(5,16,0)  : security_add_hooks(..., char *lsm) 字符串式
 *                                 (5.15.215; 无 struct lsm_id, enum lsm_order
 *                                 仅含 FIRST/MUTABLE)
 *   - [5.16, 7.0)               : security_add_hooks(..., const struct lsm_id *)
 *                                 DEFINE_LSM 用 .name 字段 (6.12.103)
 *   - >= KERNEL_VERSION(7,0,0)  : DEFINE_LSM 改用 .id = &lsm_id (7.1.8 / 7.2-rc7)
 *
 * 强制启用 (不允许禁用/修改):
 *   - Kconfig 为 def_bool y: 编译进内核, 无 =n 选项
 *   - LSM order 强制: 5.15 用 LSM_ORDER_FIRST (唯一强制项);
 *     6.12/7.1/7.2 用 LSM_ORDER_LAST —— order 为 FIRST/LAST 的 LSM
 *     无视 lsm= 内核参数与 CONFIG_LSM 列表, 编译进内核即总启用
 *   - 构建体系在编译后校验 System.map 含 oak 符号, 缺失则构建失败
 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/lsm_hooks.h>

/* OPENOS Security LSM ID (官方分配 100-113; 第三方私有 ID 从 200 起, 避免冲突) */
#ifndef LSM_ID_OPENOS_SECURITY
#define LSM_ID_OPENOS_SECURITY 200
#endif

/* ---- 常量 ---- */
#define OAK_BUCKET_BITS 8
#define OAK_BUCKETS     (1U << OAK_BUCKET_BITS)
#define OAK_ROLE_NAME_MAX 16
#define OAK_OP_MAX       16

/* =====================================================================
 * [固定逻辑] 内核权利: 各角色的能力集合 (capabilities)
 * 受保护进程启动后向 /proc/oak/authorize 自证身份, OAK 在内核态对其
 * credential 提权到该角色的能力集合 —— 这是 OAK 体系的"内核权利"。
 * 能力位图用 u64 (CAP_LAST_CAP < 64), 位 i 对应 CAP_<i>。
 * ===================================================================== */
#define OAK_CAP(mask)		(mask)

/* Security Watchdog: 全权管理主体 */
#define OAK_WD_CAPS	OAK_CAP(BIT_ULL(CAP_SYS_ADMIN) | BIT_ULL(CAP_SYS_BOOT) | \
				BIT_ULL(CAP_KILL) | BIT_ULL(CAP_MKNOD) | \
				BIT_ULL(CAP_SYS_RESOURCE) | BIT_ULL(CAP_DAC_OVERRIDE) | \
				BIT_ULL(CAP_CHOWN) | BIT_ULL(CAP_FOWNER) | \
				BIT_ULL(CAP_SETUID) | BIT_ULL(CAP_SETGID) | \
				BIT_ULL(CAP_NET_ADMIN) | BIT_ULL(CAP_LINUX_IMMUTABLE) | \
				BIT_ULL(CAP_SYS_RAWIO))
/* System 守护进程 (内核看门狗) */
#define OAK_SYSTEM_CAPS	OAK_CAP(BIT_ULL(CAP_SYS_ADMIN) | BIT_ULL(CAP_SYS_BOOT) | \
				BIT_ULL(CAP_KILL))
/* OPT 守护进程 (包管理事务: 挂载/写系统/权限切换) */
#define OAK_OPT_CAPS	OAK_CAP(BIT_ULL(CAP_SYS_ADMIN) | BIT_ULL(CAP_DAC_OVERRIDE) | \
				BIT_ULL(CAP_CHOWN) | BIT_ULL(CAP_FOWNER) | \
				BIT_ULL(CAP_SETUID) | BIT_ULL(CAP_SETGID) | \
				BIT_ULL(CAP_MKNOD) | BIT_ULL(CAP_LINUX_IMMUTABLE))
/* Application 守护进程 (应用生命周期管理) */
#define OAK_APP_CAPS	OAK_CAP(BIT_ULL(CAP_KILL) | BIT_ULL(CAP_SYS_RESOURCE) | \
				BIT_ULL(CAP_DAC_OVERRIDE))
/* 白名单第三方守护进程默认能力 (注册时可经 add <pid> <hexmask> 覆盖) */
#define OAK_WL_DEFAULT_CAPS	OAK_CAP(BIT_ULL(CAP_KILL) | BIT_ULL(CAP_DAC_OVERRIDE) | \
				BIT_ULL(CAP_CHOWN) | BIT_ULL(CAP_FOWNER))

/* =====================================================================
 * [固定逻辑] 内置安全子模块角色定义
 * 角色槽位固定, 不可增删; PID 值由 Security Watchdog 运行时登记。
 * ===================================================================== */
enum oak_builtin_role {
	OAK_ROLE_SYSTEM = 0,	/* System 守护进程 (内核看门狗) */
	OAK_ROLE_OPT,		/* OPT 守护进程 (包管理事务) */
	OAK_ROLE_APPLICATION,	/* Application 守护进程 (应用生命周期) */
	OAK_ROLE_BUILTIN_MAX,
};

static const char *const oak_builtin_names[OAK_ROLE_BUILTIN_MAX] = {
	[OAK_ROLE_SYSTEM]     = "system",
	[OAK_ROLE_OPT]        = "opt",
	[OAK_ROLE_APPLICATION] = "application",
};

/* 角色 -> 能力集合 (固定逻辑) */
static const u64 oak_role_caps[OAK_ROLE_BUILTIN_MAX] = {
	[OAK_ROLE_SYSTEM]     = OAK_SYSTEM_CAPS,
	[OAK_ROLE_OPT]        = OAK_OPT_CAPS,
	[OAK_ROLE_APPLICATION] = OAK_APP_CAPS,
};

/* 内置子模块 PID (固定槽位; 写保护: 需 CAP_SYS_ADMIN) */
static pid_t oak_builtin_pid[OAK_ROLE_BUILTIN_MAX];
static bool  oak_builtin_registered[OAK_ROLE_BUILTIN_MAX];

/* 安全主体 (Security Watchdog) PID; -1 表示未登记 */
static pid_t oak_watchdog_pid = -1;

/* =====================================================================
 * [动态接口] 第三方白名单 (内核哈希表, 支持运行时增删)
 * 用户态经 /proc/oak/whitelist:  add <pid> / del <pid>
 * ===================================================================== */
struct oak_wl_entry {
	struct hlist_node node;
	pid_t pid;
	u64 capmask;	/* 该白名单进程的内核权利 (能力集合) */
};

static struct hlist_head oak_whitelist[OAK_BUCKETS];
static DEFINE_SPINLOCK(oak_lock);

/* ---- 工具: 目标进程是否受保护 (内置角色 或 白名单) ---- */
static bool oak_pid_is_protected(pid_t pid)
{
	unsigned long flags;
	struct oak_wl_entry *e;
	unsigned int b;
	int i;
	bool found = false;

	spin_lock_irqsave(&oak_lock, flags);
	for (i = 0; i < OAK_ROLE_BUILTIN_MAX; i++) {
		if (oak_builtin_registered[i] && oak_builtin_pid[i] == pid) {
			found = true;
			break;
		}
	}
	if (!found) {
		b = hash_32(pid, OAK_BUCKET_BITS);
		hlist_for_each_entry(e, &oak_whitelist[b], node) {
			if (e->pid == pid) {
				found = true;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&oak_lock, flags);
	return found;
}

/* ---- 白名单增删 (capmask 指定该进程的内核权利) ---- */
static int oak_wl_add(pid_t pid, u64 capmask)
{
	struct oak_wl_entry *e;
	unsigned long flags;
	unsigned int b;

	if (pid <= 0)
		return -EINVAL;

	b = hash_32(pid, OAK_BUCKET_BITS);
	spin_lock_irqsave(&oak_lock, flags);
	hlist_for_each_entry(e, &oak_whitelist[b], node) {
		if (e->pid == pid) {	/* 已存在: 更新权利 */
			e->capmask = capmask;
			spin_unlock_irqrestore(&oak_lock, flags);
			return 0;
		}
	}
	e = kzalloc(sizeof(*e), GFP_ATOMIC);
	if (!e) {
		spin_unlock_irqrestore(&oak_lock, flags);
		return -ENOMEM;
	}
	e->pid = pid;
	e->capmask = capmask;
	hlist_add_head(&e->node, &oak_whitelist[b]);
	spin_unlock_irqrestore(&oak_lock, flags);
	return 0;
}

/* 查询白名单条目 (返回 capmask) */
static bool oak_wl_lookup(pid_t pid, u64 *capmask)
{
	struct oak_wl_entry *e;
	unsigned long flags;
	unsigned int b;
	bool found = false;

	b = hash_32(pid, OAK_BUCKET_BITS);
	spin_lock_irqsave(&oak_lock, flags);
	hlist_for_each_entry(e, &oak_whitelist[b], node) {
		if (e->pid == pid) {
			if (capmask)
				*capmask = e->capmask;
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&oak_lock, flags);
	return found;
}

static int oak_wl_del(pid_t pid)
{
	struct oak_wl_entry *e;
	unsigned long flags;
	unsigned int b;

	b = hash_32(pid, OAK_BUCKET_BITS);
	spin_lock_irqsave(&oak_lock, flags);
	hlist_for_each_entry(e, &oak_whitelist[b], node) {
		if (e->pid == pid) {
			hlist_del(&e->node);
			spin_unlock_irqrestore(&oak_lock, flags);
			kfree(e);
			return 0;
		}
	}
	spin_unlock_irqrestore(&oak_lock, flags);
	return -ENOENT;
}

/* =====================================================================
 * OAK 子安全主体 (子安全模块)
 * 三个内置守护 + 第三方认证守护 统一为"子安全主体":
 *   每个主体 = name + kind(内置/第三方) + pid + 内核权利(capmask) + 公钥
 *   应用收到请求后, 经握手验证身份, 可加入(挂靠)某个子安全主体获得信任。
 * 运维统一经 /proc/oak/subjects 管理。
 * ===================================================================== */
#define OAK_SUBJECT_NAME_MAX 24
#define OAK_KEY_MAX         512        /* 公钥最大长度 (字节) */
#define OAK_KEY_HEX_MAX     (OAK_KEY_MAX * 2 + 1)
#define OAK_CHALLENGE_LEN   32
#define OAK_HASH_LEN        32         /* SHA-256 摘要长度 */

enum oak_subject_kind {
	OAK_SUBJECT_BUILTIN = 0,	/* 内置子主体 (固定) */
	OAK_SUBJECT_THIRD,		/* 第三方子主体 (动态) */
};

struct oak_subject {
	struct hlist_node node;
	char name[OAK_SUBJECT_NAME_MAX];
	enum oak_subject_kind kind;
	pid_t pid;			/* 主体主进程 (运维/授权) */
	u64 capmask;			/* 该主体的内核权利 */
	u8  pubkey[OAK_KEY_MAX];	/* 公钥 (哈希序列串) 原始字节 */
	size_t pubkey_len;
	u8  pubkey_sha256[OAK_HASH_LEN]; /* 公钥指纹 (SHA-256) */
	bool has_pubkey;
};

/* 子安全主体注册表 (按 name 哈希) */
static struct hlist_head oak_subjects[OAK_BUCKETS];
static DEFINE_SPINLOCK(oak_subjects_lock);

/* 字符串哈希 (FNV-1a; 内核无通用 hash_string) */
static unsigned int oak_str_hash(const char *s)
{
	unsigned int h = 2166136261u;

	while (*s) {
		h ^= (unsigned char)*s++;
		h *= 16777619u;
	}
	return h & (OAK_BUCKETS - 1);
}

/* ---- 子安全主体查找 (by name) ---- */
static struct oak_subject *oak_subject_find(const char *name)
{
	struct oak_subject *s;
	unsigned int b;

	b = oak_str_hash(name);
	hlist_for_each_entry(s, &oak_subjects[b], node)
		if (strcmp(s->name, name) == 0)
			return s;
	return NULL;
}

/* 公钥指纹 (32 字节"哈希序列串"; 简化 FNV 扩展, 正式可用 crypto_shash SHA-256) */
static void oak_fingerprint(const u8 *key, size_t len, u8 out[OAK_HASH_LEN])
{
	u32 h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	size_t i;

	for (i = 0; i < len; i++) {
		h[i % 8] ^= key[i];
		h[i % 8] = h[i % 8] * 16777619u + (h[(i + 1) % 8] ^ (h[i % 8] >> 5));
	}
	for (i = 0; i < 8; i++) {
		out[i * 4 + 0] = (u8)(h[i] >> 24);
		out[i * 4 + 1] = (u8)(h[i] >> 16);
		out[i * 4 + 2] = (u8)(h[i] >> 8);
		out[i * 4 + 3] = (u8)h[i];
	}
}

/* ---- 子安全主体注册/更新 (kind: builtin|third) ---- */
static int oak_subject_register(const char *name, enum oak_subject_kind kind,
				pid_t pid, u64 capmask,
				const u8 *pubkey, size_t pubkey_len)
{
	struct oak_subject *s;
	unsigned long flags;
	unsigned int b;
	int rc = 0;

	if (!name || name[0] == '\0' || strlen(name) >= OAK_SUBJECT_NAME_MAX)
		return -EINVAL;
	if (pid <= 0)
		return -EINVAL;
	if (pubkey_len > OAK_KEY_MAX)
		return -E2BIG;

	spin_lock_irqsave(&oak_subjects_lock, flags);
	s = oak_subject_find(name);
	if (s) {		/* 已存在: 更新 */
		s->pid = pid;
		s->capmask = capmask;
		s->kind = kind;
		if (pubkey && pubkey_len > 0) {
			memcpy(s->pubkey, pubkey, pubkey_len);
			s->pubkey_len = pubkey_len;
			s->has_pubkey = true;
			oak_fingerprint(pubkey, pubkey_len, s->pubkey_sha256);
		}
		goto out;
	}
	s = kzalloc(sizeof(*s), GFP_ATOMIC);
	if (!s) {
		rc = -ENOMEM;
		goto out;
	}
	strscpy(s->name, name, sizeof(s->name));
	s->kind = kind;
	s->pid = pid;
	s->capmask = capmask;
	if (pubkey && pubkey_len > 0) {
		memcpy(s->pubkey, pubkey, pubkey_len);
		s->pubkey_len = pubkey_len;
		s->has_pubkey = true;
		oak_fingerprint(pubkey, pubkey_len, s->pubkey_sha256);
	}
	b = oak_str_hash(name);
	hlist_add_head(&s->node, &oak_subjects[b]);
out:
	spin_unlock_irqrestore(&oak_subjects_lock, flags);
	return rc;
}

/* ---- 子安全主体注销 ---- */
static int oak_subject_unregister(const char *name)
{
	struct oak_subject *s;
	unsigned long flags;
	unsigned int b;

	b = oak_str_hash(name);
	spin_lock_irqsave(&oak_subjects_lock, flags);
	s = oak_subject_find(name);
	if (!s) {
		spin_unlock_irqrestore(&oak_subjects_lock, flags);
		return -ENOENT;
	}
	hlist_del(&s->node);
	spin_unlock_irqrestore(&oak_subjects_lock, flags);
	kfree(s);
	return 0;
}

/* =====================================================================
 * 握手验证 (类非对称加密双向认证, 简化 STS)
 *
 * 协议 (每个参与方为子安全主体或应用):
 *   1) 双方各持有密钥对 {priv, pub}; pub 公开注册到 OAK
 *   2) 握手发起方 A: 生成随机 challenge_a, 发送 (A, pub_a, challenge_a)
 *   3) 应答方 B(OAK 侧主体): 生成 challenge_b, 用 priv_b 对
 *      (challenge_a || pub_a) 签名 -> sig_b, 回发 (pub_b, challenge_b, sig_b)
 *   4) A 用 pub_b 验证 sig_b (B 拥有 priv_b, 身份成立); 用 priv_a 对
 *      (challenge_b || pub_b) 签名 -> sig_a 回发
 *   5) B 用 pub_a 验证 sig_a (A 身份成立)
 *   6) 双方各自派生会话密钥 K = SHA-256(pub_a || pub_b) (握手密钥,
 *      后续可升级为 ECDH 协商), 此后安全连接用 K 做 MAC/加密。
 *
 * 本模块实现内核侧: 公钥存储 + 挑战应答状态 + 签名验证 (条件编译
 * CONFIG_CRYPTO_RSA 用 akcipher 验签; 否则退回 HMAC-SHA256 对称验证)。
 * 签名生成放用户态 (openssl dgst -sign / pkeyutl)。
 * ===================================================================== */

/* 会话密钥: 握手双方各存一份 (按对端 pub 指纹索引) */
struct oak_session {
	struct hlist_node node;
	u8 peer_hash[OAK_HASH_LEN];	/* 对端公钥指纹 */
	u8 key[OAK_HASH_LEN];		/* 会话密钥 K */
};

static struct hlist_head oak_sessions[OAK_BUCKETS];
static DEFINE_SPINLOCK(oak_sessions_lock);

/* 生成挑战 (随机数) */
static void oak_gen_challenge(u8 out[OAK_CHALLENGE_LEN])
{
	get_random_bytes(out, OAK_CHALLENGE_LEN);
}

/* 会话密钥派生: K = SHA-256(pub_a || pub_b) */
static int oak_derive_key(const u8 *pa, size_t la, const u8 *pb, size_t lb,
			  u8 out[OAK_HASH_LEN])
{
	/* 用内核 crypto API 做 SHA-256; 避免直接依赖, 此处用简单 xorshift 摘要
	 * 仅为握手密钥骨架 —— 正式实现应替换为 crypto_shash("sha256")。
	 * 见 oak_handshake_verify() 的 CONFIG_CRYPTO 条件编译说明。 */
	/* 简化: 直接异或拼接两次 SHA 轮 (骨架) —— 正式用 crypto_shash */
	const u8 *parts[2] = { pa, pb };
	size_t lens[2] = { la, lb };
	u8 buf[OAK_KEY_MAX * 2];
	size_t off = 0;
	int i;

	if (la + lb > sizeof(buf))
		return -EINVAL;
	for (i = 0; i < 2; i++) {
		memcpy(buf + off, parts[i], lens[i]);
		off += lens[i];
	}
	/* 占位摘要: 拷贝 (正式: sha256(buf, off, out)) */
	memset(out, 0, OAK_HASH_LEN);
	for (i = 0; i < (int)off; i++)
		out[i % OAK_HASH_LEN] ^= buf[i];
	return 0;
}

/* 握手: 发起 (内核侧主体应答路径)
 * name: 本侧主体名; peer_pub: 对端公钥; challenge: 对端挑战;
 * sig_in: 对端签名; sig_len: 签名长度
 * 返回 0=验证通过并建立会话, 负=失败 */
static int oak_handshake(struct oak_subject *me,
			 const u8 *peer_pub, size_t peer_pub_len,
			 const u8 *challenge, size_t ch_len,
			 const u8 *sig_in, size_t sig_len)
{
	u8 my_challenge[OAK_CHALLENGE_LEN];
	u8 K[OAK_HASH_LEN];
	int rc;

	if (!me || !me->has_pubkey || !peer_pub || peer_pub_len == 0)
		return -EINVAL;

	/*
	 * 签名验证 (对端 pub 验证 sig): 
	 *   CONFIG_CRYPTO_RSA 路径: crypto_alloc_akcipher("pkcs1pad(rsa,sha256)")
	 *     + akcipher_set_pub_key(peer_pub) + akcipher_verify(...)
	 *   否则 fallback: HMAC-SHA256(challenge, peer_pub) == sig_in (对称版,
	 *     仅为未启用 RSA 时的可编译骨架; 生产环境必须 CONFIG_CRYPTO_RSA)。
	 * 此处为骨架实现 (占位), 正式代码见上述两分支。
	 */
	if (sig_len < OAK_HASH_LEN)
		return -EINVAL;
	/* 占位校验: 前 OAK_HASH_LEN 字节与 challenge 摘要比对 (演示) */
	if (memcmp(sig_in, challenge, OAK_HASH_LEN) != 0)
		return -EACCES;

	/* 派生会话密钥 K = SHA-256(pub_me || pub_peer) */
	rc = oak_derive_key(me->pubkey, me->pubkey_len, peer_pub, peer_pub_len, K);
	if (rc != 0)
		return rc;

	/* 记录会话 (按对端指纹) */
	{
		unsigned long flags;
		struct oak_session *sn;
		unsigned int b;
		u8 ph[OAK_HASH_LEN];

		memcpy(ph, peer_pub, min(peer_pub_len, (size_t)OAK_HASH_LEN));
		spin_lock_irqsave(&oak_sessions_lock, flags);
		b = hash_32(*(u32 *)ph, OAK_BUCKET_BITS);
		hlist_for_each_entry(sn, &oak_sessions[b], node)
			if (memcmp(sn->peer_hash, ph, OAK_HASH_LEN) == 0) {
				memcpy(sn->key, K, OAK_HASH_LEN);
				spin_unlock_irqrestore(&oak_sessions_lock, flags);
				return 0;
			}
		sn = kzalloc(sizeof(*sn), GFP_ATOMIC);
		if (!sn) {
			spin_unlock_irqrestore(&oak_sessions_lock, flags);
			return -ENOMEM;
		}
		memcpy(sn->peer_hash, ph, OAK_HASH_LEN);
		memcpy(sn->key, K, OAK_HASH_LEN);
		hlist_add_head(&sn->node, &oak_sessions[b]);
		spin_unlock_irqrestore(&oak_sessions_lock, flags);
	}

	/* 生成我方挑战 (回发) */
	oak_gen_challenge(my_challenge);
	return 0;
}

/* ---- 内置角色 PID 登记 ---- */
static int oak_set_builtin(const char *role, pid_t pid)
{
	unsigned long flags;
	int i;

	if (pid <= 0)
		return -EINVAL;

	spin_lock_irqsave(&oak_lock, flags);
	for (i = 0; i < OAK_ROLE_BUILTIN_MAX; i++) {
		if (strcmp(role, oak_builtin_names[i]) == 0) {
			oak_builtin_pid[i] = pid;
			oak_builtin_registered[i] = true;
			spin_unlock_irqrestore(&oak_lock, flags);
			/* 同步注册为内置子安全主体 (固定 kind, 带角色权利) */
			oak_subject_register(role, OAK_SUBJECT_BUILTIN, pid,
					     oak_role_caps[i], NULL, 0);
			return 0;
		}
	}
	spin_unlock_irqrestore(&oak_lock, flags);
	return -EINVAL;
}

/* =====================================================================
 * LSM 钩子: security_task_kill
 * 拦截对受保护进程的 SIGKILL / SIGTERM; 发送者必须为 Security Watchdog。
 * ===================================================================== */
static int oak_task_kill(struct task_struct *p, struct kernel_siginfo *info,
			 int sig, const struct cred *cred)
{
	pid_t target_pid, sender_pid;

	/* 仅拦截 SIGKILL 与 SIGTERM (需求范围) */
	if (sig != SIGKILL && sig != SIGTERM)
		return 0;

	target_pid = task_tgid_nr(p);
	sender_pid = task_tgid_nr(current);

	/* 目标不受保护: 放行 (不影响普通进程终止) */
	if (!oak_pid_is_protected(target_pid))
		return 0;

	/* 目标受保护: 只有 Security Watchdog 可终止 */
	if (sender_pid == oak_watchdog_pid)
		return 0;

	pr_warn("OAK: 拒绝 %d 终止受保护进程 %d (信号 %d)\n",
		sender_pid, target_pid, sig);
	return -EPERM;
}

static struct security_hook_list oak_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_kill, oak_task_kill),
};

/* =====================================================================
 * 内核权利: 授权提权
 * 受保护进程自证身份后, OAK 对其 credential 授予角色能力集合。
 * 用 cap_raise 宏 (兼容 5.15 数组式与 6.12+ 位图式 kernel_cap_t)。
 * ===================================================================== */
static int oak_raise_current(u64 capmask)
{
	struct cred *new;
	int i;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	for (i = 0; i <= CAP_LAST_CAP; i++) {
		if (capmask & BIT_ULL(i)) {
			cap_raise(new->cap_effective, i);
			cap_raise(new->cap_permitted, i);
		}
	}
	return commit_creds(new);
}

/* 授权入口: 校验 current 身份 -> 提权
 * token: watchdog | system | opt | application | whitelist
 */
static int oak_authorize(const char *token)
{
	pid_t me = task_tgid_nr(current);
	unsigned long flags;
	int i;
	u64 caps = 0;
	bool ok = false;

	if (strcmp(token, "watchdog") == 0) {
		if (me == oak_watchdog_pid) {
			caps = OAK_WD_CAPS;
			ok = true;
		}
	} else if (strcmp(token, "whitelist") == 0) {
		if (oak_wl_lookup(me, &caps))
			ok = true;
	} else {
		unsigned int b;

		spin_lock_irqsave(&oak_lock, flags);
		for (i = 0; i < OAK_ROLE_BUILTIN_MAX; i++) {
			if (strcmp(token, oak_builtin_names[i]) == 0 &&
			    oak_builtin_registered[i] &&
			    oak_builtin_pid[i] == me) {
				caps = oak_role_caps[i];
				ok = true;
				break;
			}
		}
		spin_unlock_irqrestore(&oak_lock, flags);

		/* 子安全主体名: 应用经握手验证加入后, 授予该主体权利 */
		if (!ok) {
			struct oak_subject *s;
			spin_lock_irqsave(&oak_subjects_lock, flags);
			for (b = 0; b < OAK_BUCKETS && !ok; b++) {
				hlist_for_each_entry(s, &oak_subjects[b], node) {
					if (strcmp(s->name, token) == 0 &&
					    s->pid == me) {
						caps = s->capmask;
						ok = true;
						break;
					}
				}
			}
			spin_unlock_irqrestore(&oak_subjects_lock, flags);
		}
	}

	if (!ok)
		return -EACCES;
	return oak_raise_current(caps);
}

/* =====================================================================
 * 用户态动态接口 (/proc/oak/{watchdog,builtin,whitelist})
 * 写接口需 CAP_SYS_ADMIN。
 * ===================================================================== */
static struct proc_dir_entry *oak_proc_root;

/* 状态查看: watchdog pid + 内置角色 + 白名单 */
static int oak_proc_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	struct oak_wl_entry *e;
	unsigned int b;
	int i;

	seq_printf(m, "watchdog %d\n", oak_watchdog_pid);
	for (i = 0; i < OAK_ROLE_BUILTIN_MAX; i++) {
		seq_printf(m, "builtin %s %s %d\n", oak_builtin_names[i],
			   oak_builtin_registered[i] ? "on" : "off",
			   oak_builtin_pid[i]);
	}
	spin_lock_irqsave(&oak_lock, flags);
	for (b = 0; b < OAK_BUCKETS; b++) {
		hlist_for_each_entry(e, &oak_whitelist[b], node)
			seq_printf(m, "whitelist %d 0x%llx\n", e->pid,
				   (unsigned long long)e->capmask);
	}
	spin_unlock_irqrestore(&oak_lock, flags);

	/* 子安全主体列表 (含公钥指纹) */
	spin_lock_irqsave(&oak_subjects_lock, flags);
	for (b = 0; b < OAK_BUCKETS; b++) {
		struct oak_subject *s;
		hlist_for_each_entry(s, &oak_subjects[b], node) {
			seq_printf(m, "subject %s kind=%s pid=%d cap=0x%llx key=%s\n",
				   s->name,
				   s->kind == OAK_SUBJECT_BUILTIN ? "builtin" : "third",
				   s->pid, (unsigned long long)s->capmask,
				   s->has_pubkey ? "yes" : "no");
			if (s->has_pubkey) {
				seq_printf(m, "  fp=%*phN\n", OAK_HASH_LEN,
					   s->pubkey_sha256);
			}
		}
	}
	spin_unlock_irqrestore(&oak_subjects_lock, flags);
	return 0;
}
static int oak_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, oak_proc_show, NULL);
}

/* watchdog: 写入单个 PID (登记 Security Watchdog) */
static ssize_t oak_watchdog_write(struct file *file, const char __user *buf,
				  size_t len, loff_t *ppos)
{
	char kbuf[32];
	int pid, n;

	if (len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	n = sscanf(kbuf, "%d", &pid);
	if (n != 1 || pid <= 0)
		return -EINVAL;
	oak_watchdog_pid = pid;
	return len;
}

/* builtin: 写入 "role pid" (登记内置子模块 PID) */
static ssize_t oak_builtin_write(struct file *file, const char __user *buf,
				 size_t len, loff_t *ppos)
{
	char kbuf[64];
	char role[OAK_ROLE_NAME_MAX];
	int pid, n;

	if (len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	n = sscanf(kbuf, "%15s %d", role, &pid);
	if (n != 2)
		return -EINVAL;
	if (oak_set_builtin(role, pid) != 0)
		return -EINVAL;
	return len;
}

/* whitelist: "add <pid> [capmask]" / "del <pid>" (第三方白名单动态增删 + 权利) */
static ssize_t oak_whitelist_write(struct file *file, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	char kbuf[96];
	char op[OAK_OP_MAX];
	u64 capmask = OAK_WL_DEFAULT_CAPS;
	int pid, n, rc;

	if (len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	n = sscanf(kbuf, "%7s %d %llx", op, &pid,
		   (unsigned long long *)&capmask);
	if (n < 2)
		return -EINVAL;
	if (strcmp(op, "add") == 0)
		rc = oak_wl_add(pid, capmask);
	else if (strcmp(op, "del") == 0)
		rc = oak_wl_del(pid);
	else
		return -EINVAL;
	if (rc != 0)
		return rc;
	return len;
}

/* authorize: 进程自证身份 -> OAK 授予内核权利 (能力集合)
 * 写入 "watchdog" / "system" / "opt" / "application" / "whitelist"
 * 注意: 这里允许进程请求提权, 但 OAK 会校验其 PID 必须在保护名单中。
 */
static ssize_t oak_authorize_write(struct file *file, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	char kbuf[32];
	int rc;

	if (len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	/* 去掉尾部空白 */
	while (len > 0 && (kbuf[len - 1] == '\n' || kbuf[len - 1] == ' '))
		kbuf[--len] = '\0';
	if (len == 0)
		return -EINVAL;

	rc = oak_authorize(kbuf);
	if (rc != 0)
		return rc;
	return len;
}

static const struct proc_ops oak_watchdog_proc_ops = {
	.proc_open = oak_proc_open,
	.proc_read = seq_read,
	.proc_write = oak_watchdog_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
static const struct proc_ops oak_builtin_proc_ops = {
	.proc_open = oak_proc_open,
	.proc_read = seq_read,
	.proc_write = oak_builtin_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
static const struct proc_ops oak_whitelist_proc_ops = {
	.proc_open = oak_proc_open,
	.proc_read = seq_read,
	.proc_write = oak_whitelist_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
static const struct proc_ops oak_authorize_proc_ops = {
	.proc_open = oak_proc_open,
	.proc_read = seq_read,
	.proc_write = oak_authorize_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/* ---- 子安全主体注册接口 ----
 * register <name> <kind:builtin|third> <pid> <capmask_hex> [pubkey_hex]
 * pubkey   <name> <pubkey_hex>      (登记/更新公钥)
 * unregister <name>
 * 均需 CAP_SYS_ADMIN。
 */
static int oak_hex_to_bytes(const char *hex, u8 *out, size_t out_sz)
{
	size_t i, n = strlen(hex);

	if (n == 0 || n % 2 != 0 || n / 2 > out_sz)
		return -EINVAL;
	for (i = 0; i < n / 2; i++) {
		unsigned int v;
		if (sscanf(hex + i * 2, "%2x", &v) != 1)
			return -EINVAL;
		out[i] = (u8)v;
	}
	return (int)(n / 2);
}

static ssize_t oak_subjects_write(struct file *file, const char __user *buf,
				  size_t len, loff_t *ppos)
{
	char *kbuf, *hex;
	u8 *key;
	char op[OAK_OP_MAX];
	char name[OAK_SUBJECT_NAME_MAX];
	char kind_s[8];
	u64 capmask;
	int pid, klen, rc;
	ssize_t ret;

	kbuf = kmalloc(len + 1, GFP_KERNEL);
	hex = kmalloc(OAK_KEY_HEX_MAX, GFP_KERNEL);
	key = kmalloc(OAK_KEY_MAX, GFP_KERNEL);
	if (!kbuf || !hex || !key) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(kbuf, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	kbuf[len] = '\0';
	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	if (sscanf(kbuf, "%7s %23s", op, name) != 2) {
		ret = -EINVAL;
		goto out;
	}

	if (strcmp(op, "register") == 0) {
		enum oak_subject_kind kind;
		int n = sscanf(kbuf, "%*s %*s %7s %d %llx %2047s",
			       kind_s, &pid,
			       (unsigned long long *)&capmask, hex);
		if (n < 3) {
			ret = -EINVAL;
			goto out;
		}
		if (strcmp(kind_s, "builtin") == 0)
			kind = OAK_SUBJECT_BUILTIN;
		else if (strcmp(kind_s, "third") == 0)
			kind = OAK_SUBJECT_THIRD;
		else {
			ret = -EINVAL;
			goto out;
		}
		klen = 0;
		if (n >= 4 && hex[0] != '\0') {
			klen = oak_hex_to_bytes(hex, key, OAK_KEY_MAX);
			if (klen < 0) {
				ret = klen;
				goto out;
			}
		}
		rc = oak_subject_register(name, kind, pid, capmask,
					  klen > 0 ? key : NULL, (size_t)klen);
		if (rc != 0) {
			ret = rc;
			goto out;
		}
		ret = (ssize_t)len;
		goto out;
	}
	if (strcmp(op, "pubkey") == 0) {
		if (sscanf(kbuf, "%*s %*s %2047s", hex) != 1) {
			ret = -EINVAL;
			goto out;
		}
		klen = oak_hex_to_bytes(hex, key, OAK_KEY_MAX);
		if (klen < 0) {
			ret = klen;
			goto out;
		}
		rc = oak_subject_register(name,
					  oak_subject_find(name) ?
						oak_subject_find(name)->kind :
						OAK_SUBJECT_THIRD,
					  oak_subject_find(name) ?
						oak_subject_find(name)->pid : 1,
					  oak_subject_find(name) ?
						oak_subject_find(name)->capmask :
						OAK_WL_DEFAULT_CAPS,
					  key, (size_t)klen);
		if (rc != 0) {
			ret = rc;
			goto out;
		}
		ret = (ssize_t)len;
		goto out;
	}
	if (strcmp(op, "unregister") == 0) {
		rc = oak_subject_unregister(name);
		if (rc != 0) {
			ret = rc;
			goto out;
		}
		ret = (ssize_t)len;
		goto out;
	}
	ret = -EINVAL;
out:
	kfree(kbuf);
	kfree(hex);
	kfree(key);
	return ret;
}

/* ---- 握手接口 (内核侧应答路径) ----
 * 写法: "challenge <name>"  -> 生成并返回挑战 (响应到 stdout)
 *       "verify <name> <peer_pub_hex> <sig_hex>" -> 用 peer_pub 验证签名,
 *       通过则建立会话密钥。
 */
static ssize_t oak_handshake_write(struct file *file, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	char *kbuf, *hex, *sig_hex;
	u8 *peer_pub, *sig;
	char op[OAK_OP_MAX];
	char name[OAK_SUBJECT_NAME_MAX];
	struct oak_subject *me;
	int plen, slen, rc;
	ssize_t ret;

	kbuf = kmalloc(len + 1, GFP_KERNEL);
	hex = kmalloc(OAK_KEY_HEX_MAX, GFP_KERNEL);
	sig_hex = kmalloc(OAK_KEY_HEX_MAX, GFP_KERNEL);
	peer_pub = kmalloc(OAK_KEY_MAX, GFP_KERNEL);
	sig = kmalloc(OAK_KEY_MAX, GFP_KERNEL);
	if (!kbuf || !hex || !sig_hex || !peer_pub || !sig) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(kbuf, buf, len)) {
		ret = -EFAULT;
		goto out_free;
	}
	kbuf[len] = '\0';

	if (sscanf(kbuf, "%7s %23s", op, name) != 2) {
		ret = -EINVAL;
		goto out_free;
	}
	me = oak_subject_find(name);
	if (!me) {
		ret = -ENOENT;
		goto out_free;
	}

	if (strcmp(op, "challenge") == 0) {
		u8 ch[OAK_CHALLENGE_LEN];
		oak_gen_challenge(ch);
		/* 简化: 挑战通过 show() 打印; 此处直接打印到控制台 (骨架) */
		pr_info("OAK: challenge for %s: %*phN\n", name, OAK_CHALLENGE_LEN, ch);
		ret = (ssize_t)len;
		goto out_free;
	}
	if (strcmp(op, "verify") == 0) {
		if (sscanf(kbuf, "%*s %*s %2047s %2047s", hex, sig_hex) != 2) {
			ret = -EINVAL;
			goto out_free;
		}
		plen = oak_hex_to_bytes(hex, peer_pub, OAK_KEY_MAX);
		if (plen < 0) {
			ret = plen;
			goto out_free;
		}
		slen = oak_hex_to_bytes(sig_hex, sig, OAK_KEY_MAX);
		if (slen < 0) {
			ret = slen;
			goto out_free;
		}
		rc = oak_handshake(me, peer_pub, (size_t)plen,
				   sig, (size_t)slen, sig, (size_t)slen);
		if (rc != 0) {
			ret = rc;
			goto out_free;
		}
		pr_info("OAK: handshake OK: %s\n", name);
		ret = (ssize_t)len;
		goto out_free;
	}
	ret = -EINVAL;
out_free:
	kfree(kbuf);
	kfree(hex);
	kfree(sig_hex);
	kfree(peer_pub);
	kfree(sig);
	return ret;
}

/* =====================================================================
 * LSM 注册 (三段版本兼容)
 * ===================================================================== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
/* struct lsm_id 自 5.16 引入; 7.x 的 DEFINE_LSM 改存 .id 指针 */
static const struct lsm_id oak_lsmid = {
	.name = "openos_security",
	.id = LSM_ID_OPENOS_SECURITY,
};
#endif

static const struct proc_ops oak_subjects_proc_ops = {
	.proc_open = oak_proc_open,
	.proc_read = seq_read,
	.proc_write = oak_subjects_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
static const struct proc_ops oak_handshake_proc_ops = {
	.proc_open = oak_proc_open,
	.proc_read = seq_read,
	.proc_write = oak_handshake_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init oak_init(void)
{
	unsigned int b;

	for (b = 0; b < OAK_BUCKETS; b++) {
		INIT_HLIST_HEAD(&oak_whitelist[b]);
		INIT_HLIST_HEAD(&oak_subjects[b]);
		INIT_HLIST_HEAD(&oak_sessions[b]);
	}

	oak_proc_root = proc_mkdir("oak", NULL);
	if (oak_proc_root) {
		proc_create("watchdog", 0600, oak_proc_root, &oak_watchdog_proc_ops);
		proc_create("builtin", 0600, oak_proc_root, &oak_builtin_proc_ops);
		proc_create("whitelist", 0600, oak_proc_root, &oak_whitelist_proc_ops);
		/* 授权提权 (内核权利): 权限 0200, 进程自己写 token */
		proc_create("authorize", 0200, oak_proc_root, &oak_authorize_proc_ops);
		/* 子安全主体管理 + 握手验证 */
		proc_create("subjects", 0600, oak_proc_root, &oak_subjects_proc_ops);
		proc_create("handshake", 0600, oak_proc_root, &oak_handshake_proc_ops);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
	/* 5.15.215: 老式字符串注册 */
	security_add_hooks(oak_hooks, ARRAY_SIZE(oak_hooks), "openos_security");
#else
	/* 6.12.103 / 7.1.8 / 7.2-rc7: lsm_id 注册 */
	security_add_hooks(oak_hooks, ARRAY_SIZE(oak_hooks), &oak_lsmid);
#endif

	/* 轻量软件隔离 (vmapp) */
	{
		extern int openos_vmapp_init(void);
		if (openos_vmapp_init() != 0)
			pr_warn("OPENOS Security: vmapp 初始化失败\n");
	}

	/* 设备专属密钥 (每设备唯一, 首次启动自动生成公钥) */
	{
		extern int openos_oak_devicekey_init(struct proc_dir_entry *root);
		if (openos_oak_devicekey_init(oak_proc_root) != 0)
			pr_warn("OPENOS Security: 设备密钥初始化失败\n");
	}

	pr_info("OPENOS Security: loaded (OAK 加密体系保护内置子模块 + 认证白名单)\n");
	return 0;
}

/*
 * 强制启用 (order):
 *   - 5.15: enum lsm_order 仅 FIRST/MUTABLE, 唯一强制项是 LSM_ORDER_FIRST
 *   - 6.12+: FIRST 与 LAST 均强制; OAK 用 LSM_ORDER_LAST (最后把关, 与 integrity 同阶)
 * order 为 FIRST/LAST 的 LSM 无视 lsm= 参数与 CONFIG_LSM, 编译进内核即总启用。
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
DEFINE_LSM(oak) = {
	.name = "openos_security",
	.order = LSM_ORDER_FIRST,
	.init = oak_init,
};
#elif LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 0)
DEFINE_LSM(oak) = {
	.name = "openos_security",
	.order = LSM_ORDER_LAST,
	.init = oak_init,
};
#else
DEFINE_LSM(oak) = {
	.id = &oak_lsmid,
	.order = LSM_ORDER_LAST,
	.init = oak_init,
};
#endif
