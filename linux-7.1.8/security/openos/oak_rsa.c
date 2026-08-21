// SPDX-License-Identifier: GPL-2.0-only
/*
 * OPENOS Security — OPEN RSA 握手协议 (内核实现)
 *
 * 由内核 (OPENOS Security 模块) 提供 OPEN RSA 握手, 供 System/OPT/Application
 * 子安全主体及经 OAK 认证的第三方在系统内部建立安全连接时调用。
 *
 * 协议 (与用户态 openrsa.c 一致):
 *   1. 客户端(软件)用私钥对 数据||毫秒时间戳 签名 -> H1
 *   2. 服务端(内核/系统)用客户端公钥验签 H1 (确认消息来自该客户端)
 *   3. 服务端用私钥对 H1||毫秒时间戳 叠加签名 -> H2
 *   4. 时间戳毫秒级: ktime_get_real_ts64 -> ns -> ms (防重放)
 *
 * 算法: RSA + SHA-256 (内核 crypto API, akcipher + crypto_shash)。
 * 说明: 内核验签用 akcipher_set_pub_key(client_pubkey) +
 *       akcipher_verify 需按算法指定编码 (rsa / pkcs1pad(rsa,sha256) /
 *       pkcs1pad(rsa,sha256-raw)), 本文件提供框架与编码参数选择。
 *
 * 注意: 需 CONFIG_CRYPTO_RSA 与对应 akcipher 模板; 若未配置, 返回 -ENOPROTOOPT。
 */

#include <crypto/akcipher.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/time64.h>

#define OPENRSA_SHA256_LEN  32
#define OPENRSA_TS_MS_LEN   24
#define OPENRSA_INPUT_MAX   4096

/* 验签 akcipher 模板 (PSS 需内核 6.x 以上 akcipher verify 支持;
 * 最通用为 pkcs1pad(rsa,sha256), 若不可用回退 "rsa") */
#define OPENRSA_AKCIPHER     "pkcs1pad(rsa,sha256)"

/* Forward declarations */
s64 openrsa_ms(void);
int openrsa_handshake(const u8 *client_data, size_t len,
		      const u8 *client_pubkey, size_t pubkey_len,
		      const u8 *server_privkey, size_t privkey_len,
		      const u8 *h1_from_client, size_t h1_len,
		      s64 *out_ms,
		      u8 *out_h2, size_t *out_h2_len);

/* ---- 毫秒时间戳 (ktime, CLOCK_REALTIME) ---- */
s64 openrsa_ms(void)
{
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* ---- 构造签名输入: data || ms ---- */
static int openrsa_ts_input(const u8 *data, size_t len, s64 ms,
			    u8 *out, size_t out_sz)
{
	char ts[OPENRSA_TS_MS_LEN];
	int tlen;

	tlen = snprintf(ts, sizeof ts, "%lld", ms);
	if (tlen < 0 || (size_t)tlen + len > out_sz)
		return -1;
	memcpy(out, data, len);
	memcpy(out + len, ts, (size_t)tlen);
	return (int)(len + (size_t)tlen);
}

/* ---- SHA-256 (crypto_shash) ---- */
#if 0
static int openrsa_sha256(const void *data, unsigned int len, u8 out[32])
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
#endif

/* =====================================================================
 * 核心: 服务端握手
 * 验签 H1 (客户端公钥) + 叠加生成 H2 (服务端私钥)
 *
 * 入参:
 *   client_data   客户端原始数据
 *   len           数据长度
 *   client_pubkey 客户端公钥 (DER)
 *   pubkey_len
 *   server_privkey 服务端私钥 (DER)
 *   privkey_len
 *   h1_from_client 客户端签名 H1
 *   h1_len
 *   out_ms         输出本次毫秒时间戳 (可为 NULL)
 *   out_h2         输出叠加签名 H2
 *   out_h2_len     入=缓冲大小, 出=实际长度
 *
 * 返回: 0 成功 / -1 参数错误 / -2 验签失败 / -ENOPROTOOPT 无 RSA 支持
 * ===================================================================== */
int openrsa_handshake(const u8 *client_data, size_t len,
		      const u8 *client_pubkey, size_t pubkey_len,
		      const u8 *server_privkey, size_t privkey_len,
		      const u8 *h1_from_client, size_t h1_len,
		      s64 *out_ms,
		      u8 *out_h2, size_t *out_h2_len)
{
	u8 input[OPENRSA_INPUT_MAX];
	int in_len;
	s64 ms;
	int rc;

	if (!client_data || !client_pubkey || !server_privkey ||
	    !h1_from_client || !out_h2 || !out_h2_len)
		return -EINVAL;
	if (h1_len == 0 || !pubkey_len || !privkey_len)
		return -EINVAL;

	ms = openrsa_ms();
	if (out_ms)
		*out_ms = ms;

	/* 1. 用客户端公钥验签 H1 (确认数据确实来自该客户端) */
	in_len = openrsa_ts_input(client_data, len, ms, input, sizeof input);
	if (in_len < 0)
		return -EINVAL;

	/* 内核 akcipher 验签路径 (需 CONFIG_CRYPTO_RSA)
	 * 骨架: 完整实现用 crypto_alloc_akcipher(OPENRSA_AKCIPHER) +
	 *   akcipher_set_pub_key / akcipher_set_priv_key /
	 *   akcipher_verify(h1, 摘要)。当前为占位 + 失败提示。
	 */
#if IS_ENABLED(CONFIG_CRYPTO_RSA)
	rc = -ENOSYS;	/* TODO: akcipher 验签接入 (见文件头说明) */
#else
	rc = -ENOPROTOOPT;
#endif
	if (rc != 0)
		return rc;	/* 验签失败 -> -2 由调用方映射; 此处返回内核错误 */

	/* 2. 服务端叠加签名 -> H2 = sign(privS, H1||ms) */
	rc = -ENOSYS;	/* TODO: akcipher 签名接入 */
	if (rc != 0)
		return rc;

	return 0;
}

/*
 * 说明 (生产接入要点):
 *   - 验签: crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0)
 *       -> akcipher_set_pub_key(client_pubkey DER)
 *       -> 用 crypto_shash 对 input 算 sha256
 *       -> akcipher_verify(sig=h1, digest)  返回 0 则通过
 *   - 服务端签名 H2: crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0)
 *       -> akcipher_set_priv_key(server_privkey DER)
 *       -> akcipher_sign(digest) 得到 H2
 *   - 若内核该模板不可用 (较老内核), 可用 "rsa" 裸 RSA + 手动 PKCS#1 v1.5
 *     或切换到 CONFIG_CRYPTO_PKCS1_PAD。
 */
