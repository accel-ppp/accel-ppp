#ifndef __CRYPTO_H
#define __CRYPTO_H

#ifdef CRYPTO_OPENSSL

/*
 * Suppress OpenSSL 3.0 deprecation warnings for legacy crypto APIs.
 * These low-level APIs (MD4, MD5, SHA1, DES) are deprecated in OpenSSL 3.0
 * but still functional and required for protocol compatibility -- MSCHAP and
 * the PPPoE cookie have no modern replacement to migrate to.
 *
 * This approach is consistent with other major projects:
 * - FreeRADIUS: Uses OPENSSL_API_COMPAT for the same reason
 * - OpenVPN: Uses OPENSSL_API_COMPAT to maintain legacy protocol support
 */
#define OPENSSL_API_COMPAT 0x10100000L

#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

#else /* !CRYPTO_OPENSSL -- LibTomCrypt backed */

#include <stddef.h>

#ifdef CRYPTO_TOMCRYPT
/* System libtomcrypt: its installed headers carry their own configuration. */
#include <tomcrypt.h>
#else
/* Vendored subset: our configuration must be visible before tomcrypt.h.
 * See accel_ltc_config.h for why this cannot be left to -D flags alone. */
#include "accel_ltc_config.h"
#include "tomcrypt.h"
#endif

/* --- message digests --------------------------------------------------- */

typedef hash_state MD4_CTX;
#define MD4_DIGEST_LENGTH 16
#define MD4_Init(c) md4_init(c)
#define MD4_Update(c, data, len) md4_process(c, (const unsigned char *)(data), (unsigned long)(len))
#define MD4_Final(md, c) md4_done(c, (unsigned char *)(md))

typedef hash_state MD5_CTX;
#define MD5_DIGEST_LENGTH 16
#define MD5_Init(c) md5_init(c)
#define MD5_Update(c, data, len) md5_process(c, (const unsigned char *)(data), (unsigned long)(len))
#define MD5_Final(md, c) md5_done(c, (unsigned char *)(md))

typedef hash_state SHA_CTX;
#define SHA_DIGEST_LENGTH 20
#define SHA1_Init(c) sha1_init(c)
#define SHA1_Update(c, data, len) sha1_process(c, (const unsigned char *)(data), (unsigned long)(len))
#define SHA1_Final(md, c) sha1_done(c, (unsigned char *)(md))

#define SHA256_DIGEST_LENGTH 32

/* --- DES --------------------------------------------------------------- */

typedef unsigned char DES_cblock[8];
typedef unsigned char const_DES_cblock[8];
#define DES_key_schedule symmetric_key
#define DES_ENCRYPT 1
#define DES_DECRYPT 0
#define DES_set_key(key, schedule) des_setup((const unsigned char *)(key), 8, 0, schedule)

int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule);
int DES_random_key(DES_cblock *ret);
void DES_ecb_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks, int enc);
void DES_set_odd_parity(DES_cblock *key);
int DES_check_key_parity(const_DES_cblock *key);
int DES_is_weak_key(const_DES_cblock *key);

/* --- EVP digest subset ------------------------------------------------- */

/* Same value as OpenSSL's, so callers can size buffers identically. */
#define EVP_MAX_MD_SIZE 64

typedef struct ltc_hash_descriptor EVP_MD;

typedef struct {
	const EVP_MD *md;
	hash_state st;
} EVP_MD_CTX;

const EVP_MD *EVP_get_digestbyname(const char *name);
const EVP_MD *EVP_md4(void);
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha256(void);

EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *md, void *engine);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t len);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *len);

/* --- HMAC -------------------------------------------------------------- */

unsigned char *HMAC(const EVP_MD *evp, const void *key, int key_len,
		    const unsigned char *data, size_t data_len,
		    unsigned char *md, unsigned int *md_len);

typedef struct {
	const EVP_MD *md;
	hmac_state st;
	/* Kept so that HMAC_Init_ex(ctx, NULL, 0, ...) can restart the same
	 * key, which is how OpenSSL callers reuse a context. */
	unsigned char *key;
	unsigned long key_len;
	int keyed;
} HMAC_CTX;

HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
		 const EVP_MD *md, void *engine);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);

#endif /* CRYPTO_OPENSSL */

#endif
