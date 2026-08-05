#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <pthread.h>

#include "crypto.h"

#ifdef CRYPTO_OPENSSL

#include <openssl/ssl.h>

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L) && !defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/provider.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
/*
 * Pre-1.1.0 OpenSSL leaves locking to the application: without these
 * callbacks libcrypto is not thread-safe, and accel-pppd is threaded.
 */
static pthread_mutex_t *ssl_lock_cs;

static unsigned long ssl_thread_id(void)
{
	return (unsigned long)pthread_self();
}

static void ssl_lock(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&ssl_lock_cs[type]);
	else
		pthread_mutex_unlock(&ssl_lock_cs[type]);
}

static void ssl_lock_init(void)
{
	int i;

	ssl_lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&ssl_lock_cs[i], NULL);

	CRYPTO_set_id_callback(ssl_thread_id);
	CRYPTO_set_locking_callback(ssl_lock);
}
#endif

void ap_crypto_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ssl_lock_init();
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L) && !defined(LIBRESSL_VERSION_NUMBER)
	/* Handles are intentionally not released: they live for the life of
	 * the process, and unloading would break every later digest. */
	OSSL_PROVIDER_load(NULL, "default");
	OSSL_PROVIDER_load(NULL, "legacy");
#endif
}

#else /* !CRYPTO_OPENSSL */

#if !defined(LTC_MD4) || !defined(LTC_MD5) || !defined(LTC_SHA1) || \
    !defined(LTC_SHA256) || !defined(LTC_DES) || !defined(LTC_HMAC)
#error "libtomcrypt is missing an algorithm accel-ppp requires (MD4, MD5, SHA1, SHA256, DES, HMAC)"
#endif

/* ----------------------------------------------------------------------
 * one-time setup
 * ---------------------------------------------------------------------- */

static pthread_once_t crypto_once = PTHREAD_ONCE_INIT;
static int urandom_fd = -1;

static void crypto_init(void)
{
	/* HMAC takes a registry index rather than a descriptor, so the hashes
	 * we expose have to be registered before find_hash() can see them. */
	register_hash(&md4_desc);
	register_hash(&md5_desc);
	register_hash(&sha1_desc);
	register_hash(&sha256_desc);

	urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
}

void ap_crypto_init(void)
{
	pthread_once(&crypto_once, crypto_init);
}

/* ----------------------------------------------------------------------
 * DES
 * ---------------------------------------------------------------------- */

static const unsigned char odd_parity[256] = {
		1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
	 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
	 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
	 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
	 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
	 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
	 97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
	112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
	128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
	145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
	161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
	176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
	193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
	208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
	224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
	241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
};

void DES_set_odd_parity(DES_cblock *key)
{
	unsigned int i;

	for (i = 0; i < sizeof(DES_cblock); i++)
		(*key)[i] = odd_parity[(*key)[i]];
}

int DES_check_key_parity(const_DES_cblock *key)
{
	unsigned int i;

	for (i = 0; i < sizeof(DES_cblock); i++) {
		if ((*key)[i] != odd_parity[(*key)[i]])
			return 0;
	}

	return 1;
}

static const DES_cblock weak_keys[] = {
	/* weak keys */
	{0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
	{0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE},
	{0x1F,0x1F,0x1F,0x1F,0x0E,0x0E,0x0E,0x0E},
	{0xE0,0xE0,0xE0,0xE0,0xF1,0xF1,0xF1,0xF1},
	/* semi-weak keys */
	{0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE},
	{0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01},
	{0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1},
	{0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E},
	{0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1},
	{0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01},
	{0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE},
	{0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E},
	{0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E},
	{0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01},
	{0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
	{0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1}
};

int DES_is_weak_key(const_DES_cblock *key)
{
	/* NB: the element count, not sizeof(weak_keys).  The original shim
	 * looped to sizeof(weak_keys) == 128 and read 112 entries past the
	 * end of the array. */
	unsigned int i;

	for (i = 0; i < sizeof(weak_keys) / sizeof(weak_keys[0]); i++)
		if (!memcmp(weak_keys[i], *key, sizeof(DES_cblock)))
			return 1;

	return 0;
}

/* Returns 0 on success, -1 on parity error, -2 on weak key, as OpenSSL does.
 * Like OpenSSL, the schedule is left untouched when the key is rejected. */
int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule)
{
	if (!DES_check_key_parity(key))
		return -1;

	if (DES_is_weak_key(key))
		return -2;

	return des_setup((const unsigned char *)key, 8, 0, schedule) == CRYPT_OK ? 0 : -3;
}

/* Returns 1 on success and 0 on failure, as OpenSSL does.  The original shim
 * ignored read() failures entirely and always reported success, so a missing
 * or exhausted /dev/urandom silently produced a constant key. */
int DES_random_key(DES_cblock *ret)
{
	pthread_once(&crypto_once, crypto_init);

	if (urandom_fd < 0)
		return 0;

	for (;;) {
		size_t off = 0;

		while (off < sizeof(DES_cblock)) {
			ssize_t n = read(urandom_fd, (unsigned char *)ret + off,
					 sizeof(DES_cblock) - off);
			if (n > 0)
				off += n;
			else if (n < 0 && errno == EINTR)
				continue;
			else
				return 0;
		}

		if (!DES_is_weak_key((const_DES_cblock *)ret))
			break;
	}

	DES_set_odd_parity(ret);

	return 1;
}

void DES_ecb_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks, int enc)
{
	/* No des_done() here.  The original shim tore the schedule down after
	 * every single block, which breaks any caller that reuses a schedule
	 * across calls -- pppoe.c encrypts three blocks with one long-lived
	 * serv->des_ks.  It only ever worked because des_done() happens to be
	 * a no-op in libtomcrypt; that is not part of its contract. */
	if (enc == DES_ENCRYPT)
		des_ecb_encrypt((const unsigned char *)input, (unsigned char *)output, ks);
	else if (enc == DES_DECRYPT)
		des_ecb_decrypt((const unsigned char *)input, (unsigned char *)output, ks);
}

/* ----------------------------------------------------------------------
 * EVP digest subset
 * ---------------------------------------------------------------------- */

const EVP_MD *EVP_md4(void)    { return &md4_desc; }
const EVP_MD *EVP_md5(void)    { return &md5_desc; }
const EVP_MD *EVP_sha1(void)   { return &sha1_desc; }
const EVP_MD *EVP_sha256(void) { return &sha256_desc; }

/*
 * OpenSSL's lookup is case-insensitive and tolerates the dashed spellings
 * ("SHA-256"), and the chap-secrets "username-hash" option is user-facing
 * config, so accept the same spellings here rather than silently rejecting
 * a config that works on an OpenSSL build.
 */
const EVP_MD *EVP_get_digestbyname(const char *name)
{
	char buf[16];
	size_t i, n = 0;

	if (!name)
		return NULL;

	for (i = 0; name[i]; i++) {
		if (name[i] == '-' || name[i] == '_')
			continue;
		if (n + 1 >= sizeof(buf))
			return NULL;
		buf[n++] = tolower((unsigned char)name[i]);
	}
	buf[n] = 0;

	if (!strcmp(buf, "sha"))
		return &sha1_desc;
	if (!strcmp(buf, "md4"))
		return &md4_desc;
	if (!strcmp(buf, "md5"))
		return &md5_desc;
	if (!strcmp(buf, "sha1"))
		return &sha1_desc;
	if (!strcmp(buf, "sha256"))
		return &sha256_desc;

	return NULL;
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
	EVP_MD_CTX *ctx = calloc(1, sizeof(*ctx));

	return ctx;
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	if (!ctx)
		return;

	zeromem(ctx, sizeof(*ctx));
	free(ctx);
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *md, void *engine)
{
	if (!ctx || !md)
		return 0;

	ctx->md = md;

	return md->init(&ctx->st) == CRYPT_OK;
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t len)
{
	if (!ctx || !ctx->md)
		return 0;

	return ctx->md->process(&ctx->st, (const unsigned char *)data,
				(unsigned long)len) == CRYPT_OK;
}

int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *len)
{
	if (!ctx || !ctx->md)
		return 0;

	if (ctx->md->done(&ctx->st, md) != CRYPT_OK)
		return 0;

	if (len)
		*len = ctx->md->hashsize;

	return 1;
}

/* ----------------------------------------------------------------------
 * HMAC
 * ---------------------------------------------------------------------- */

unsigned char *HMAC(const EVP_MD *evp, const void *key, int key_len,
		    const unsigned char *data, size_t data_len,
		    unsigned char *md, unsigned int *md_len)
{
	unsigned char tmp[EVP_MAX_MD_SIZE];
	unsigned long outlen;
	int idx;

	if (!evp || !md)
		return NULL;

	pthread_once(&crypto_once, crypto_init);

	idx = find_hash(evp->name);
	if (idx < 0)
		return NULL;

	/* Digest into a scratch buffer, not straight into md: sstp's Compound
	 * MAC computes in place (output inside the input buffer), which works
	 * with OpenSSL because the input is fully consumed before the digest
	 * is written.  hmac_memory() happens to behave the same way, but it
	 * can dispatch to a hash descriptor's own hmac_block() -- so with a
	 * system libtomcrypt that is somebody else's code.  Don't depend on it. */
	outlen = sizeof(tmp);
	if (hmac_memory(idx, (const unsigned char *)key, (unsigned long)key_len,
			data, (unsigned long)data_len, tmp, &outlen) != CRYPT_OK)
		return NULL;

	memcpy(md, tmp, outlen);
	zeromem(tmp, sizeof(tmp));

	if (md_len)
		*md_len = outlen;

	return md;
}

/*
 * Streaming counterpart.  All of these return 1 on success and 0 on failure,
 * as OpenSSL's do -- callers written against OpenSSL check for != 1.
 */

HMAC_CTX *HMAC_CTX_new(void)
{
	return calloc(1, sizeof(HMAC_CTX));
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (!ctx)
		return;

	if (ctx->key) {
		zeromem(ctx->key, ctx->key_len);
		free(ctx->key);
	}

	zeromem(ctx, sizeof(*ctx));
	free(ctx);
}

int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
		 const EVP_MD *md, void *engine)
{
	int idx;

	if (!ctx)
		return 0;

	pthread_once(&crypto_once, crypto_init);

	if (md)
		ctx->md = md;
	if (!ctx->md)
		return 0;

	idx = find_hash(ctx->md->name);
	if (idx < 0)
		return 0;

	/* A NULL key means "same key again", so keep our own copy of it. */
	if (key) {
		unsigned char *copy = NULL;

		if (key_len < 0)
			return 0;

		if (key_len) {
			copy = malloc(key_len);
			if (!copy)
				return 0;
			memcpy(copy, key, key_len);
		}

		if (ctx->key) {
			zeromem(ctx->key, ctx->key_len);
			free(ctx->key);
		}
		ctx->key = copy;
		ctx->key_len = key_len;
		ctx->keyed = 1;
	} else if (!ctx->keyed)
		return 0;

	return hmac_init(&ctx->st, idx, ctx->key, ctx->key_len) == CRYPT_OK;
}

int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len)
{
	if (!ctx || !ctx->md)
		return 0;

	return hmac_process(&ctx->st, data, (unsigned long)len) == CRYPT_OK;
}

int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
	unsigned long outlen;

	if (!ctx || !ctx->md || !md)
		return 0;

	outlen = ctx->md->hashsize;
	if (hmac_done(&ctx->st, md, &outlen) != CRYPT_OK)
		return 0;

	if (len)
		*len = outlen;

	return 1;
}

#endif /* !CRYPTO_OPENSSL */
