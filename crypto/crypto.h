#ifndef __CRYPTO_H
#define __CRYPTO_H

#ifdef CRYPTO_OPENSSL

/*
 * Suppress OpenSSL 3.0 deprecation warnings for legacy crypto APIs.
 * These low-level APIs (MD5, SHA1, DES, etc.) are deprecated in OpenSSL 3.0
 * but still functional and required for protocol compatibility.
 *
 * This approach is consistent with other major projects:
 * - FreeRADIUS: Uses OPENSSL_API_COMPAT for the same reason
 * - OpenVPN: Uses OPENSSL_API_COMPAT to maintain legacy protocol support
 *
 * The deprecated functions will remain available in OpenSSL 3.x series.
 * Migration to EVP API may be considered for future major versions.
 */
#define OPENSSL_API_COMPAT 0x10100000L

#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/evp.h>

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif
#else

#ifdef CRYPTO_TOMCRYPT
#include <tomcrypt.h>
#else
#include "tomcrypt.h"
#endif

typedef hash_state MD4_CTX;
#define MD4_DIGEST_LENGTH 16
#define MD4_Init(c) md4_init(c)
#define MD4_Update(c, data, len) md4_process(c, (const unsigned char *)(data), (unsigned long)(len))
#define MD4_Final(md, c) md4_done(c, (unsigned char*)(md))

typedef hash_state MD5_CTX;
#define MD5_DIGEST_LENGTH 16
#define MD5_Init(c) md5_init(c)
#define MD5_Update(c, data, len) md5_process(c, (const unsigned char *)(data), (unsigned long)(len))
#define MD5_Final(md, c) md5_done(c, (unsigned char*)(md))

typedef hash_state SHA_CTX;
#define SHA_DIGEST_LENGTH 20
#define SHA1_Init(c) sha1_init(c)
#define SHA1_Update(c, data, len) sha1_process(c, (const unsigned char *)(data), (unsigned long)(len))
#define SHA1_Final(md, c) sha1_done(c, (unsigned char*)(md))

typedef unsigned char DES_cblock[8];
typedef unsigned char const_DES_cblock[8];
#define DES_key_schedule symmetric_key
#define DES_ENCRYPT 1
#define DES_DECRYPT 0
#define DES_set_key(key, schedule) des_setup((const unsigned char *)key, 8, 0, schedule)

int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule);
int DES_random_key(DES_cblock *ret);
void DES_ecb_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks, int enc);

#endif

#endif
