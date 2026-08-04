#ifndef __ACCEL_PPP_LTC_CONFIG_H
#define __ACCEL_PPP_LTC_CONFIG_H

/*
 * Build configuration for the vendored LibTomCrypt subset (CRYPTO=INTERNAL).
 *
 * This must be the single source of truth, and every translation unit that
 * ends up including <tomcrypt.h> must see it.  The reason is hash_state:
 * tomcrypt_hash.h declares it as a union whose members are #ifdef'd per
 * algorithm, so a TU compiled with a different set of LTC_* defines gets a
 * differently sized hash_state.  Since accel-pppd declares MD5_CTX (== a
 * hash_state) on the stack, any mismatch between the library and its callers
 * is silent stack corruption rather than a link error.
 *
 * crypto.h includes this header before "tomcrypt.h", and crypto/CMakeLists.txt
 * force-includes it (-include) when compiling the vendored sources, so both
 * sides are guaranteed to agree.
 *
 * Not used for CRYPTO=TOMCRYPT: a system libtomcrypt carries its own baked-in
 * configuration in its installed headers.
 */

/* Start from nothing and opt in, so refreshing the vendored subset can never
 * silently pull in algorithms we do not compile. */
#define LTC_NOTHING

#define LTC_MD4			/* MSCHAPv1/v2, chap-secrets */
#define LTC_MD5			/* CHAP, RADIUS, L2TP, PPPoE cookies */
#define LTC_SHA1		/* MSCHAPv2, RADIUS, SSTP Compound MAC */
#define LTC_SHA256		/* SSTP Compound MAC (MS-SSTP 3.3.5.2.3) */
#define LTC_DES			/* MSCHAP challenge/response, PPPoE cookies */
#define LTC_HMAC		/* RADIUS Message-Authenticator, SSTP */
#define LTC_HASH_HELPERS	/* hash_memory(), used by hmac_init for long keys */

/*
 * Required even though no block-cipher mode is compiled in: tomcrypt_private.h
 * declares ecb_encrypt_block()/ecb_decrypt_block() in terms of symmetric_ECB
 * unconditionally, and leaving LTC_ECB_MODE undefined also walks into an
 * upstream preprocessor syntax error (see libtomcrypt/UPSTREAM).
 */
#define LTC_ECB_MODE

/* Portable C only.  accel-ppp is built for s390x and 32-bit targets in CI and
 * the runtime CPU dispatch buys nothing on the tiny digests used here. */
#define LTC_NO_ASM

/* Return CRYPT_INVALID_ARG instead of raising SIGABRT on a bad argument; a
 * BRAS must not take the whole daemon down over one malformed packet. */
#define ARGTYPE 4

#define LTC_NO_TEST
#define LTC_NO_FILE

#endif
