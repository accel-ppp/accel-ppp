/*
 * Known-answer tests for the crypto shim.
 *
 * Builds and runs identically against every CRYPTO backend (OPENSSL,
 * TOMCRYPT, INTERNAL).  The point is not to test the underlying libraries --
 * they test themselves -- but to prove the three backends are interchangeable
 * behind crypto.h, which is the property that rotted unnoticed for 14 years
 * because nothing ever built, let alone ran, the non-OpenSSL configurations.
 *
 * Vectors are from RFC 1320 (MD4), RFC 1321 (MD5), FIPS 180 (SHA-1),
 * RFC 2202 (HMAC-MD5/SHA-1), RFC 4231 (HMAC-SHA-256) and the NBS DES set.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"

static int failures;

static void hex(char *out, const unsigned char *in, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		sprintf(out + i * 2, "%02x", in[i]);
}

static void check(const char *what, const unsigned char *got, size_t got_len,
		  const char *expect)
{
	char buf[2 * EVP_MAX_MD_SIZE + 1];

	hex(buf, got, got_len);

	if (strcmp(buf, expect)) {
		printf("FAIL %-24s got %s\n%-29s want %s\n", what, buf, "", expect);
		failures++;
	} else
		printf("ok   %-24s %s\n", what, buf);
}

static void check_int(const char *what, long got, long expect)
{
	if (got != expect) {
		printf("FAIL %-24s got %ld, want %ld\n", what, got, expect);
		failures++;
	} else
		printf("ok   %-24s %ld\n", what, got);
}

/* ---------------------------------------------------------------- digests */

static void test_digests(void)
{
	unsigned char d[EVP_MAX_MD_SIZE];
	MD4_CTX md4;
	MD5_CTX md5;
	SHA_CTX sha;
	int i;

	MD4_Init(&md4);
	MD4_Update(&md4, "abc", 3);
	MD4_Final(d, &md4);
	check("md4(abc)", d, MD4_DIGEST_LENGTH,
	      "a448017aaf21d8525fc10ae87aa6729d");

	MD5_Init(&md5);
	MD5_Update(&md5, "abc", 3);
	MD5_Final(d, &md5);
	check("md5(abc)", d, MD5_DIGEST_LENGTH,
	      "900150983cd24fb0d6963f7d28e17f72");

	SHA1_Init(&sha);
	SHA1_Update(&sha, "abc", 3);
	SHA1_Final(d, &sha);
	check("sha1(abc)", d, SHA_DIGEST_LENGTH,
	      "a9993e364706816aba3e25717850c26c9cd0d89d");

	/* Same input fed one byte at a time: catches block-buffering bugs and
	 * any backend that mishandles repeated small updates, which is how
	 * every caller in accel-ppp actually uses these. */
	MD5_Init(&md5);
	for (i = 0; i < 3; i++)
		MD5_Update(&md5, "abc" + i, 1);
	MD5_Final(d, &md5);
	check("md5(abc) bytewise", d, MD5_DIGEST_LENGTH,
	      "900150983cd24fb0d6963f7d28e17f72");

	/* Spans a 64-byte block boundary. */
	{
		unsigned char big[200];

		memset(big, 'a', sizeof(big));
		SHA1_Init(&sha);
		SHA1_Update(&sha, big, 100);
		SHA1_Update(&sha, big + 100, 100);
		SHA1_Final(d, &sha);
		check("sha1(200*a) split", d, SHA_DIGEST_LENGTH,
		      "e61cfffe0d9195a525fc6cf06ca2d77119c24a40");
	}
}

/* ------------------------------------------------------------------- hmac */

static void test_hmac(void)
{
	unsigned char key[20], d[EVP_MAX_MD_SIZE];
	unsigned int len = 0;

	memset(key, 0x0b, sizeof(key));

	/* RFC 2202 test case 1 */
	if (!HMAC(EVP_md5(), key, 16, (unsigned char *)"Hi There", 8, d, &len)) {
		printf("FAIL hmac-md5 returned NULL\n");
		failures++;
	} else
		check("hmac-md5", d, len, "9294727a3638bb1c13f48ef8158bfc9d");

	if (!HMAC(EVP_sha1(), key, 20, (unsigned char *)"Hi There", 8, d, &len)) {
		printf("FAIL hmac-sha1 returned NULL\n");
		failures++;
	} else
		check("hmac-sha1", d, len,
		      "b617318655057264e28bc0b6fb378c8ef146be00");

	/* RFC 4231 test case 1 -- used by the SSTP Compound MAC */
	if (!HMAC(EVP_sha256(), key, 20, (unsigned char *)"Hi There", 8, d, &len)) {
		printf("FAIL hmac-sha256 returned NULL\n");
		failures++;
	} else
		check("hmac-sha256", d, len,
		      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

	/* Key longer than the block size takes the hash-the-key path. */
	{
		unsigned char longkey[131];
		static const char msg[] =
			"Test Using Larger Than Block-Size Key - Hash Key First";

		memset(longkey, 0xaa, sizeof(longkey));
		if (!HMAC(EVP_sha256(), longkey, sizeof(longkey),
			  (const unsigned char *)msg, sizeof(msg) - 1, d, &len)) {
			printf("FAIL hmac-sha256 longkey returned NULL\n");
			failures++;
		} else
			check("hmac-sha256 longkey", d, len,
			      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
	}
}

/* --------------------------------------------------------------- hmac ctx */

/*
 * The streaming API, used by the RADIUS Message-Authenticator.  Same vector
 * as above, so a backend that streams differently than it one-shots shows up.
 */
static void test_hmac_ctx(void)
{
	unsigned char key[20], d[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	HMAC_CTX *ctx;

	memset(key, 0x0b, sizeof(key));

	ctx = HMAC_CTX_new();
	if (!ctx) {
		printf("FAIL HMAC_CTX_new returned NULL\n");
		failures++;
		return;
	}

	check_int("HMAC_Init_ex", HMAC_Init_ex(ctx, key, 16, EVP_md5(), NULL), 1);
	check_int("HMAC_Update a", HMAC_Update(ctx, (unsigned char *)"Hi ", 3), 1);
	check_int("HMAC_Update b", HMAC_Update(ctx, (unsigned char *)"There", 5), 1);
	check_int("HMAC_Final", HMAC_Final(ctx, d, &len), 1);
	check("hmac-md5 streamed", d, len, "9294727a3638bb1c13f48ef8158bfc9d");

	/* A NULL key means "same key again" -- OpenSSL callers reuse contexts. */
	check_int("HMAC_Init_ex reuse", HMAC_Init_ex(ctx, NULL, 0, NULL, NULL), 1);
	check_int("HMAC_Update reuse",
		  HMAC_Update(ctx, (unsigned char *)"Hi There", 8), 1);
	check_int("HMAC_Final reuse", HMAC_Final(ctx, d, &len), 1);
	check("hmac-md5 reused key", d, len, "9294727a3638bb1c13f48ef8158bfc9d");

	HMAC_CTX_free(ctx);
}

/* -------------------------------------------------------------------- evp */

static void test_evp(void)
{
	static const char *names[] = {"md4", "md5", "sha1", "sha256"};
	static const unsigned int sizes[] = {16, 16, 20, 32};
	unsigned char d[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	EVP_MD_CTX *ctx;
	const EVP_MD *md;
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		md = EVP_get_digestbyname(names[i]);
		if (!md) {
			printf("FAIL EVP_get_digestbyname(%s) -> NULL\n", names[i]);
			failures++;
			continue;
		}

		ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(ctx, md, NULL);
		EVP_DigestUpdate(ctx, "abc", 3);
		EVP_DigestFinal_ex(ctx, d, &len);
		EVP_MD_CTX_free(ctx);

		check_int(names[i], len, sizes[i]);
	}

	/* chap-secrets' username-hash option is user-facing config, so the
	 * spellings OpenSSL accepts have to keep working on every backend. */
	check_int("byname MD5 (upper)", EVP_get_digestbyname("MD5") != NULL, 1);
	check_int("byname SHA1 (upper)", EVP_get_digestbyname("SHA1") != NULL, 1);
	check_int("byname SHA-256 (dash)", EVP_get_digestbyname("SHA-256") != NULL, 1);
	check_int("byname bogus", EVP_get_digestbyname("nosuchhash") != NULL, 0);

	md = EVP_get_digestbyname("md5");
	ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, "abc", 3);
	EVP_DigestFinal_ex(ctx, d, &len);
	EVP_MD_CTX_free(ctx);
	check("evp md5(abc)", d, len, "900150983cd24fb0d6963f7d28e17f72");
}

/* -------------------------------------------------------------------- des */

static void test_des(void)
{
	/* NBS known-answer pair. */
	static const_DES_cblock key = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	static const_DES_cblock pt  = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xe7};
	static const_DES_cblock weak = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
	static const_DES_cblock semiweak = {0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1};
	DES_key_schedule ks;
	DES_cblock ct, back, k1, k2;
	int i;

	check_int("DES_set_key_checked", DES_set_key_checked(&key, &ks), 0);

	DES_ecb_encrypt(&pt, &ct, &ks, DES_ENCRYPT);
	check("des-ecb", ct, 8, "c95744256a5ed31d");

	DES_ecb_encrypt((const_DES_cblock *)&ct, &back, &ks, DES_DECRYPT);
	check_int("des-ecb roundtrip", memcmp(back, pt, 8), 0);

	/*
	 * Regression test for the original shim's DES_ecb_encrypt(), which
	 * called des_done() on the schedule after every block.  pppoe.c
	 * encrypts three blocks with one long-lived serv->des_ks, so only the
	 * first would have used a live key.  Encrypt the same block three
	 * times through one schedule; all three must be identical.
	 */
	for (i = 0; i < 3; i++) {
		DES_cblock again;

		DES_ecb_encrypt(&pt, &again, &ks, DES_ENCRYPT);
		if (memcmp(again, ct, 8)) {
			printf("FAIL des schedule reuse broke on block %d\n", i);
			failures++;
			break;
		}
	}
	if (i == 3)
		printf("ok   %-24s schedule survives reuse\n", "des-ecb reuse");

	/*
	 * Regression test for DES_is_weak_key(), which looped to
	 * sizeof(weak_keys) == 128 rather than the 16-element count and read
	 * 112 entries past the end of the table.
	 */
	check_int("weak key detected", DES_is_weak_key(&weak), 1);
	check_int("semi-weak detected", DES_is_weak_key(&semiweak), 1);
	check_int("strong key accepted", DES_is_weak_key(&key), 0);
	check_int("weak key rejected", DES_set_key_checked(&weak, &ks), -2);

	/* Odd parity is what DES_set_key_checked demands; a key with a byte
	 * flipped to even parity must be refused. */
	{
		DES_cblock bad;

		memcpy(bad, key, 8);
		bad[0] ^= 1;
		check_int("bad parity rejected",
			  DES_set_key_checked((const_DES_cblock *)&bad, &ks), -1);
	}

	/*
	 * DES_random_key() used to ignore read() errors and report success
	 * unconditionally, so a failure produced a constant key and therefore
	 * predictable PPPoE cookies.
	 */
	check_int("DES_random_key ok", DES_random_key(&k1), 1);
	check_int("DES_random_key ok", DES_random_key(&k2), 1);
	check_int("random keys differ", memcmp(k1, k2, 8) != 0, 1);
	check_int("random key not weak", DES_is_weak_key((const_DES_cblock *)&k1), 0);
	check_int("random key odd parity",
		  DES_check_key_parity((const_DES_cblock *)&k1), 1);
}

int main(void)
{
#if defined(CRYPTO_OPENSSL)
	const char *backend = "OPENSSL";
#elif defined(CRYPTO_TOMCRYPT)
	const char *backend = "TOMCRYPT";
#else
	const char *backend = "INTERNAL";
#endif

	printf("crypto backend: %s\n\n", backend);

	ap_crypto_init();

	test_digests();
	test_hmac();
	test_hmac_ctx();
	test_evp();
	test_des();

	printf("\n%s: %d failure(s)\n", backend, failures);

	return failures ? 1 : 0;
}
