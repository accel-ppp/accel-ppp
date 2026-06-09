/*
 * Standalone sanity test for the bitmap IP-pool allocator core.
 *
 * Not part of the cmake build. Compile and run with:
 *   gcc -O2 -Wall -o /tmp/bitpool_test accel-pppd/extra/bitpool_test.c && /tmp/bitpool_test
 *
 * It validates:
 *   - bitpool.h: bm_set/clear/test, bm_find_free wrap + remainder bits +
 *     exhaustion, and that every freed bit is re-handed exactly once.
 *   - IPv4 addr<->bit round-trip for p2p and net30 geometry, incl. alignment
 *     and out-of-range rejection.
 *   - IPv6 prefix<->bit round-trip (the exact helpers used by ipv6pool.c),
 *     cross-checked against __int128 reference math, incl. prefix_len==128,
 *     mask<=64 / mask>64, and an unaligned base.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "bitpool.h"

static int failures;
#define CHECK(cond) do { if (!(cond)) { \
	fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

/* ---- mimic a finalized range bitmap: count bits free, remainder bits set ---- */
static bm_word_t *make_map(uint64_t count)
{
	uint64_t nw = BM_NWORDS(count), b;
	bm_word_t *bm = calloc(nw, sizeof(bm_word_t));
	for (b = count; b < nw * BM_WORD_BITS; b++)
		bm_set(bm, b);
	return bm;
}

static void test_bitmap_basic(void)
{
	uint64_t count = 200;		/* not a multiple of 64 -> exercises remainder */
	bm_word_t *bm = make_map(count);
	uint64_t i, bit, n = 0;
	char *seen = calloc(count, 1);

	/* allocate the whole pool via rolling cursor; each bit unique and < count */
	uint64_t cursor = 0;
	while ((bit = bm_find_free(bm, count, cursor)) != BM_INVALID) {
		CHECK(bit < count);
		CHECK(!seen[bit]);
		seen[bit] = 1;
		bm_set(bm, bit);
		cursor = bit + 1;
		n++;
		CHECK(n <= count);
	}
	CHECK(n == count);				/* exactly count handed out */
	for (i = 0; i < count; i++)
		CHECK(seen[i]);				/* every unit handed out once */
	CHECK(bm_find_free(bm, count, 0) == BM_INVALID); /* exhausted */

	/* free three, confirm exactly those three come back */
	bm_clear(bm, 5); bm_clear(bm, 130); bm_clear(bm, 199);
	memset(seen, 0, count);
	for (n = 0; (bit = bm_find_free(bm, count, 0)) != BM_INVALID; n++) {
		CHECK(bit == 5 || bit == 130 || bit == 199);
		seen[bit] = 1; bm_set(bm, bit);
	}
	CHECK(n == 3 && seen[5] && seen[130] && seen[199]);

	/* wrap-around: only bit 1 free, search starting past it must still find it */
	memset(bm, 0xff, BM_NWORDS(count) * sizeof(bm_word_t));
	bm_clear(bm, 1);
	CHECK(bm_find_free(bm, count, 50) == 1);
	CHECK(bm_find_free(bm, count, 0) == 1);

	/* zero-size pool */
	CHECK(bm_find_free(bm, 0, 0) == BM_INVALID);

	free(seen);
	free(bm);
	printf("ok  bitmap basic/wrap/remainder/exhaustion\n");
}

/* ---- IPv4 geometry (mirrors ippool.c range_addr_to_bit / bit->addr) ---- */
static uint64_t v4_addr_to_bit(uint32_t start, uint32_t step, int peer_off,
			       uint64_t count, uint32_t peer)
{
	uint32_t base, delta;
	uint64_t bit;
	if (peer < (uint32_t)peer_off) return BM_INVALID;
	base = peer - peer_off;
	if (base < start) return BM_INVALID;
	delta = base - start;
	if (delta % step) return BM_INVALID;
	bit = delta / step;
	if (bit >= count) return BM_INVALID;
	return bit;
}

static void test_v4(void)
{
	/* p2p: 10.0.0.0 - 10.0.1.255 (512 addrs), step 1, peer_off 0 */
	uint32_t start = (10u << 24);
	uint32_t end = (10u << 24) | 0x1ff;
	uint64_t count = (uint64_t)(end - start) + 1;
	uint64_t i;
	CHECK(count == 512);
	for (i = 0; i < count; i++) {
		uint32_t peer = start + (uint32_t)i * 1 + 0;
		CHECK(v4_addr_to_bit(start, 1, 0, count, peer) == i);
	}
	CHECK(v4_addr_to_bit(start, 1, 0, count, start - 1) == BM_INVALID);
	CHECK(v4_addr_to_bit(start, 1, 0, count, end + 1) == BM_INVALID);
	printf("ok  v4 p2p round-trip (512 addrs)\n");

	/* net30: same range, step 4, gw_off 1, peer_off 2 -> 128 blocks */
	count = ((uint64_t)(end - start) + 1) / 4;
	CHECK(count == 128);
	for (i = 0; i < count; i++) {
		uint32_t base = start + (uint32_t)i * 4;
		uint32_t peer = base + 2;	/* .2 client */
		CHECK(v4_addr_to_bit(start, 4, 2, count, peer) == i);
		/* .1 router and .0/.3 are NOT valid leases */
		CHECK(v4_addr_to_bit(start, 4, 2, count, base + 1) == BM_INVALID);
		CHECK(v4_addr_to_bit(start, 4, 2, count, base + 0) == BM_INVALID);
		CHECK(v4_addr_to_bit(start, 4, 2, count, base + 3) == BM_INVALID);
	}
	printf("ok  v4 net30 round-trip + alignment (128 blocks)\n");
}

/* ---- IPv6 helpers: EXACT copies of the ones in ipv6pool.c ---- */
static void in6_sub(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
	int i, borrow = 0;
	for (i = 15; i >= 0; i--) {
		int v = (int)a[i] - b[i] - borrow;
		if (v < 0) { v += 256; borrow = 1; } else borrow = 0;
		o[i] = v;
	}
}
static int in6_shr_u64(const uint8_t *d, int shift, uint64_t *out)
{
	int p; uint64_t v = 0;
	for (p = 0; p < 64; p++) {
		int sp = shift + p;
		if (sp < 128 && (d[15 - (sp >> 3)] & (1 << (sp & 7)))) v |= (uint64_t)1 << p;
	}
	for (p = shift + 64; p < 128; p++)
		if (d[15 - (p >> 3)] & (1 << (p & 7))) return -1;
	*out = v; return 0;
}
static void in6_index_to_addr(uint8_t *out, const uint8_t *start, uint64_t i, int shift)
{
	uint8_t add[16] = { 0 }; int p, b, carry = 0;
	for (p = 0; p < 64; p++)
		if (i & ((uint64_t)1 << p)) { int sp = shift + p; if (sp < 128) add[15 - (sp >> 3)] |= (1 << (sp & 7)); }
	memcpy(out, start, 16);
	for (b = 15; b >= 0; b--) { int s = out[b] + add[b] + carry; out[b] = s & 0xff; carry = s >> 8; }
}
static int in6_cmp(const uint8_t *a, const uint8_t *b)
{
	int i; for (i = 0; i < 16; i++) { if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; } return 0;
}
static uint64_t v6_addr_to_bit(const uint8_t *start, int shift, uint64_t count, const uint8_t *addr)
{
	uint8_t delta[16]; uint64_t i; int p;
	if (in6_cmp(addr, start) < 0) return BM_INVALID;
	in6_sub(delta, addr, start);
	for (p = 0; p < shift; p++)
		if (delta[15 - (p >> 3)] & (1 << (p & 7))) return BM_INVALID;
	if (in6_shr_u64(delta, shift, &i)) return BM_INVALID;
	if (i >= count) return BM_INVALID;
	return i;
}

/* ---- __int128 reference ---- */
static __uint128_t to_u128(const uint8_t a[16]) { __uint128_t v = 0; int i; for (i = 0; i < 16; i++) v = (v << 8) | a[i]; return v; }
static void from_u128(uint8_t a[16], __uint128_t v) { int i; for (i = 15; i >= 0; i--) { a[i] = v & 0xff; v >>= 8; } }

static void test_v6_one(const char *label, const uint8_t start[16], int mask, int prefix_len)
{
	int shift = 128 - prefix_len;
	__uint128_t s = to_u128(start);
	__uint128_t hostmask = (mask == 0) ? ~(__uint128_t)0 : (((__uint128_t)1 << (128 - mask)) - 1);
	__uint128_t end = s | hostmask;
	uint8_t endb[16]; uint8_t delta[16]; uint64_t span, count, i, step_lo;
	__uint128_t step = (__uint128_t)1 << shift;

	from_u128(endb, end);
	in6_sub(delta, endb, start);
	CHECK(in6_shr_u64(delta, shift, &span) == 0);
	count = span + 1;
	CHECK(count == (uint64_t)(((end - s) >> shift) + 1));	/* matches reference */

	/* round-trip boundary + sampled indices */
	uint64_t samples[] = { 0, 1, count / 2, count - 1 };
	for (size_t k = 0; k < sizeof(samples) / sizeof(samples[0]); k++) {
		i = samples[k];
		if (i >= count) continue;
		uint8_t addr[16]; in6_index_to_addr(addr, start, i, shift);
		__uint128_t ref = s + (__uint128_t)i * step;
		uint8_t refb[16]; from_u128(refb, ref);
		CHECK(memcmp(addr, refb, 16) == 0);			/* bit->addr matches ref */
		CHECK(v6_addr_to_bit(start, shift, count, addr) == i);	/* addr->bit round-trip */
		/* misaligned address (only when there is room below a prefix) */
		if (shift > 0) {
			uint8_t bad[16]; memcpy(bad, addr, 16); bad[15] |= 1;
			CHECK(v6_addr_to_bit(start, shift, count, bad) == BM_INVALID);
		}
	}
	/* below start and past end reject */
	if (s > 0) { uint8_t below[16]; from_u128(below, s - 1); CHECK(v6_addr_to_bit(start, shift, count, below) == BM_INVALID); }
	{ uint8_t past[16]; from_u128(past, s + (__uint128_t)count * step); CHECK(v6_addr_to_bit(start, shift, count, past) == BM_INVALID); }

	(void)step_lo;
	printf("ok  v6 %s (mask=%d plen=%d shift=%d count=%llu)\n",
	       label, mask, prefix_len, shift, (unsigned long long)count);
}

static void test_v6(void)
{
	uint8_t a[16];

	/* 2001:db8::/48 carved into /64s -> 65536 prefixes (mask<=64) */
	memset(a, 0, 16); a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8;
	test_v6_one("/48->/64", a, 48, 64);

	/* mask>64: 2001:db8:0:0:8000::/72 -> /80 (mask>64 path) */
	memset(a, 0, 16); a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8; a[8] = 0x80;
	test_v6_one("/72->/80", a, 72, 80);

	/* prefix_len == 128: single addresses, step 1 */
	memset(a, 0, 16); a[0] = 0xfc; a[15] = 0x00;
	test_v6_one("/120->/128", a, 120, 128);

	/* unaligned base within the mask host bits (start not on a /64 boundary) */
	memset(a, 0, 16); a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8; a[7] = 0x05;
	test_v6_one("/48->/64 unaligned base", a, 48, 64);

	/* big delegation: /32 -> /56 = 2^24 prefixes (the cap boundary) */
	memset(a, 0, 16); a[0] = 0x2a; a[1] = 0x00;
	test_v6_one("/32->/56 (cap)", a, 32, 56);
}

int main(void)
{
	test_bitmap_basic();
	test_v4();
	test_v6();
	if (failures) {
		printf("\n%d CHECK(s) FAILED\n", failures);
		return 1;
	}
	printf("\nALL TESTS PASSED\n");
	return 0;
}
