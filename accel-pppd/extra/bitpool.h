#ifndef __BITPOOL_H
#define __BITPOOL_H

#include <stdint.h>
#include <stddef.h>

/*
 * Fixed-size bit array shared by the IPv4/IPv6 address pool allocators.
 *
 * Semantics: bit == 1 => allocated/unavailable, bit == 0 => free. A freshly
 * calloc'd map is therefore all-free. The caller is responsible for pre-setting
 * to 1 any bit it never wants handed out:
 *   - "remainder" bits in the final word (indices >= count), and
 *   - reserved in-range bits (e.g. the p2p gateway collision),
 * so the word-at-a-time scan can never return a non-existent unit.
 */

typedef unsigned long bm_word_t;
#define BM_WORD_BITS  (8 * sizeof(bm_word_t))
#define BM_NWORDS(n)  (((n) + BM_WORD_BITS - 1) / BM_WORD_BITS)
#define BM_INVALID    ((uint64_t)-1)

static inline void bm_set(bm_word_t *bm, uint64_t i)
{
	bm[i / BM_WORD_BITS] |= (bm_word_t)1 << (i % BM_WORD_BITS);
}

static inline void bm_clear(bm_word_t *bm, uint64_t i)
{
	bm[i / BM_WORD_BITS] &= ~((bm_word_t)1 << (i % BM_WORD_BITS));
}

static inline int bm_test(const bm_word_t *bm, uint64_t i)
{
	return (bm[i / BM_WORD_BITS] >> (i % BM_WORD_BITS)) & 1;
}

/*
 * Find the first free (0) bit at or after `from`, wrapping once back to 0.
 * `count` is the number of valid bits; remainder bits in the final word must
 * already be set to 1 by the caller so they are never returned. Returns the
 * bit index in [0,count), or BM_INVALID if every bit is used.
 *
 * Word-at-a-time: a fully-used word (~w == 0) is skipped in one branch, so the
 * scan is O(1) amortized for a sparse pool and O(count/word) worst case.
 */
static inline uint64_t bm_find_free(const bm_word_t *bm, uint64_t count, uint64_t from)
{
	uint64_t nwords, fw, i;
	unsigned fb;

	if (!count)
		return BM_INVALID;
	if (from >= count)
		from = 0;

	nwords = BM_NWORDS(count);
	fw = from / BM_WORD_BITS;
	fb = from % BM_WORD_BITS;

	/* Probe nwords+1 times: the start word is examined first with its low bits
	 * (< from) masked off, and once more at the end with only those low bits,
	 * so every bit is considered exactly once across the wrap. */
	for (i = 0; i <= nwords; i++) {
		uint64_t word = fw + i;
		bm_word_t inv;

		if (word >= nwords)
			word -= nwords;

		inv = ~bm[word];

		if (i == 0)
			inv &= ~(((bm_word_t)1 << fb) - 1);	/* skip bits below `from` */
		else if (i == nwords)
			inv &= ((bm_word_t)1 << fb) - 1;	/* wrapped: only those skipped bits */

		if (inv) {
			uint64_t bit = word * BM_WORD_BITS + __builtin_ctzl(inv);
			if (bit < count)
				return bit;
		}
	}

	return BM_INVALID;
}

#endif
