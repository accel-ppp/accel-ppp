#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <endian.h>

#include "triton.h"
#include "events.h"
#include "ipdb.h"
#include "list.h"
#include "log.h"
#include "spinlock.h"
#include "ap_session.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "bitpool.h"
#include "memdebug.h"

/*
 * Bitmap IPv6 address (IA_NA) and delegated-prefix (IA_PD) pools.
 *
 * Same model as the IPv4 pool: each pool holds a list of contiguous ranges,
 * each range owns one bitmap indexing per-lease prefixes (bit i -> start +
 * i*2^(128-prefix_len)). A lease is a per-session malloc wrapper that embeds
 * the single ipv6db_addr_t node linked into the item's addr/prefix list. The
 * whole set is rebuilt and swapped on EV_CONFIG_RELOAD with a reconcile pass.
 *
 * TODO: a sparse/hierarchical allocator would lift IPPOOL_MAX_BITS; the dense
 * bitmap requires (prefix_len - mask) <= 24, i.e. <= ~16.7M prefixes per range.
 */

#define IPPOOL_MAX_BITS (1u << 24)
#define IPPOOL_MAX_SHIFT 24		/* prefix_len - mask cap (2^24 entries) */

enum ippool_type {
	IPPOOL_ADDRESS,
	IPPOOL_PREFIX,
};

enum {
	ORPHAN_KEEP = 0,
	ORPHAN_DISCONNECT,
};

struct ip6_range {
	struct list_head entry;
	struct in6_addr start;
	int prefix_len;
	int shift;		/* 128 - prefix_len */
	uint64_t count;		/* number of prefixes = bits */
	uint64_t cursor;
	uint64_t used;
	bm_word_t *bitmap;
};

struct ip6_pool {
	struct list_head entry;
	char *name;		/* NULL for default pool */
	struct ip6_pool *next;
	struct list_head ranges;
	spinlock_t lock;
};

struct pool_set {
	struct list_head ippools;	/* named NA pools */
	struct list_head dppools;	/* named PD pools */
	struct ip6_pool *def_ippool;
	struct ip6_pool *def_dppool;
	struct in6_addr gw_addr;
	int orphan_policy;
};

struct ip6_lease {
	struct ip6_pool *pool;
	struct ip6_range *range;
	struct ipv6db_item_t it;	/* ses->ipv6 = &it */
	struct ipv6db_addr_t node;	/* linked into it.addr_list */
};

struct dp_lease {
	struct ip6_pool *pool;
	struct ip6_range *range;
	struct ipv6db_prefix_t it;	/* ses->ipv6_dp = &it */
	struct ipv6db_addr_t node;	/* linked into it.prefix_list */
};

struct disc_node {
	struct list_head entry;
	struct ap_session *ses;
};

static struct ipdb_t ipdb;

static pthread_rwlock_t pool_set_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct pool_set *cur_set;

#ifdef RADIUS
static int conf_vendor = 0;
static int conf_dppool_attr = 171; // Delegated-IPv6-Prefix-Pool
static int conf_ippool_attr = 172; // Stateful-IPv6-Address-Pool
#endif

/* ===== 128-bit helpers (big-endian s6_addr[16]) ===== */

static int in6_addr_cmp(const struct in6_addr *n1, const struct in6_addr *n2)
{
	int i;

	for (i = 0; i < 16; i++) {
		if (n1->s6_addr[i] < n2->s6_addr[i])
			return -1;
		if (n1->s6_addr[i] > n2->s6_addr[i])
			return 1;
	}

	return 0;
}

/* o = a - b (assumes a >= b) */
static void in6_sub(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
	int i, borrow = 0;

	for (i = 15; i >= 0; i--) {
		int v = (int)a[i] - b[i] - borrow;
		if (v < 0) {
			v += 256;
			borrow = 1;
		} else
			borrow = 0;
		o[i] = v;
	}
}

/* floor(delta >> shift) into *out; returns -1 if it doesn't fit in uint64 */
static int in6_shr_u64(const uint8_t *d, int shift, uint64_t *out)
{
	int p;
	uint64_t v = 0;

	for (p = 0; p < 64; p++) {
		int sp = shift + p;
		if (sp < 128 && (d[15 - (sp >> 3)] & (1 << (sp & 7))))
			v |= (uint64_t)1 << p;
	}
	for (p = shift + 64; p < 128; p++) {
		if (d[15 - (p >> 3)] & (1 << (p & 7)))
			return -1;
	}

	*out = v;
	return 0;
}

/* out = start + (i << shift) */
static void in6_index_to_addr(struct in6_addr *out, const struct in6_addr *start,
			      uint64_t i, int shift)
{
	uint8_t add[16] = { 0 };
	int p, b, carry = 0;

	for (p = 0; p < 64; p++) {
		if (i & ((uint64_t)1 << p)) {
			int sp = shift + p;
			if (sp < 128)
				add[15 - (sp >> 3)] |= (1 << (sp & 7));
		}
	}

	memcpy(out, start, 16);
	for (b = 15; b >= 0; b--) {
		int s = out->s6_addr[b] + add[b] + carry;
		out->s6_addr[b] = s & 0xff;
		carry = s >> 8;
	}
}

/* bit index of a leased prefix within a range, or BM_INVALID */
static uint64_t range_addr_to_bit(const struct ip6_range *r, const struct in6_addr *addr)
{
	uint8_t delta[16];
	uint64_t i;
	int p;

	if (in6_addr_cmp(addr, &r->start) < 0)
		return BM_INVALID;

	in6_sub(delta, addr->s6_addr, r->start.s6_addr);

	/* must sit on a prefix boundary: low `shift` bits zero */
	for (p = 0; p < r->shift; p++) {
		if (delta[15 - (p >> 3)] & (1 << (p & 7)))
			return BM_INVALID;
	}

	if (in6_shr_u64(delta, r->shift, &i))
		return BM_INVALID;
	if (i >= r->count)
		return BM_INVALID;

	return i;
}

/* ===== pool set construction ===== */

static struct ip6_pool *create_pool(struct list_head *pool_list, char *name)
{
	struct ip6_pool *p = _malloc(sizeof(*p));

	if (!p)
		return NULL;

	memset(p, 0, sizeof(*p));
	p->name = name;
	INIT_LIST_HEAD(&p->ranges);
	spinlock_init(&p->lock);

	if (name)
		list_add_tail(&p->entry, pool_list);

	return p;
}

static struct ip6_pool *find_pool(struct list_head *pool_list, const char *name, int create)
{
	struct ip6_pool *p;

	list_for_each_entry(p, pool_list, entry) {
		if (p->name && !strcmp(p->name, name))
			return p;
	}

	if (create) {
		char *dup = _strdup(name);
		if (!dup)
			return NULL;
		return create_pool(pool_list, dup);
	}

	return NULL;
}

/* parse "<addr>/<mask>,<prefix_len>" and append a range to `pool` */
static void add_prefix(struct ip6_pool *pool, const char *_val)
{
	char *val = _strdup(_val);
	char *ptr1, *ptr2;
	struct in6_addr start, end;
	int prefix_len, mask, shift;
	uint64_t count;
	struct ip6_range *r;

	if (!val)
		return;

	ptr1 = strchr(val, '/');
	if (!ptr1)
		goto err;
	*ptr1 = 0;

	ptr2 = strchr(ptr1 + 1, ',');
	if (!ptr2)
		goto err;
	*ptr2 = 0;

	if (inet_pton(AF_INET6, val, &start) == 0)
		goto err;
	if (sscanf(ptr1 + 1, "%i", &mask) != 1)
		goto err;
	if (mask < 7 || mask > 127)
		goto err;
	if (sscanf(ptr2 + 1, "%i", &prefix_len) != 1)
		goto err;
	if (prefix_len > 128 || prefix_len < mask)
		goto err;

	if (prefix_len - mask > IPPOOL_MAX_SHIFT) {
		log_error("ipv6_pool: range '%s' has 2^%d prefixes, exceeds cap 2^%d; skipping\n",
			  _val, prefix_len - mask, IPPOOL_MAX_SHIFT);
		_free(val);
		return;
	}

	shift = 128 - prefix_len;

	/* end = start | hostmask(mask) (matches the original generator) */
	memcpy(&end, &start, sizeof(end));
	if (mask > 64)
		*(uint64_t *)(end.s6_addr + 8) = htobe64(be64toh(*(uint64_t *)(end.s6_addr + 8)) | ((1llu << (128 - mask)) - 1));
	else {
		memset(end.s6_addr + 8, 0xff, 8);
		*(uint64_t *)end.s6_addr = htobe64(be64toh(*(uint64_t *)end.s6_addr) | ((1llu << (64 - mask)) - 1));
	}

	{
		uint8_t delta[16];
		uint64_t span;
		in6_sub(delta, end.s6_addr, start.s6_addr);
		if (in6_shr_u64(delta, shift, &span) || span >= IPPOOL_MAX_BITS) {
			log_error("ipv6_pool: range '%s' exceeds cap; skipping\n", _val);
			_free(val);
			return;
		}
		count = span + 1;
	}

	r = _malloc(sizeof(*r));
	if (!r) {
		_free(val);
		return;
	}
	memset(r, 0, sizeof(*r));
	memcpy(&r->start, &start, sizeof(start));
	r->prefix_len = prefix_len;
	r->shift = shift;
	r->count = count;
	list_add_tail(&r->entry, &pool->ranges);

	_free(val);
	return;

err:
	log_error("ipv6_pool: failed to parse '%s'\n", _val);
	_free(val);
}

static int finalize_ranges(struct ip6_pool *p)
{
	struct ip6_range *r;

	list_for_each_entry(r, &p->ranges, entry) {
		uint64_t nw = BM_NWORDS(r->count);
		uint64_t b;

		r->bitmap = _malloc(nw * sizeof(bm_word_t));
		if (!r->bitmap)
			return -1;
		memset(r->bitmap, 0, nw * sizeof(bm_word_t));

		for (b = r->count; b < nw * BM_WORD_BITS; b++)
			bm_set(r->bitmap, b);
	}

	return 0;
}

static int parse_line_opts(struct pool_set *set, enum ippool_type type, const char *opt,
			   struct ip6_pool **pool)
{
	struct list_head *pool_list = (type == IPPOOL_PREFIX) ? &set->dppools : &set->ippools;
	char *name, *ptr;

	name = strstr(opt, ",name=");
	if (name) {
		name += sizeof(",name=") - 1;
		ptr = strchrnul(name, ',');
		name = _strndup(name, ptr - name);
		if (!name)
			return -1;
		*pool = find_pool(pool_list, name, 1);
		_free(name);
	} else
		*pool = (type == IPPOOL_PREFIX) ? set->def_dppool : set->def_ippool;

	if (!*pool)
		return -1;

	name = strstr(opt, ",next=");
	if (name) {
		struct ip6_pool *next;
		name += sizeof(",next=") - 1;
		ptr = strchrnul(name, ',');
		name = _strndup(name, ptr - name);
		if (!name)
			return -1;
		next = find_pool(pool_list, name, 1);
		_free(name);
		if (next)
			(*pool)->next = next;
	}

	return 0;
}

static void free_pool(struct ip6_pool *p)
{
	struct ip6_range *r;

	while (!list_empty(&p->ranges)) {
		r = list_first_entry(&p->ranges, typeof(*r), entry);
		list_del(&r->entry);
		if (r->bitmap)
			_free(r->bitmap);
		_free(r);
	}
	if (p->name)
		_free(p->name);
	_free(p);
}

static void free_pool_list(struct list_head *l)
{
	struct ip6_pool *p;

	while (!list_empty(l)) {
		p = list_first_entry(l, typeof(*p), entry);
		list_del(&p->entry);
		free_pool(p);
	}
}

static void free_pool_set(struct pool_set *set)
{
	if (!set)
		return;

	free_pool_list(&set->ippools);
	free_pool_list(&set->dppools);
	if (set->def_ippool)
		free_pool(set->def_ippool);
	if (set->def_dppool)
		free_pool(set->def_dppool);
	_free(set);
}

static int finalize_set(struct pool_set *set)
{
	struct ip6_pool *p;

	if (set->def_ippool && finalize_ranges(set->def_ippool))
		return -1;
	if (set->def_dppool && finalize_ranges(set->def_dppool))
		return -1;
	list_for_each_entry(p, &set->ippools, entry) {
		if (finalize_ranges(p))
			return -1;
		if (list_empty(&p->ranges))
			log_warn("ipv6_pool: pool '%s' is empty or not defined\n", p->name);
	}
	list_for_each_entry(p, &set->dppools, entry) {
		if (finalize_ranges(p))
			return -1;
		if (list_empty(&p->ranges))
			log_warn("ipv6_pool: delegate pool '%s' is empty or not defined\n", p->name);
	}

	return 0;
}

#ifdef RADIUS
static int parse_attr_opt(const char *opt)
{
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;

	if (conf_vendor)
		vendor = rad_dict_find_vendor_id(conf_vendor);
	else
		vendor = NULL;

	if (conf_vendor) {
		if (vendor)
			attr = rad_dict_find_vendor_attr(vendor, opt);
		else
			attr = NULL;
	} else
		attr = rad_dict_find_attr(opt);

	if (attr)
		return attr->id;

	return atoi(opt);
}

static int parse_vendor_opt(const char *opt)
{
	struct rad_dict_vendor_t *vendor;

	vendor = rad_dict_find_vendor_name(opt);
	if (vendor)
		return vendor->id;

	return atoi(opt);
}
#endif

static struct pool_set *build_pool_set(void)
{
	struct conf_sect_t *s = conf_get_section("ipv6-pool");
	struct conf_option_t *opt;
	struct pool_set *set;
#ifdef RADIUS
	int dppool_attr = 0, ippool_attr = 0;
#endif

	set = _malloc(sizeof(*set));
	if (!set)
		return NULL;
	memset(set, 0, sizeof(*set));
	INIT_LIST_HEAD(&set->ippools);
	INIT_LIST_HEAD(&set->dppools);
	set->orphan_policy = ORPHAN_KEEP;

#ifdef RADIUS
	/* statics persist across reloads; reset to defaults so a removed
	 * vendor/attr line doesn't leave stale values behind. A stale
	 * conf_vendor would otherwise force conf_dppool_attr/conf_ippool_attr
	 * to 0 below, silently disabling pool-name matching. */
	conf_vendor = 0;
	conf_dppool_attr = 171; // Delegated-IPv6-Prefix-Pool
	conf_ippool_attr = 172; // Stateful-IPv6-Address-Pool
#endif

	if (!s)
		return set;

	set->def_ippool = create_pool(&set->ippools, NULL);
	set->def_dppool = create_pool(&set->dppools, NULL);
	if (!set->def_ippool || !set->def_dppool)
		goto err;

	list_for_each_entry(opt, &s->items, entry) {
		enum ippool_type type;
		const char *val;
		struct ip6_pool *pool;

#ifdef RADIUS
		if (triton_module_loaded("radius")) {
			if (!strcmp(opt->name, "vendor")) {
				if (opt->val)
					conf_vendor = parse_vendor_opt(opt->val);
				continue;
			} else if (!strcmp(opt->name, "attr-prefix")) {
				if (opt->val)
					dppool_attr = parse_attr_opt(opt->val);
				continue;
			} else if (!strcmp(opt->name, "attr-address")) {
				if (opt->val)
					ippool_attr = parse_attr_opt(opt->val);
				continue;
			}
		}
#endif
		if (!strcmp(opt->name, "gw-ip6-address")) {
			if (opt->val && inet_pton(AF_INET6, opt->val, &set->gw_addr) == 0)
				log_error("ipv6_pool: failed to parse '%s'\n", opt->raw);
			continue;
		}
		if (!strcmp(opt->name, "reload-orphan")) {
			if (opt->val && !strcmp(opt->val, "disconnect"))
				set->orphan_policy = ORPHAN_DISCONNECT;
			else
				set->orphan_policy = ORPHAN_KEEP;
			continue;
		}

		if (!strcmp(opt->name, "delegate")) {
			type = IPPOOL_PREFIX;
			val = opt->val;
		} else {
			type = IPPOOL_ADDRESS;
			val = opt->name;
		}

		if (!val)
			continue;

		if (parse_line_opts(set, type, opt->raw, &pool)) {
			log_error("ipv6_pool: failed to parse '%s'\n", opt->raw);
			continue;
		}

		add_prefix(pool, val);
	}

#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		if (conf_vendor || dppool_attr)
			conf_dppool_attr = dppool_attr;
		if (conf_vendor || ippool_attr)
			conf_ippool_attr = ippool_attr;
	}
#endif

	if (finalize_set(set))
		goto err;

	return set;

err:
	free_pool_set(set);
	return NULL;
}

/* ===== address lookup ===== */

static int pool_contains(struct ip6_pool *p, const struct in6_addr *addr,
			 struct ip6_range **out_r, uint64_t *out_bit)
{
	struct ip6_range *r;

	list_for_each_entry(r, &p->ranges, entry) {
		uint64_t bit = range_addr_to_bit(r, addr);
		if (bit != BM_INVALID) {
			*out_r = r;
			*out_bit = bit;
			return 1;
		}
	}
	return 0;
}

static int find_target(struct list_head *pool_list, struct ip6_pool *def_pool,
		       const struct in6_addr *addr, const char *pref_name,
		       struct ip6_pool **op, struct ip6_range **orr, uint64_t *obit)
{
	struct ip6_pool *p;

	if (pref_name) {
		p = find_pool(pool_list, pref_name, 0);
		if (p && pool_contains(p, addr, orr, obit)) {
			*op = p;
			return 1;
		}
	}

	if (def_pool && pool_contains(def_pool, addr, orr, obit)) {
		*op = def_pool;
		return 1;
	}
	list_for_each_entry(p, pool_list, entry) {
		if (pool_contains(p, addr, orr, obit)) {
			*op = p;
			return 1;
		}
	}

	return 0;
}

/* alloc a free bit from a pool's next-chain; returns range+bit+pool or NULL */
static struct ip6_range *alloc_from(struct ip6_pool *pool, struct ip6_pool **found_p, uint64_t *found_bit)
{
	struct ip6_pool *start = pool;
	struct ip6_range *r, *found_r = NULL;
	uint64_t bit = BM_INVALID;

	do {
		spin_lock(&pool->lock);
		list_for_each_entry(r, &pool->ranges, entry) {
			bit = bm_find_free(r->bitmap, r->count, r->cursor);
			if (bit != BM_INVALID) {
				bm_set(r->bitmap, bit);
				r->used++;
				r->cursor = bit + 1;
				found_r = r;
				*found_p = pool;
				*found_bit = bit;
				break;
			}
		}
		spin_unlock(&pool->lock);
		if (found_r)
			return found_r;
		pool = pool->next;
	} while (pool && pool != start);

	return NULL;
}

/* ===== ipdb get/put: NA ===== */

static struct ipv6db_item_t *get_ip(struct ap_session *ses)
{
	struct pool_set *set;
	struct ip6_pool *pool, *found_p = NULL;
	struct ip6_range *r;
	struct ip6_lease *lease;
	uint64_t bit;

	pthread_rwlock_rdlock(&pool_set_rwlock);
	set = cur_set;
	if (!set) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	pool = ses->ipv6_pool_name ? find_pool(&set->ippools, ses->ipv6_pool_name, 0) : set->def_ippool;
	if (!pool) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	r = alloc_from(pool, &found_p, &bit);
	if (!r) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	lease = _malloc(sizeof(*lease));
	if (!lease) {
		spin_lock(&found_p->lock);
		bm_clear(r->bitmap, bit);
		r->used--;
		spin_unlock(&found_p->lock);
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	memset(lease, 0, sizeof(*lease));
	lease->pool = found_p;
	lease->range = r;
	lease->it.owner = &ipdb;
	INIT_LIST_HEAD(&lease->it.addr_list);
	in6_index_to_addr(&lease->node.addr, &r->start, bit, r->shift);
	lease->node.prefix_len = r->prefix_len;
	list_add_tail(&lease->node.entry, &lease->it.addr_list);

	if (r->prefix_len == 128) {
		memcpy(&lease->it.intf_id, set->gw_addr.s6_addr + 8, 8);
		memcpy(&lease->it.peer_intf_id, lease->node.addr.s6_addr + 8, 8);
	} else {
		lease->it.intf_id = 0;
		lease->it.peer_intf_id = 0;
	}

	pthread_rwlock_unlock(&pool_set_rwlock);

	return &lease->it;
}

static void put_ip(struct ap_session *ses, struct ipv6db_item_t *it)
{
	struct ip6_lease *lease = container_of(it, typeof(*lease), it);

	pthread_rwlock_rdlock(&pool_set_rwlock);
	if (lease->pool && lease->range) {
		uint64_t bit = range_addr_to_bit(lease->range, &lease->node.addr);
		spin_lock(&lease->pool->lock);
		if (bit != BM_INVALID && bm_test(lease->range->bitmap, bit)) {
			bm_clear(lease->range->bitmap, bit);
			lease->range->used--;
		}
		spin_unlock(&lease->pool->lock);
	}
	pthread_rwlock_unlock(&pool_set_rwlock);

	_free(lease);
}

/* ===== ipdb get/put: PD ===== */

static struct ipv6db_prefix_t *get_dp(struct ap_session *ses)
{
	struct pool_set *set;
	struct ip6_pool *pool, *found_p = NULL;
	struct ip6_range *r;
	struct dp_lease *lease;
	uint64_t bit;

	pthread_rwlock_rdlock(&pool_set_rwlock);
	set = cur_set;
	if (!set) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	pool = ses->dpv6_pool_name ? find_pool(&set->dppools, ses->dpv6_pool_name, 0) : set->def_dppool;
	if (!pool) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	r = alloc_from(pool, &found_p, &bit);
	if (!r) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	lease = _malloc(sizeof(*lease));
	if (!lease) {
		spin_lock(&found_p->lock);
		bm_clear(r->bitmap, bit);
		r->used--;
		spin_unlock(&found_p->lock);
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	memset(lease, 0, sizeof(*lease));
	lease->pool = found_p;
	lease->range = r;
	lease->it.owner = &ipdb;
	INIT_LIST_HEAD(&lease->it.prefix_list);
	in6_index_to_addr(&lease->node.addr, &r->start, bit, r->shift);
	lease->node.prefix_len = r->prefix_len;
	list_add_tail(&lease->node.entry, &lease->it.prefix_list);

	pthread_rwlock_unlock(&pool_set_rwlock);

	return &lease->it;
}

static void put_dp(struct ap_session *ses, struct ipv6db_prefix_t *it)
{
	struct dp_lease *lease = container_of(it, typeof(*lease), it);

	pthread_rwlock_rdlock(&pool_set_rwlock);
	if (lease->pool && lease->range) {
		uint64_t bit = range_addr_to_bit(lease->range, &lease->node.addr);
		spin_lock(&lease->pool->lock);
		if (bit != BM_INVALID && bm_test(lease->range->bitmap, bit)) {
			bm_clear(lease->range->bitmap, bit);
			lease->range->used--;
		}
		spin_unlock(&lease->pool->lock);
	}
	pthread_rwlock_unlock(&pool_set_rwlock);

	_free(lease);
}

static struct ipdb_t ipdb = {
	.get_ipv6 = get_ip,
	.put_ipv6 = put_ip,
	.get_ipv6_prefix = get_dp,
	.put_ipv6_prefix = put_dp,
};

/* ===== reconcile on reload ===== */

static void reserve_bit(struct ip6_pool *np, struct ip6_range *nr, uint64_t bit)
{
	spin_lock(&np->lock);
	if (!bm_test(nr->bitmap, bit)) {
		bm_set(nr->bitmap, bit);
		nr->used++;
	}
	spin_unlock(&np->lock);
}

static void reconcile_na(struct pool_set *new_set, struct ap_session *ses,
			 int policy, struct list_head *disc)
{
	struct ipv6db_item_t *it = ses->ipv6;
	struct ip6_pool *np;
	struct ip6_range *nr;
	uint64_t bit;

	if (!it || !it->owner)
		return;

	if (it->owner == &ipdb) {
		struct ip6_lease *lease = container_of(it, typeof(*lease), it);
		if (find_target(&new_set->ippools, new_set->def_ippool, &lease->node.addr,
				ses->ipv6_pool_name, &np, &nr, &bit)) {
			reserve_bit(np, nr, bit);
			lease->pool = np;
			lease->range = nr;
		} else {
			lease->pool = NULL;
			lease->range = NULL;
			if (policy == ORPHAN_DISCONNECT) {
				struct disc_node *d = _malloc(sizeof(*d));
				if (d) {
					d->ses = ses;
					list_add_tail(&d->entry, disc);
				}
			}
		}
	} else {
		struct ipv6db_addr_t *a;
		list_for_each_entry(a, &it->addr_list, entry) {
			if (find_target(&new_set->ippools, new_set->def_ippool, &a->addr,
					NULL, &np, &nr, &bit))
				reserve_bit(np, nr, bit);
		}
	}
}

static void reconcile_pd(struct pool_set *new_set, struct ap_session *ses,
			 int policy, struct list_head *disc)
{
	struct ipv6db_prefix_t *it = ses->ipv6_dp;
	struct ip6_pool *np;
	struct ip6_range *nr;
	uint64_t bit;

	if (!it || !it->owner)
		return;

	if (it->owner == &ipdb) {
		struct dp_lease *lease = container_of(it, typeof(*lease), it);
		if (find_target(&new_set->dppools, new_set->def_dppool, &lease->node.addr,
				ses->dpv6_pool_name, &np, &nr, &bit)) {
			reserve_bit(np, nr, bit);
			lease->pool = np;
			lease->range = nr;
		} else {
			lease->pool = NULL;
			lease->range = NULL;
			if (policy == ORPHAN_DISCONNECT) {
				struct disc_node *d = _malloc(sizeof(*d));
				if (d) {
					d->ses = ses;
					list_add_tail(&d->entry, disc);
				}
			}
		}
	} else {
		struct ipv6db_addr_t *a;
		list_for_each_entry(a, &it->prefix_list, entry) {
			if (find_target(&new_set->dppools, new_set->def_dppool, &a->addr,
					NULL, &np, &nr, &bit))
				reserve_bit(np, nr, bit);
		}
	}
}

static void terminate_orphan(void *arg)
{
	struct ap_session *ses = arg;
	ap_session_terminate(ses, TERM_NAS_REBOOT, 0);
}

static void load_config(void *data)
{
	struct pool_set *new_set, *old_set;
	struct ap_session *ses;
	struct disc_node *d;
	LIST_HEAD(disc_list);
	int policy;

	new_set = build_pool_set();
	if (!new_set) {
		log_error("ipv6_pool: reload failed, keeping current pools\n");
		return;
	}
	policy = new_set->orphan_policy;

	pthread_rwlock_wrlock(&pool_set_rwlock);
	pthread_rwlock_rdlock(&ses_lock);

	list_for_each_entry(ses, &ses_list, entry) {
		reconcile_na(new_set, ses, policy, &disc_list);
		reconcile_pd(new_set, ses, policy, &disc_list);
	}

	old_set = cur_set;
	cur_set = new_set;

	pthread_rwlock_unlock(&ses_lock);
	pthread_rwlock_unlock(&pool_set_rwlock);

	free_pool_set(old_set);

	while (!list_empty(&disc_list)) {
		d = list_first_entry(&disc_list, typeof(*d), entry);
		list_del(&d->entry);
		triton_context_call(d->ses->ctrl->ctx, terminate_orphan, d->ses);
		_free(d);
	}
}

#ifdef RADIUS
static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct rad_attr_t *attr;
	struct ap_session *ses = ev->ses;

	list_for_each_entry(attr, &ev->reply->attrs, entry) {
		if (attr->attr->type != ATTR_TYPE_STRING)
			continue;
		if (attr->vendor && attr->vendor->id != conf_vendor)
			continue;
		if (!attr->vendor && conf_vendor)
			continue;

		if (conf_dppool_attr && conf_dppool_attr == attr->attr->id) {
			if (ses->dpv6_pool_name)
				_free(ses->dpv6_pool_name);
			ses->dpv6_pool_name = _strdup(attr->val.string);
		} else if (conf_ippool_attr && conf_ippool_attr == attr->attr->id) {
			if (ses->ipv6_pool_name)
				_free(ses->ipv6_pool_name);
			ses->ipv6_pool_name = _strdup(attr->val.string);
		}
	}
}
#endif

/* ===== init ===== */

static void ippool_init1(void)
{
	ipdb_register(&ipdb);
}

static void ippool_init2(void)
{
	load_config(NULL);

	if (triton_event_register_handler(EV_CONFIG_RELOAD, load_config) < 0)
		log_error("ipv6_pool: registration of CONFIG_RELOAD event failed,"
			  " pools will not reload\n");

#ifdef RADIUS
	if (triton_module_loaded("radius"))
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
#endif
}

DEFINE_INIT(51, ippool_init1);
DEFINE_INIT2(52, ippool_init2);
