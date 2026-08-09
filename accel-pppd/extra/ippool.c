#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "triton.h"
#include "events.h"
#include "log.h"
#include "list.h"
#include "spinlock.h"
#include "backup.h"
#include "ap_session.h"
#include "ap_session_backup.h"

#include "ipdb.h"
#include "cli.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "bitpool.h"
#include "memdebug.h"

/*
 * Bitmap IPv4 address pool.
 *
 * Each pool holds a list of contiguous ranges; each range owns one bitmap
 * (1 bit per allocatable block). A lease is a small per-session malloc wrapper
 * around the ipv4db_item_t returned to the session, so pool memory is never
 * shared/mutated by sessions. The whole pool set is rebuilt and swapped on
 * EV_CONFIG_RELOAD, reconciling live sessions against the new ranges.
 *
 * TODO: a sparse/hierarchical allocator would lift IPPOOL_MAX_BITS; the dense
 * bitmap is fine for realistic IPv4 ranges (a /8 sits right at the cap).
 */

#define IPPOOL_MAX_BITS (1u << 24)	/* ~16.7M units, ~2MB bitmap */

enum {
	ORPHAN_KEEP = 0,	/* keep the session, no-op its later put */
	ORPHAN_DISCONNECT,	/* terminate sessions whose address left the pools */
};

/* one contiguous range = one bitmap. step/offsets encode the allocator:
 *   p2p:   step=1, gw_offset=-1 (local addr from gw-ip-address/0), peer_offset=0
 *   net30: step=4, gw_offset=1  (.1 router), peer_offset=2 (.2 client)         */
struct ip_range {
	struct list_head entry;
	uint32_t start;		/* host order, first block base */
	uint32_t end;		/* host order, last address in range */
	uint32_t step;
	int gw_offset;
	int peer_offset;
	uint64_t count;		/* number of blocks = bits in bitmap */
	uint64_t cursor;	/* round-robin search hint */
	uint64_t used;
	bm_word_t *bitmap;
};

struct ip_pool {
	struct list_head entry;	/* in set->pools; named pools only */
	char *name;		/* NULL for the default pool */
	struct ip_pool *next;	/* overflow chain */
	struct list_head ranges;
	spinlock_t lock;	/* guards every range's bitmap/cursor/used */
};

struct pool_set {
	struct list_head pools;	/* named pools */
	struct ip_pool *def_pool;	/* unnamed default (not on `pools`) */
	in_addr_t gw_ip_address; /* prevents the configured gateway address from being handed out as a peer address */
	int shuffle;
	int orphan_policy;
};

struct ip_lease {
	struct ip_pool *pool;	/* NULL once orphaned by a reload */
	struct ip_range *range;	/* Range that supplied this lease's peer address; NULL if orphaned */
	struct ipv4db_item_t it;	/* ses->ipv4 = &it */
};

/* collected during reconcile, acted on after locks are dropped */
struct disc_node {
	struct list_head entry;
	struct ap_session *ses;
};

static struct ipdb_t ipdb;

static pthread_rwlock_t pool_set_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct pool_set *cur_set;

#ifdef RADIUS
static int conf_vendor = 0;
static int conf_attr = 88; // Framed-Pool

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

/* ===== randomness for shuffle ===== */

static uint64_t rand_u64(void)
{
	uint64_t r = 0;

	if (read(urandom_fd, &r, sizeof(r)) != sizeof(r))
		r = 0;

	return r;
}

/* ===== range arithmetic ===== */

//parses ranges like x.x.x.x/mask
static int parse1(const char *str, uint32_t *begin, uint32_t *end)
{
	int n;
	unsigned int f1, f2, f3, f4, m;

	n = sscanf(str, "%u.%u.%u.%u/%u", &f1, &f2, &f3, &f4, &m);
	if (n != 5)
		return -1;
	if (f1 > 255 || f2 > 255 || f3 > 255 || f4 > 255)
		return -1;
	if (m == 0 || m > 32)
		return -1;

	*begin = (f1 << 24) | (f2 << 16) | (f3 << 8) | f4;

	m = m == 32 ? 0 : ((1 << (32 - m)) - 1);
	*end = *begin | m;

	return 0;
}

//parses ranges like x.x.x.x-y
static int parse2(const char *str, uint32_t *begin, uint32_t *end)
{
	int n;
	unsigned int f1, f2, f3, f4, f5;

	n = sscanf(str, "%u.%u.%u.%u-%u", &f1, &f2, &f3, &f4, &f5);
	if (n != 5)
		return -1;
	if (f1 > 255 || f2 > 255 || f3 > 255 || f4 > 255)
		return -1;
	if (f5 < f4 || f5 > 255)
		return -1;

	*begin = (f1 << 24) | (f2 << 16) | (f3 << 8) | f4;
	*end = (f1 << 24) | (f2 << 16) | (f3 << 8) | f5;

	return 0;
}

/* bit index of a leased peer address within a range, or BM_INVALID */
static uint64_t range_addr_to_bit(const struct ip_range *r, uint32_t peer_host)
{
	uint32_t base, delta;
	uint64_t bit;

	if (peer_host < (uint32_t)r->peer_offset)
		return BM_INVALID;
	base = peer_host - r->peer_offset;
	if (base < r->start)
		return BM_INVALID;
	delta = base - r->start;
	if (delta % r->step)
		return BM_INVALID;
	bit = delta / r->step;
	if (bit >= r->count)
		return BM_INVALID;

	return bit;
}

/* ===== pool set construction ===== */

static struct ip_pool *create_pool(struct pool_set *set, char *name)
{
	struct ip_pool *p = _malloc(sizeof(*p));

	if (!p)
		return NULL;

	memset(p, 0, sizeof(*p));
	p->name = name;
	INIT_LIST_HEAD(&p->ranges);
	spinlock_init(&p->lock);

	if (name)
		list_add_tail(&p->entry, &set->pools);

	return p;
}

static struct ip_pool *find_pool(struct pool_set *set, const char *name, int create)
{
	struct ip_pool *p;

	list_for_each_entry(p, &set->pools, entry) {
		if (p->name && !strcmp(p->name, name))
			return p;
	}

	if (create) {
		char *dup = _strdup(name);
		if (!dup)
			return NULL;
		return create_pool(set, dup);
	}

	return NULL;
}

static int add_range_to_pool(struct ip_pool *p, const char *str,
			     uint32_t step, int gw_offset, int peer_offset)
{
	uint32_t start, end;
	uint64_t count;
	struct ip_range *r;

	if (parse1(str, &start, &end)) {
		if (parse2(str, &start, &end)) {
			log_error("ippool: can't parse range '%s'\n", str);
			return -1;
		}
	}

	if (end < start) {
		log_error("ippool: range '%s' ends before it starts\n", str);
		return -1;
	}

	count = ((uint64_t)(end - start) + 1) / step;	/* floor: net30 tail dropped */
	if (count == 0) {
		log_warn("ippool: range '%s' is empty for this allocator\n", str);
		return 0;
	}
	if (count > IPPOOL_MAX_BITS) {
		log_error("ippool: range '%s' has %llu units, exceeds cap %u; skipping\n",
			  str, (unsigned long long)count, IPPOOL_MAX_BITS);
		return -1;
	}

	r = _malloc(sizeof(*r));
	if (!r)
		return -1;
	memset(r, 0, sizeof(*r));
	r->start = start;
	r->end = end;
	r->step = step;
	r->gw_offset = gw_offset;
	r->peer_offset = peer_offset;
	r->count = count;
	list_add_tail(&r->entry, &p->ranges);

	return 0;
}

/* allocate + finalize bitmaps once the whole section (incl. gw-ip-address) is known */
static int finalize_ranges(struct pool_set *set, struct ip_pool *p)
{
	struct ip_range *r;

	list_for_each_entry(r, &p->ranges, entry) {
		uint64_t nw = BM_NWORDS(r->count);
		uint64_t b;

		r->bitmap = _malloc(nw * sizeof(bm_word_t));
		if (!r->bitmap)
			return -1;
		memset(r->bitmap, 0, nw * sizeof(bm_word_t));

		/* remainder bits past count must never be handed out */
		for (b = r->count; b < nw * BM_WORD_BITS; b++)
			bm_set(r->bitmap, b);

		/* p2p: reserve the bit colliding with the configured gateway,
		 * reproducing the old generate_pool_p2p skip */
		if (r->step == 1 && r->peer_offset == 0 && set->gw_ip_address) {
			uint32_t gw = ntohl(set->gw_ip_address);
			if (gw >= r->start && gw <= r->end) {
				uint64_t bit = gw - r->start;
				if (bit < r->count && !bm_test(r->bitmap, bit)) {
					bm_set(r->bitmap, bit);
					r->used++;
				}
			}
		}
	}

	return 0;
}

static void parse_gw_ip_address(const char *val, in_addr_t *out)
{
	char addr[17];
	char *ptr;

	if (!val)
		return;

	ptr = strchr(val, '/');
	if (ptr) {
		if (ptr - val > 15 || ptr - val < 7)
			return;
		memcpy(addr, val, ptr - val);
		addr[ptr - val] = 0;
		*out = inet_addr(addr);
	} else
		*out = inet_addr(val);
}

/* parse ,name= / ,allocator= / ,next= from a raw option line */
static int parse_line_opts(struct pool_set *set, const char *opt, struct ip_pool **pool,
			   uint32_t *step, int *gw_offset, int *peer_offset)
{
	char *name, *ptr;

	name = strstr(opt, ",name=");
	if (name) {
		name += sizeof(",name=") - 1;
		ptr = strchrnul(name, ',');
		name = _strndup(name, ptr - name);
		if (!name)
			return -1;
		*pool = find_pool(set, name, 1);
		_free(name);
	} else if ((name = strchr(opt, ',')) && !strchr(name + 1, '=')) {
		name = _strndup(name + 1, strchrnul(name + 1, ',') - (name + 1));
		if (!name)
			return -1;
		*pool = find_pool(set, name, 1);
		_free(name);
	} else
		*pool = set->def_pool;

	if (!*pool)
		return -1;

	/* defaults: p2p */
	*step = 1;
	*gw_offset = -1;
	*peer_offset = 0;

	name = strstr(opt, ",allocator=");
	if (name) {
		name += sizeof(",allocator=") - 1;
		ptr = strchrnul(name, ',');
		if (!strncmp(name, "p2p", ptr - name) && (size_t)(ptr - name) == 3) {
			*step = 1; *gw_offset = -1; *peer_offset = 0;
		} else if (!strncmp(name, "net30", ptr - name) && (size_t)(ptr - name) == 5) {
			*step = 4; *gw_offset = 1; *peer_offset = 2;
		} else {
			log_error("ippool: '%s': unknown allocator\n", opt);
			return -1;
		}
	}

	name = strstr(opt, ",next=");
	if (name) {
		struct ip_pool *next;
		name += sizeof(",next=") - 1;
		ptr = strchrnul(name, ',');
		name = _strndup(name, ptr - name);
		if (!name)
			return -1;
		next = find_pool(set, name, 1);
		_free(name);
		if (next)
			(*pool)->next = next;
	}

	return 0;
}

static void free_pool(struct ip_pool *p)
{
	struct ip_range *r;

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

static void free_pool_set(struct pool_set *set)
{
	struct ip_pool *p;

	if (!set)
		return;

	while (!list_empty(&set->pools)) {
		p = list_first_entry(&set->pools, typeof(*p), entry);
		list_del(&p->entry);
		free_pool(p);
	}
	if (set->def_pool)
		free_pool(set->def_pool);
	_free(set);
}

static struct pool_set *build_pool_set(void)
{
	struct conf_sect_t *s = conf_get_section("ip-pool");
	struct conf_option_t *opt;
	struct pool_set *set;
	struct ip_pool *p;

	set = _malloc(sizeof(*set));
	if (!set)
		return NULL;
	memset(set, 0, sizeof(*set));
	INIT_LIST_HEAD(&set->pools);
	set->orphan_policy = ORPHAN_KEEP;

#ifdef RADIUS
	/* statics persist across reloads; reset to defaults so a removed
	 * vendor/attr line doesn't leave stale values behind */
	conf_vendor = 0;
	conf_attr = 88; // Framed-Pool
#endif

	if (!s)
		return set;	/* no section: an empty (inert) set */

	set->def_pool = create_pool(set, NULL);
	if (!set->def_pool)
		goto err;

	list_for_each_entry(opt, &s->items, entry) {
		const char *range_str;
		struct ip_pool *pool;
		uint32_t step;
		int gw_offset, peer_offset;

#ifdef RADIUS
		if (triton_module_loaded("radius")) {
			if (!strcmp(opt->name, "vendor")) {
				if (opt->val)
					conf_vendor = parse_vendor_opt(opt->val);
				continue;
			} else if (!strcmp(opt->name, "attr")) {
				if (opt->val)
					conf_attr = parse_attr_opt(opt->val);
				continue;
			}
		}
#endif
		if (!strcmp(opt->name, "gw-ip-address")) {
			parse_gw_ip_address(opt->val, &set->gw_ip_address);
			continue;
		}
		if (!strcmp(opt->name, "shuffle")) {
			set->shuffle = opt->val ? atoi(opt->val) : 0;
			continue;
		}
		if (!strcmp(opt->name, "reload-orphan")) {
			if (opt->val && !strcmp(opt->val, "disconnect"))
				set->orphan_policy = ORPHAN_DISCONNECT;
			else
				set->orphan_policy = ORPHAN_KEEP;
			continue;
		}
		if (!strcmp(opt->name, "gw")) {
			/* deprecated/no-op: the per-block local address has long been
			 * overwritten at get time by gw-ip-address/0. Accept and ignore. */
			log_warn("ippool: 'gw=' is deprecated and ignored\n");
			continue;
		}

		if (!strcmp(opt->name, "tunnel"))
			range_str = opt->val;
		else if (!opt->val || strchr(opt->name, ','))
			range_str = opt->name;
		else
			continue;	/* unrecognized option */

		if (!range_str)
			continue;

		if (parse_line_opts(set, opt->raw, &pool, &step, &gw_offset, &peer_offset)) {
			log_error("ippool: failed to parse '%s'\n", opt->raw);
			continue;
		}

		add_range_to_pool(pool, range_str, step, gw_offset, peer_offset);
	}

	if (finalize_ranges(set, set->def_pool))
		goto err;
	list_for_each_entry(p, &set->pools, entry) {
		if (finalize_ranges(set, p))
			goto err;
		if (list_empty(&p->ranges))
			log_warn("ippool: pool '%s' is empty or not defined\n", p->name);
	}

	return set;

err:
	free_pool_set(set);
	return NULL;
}

/* ===== address lookup across a set ===== */

static int pool_contains(struct ip_pool *p, uint32_t peer_host,
			 struct ip_range **out_r, uint64_t *out_bit)
{
	struct ip_range *r;

	list_for_each_entry(r, &p->ranges, entry) {
		uint64_t bit = range_addr_to_bit(r, peer_host);
		if (bit != BM_INVALID) {
			*out_r = r;
			*out_bit = bit;
			return 1;
		}
	}
	return 0;
}

/* find the pool+range+bit owning `peer_host`, preferring `pref_name` on overlap */
static int find_target(struct pool_set *set, uint32_t peer_host, const char *pref_name,
		       struct ip_pool **op, struct ip_range **orr, uint64_t *obit)
{
	struct ip_pool *p;

	if (!set)
		return 0;

	if (pref_name) {
		p = find_pool(set, pref_name, 0);
		if (p && pool_contains(p, peer_host, orr, obit)) {
			*op = p;
			return 1;
		}
	}

	if (set->def_pool && pool_contains(set->def_pool, peer_host, orr, obit)) {
		*op = set->def_pool;
		return 1;
	}
	list_for_each_entry(p, &set->pools, entry) {
		if (pool_contains(p, peer_host, orr, obit)) {
			*op = p;
			return 1;
		}
	}

	return 0;
}

/* ===== ipdb get/put ===== */

static struct ipv4db_item_t *get_ip(struct ap_session *ses)
{
	struct pool_set *set;
	struct ip_pool *pool, *start, *found_p = NULL;
	struct ip_range *r, *found_r = NULL;
	struct ip_lease *lease;
	uint64_t bit = BM_INVALID;
	uint64_t rnd;
	uint32_t base;

	pthread_rwlock_rdlock(&pool_set_rwlock);
	set = cur_set;
	if (!set) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	if (ses->ipv4_pool_name)
		pool = find_pool(set, ses->ipv4_pool_name, 0);
	else
		pool = set->def_pool;

	if (!pool) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	/* draw randomness once, outside the lock: read(urandom_fd) is a
	 * blocking syscall and must not run while holding pool->lock */
	rnd = set->shuffle ? rand_u64() : 0;

	start = pool;
	do {
		spin_lock(&pool->lock);
		list_for_each_entry(r, &pool->ranges, entry) {
			uint64_t from = set->shuffle ? (r->count ? rnd % r->count : 0) : r->cursor;
			bit = bm_find_free(r->bitmap, r->count, from);
			if (bit != BM_INVALID) {
				bm_set(r->bitmap, bit);
				r->used++;
				r->cursor = bit + 1;
				found_r = r;
				found_p = pool;
				break;
			}
		}
		spin_unlock(&pool->lock);
		if (found_r)
			break;
		pool = pool->next;
	} while (pool && pool != start);

	if (!found_r) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	lease = _malloc(sizeof(*lease));
	if (!lease) {
		spin_lock(&found_p->lock);
		bm_clear(found_r->bitmap, bit);
		found_r->used--;
		spin_unlock(&found_p->lock);
		pthread_rwlock_unlock(&pool_set_rwlock);
		return NULL;
	}

	memset(lease, 0, sizeof(*lease));
	lease->pool = found_p;
	lease->range = found_r;
	lease->it.owner = &ipdb;
	base = found_r->start + (uint32_t)bit * found_r->step;
	lease->it.peer_addr = htonl(base + found_r->peer_offset);
	lease->it.addr = ses->ctrl->ppp ? set->gw_ip_address : 0;
	lease->it.mask = 0;

	pthread_rwlock_unlock(&pool_set_rwlock);

	return &lease->it;
}

static void put_ip(struct ap_session *ses, struct ipv4db_item_t *it)
{
	struct ip_lease *lease = container_of(it, typeof(*lease), it);

	pthread_rwlock_rdlock(&pool_set_rwlock);
	if (lease->pool && lease->range) {
		uint64_t bit = range_addr_to_bit(lease->range, ntohl(it->peer_addr));
		spin_lock(&lease->pool->lock);
		if (bit != BM_INVALID && bm_test(lease->range->bitmap, bit)) {
			bm_clear(lease->range->bitmap, bit);
			lease->range->used--;
		}
		spin_unlock(&lease->pool->lock);
	}
	/* else: orphaned by a reload - nothing to release, just free the wrapper */
	pthread_rwlock_unlock(&pool_set_rwlock);

	_free(lease);
}

static struct ipdb_t ipdb = {
	.get_ipv4 = get_ip,
	.put_ipv4 = put_ip,
};

#ifdef USE_BACKUP
static void put_ip_b(struct ap_session *ses, struct ipv4db_item_t *it)
{
	_free(it);
}

static struct ipdb_t ipdb_b = {
	.put_ipv4 = put_ip_b,
};

static int session_save(struct ap_session *ses, struct backup_mod *m)
{
	if (!ses->ipv4 || ses->ipv4->owner != &ipdb)
		return -2;

	return 0;
}

static int session_restore(struct ap_session *ses, struct backup_mod *m)
{
	struct backup_tag *tag;
	in_addr_t addr = 0, peer_addr = 0;
	struct ip_pool *np;
	struct ip_range *nr;
	uint64_t bit;

	m = backup_find_mod(m->data, MODID_COMMON);

	list_for_each_entry(tag, &m->tag_list, entry) {
		switch (tag->id) {
			case SES_TAG_IPV4_ADDR:
				addr = *(in_addr_t *)tag->data;
				break;
			case SES_TAG_IPV4_PEER_ADDR:
				peer_addr = *(in_addr_t *)tag->data;
				break;
		}
	}

	pthread_rwlock_rdlock(&pool_set_rwlock);
	if (find_target(cur_set, ntohl(peer_addr), NULL, &np, &nr, &bit)) {
		struct ip_lease *lease = _malloc(sizeof(*lease));
		if (lease) {
			memset(lease, 0, sizeof(*lease));
			lease->pool = np;
			lease->range = nr;
			lease->it.owner = &ipdb;
			lease->it.addr = addr;
			lease->it.peer_addr = peer_addr;
			spin_lock(&np->lock);
			if (!bm_test(nr->bitmap, bit)) {
				bm_set(nr->bitmap, bit);
				nr->used++;
			}
			spin_unlock(&np->lock);
			ses->ipv4 = &lease->it;
		}
	}
	pthread_rwlock_unlock(&pool_set_rwlock);

	if (!ses->ipv4) {
		ses->ipv4 = _malloc(sizeof(*ses->ipv4));
		if (ses->ipv4) {
			memset(ses->ipv4, 0, sizeof(*ses->ipv4));
			ses->ipv4->addr = addr;
			ses->ipv4->peer_addr = peer_addr;
			ses->ipv4->owner = &ipdb_b;
		}
	}

	return 0;
}

static struct backup_module backup_mod = {
	.id = MODID_IPPOOL,
	.save = session_save,
	.restore = session_restore,
};
#endif

/* ===== reconcile on reload ===== */

static void reconcile_v4(struct pool_set *new_set, struct ap_session *ses,
			 int policy, struct list_head *disc)
{
	struct ipv4db_item_t *it = ses->ipv4;
	uint32_t peer_host;
	struct ip_pool *np;
	struct ip_range *nr;
	uint64_t bit;

	if (!it || !it->owner)
		return;

	peer_host = ntohl(it->peer_addr);

	if (it->owner == &ipdb) {
		struct ip_lease *lease = container_of(it, typeof(*lease), it);
		if (find_target(new_set, peer_host, ses->ipv4_pool_name, &np, &nr, &bit)) {
			spin_lock(&np->lock);
			if (!bm_test(nr->bitmap, bit)) {
				bm_set(nr->bitmap, bit);
				nr->used++;
			}
			spin_unlock(&np->lock);
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
		/* foreign owner (radius/chap-secrets/static): reserve the bit so we
		 * never hand out a live address. We do not own or free it. */
		if (find_target(new_set, peer_host, NULL, &np, &nr, &bit)) {
			spin_lock(&np->lock);
			if (!bm_test(nr->bitmap, bit)) {
				bm_set(nr->bitmap, bit);
				nr->used++;
			}
			spin_unlock(&np->lock);
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
		log_error("ippool: reload failed, keeping current pools\n");
		return;
	}
	policy = new_set->orphan_policy;

	pthread_rwlock_wrlock(&pool_set_rwlock);
	pthread_rwlock_rdlock(&ses_lock);

	list_for_each_entry(ses, &ses_list, entry)
		reconcile_v4(new_set, ses, policy, &disc_list);

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
static int parse_attr(struct ap_session *ses, struct rad_attr_t *attr)
{
	if (conf_vendor == 9) {
		/* VENDOR_Cisco */
		if (attr->len > sizeof("ip:addr-pool=") && memcmp(attr->val.string, "ip:addr-pool=", sizeof("ip:addr-pool=") - 1) == 0) {
			if (ses->ipv4_pool_name)
				_free(ses->ipv4_pool_name);
			ses->ipv4_pool_name = _strdup(attr->val.string + sizeof("ip:addr-pool=") - 1);
		}
	} else {
		if (ses->ipv4_pool_name)
			_free(ses->ipv4_pool_name);

		ses->ipv4_pool_name = _strdup(attr->val.string);
	}

	return 0;
}

static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct rad_attr_t *attr;

	list_for_each_entry(attr, &ev->reply->attrs, entry) {
		if (attr->attr->type != ATTR_TYPE_STRING)
			continue;
		if (attr->vendor && attr->vendor->id != conf_vendor)
			continue;
		if (!attr->vendor && conf_vendor)
			continue;
		if (attr->attr->id != conf_attr)
			continue;
		parse_attr(ev->ses, attr);
	}
}
#endif

/* ===== cli ===== */

static int show_ippool_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	struct ip_pool *pool;
	struct ip_range *r;
	uint64_t total, used;

	cli_send(client, "IP Pool Usage Report\r\n");
	cli_send(client, "====================\r\n");

	pthread_rwlock_rdlock(&pool_set_rwlock);
	if (!cur_set) {
		pthread_rwlock_unlock(&pool_set_rwlock);
		return CLI_CMD_OK;
	}

	if (cur_set->def_pool) {
		pool = cur_set->def_pool;
		total = used = 0;
		spin_lock(&pool->lock);
		list_for_each_entry(r, &pool->ranges, entry) {
			total += r->count;
			used += r->used;
		}
		spin_unlock(&pool->lock);
		if (total > 0)
			cli_sendv(client, "<default>\r\n    total: %llu\r\n    used: %llu\r\n    available: %llu\r\n    usage: %llu%%\r\n",
				(unsigned long long)total, (unsigned long long)used,
				(unsigned long long)(total - used),
				(unsigned long long)(used * 100 / total));
	}

	list_for_each_entry(pool, &cur_set->pools, entry) {
		if (!pool->name)
			continue;
		total = used = 0;
		spin_lock(&pool->lock);
		list_for_each_entry(r, &pool->ranges, entry) {
			total += r->count;
			used += r->used;
		}
		spin_unlock(&pool->lock);
		if (total > 0)
			cli_sendv(client, "%s\r\n    total: %llu\r\n    used: %llu\r\n    available: %llu\r\n    usage: %llu%%\r\n",
				pool->name, (unsigned long long)total, (unsigned long long)used,
				(unsigned long long)(total - used),
				(unsigned long long)(used * 100 / total));
	}

	pthread_rwlock_unlock(&pool_set_rwlock);

	return CLI_CMD_OK;
}

static void show_ippool_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "show ippool - shows IP pool statistics\r\n");
}

/* ===== init ===== */

static void ippool_init1(void)
{
	ipdb_register(&ipdb);
}

static void ippool_init2(void)
{
	load_config(NULL);

	if (triton_event_register_handler(EV_CONFIG_RELOAD, load_config) < 0)
		log_error("ippool: registration of CONFIG_RELOAD event failed,"
			  " pools will not reload\n");

#ifdef USE_BACKUP
	backup_register_module(&backup_mod);
#endif

#ifdef RADIUS
	if (triton_module_loaded("radius"))
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
#endif

	cli_register_simple_cmd2(show_ippool_exec, show_ippool_help, 2, "show", "ippool");
}

DEFINE_INIT(51, ippool_init1);
DEFINE_INIT2(52, ippool_init2);
