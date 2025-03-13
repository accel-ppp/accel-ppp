#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "events.h"
#include "log.h"
#include "list.h"
#include "spinlock.h"
#include "backup.h"
#include "ap_session_backup.h"

#include "ipdb.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "memdebug.h"

struct ippool_t;

typedef void (*generate_func)(struct ippool_t *);

struct ippool_t
{
	struct list_head entry;
	char *name;
	struct list_head gw_list;
	struct list_head tunnel_list;
	struct list_head items;
	uint32_t startip;
	uint32_t endip;
	struct ippool_t *next;
	generate_func generate;
	spinlock_t lock;
};

struct ippool_item_t
{
	struct list_head entry;
	struct ippool_t *pool;
	struct ipv4db_item_t it;
};

struct ipaddr_t
{
	struct list_head entry;
	in_addr_t addr;
};

static struct ipdb_t ipdb;

static in_addr_t conf_gw_ip_address;
static int conf_shuffle;

#ifdef RADIUS
static int conf_vendor = 0;
static int conf_attr = 88; // Framed-Pool
#endif

static int cnt;
static LIST_HEAD(pool_list);
static struct ippool_t *def_pool;

struct ippool_t *create_pool(char *name)
{
	struct ippool_t *p = malloc(sizeof(*p));

	memset(p, 0, sizeof(*p));
	p->name = name;

	INIT_LIST_HEAD(&p->gw_list);
	INIT_LIST_HEAD(&p->tunnel_list);
	INIT_LIST_HEAD(&p->items);
	spinlock_init(&p->lock);

	if (name)
		list_add_tail(&p->entry, &pool_list);

	return p;
}

struct ippool_t *find_pool(char *name, int create)
{
	struct ippool_t *p;

	list_for_each_entry(p, &pool_list, entry) {
		if (!strcmp(p->name, name))
			return p;
	}

	if (create)
		return create_pool(name);

	return NULL;
}

static void parse_gw_ip_address(const char *val)
{
	char addr[17];
	char *ptr;

	if (!val)
		return;

	ptr = strchr(val, '/');
	if (ptr) {
		// safeguard, don't crash on oversized or undersized strings
		if (ptr - val > 15 || ptr - val < 7)
			return;
		memcpy(addr, val, ptr - val);
		addr[ptr - val] = 0;
		conf_gw_ip_address = inet_addr(addr);
	}
	else
		conf_gw_ip_address = inet_addr(val);
}

//parses ranges like x.x.x.x/mask
static int parse1(const char *str, uint32_t *begin, uint32_t *end)
{
	int n;
	unsigned int f1, f2, f3, f4, m;

	n = sscanf(str, "%u.%u.%u.%u/%u",&f1, &f2, &f3, &f4, &m);
	if (n != 5)
		return -1;
	if (f1 > 255)
		return -1;
	if (f2 > 255)
		return -1;
	if (f3 > 255)
		return -1;
	if (f4 > 255)
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

	n = sscanf(str, "%u.%u.%u.%u-%u",&f1, &f2, &f3, &f4, &f5);
	if (n != 5)
		return -1;
	if (f1 > 255)
		return -1;
	if (f2 > 255)
		return -1;
	if (f3 > 255)
		return -1;
	if (f4 > 255)
		return -1;
	if (f5 < f4 || f5 > 255)
		return -1;

	*begin = (f1 << 24) | (f2 << 16) | (f3 << 8) | f4;
	*end = (f1 << 24) | (f2 << 16) | (f3 << 8) | f5;

	return 0;
}

static void add_range(struct ippool_t *p, struct list_head *list, const char *name, void (*generate)(struct ippool_t *))
{
	uint32_t i,startip, endip;
	struct ipaddr_t *ip;

	if (parse1(name, &startip, &endip)) {
		if (parse2(name, &startip, &endip)) {
			fprintf(stderr, "ippool: cann't parse '%s'\n", name);
			_exit(EXIT_FAILURE);
		}
	}

	for (i = startip; i <= endip; i++) {
		ip = malloc(sizeof(*ip));
		ip->addr = htonl(i);
		list_add_tail(&ip->entry, list);
		cnt++;
	}

	p->startip = startip;
	p->endip = endip;
	p->generate = generate;
}

static uint8_t get_random()
{
	static uint8_t buf[128];
	static int pos = 0;
	int r;

	if (pos == 0)
		read(urandom_fd, buf, 128);

	r = buf[pos++];

	if (pos == 128)
		pos = 0;

	return r;
}

static void generate_pool_p2p(struct ippool_t *p)
{
	struct ippool_item_t *it;
	struct ipaddr_t *addr = NULL;
	struct ipaddr_t *peer_addr;
	struct list_head *pos = NULL, *pos1 = p->tunnel_list.next, *pos2 = p->tunnel_list.prev;
	uint8_t r, t = 0;

	while (1) {
		if (list_empty(&p->tunnel_list))
			break;
		else {
			if (conf_shuffle) {
				if (pos1 == &p->tunnel_list)
					pos1 = pos1->next;

				if (pos2 == &p->tunnel_list)
					pos2 = pos2->prev;

				if (t++ < 10)
					r = get_random();
				else
					r = get_random()%64;

				if (r < 32)
					pos = pos1;
				else if (r < 64)
					pos = pos2;

				pos1 = pos1->next;
				pos2 = pos2->prev;

				if (r >= 64)
					continue;

				peer_addr = list_entry(pos, typeof(*peer_addr), entry);
				if (pos == pos1)
					pos1 = pos1->next;

				if (pos == pos2)
					pos2 = pos2->prev;

				list_del(&peer_addr->entry);
				t = 0;
			} else {
				peer_addr = list_entry(p->tunnel_list.next, typeof(*peer_addr), entry);
				list_del(&peer_addr->entry);
			}
		}

		if (!conf_gw_ip_address) {
			if (list_empty(&p->gw_list))
				break;
			else {
				addr = list_entry(p->gw_list.next, typeof(*addr), entry);
				list_del(&addr->entry);
			}
		} else if (conf_gw_ip_address == peer_addr->addr)
			continue;

		it = malloc(sizeof(*it));
		if (!it) {
			fprintf(stderr, "ippool: out of memory\n");
			break;
		}

		memset(it, 0, sizeof(*it));
		it->pool = p;
		it->it.owner = &ipdb;
		if (conf_gw_ip_address)
			it->it.addr = conf_gw_ip_address;
		else
			it->it.addr = addr->addr;

		it->it.peer_addr = peer_addr->addr;

		list_add_tail(&it->entry, &p->items);
	}
}

static void generate_pool_net30(struct ippool_t *p)
{
	struct ippool_item_t *it;
	struct ipaddr_t *addr[4];
	int i;

	while (1) {
		memset(addr, 0, sizeof(addr));

		for (i = 0; i < 4; i++) {
			if (list_empty(&p->tunnel_list))
				break;

			addr[i] = list_entry(p->tunnel_list.next, typeof(*addr[i]), entry);
			list_del(&addr[i]->entry);
		}

		if (!addr[2])
			break;


		it = malloc(sizeof(*it));
		if (!it) {
			log_emerg("ippool: out of memory\n");
			break;
		}

		memset(it, 0, sizeof(*it));
		it->pool = p;
		it->it.owner = &ipdb;
		it->it.addr = addr[1]->addr;
		it->it.peer_addr = addr[2]->addr;

		list_add_tail(&it->entry, &p->items);

		for (i = 0; i < 4; i++) {
			if (addr[i])
				free(addr[i]);
		}
	}

	for (i = 0; i < 4; i++) {
		if (addr[i])
			free(addr[i]);
	}
}


static struct ipv4db_item_t *get_ip(struct ap_session *ses)
{
	struct ippool_item_t *it;
	struct ippool_t *pool, *start;

	if (ses->ipv4_pool_name)
		pool = find_pool(ses->ipv4_pool_name, 0);
	else
		pool = def_pool;

	if (!pool)
		return NULL;

	start = pool;
	do {
		spin_lock(&pool->lock);
		if (!list_empty(&pool->items)) {
			it = list_entry(pool->items.next, typeof(*it), entry);
			list_del(&it->entry);
		} else
			it = NULL;
		spin_unlock(&pool->lock);

		if (it) {
			if (ses->ctrl->ppp)
				it->it.addr = conf_gw_ip_address;
			else
				it->it.addr = 0;

			it->it.mask = 0;

			return &it->it;
		}

		pool = pool->next;
	} while (pool && pool != start);

	return NULL;
}

static void put_ip(struct ap_session *ses, struct ipv4db_item_t *it)
{
	struct ippool_item_t *pit = container_of(it, typeof(*pit), it);

	spin_lock(&pit->pool->lock);
	list_add_tail(&pit->entry, &pit->pool->items);
	spin_unlock(&pit->pool->lock);
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
	in_addr_t addr = 0, peer_addr;
	struct ippool_t *p;
	struct ippool_item_t *it, *it0 = NULL;

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

	spin_lock(&def_pool->lock);
	list_for_each_entry(it, &def_pool->items, entry) {
		if (peer_addr == it->it.peer_addr && addr == it->it.addr) {
			list_del(&it->entry);
			it0 = it;
			break;
		}
	}
	spin_unlock(&def_pool->lock);

	if (!it0) {
		list_for_each_entry(p, &pool_list, entry) {
			spin_lock(&p->lock);
			list_for_each_entry(it, &p->items, entry) {
				if (peer_addr == it->it.peer_addr && addr == it->it.addr) {
					list_del(&it->entry);
					it0 = it;
					break;
				}
			}
			spin_unlock(&p->lock);
			if (it0)
				break;
		}
	}

	if (it0)
		ses->ipv4 = &it0->it;
	else {
		ses->ipv4 = _malloc(sizeof(*ses->ipv4));
		memset(ses->ipv4, 0, sizeof(*ses->ipv4));
		ses->ipv4->addr = addr;
		ses->ipv4->peer_addr = peer_addr;
		ses->ipv4->owner = &ipdb_b;
	}

	return 0;
}

static struct backup_module backup_mod = {
	.id = MODID_IPPOOL,
	.save = session_save,
	.restore = session_restore,
};
#endif

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
	}else
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

static int parse_options(const char *opt, struct ippool_t **pool, generate_func *generate, struct ippool_t **next)
{
	char *name, *ptr;

	name = strstr(opt, ",name=");
	if (name) {
		name += sizeof(",name=") - 1;
		ptr = strchrnul(name, ',');
		name = _strndup(name, ptr - name);
		if (!name)
			return -1;
		*pool = find_pool(name, 1);
	} else if ((name = strchr(opt, ',')) && !strchr(name + 1, '=')) {
		name = _strdup(name + 1);
		if (!name)
			return -1;
		*pool = find_pool(name, 1);
	} else
		*pool = def_pool;

	name = strstr(opt, ",allocator=");
	if (name) {
		name += sizeof(",allocator=") - 1;
		ptr = strchrnul(name, ',');
		name = strncpy(alloca(ptr - name + 1), name, ptr - name + 1);
		if (strcmp(name, "p2p") == 0)
			*generate = generate_pool_p2p;
		else if (strcmp(name, "net30") == 0)
			*generate = generate_pool_net30;
		else {
			log_error("ipool: '%s': unknown allocator\n", opt);
			return -1;
		}
	} else
		*generate = generate_pool_p2p;

	name = strstr(opt, ",next=");
	if (name) {
		name += sizeof(",next=") - 1;
		ptr = strchrnul(name, ',');
		name = strncpy(alloca(ptr - name + 1), name, ptr - name + 1);
		*next = find_pool(name, 0);
		if (!*next) {
			name = _strdup(name);
			if (!name)
				return -1;
			*next = find_pool(name, 1);
		}
	} else
		*next = NULL;

	return 0;
}

static void ippool_init1(void)
{
	ipdb_register(&ipdb);
}

static void ippool_init2(void)
{
	struct conf_sect_t *s = conf_get_section("ip-pool");
	struct conf_option_t *opt;
	struct ippool_t *pool, *next;
	generate_func generate;

	if (!s)
		return;

	def_pool = create_pool(NULL);

	list_for_each_entry(opt, &s->items, entry) {
#ifdef RADIUS
		if (triton_module_loaded("radius")) {
			if (!strcmp(opt->name, "vendor")) {
				conf_vendor = parse_vendor_opt(opt->val);
				continue;
			} else if (!strcmp(opt->name, "attr")) {
				conf_attr = parse_attr_opt(opt->val);
				continue;
			}
		}
#endif
		if (!strcmp(opt->name, "gw-ip-address"))
			parse_gw_ip_address(opt->val);
		else if (!strcmp(opt->name, "shuffle"))
			conf_shuffle = atoi(opt->val);
		else {
			if (parse_options(opt->raw, &pool, &generate, &next)) {
				log_error("ippool: failed to parse '%s'\n", opt->raw);
				continue;
			}

			if (!strcmp(opt->name, "gw"))
				add_range(pool, &pool->gw_list, opt->val, generate);
			else if (!strcmp(opt->name, "tunnel"))
				add_range(pool, &pool->tunnel_list, opt->val, generate);
			else if (!opt->val || strchr(opt->name, ','))
				add_range(pool, &pool->tunnel_list, opt->name, generate);

			if (next)
				pool->next = next;
		}
	}

	if (def_pool->generate)
		def_pool->generate(def_pool);

	list_for_each_entry(pool, &pool_list, entry) {
		if (pool->generate)
			pool->generate(pool);
		else
			log_warn("ippool: pool '%s' is empty or not defined\n", pool->name);
	}

#ifdef USE_BACKUP
	backup_register_module(&backup_mod);
#endif

#ifdef RADIUS
	if (triton_module_loaded("radius"))
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
#endif
}

DEFINE_INIT(51, ippool_init1);
DEFINE_INIT2(52, ippool_init2);
