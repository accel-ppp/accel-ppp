#include <string.h>

#include "triton.h"
#include "ipdb.h"

#include "memdebug.h"

static LIST_HEAD(ipdb_handlers);

struct ipv4db_item_t __export *ipdb_get_ipv4(struct ap_session *ses)
{
	struct ipdb_t *ipdb;
	struct ipv4db_item_t *it;

	list_for_each_entry(ipdb, &ipdb_handlers, entry) {
		if (!ipdb->get_ipv4)
			continue;
		it = ipdb->get_ipv4(ses);
		if (it)
			return it;
	}

	return NULL;
}

void __export ipdb_put_ipv4(struct ap_session *ses, struct ipv4db_item_t *it)
{
	if (it->owner->put_ipv4)
		it->owner->put_ipv4(ses, it);
}

struct ipv6db_item_t __export *ipdb_get_ipv6(struct ap_session *ses)
{
	struct ipdb_t *ipdb;
	struct ipv6db_item_t *it;

	list_for_each_entry(ipdb, &ipdb_handlers, entry) {
		if (!ipdb->get_ipv6)
			continue;
		it = ipdb->get_ipv6(ses);
		if (it)
			return it;
	}

	return NULL;
}

void __export ipdb_put_ipv6(struct ap_session *ses, struct ipv6db_item_t *it)
{
	if (it->owner->put_ipv6)
		it->owner->put_ipv6(ses, it);
}

struct ipv6db_prefix_t __export *ipdb_get_ipv6_prefix(struct ap_session *ses)
{
	struct ipdb_t *ipdb;
	struct ipv6db_prefix_t *it;

	list_for_each_entry(ipdb, &ipdb_handlers, entry) {
		if (!ipdb->get_ipv6_prefix)
			continue;
		it = ipdb->get_ipv6_prefix(ses);
		if (it)
			return it;
	}

	return NULL;
}

void __export ipdb_put_ipv6_prefix(struct ap_session *ses, struct ipv6db_prefix_t *it)
{
	if (it->owner->put_ipv6_prefix)
		it->owner->put_ipv6_prefix(ses, it);
}

void __export build_ip6_addr(struct ipv6db_addr_t *a, uint64_t intf_id, struct in6_addr *addr)
{
	memcpy(addr, &a->addr, sizeof(*addr));

	if (a->prefix_len == 128)
		return;

	if (a->prefix_len <= 64)
		*(uint64_t *)(addr->s6_addr + 8) = intf_id;
	else
		/* prefix_len 65..127 means a shift of up to 63 bits: a plain
		 * int literal 1 is undefined behavior for shifts >= 31, so the
		 * host bits mask must be built from a 64-bit constant */
		*(uint64_t *)(addr->s6_addr + 8) |= intf_id & htobe64((UINT64_C(1) << (128 - a->prefix_len)) - 1);

}

void __export ipdb_register(struct ipdb_t *ipdb)
{
	list_add_tail(&ipdb->entry, &ipdb_handlers);
}
