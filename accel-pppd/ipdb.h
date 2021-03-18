#ifndef IPDB_H
#define IPDB_H

#include "ppp.h"
#include "list.h"

struct ipv4db_item_t
{
	struct ipdb_t *owner;
	in_addr_t addr;
	in_addr_t peer_addr;
	int mask;
};

struct ipv6db_addr_t
{
	struct list_head entry;
	struct in6_addr addr;
	int prefix_len;
	unsigned int flag_onlink:1;
	unsigned int flag_auto:1;
	unsigned int installed:1;
};

struct ipv6db_item_t
{
	struct ipdb_t *owner;
	uint64_t intf_id;
	uint64_t peer_intf_id;
	struct list_head addr_list;
};

struct ipv6db_prefix_t
{
	struct ipdb_t *owner;
	struct list_head prefix_list;
};


struct ipdb_t
{
	struct list_head entry;

	struct ipv4db_item_t *(*get_ipv4)(struct ap_session *ses);
	void (*put_ipv4)(struct ap_session *ses, struct ipv4db_item_t *);

	struct ipv6db_item_t *(*get_ipv6)(struct ap_session *ses);
	void (*put_ipv6)(struct ap_session *ses, struct ipv6db_item_t *);

	struct ipv6db_prefix_t *(*get_ipv6_prefix)(struct ap_session *ses);
	void (*put_ipv6_prefix)(struct ap_session *ses, struct ipv6db_prefix_t *);
};

struct ipv4db_item_t *ipdb_get_ipv4(struct ap_session *ses);
void ipdb_put_ipv4(struct ap_session *ses, struct ipv4db_item_t *);

struct ipv6db_item_t *ipdb_get_ipv6(struct ap_session *ses);
void ipdb_put_ipv6(struct ap_session *ses, struct ipv6db_item_t *);

struct ipv6db_prefix_t *ipdb_get_ipv6_prefix(struct ap_session *ses);
void ipdb_put_ipv6_prefix(struct ap_session *ses, struct ipv6db_prefix_t *it);

void ipdb_register(struct ipdb_t *);

void build_ip6_addr(struct ipv6db_addr_t *a, uint64_t intf_id, struct in6_addr *addr);

#endif

