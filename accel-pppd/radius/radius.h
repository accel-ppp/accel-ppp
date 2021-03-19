#ifndef __RADIUS_H
#define __RADIUS_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/time.h>

#include "ap_session.h"
#include "list.h"

#define REQ_LENGTH_MAX 4096

#define ATTR_TYPE_INTEGER 0
#define ATTR_TYPE_STRING  1
#define ATTR_TYPE_OCTETS  2
#define ATTR_TYPE_DATE    3
#define ATTR_TYPE_IPADDR  4
#define ATTR_TYPE_IFID    5
#define ATTR_TYPE_IPV6ADDR 6
#define ATTR_TYPE_IPV6PREFIX 7
#define ATTR_TYPE_ETHER   8
#define ATTR_TYPE_TLV     9

#define CODE_ACCESS_REQUEST 1
#define CODE_ACCESS_ACCEPT  2
#define CODE_ACCESS_REJECT  3
#define CODE_ACCESS_CHALLENGE 11

#define CODE_ACCOUNTING_REQUEST  4
#define CODE_ACCOUNTING_RESPONSE 5

#define CODE_DISCONNECT_REQUEST 40
#define CODE_DISCONNECT_ACK     41
#define CODE_DISCONNECT_NAK     42
#define CODE_COA_REQUEST 43
#define CODE_COA_ACK     44
#define CODE_COA_NAK     45

typedef union
{
		int integer;
		char *string;
		uint8_t *octets;
		time_t date;
		in_addr_t ipaddr;
		uint64_t ifid;
		struct in6_addr ipv6addr;
		struct {
			struct in6_addr prefix;
			uint8_t len;
		} ipv6prefix;
} rad_value_t;

struct rad_dict_t
{
	struct list_head items;
	struct list_head vendors;
};

struct rad_dict_vendor_t
{
	struct list_head entry;
	int id;
	int tag;
	int len;
	const char *name;
	struct list_head items;
};

struct rad_dict_value_t
{
	struct list_head entry;
	rad_value_t val;
	const char *name;
};

struct rad_dict_attr_t
{
	struct list_head entry;
	const char *name;
	int id;
	int type:30;
	unsigned int array:1;
	int size;
	struct list_head values;
	struct list_head tlv;
};

struct rad_attr_t
{
	struct list_head entry;
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;
	//struct rad_dict_value_t *val;
	int len;
	int cnt;
	unsigned int alloc:1;
	void *raw;
	rad_value_t val;
};

struct rad_packet_t
{
	int code;
	uint8_t id;
	int len;
	struct timespec tv;
	struct list_head attrs;
	uint8_t *buf;
};

struct rad_plugin_t
{
	struct list_head entry;
	int (*send_access_request)(struct rad_plugin_t *, struct rad_packet_t *pack);
	int (*send_accounting_request)(struct rad_plugin_t *, struct rad_packet_t *pack);
};

void rad_register_plugin(struct ap_session *, struct rad_plugin_t *);

struct rad_dict_attr_t *rad_dict_find_attr(const char *name);
struct rad_dict_attr_t *rad_dict_find_attr_id(struct rad_dict_vendor_t *vendor, int type);
struct rad_dict_value_t *rad_dict_find_val_name(struct rad_dict_attr_t *, const char *name);
struct rad_dict_value_t *rad_dict_find_val(struct rad_dict_attr_t *, rad_value_t val);
struct rad_dict_vendor_t *rad_dict_find_vendor_name(const char *name);
struct rad_dict_vendor_t *rad_dict_find_vendor_id(int id);
struct rad_dict_attr_t *rad_dict_find_vendor_attr(struct rad_dict_vendor_t *vendor, const char *name);

struct rad_attr_t *rad_packet_find_attr(struct rad_packet_t *pack, const char *vendor, const char *name);
int rad_packet_add_int(struct rad_packet_t *pack, const char *vendor, const char *name, int val);
int rad_packet_add_val(struct rad_packet_t *pack, const char *vendor, const char *name, const char *val);
int rad_packet_add_str(struct rad_packet_t *pack, const char *vendor, const char *name, const char *val);
int rad_packet_add_octets(struct rad_packet_t *pack, const char *vendor, const char *name, const uint8_t *val, int len);
int rad_packet_change_int(struct rad_packet_t *pack, const char *vendor, const char *name, int val);
int rad_packet_change_val(struct rad_packet_t *pack, const char *vendor, const char *name, const char *val);
int rad_packet_change_octets(struct rad_packet_t *pack, const char *vendor, const char *name, const uint8_t *val, int len);
int rad_packet_add_ipaddr(struct rad_packet_t *pack, const char *vendor, const char *name, in_addr_t ipaddr);
int rad_packet_add_ifid(struct rad_packet_t *pack, const char *vendor, const char *name, uint64_t ifid);
int rad_packet_add_ipv6prefix(struct rad_packet_t *pack, const char *vendor, const char *name, struct in6_addr *prefix, int len);

#endif

