#ifndef __L2TP_H
#define __L2TP_H

#include <netinet/in.h>

#include "list.h"
#include "l2tp_prot.h"

#define ATTR_TYPE_NONE    0
#define ATTR_TYPE_INT16   1
#define ATTR_TYPE_INT32   2
#define ATTR_TYPE_INT64   3
#define ATTR_TYPE_OCTETS  4
#define ATTR_TYPE_STRING  5

#define L2TP_MAX_PACKET_SIZE 65536

#define L2TP_V2_PROTOCOL_VERSION ( 1 << 8 | 0 )

#define L2TP_DATASEQ_ALLOW  -1
#define L2TP_DATASEQ_DENY    0
#define L2TP_DATASEQ_PREFER  1
#define L2TP_DATASEQ_REQUIRE 2

typedef union
{
	uint32_t uint32;
	int32_t  int32;
	uint16_t uint16;
	int16_t  int16;
	uint64_t uint64;
	uint8_t *octets;
	char    *string;
} l2tp_value_t;

struct l2tp_dict_attr_t
{
	struct list_head entry;
	const char *name;
	int id;
	int type;
	int M;
	int H;
	struct list_head values;
};

struct l2tp_dict_value_t
{
	struct list_head entry;
	const char *name;
	l2tp_value_t val;
};

struct l2tp_attr_t
{
	struct list_head entry;
	struct l2tp_dict_attr_t *attr;
	unsigned int M:1;
	unsigned int H:1;
	int length;
	l2tp_value_t val;
};

struct l2tp_packet_t
{
	struct list_head entry;
	struct list_head sess_entry;
	struct sockaddr_in addr;
	struct l2tp_hdr_t hdr;
	struct list_head attrs;
	struct l2tp_attr_t *last_RV;
	const char *secret;
	size_t secret_len;
	int hide_avps;
};

extern int conf_verbose;
extern int conf_avp_permissive;

static inline int l2tp_packet_is_ZLB(const struct l2tp_packet_t *pack)
{
	return list_empty(&pack->attrs);
}

struct l2tp_dict_attr_t *l2tp_dict_find_attr_by_name(const char *name);
struct l2tp_dict_attr_t *l2tp_dict_find_attr_by_id(int id);
const struct l2tp_dict_value_t *l2tp_dict_find_value(const struct l2tp_dict_attr_t *attr,
						     l2tp_value_t val);

int l2tp_recv(int fd, struct l2tp_packet_t **, struct in_pktinfo *,
	      const char *secret, size_t secret_len);
void l2tp_packet_free(struct l2tp_packet_t *);
void l2tp_packet_print(const struct l2tp_packet_t *,
		       void (*print)(const char *fmt, ...));
struct l2tp_packet_t *l2tp_packet_alloc(int ver, int msg_type,
					const struct sockaddr_in *addr, int H,
					const char *secret, size_t secret_len);
int l2tp_packet_send(int sock, struct l2tp_packet_t *);
int l2tp_packet_add_int16(struct l2tp_packet_t *pack, int id, int16_t val, int M);
int l2tp_packet_add_int32(struct l2tp_packet_t *pack, int id, int32_t val, int M);
int l2tp_packet_add_int64(struct l2tp_packet_t *pack, int id, int64_t val, int M);
int l2tp_packet_add_string(struct l2tp_packet_t *pack, int id, const char *val, int M);
int l2tp_packet_add_octets(struct l2tp_packet_t *pack, int id, const uint8_t *val, int size, int M);

void l2tp_nl_create_tunnel(int fd, int tid, int peer_tid);
void l2tp_nl_create_session(int tid, int sid, int peer_sid);
void l2tp_nl_delete_tunnel(int tid);

#endif
