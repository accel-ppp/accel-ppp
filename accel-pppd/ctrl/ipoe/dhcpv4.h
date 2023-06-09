#ifndef __DHCPV4_H
#define __DHCPV4_H

#include <stdint.h>
#include <pthread.h>
#include <endian.h>
#include "list.h"

#include "triton.h"

#define __aligned(n) __attribute__((aligned (n)))
#define __packed __attribute__((packed))

#define DHCP_SERV_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC "\x63\x82\x53\x63"

#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY   2

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define DHCP_F_BROADCAST 0x0080
#else
#define DHCP_F_BROADCAST 0x8000
#endif

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define ACCEL_PPP_MAGIC 0xfd56b60a

struct dhcpv4_hdr {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t sec;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	char sname[64];
	char file[128];
	uint8_t magic[4];
} __packed;

struct dhcpv4_option {
	struct list_head entry;
	struct list_head list;
	uint8_t type;
	uint8_t len;
	uint8_t *data;
};

struct dhcpv4_packet {
	struct dhcpv4_hdr *hdr;
	struct list_head options;
	struct dhcpv4_option *client_id;
	struct dhcpv4_option *relay_agent;
	uint32_t request_ip;
	uint32_t server_id;
	int msg_type;
	in_addr_t src_addr;
	in_addr_t dst_addr;
	int volatile refs;
	uint8_t *ptr;
	uint8_t data[0];
};

struct dhcpv4_iprange {
	struct list_head entry;
	uint32_t routerip;
	uint32_t startip;
	int mask;
	int pos;
	int len;
	pthread_mutex_t lock;
	unsigned long free[0];
};

struct dhcpv4_serv {
	struct triton_context_t *ctx;
	struct triton_md_handler_t hnd;
	uint8_t hwaddr[6];
	int ifindex;
	void (*recv)(struct dhcpv4_serv *serv, struct dhcpv4_packet *pack);
	struct dhcpv4_iprange *range;
};

struct dhcpv4_relay {
	struct list_head entry;
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct list_head ctx_list;
	in_addr_t addr;
	in_addr_t giaddr;
};

struct ap_session;
struct rad_packet_t;

struct dhcpv4_serv *dhcpv4_create(struct triton_context_t *ctx, const char *ifname, const char *opt);
void dhcpv4_free(struct dhcpv4_serv *);

struct dhcpv4_relay *dhcpv4_relay_create(const char *addr, in_addr_t giaddr, struct triton_context_t *ctx, triton_event_func recv);
void dhcpv4_relay_free(struct dhcpv4_relay *, struct triton_context_t *);
int dhcpv4_relay_send(struct dhcpv4_relay *relay, struct dhcpv4_packet *request, uint32_t server_id,
        const char *agent_circuit_id, const char *agent_remote_id,
        const char *link_selection);
int dhcpv4_relay_send_release(struct dhcpv4_relay *relay, uint8_t *chaddr, uint32_t xid, uint32_t ciaddr,
	struct dhcpv4_option *client_id, struct dhcpv4_option *relay_agent,
        const char *agent_circuit_id, const char *agent_remote_id,
        const char *link_selection);
int dhcpv4_send_reply(int msg_type, struct dhcpv4_serv *serv, struct dhcpv4_packet *req,
	uint32_t yiaddr, uint32_t siaddr, uint32_t router, uint32_t mask,
	int lease_time, int renew_time, int rebind_time, struct dhcpv4_packet *relay_reply);
int dhcpv4_send_nak(struct dhcpv4_serv *serv, struct dhcpv4_packet *req, const char *err);

void dhcpv4_send_notify(struct dhcpv4_serv *serv, struct dhcpv4_packet *req, unsigned int weight);

void dhcpv4_packet_ref(struct dhcpv4_packet *pack);
struct dhcpv4_option *dhcpv4_packet_find_opt(struct dhcpv4_packet *pack, int type);
int dhcpv4_packet_insert_opt82(struct dhcpv4_packet *pack, const char *agent_circuit_id, const char *agent_remote_id, const char *link_selection);
void dhcpv4_packet_free(struct dhcpv4_packet *pack);
struct dhcpv4_packet *dhcpv4_clone_radius(struct rad_packet_t *);

int dhcpv4_check_options(struct dhcpv4_packet *);
void dhcpv4_print_options(struct dhcpv4_packet *, void (*)(const char *, ...));

void dhcpv4_print_packet(struct dhcpv4_packet *pack, int relay, void (*print)(const char *fmt, ...));

int dhcpv4_parse_opt82(struct dhcpv4_option *opt, uint8_t **agent_circuit_id, uint8_t **agent_remote_id, uint8_t **link_selection);

int dhcpv4_get_ip(struct dhcpv4_serv *serv, uint32_t *yiaddr, uint32_t *siaddr, int *mask);
void dhcpv4_put_ip(struct dhcpv4_serv *serv, uint32_t ip);
void dhcpv4_reserve_ip(struct dhcpv4_serv *serv, uint32_t ip);

#endif
