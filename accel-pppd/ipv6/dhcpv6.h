#ifndef __DHCPV6_H
#define __DHCPV6_H

#include <stdint.h>
#include <netinet/in.h>

#include "list.h"

#define __packed __attribute__((packed))

#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERV_PORT 547

#define D6_OPTION_CLIENTID         1
#define D6_OPTION_SERVERID         2
#define D6_OPTION_IA_NA            3
#define D6_OPTION_IA_TA            4
#define D6_OPTION_IAADDR           5
#define D6_OPTION_ORO              6
#define D6_OPTION_PREFERENCE       7
#define D6_OPTION_ELAPSED_TIME     8
#define D6_OPTION_RELAY_MSG        9
#define D6_OPTION_AUTH            11
#define D6_OPTION_UNICAST         12
#define D6_OPTION_STATUS_CODE     13
#define D6_OPTION_RAPID_COMMIT    14
#define D6_OPTION_USER_CLASS      15
#define D6_OPTION_VENDOR_CLASS    16
#define D6_OPTION_VENDOR_SPECIFIC 17
#define D6_OPTION_INTERFACE_ID    18
#define D6_OPTION_RECONF_MSG      19
#define D6_OPTION_RECONF_ACCEPT   20
#define D6_OPTION_DNS_SERVERS     23
#define D6_OPTION_DOMAIN_LIST     24
#define D6_OPTION_IA_PD           25
#define D6_OPTION_IAPREFIX        26
#define D6_OPTION_IAPREFIX        26

#define D6_SOLICIT                 1
#define D6_ADVERTISE               2
#define D6_REQUEST                 3
#define D6_CONFIRM                 4
#define D6_RENEW                   5
#define D6_REBIND                  6
#define D6_REPLY                   7
#define D6_RELEASE                 8
#define D6_DECLINE                 9
#define D6_RECONFIGURE            10
#define D6_INFORMATION_REQUEST    11
#define D6_RELAY_FORW             12
#define D6_RELAY_REPL             13

#define D6_STATUS_Success          0
#define D6_STATUS_UnspecFail       1
#define D6_STATUS_NoAddrsAvail     2
#define D6_STATUS_NoBinding        3
#define D6_STATUS_NotOnLink        4
#define D6_STATUS_UseMulticast     5
#define D6_STATUS_NoPrefixAvail    6

#define DUID_LLT 1
#define DUID_EN  2
#define DUID_LL  3

struct dhcpv6_opt_hdr {
	uint16_t code;
	uint16_t len;
	uint8_t data[0];
} __packed;

struct dhcpv6_msg_hdr {
	uint32_t type:8;
	uint32_t trans_id:24;
	uint8_t data[0];
} __packed;

struct dhcpv6_relay_hdr {
	uint8_t type;
	uint8_t hop_cnt;
	struct in6_addr link_addr;
	struct in6_addr peer_addr;
	uint8_t data[0];
} __packed;

struct dhcpv6_duid {
	uint16_t type;
	union {
		struct {
			uint16_t htype;
			uint32_t time;
			uint8_t addr[0];
		} __packed llt;
		struct {
			uint32_t enterprise;
			uint8_t id[0];
		} __packed en;
		struct {
			uint16_t htype;
			uint8_t addr[0];
		} __packed ll;
		uint8_t raw[0];
	} u;
} __packed;

struct dhcpv6_opt_clientid {
	struct dhcpv6_opt_hdr hdr;
	struct dhcpv6_duid duid;
} __packed;

struct dhcpv6_opt_serverid {
	struct dhcpv6_opt_hdr hdr;
	struct dhcpv6_duid duid;
} __packed;

struct dhcpv6_opt_ia_na {
	struct dhcpv6_opt_hdr hdr;
	uint32_t iaid;
	uint32_t T1;
	uint32_t T2;
} __packed;

struct dhcpv6_opt_ia_ta {
	struct dhcpv6_opt_hdr hdr;
	uint32_t iaid;
} __packed;


struct dhcpv6_opt_ia_addr {
	struct dhcpv6_opt_hdr hdr;
	struct in6_addr addr;
	uint32_t pref_lifetime;
	uint32_t valid_lifetime;
} __packed;

struct dhcpv6_opt_oro {
	struct dhcpv6_opt_hdr hdr;
	uint16_t opt[0];
} __packed;

struct dhcpv6_opt_status {
	struct dhcpv6_opt_hdr hdr;
	uint16_t code;
	char msg[0];
} __packed;

struct dhcpv6_opt_ia_prefix {
	struct dhcpv6_opt_hdr hdr;
	uint32_t pref_lifetime;
	uint32_t valid_lifetime;
	uint8_t prefix_len;
	struct in6_addr prefix;
} __packed;


struct dhcpv6_option {
	struct list_head entry;

	struct dhcpv6_opt_hdr *hdr;

	struct dhcpv6_option *parent;
	struct list_head opt_list;
};

struct dhcpv6_pd;

struct dhcpv6_relay {
	struct list_head entry;
	int hop_cnt;
	struct in6_addr link_addr;
	struct in6_addr peer_addr;
	void *hdr;
};

struct dhcpv6_packet {
	struct ap_session *ses;
	struct dhcpv6_pd *pd;
	struct sockaddr_in6 addr;

	struct dhcpv6_msg_hdr *hdr;
	struct dhcpv6_opt_clientid *clientid;
	struct dhcpv6_opt_serverid *serverid;

	struct list_head relay_list;

	unsigned int rapid_commit:1;

	struct list_head opt_list;
	void *endptr;
};

extern int conf_verbose;

struct dhcpv6_packet *dhcpv6_packet_parse(const void *buf, size_t size);
void dhcpv6_packet_free(struct dhcpv6_packet *pkt);
void dhcpv6_packet_print(struct dhcpv6_packet *pkt, void (*print)(const char *fmt, ...));
struct dhcpv6_packet *dhcpv6_packet_alloc_reply(struct dhcpv6_packet *req, int type);
struct dhcpv6_option *dhcpv6_option_alloc(struct dhcpv6_packet *pkt, int code, int len);
struct dhcpv6_option *dhcpv6_nested_option_alloc(struct dhcpv6_packet *pkt, struct dhcpv6_option *opt, int code, int len);
void dhcpv6_fill_relay_info(struct dhcpv6_packet *pkt);

#endif
