#ifndef __IPOE_H
#define __IPOE_H

#include <stdint.h>
#include <pthread.h>
#include <linux/if.h>

#include "triton.h"
#include "ap_session.h"
#include "ipdb.h"
#include "dhcpv4.h"

#ifdef RADIUS
#include "radius.h"
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct _arphdr {
	__be16 ar_hrd;
	__be16 ar_pro;
	__u8   ar_hln;
	__u8   ar_pln;
	__be16 ar_op;
	__u8   ar_sha[ETH_ALEN];
	__be32 ar_spa;
	__u8   ar_tha[ETH_ALEN];
	__be32 ar_tpa;
} __packed;

struct ipoe_serv {
	struct list_head entry;
	struct triton_context_t ctx;
	char ifname[IFNAMSIZ];
	int ifindex;
	uint8_t hwaddr[ETH_ALEN];
	struct list_head sessions;
	unsigned int sess_cnt;
	struct dhcpv4_serv *dhcpv4;
	void *arp;
	struct list_head disc_list;
	struct list_head arp_list;
	struct list_head req_list;
	struct list_head relay_list;
	struct triton_timer_t disc_timer;
	struct triton_timer_t timer;
	pthread_mutex_t lock;
	int parent_ifindex;
	int vid;
	int parent_vid;
	int opt_mode;
	uint32_t opt_src;
	int opt_arp;
	int opt_username;
	int opt_mtu;
#ifdef USE_LUA
	char *opt_lua_username_func;
#endif
	int opt_weight;
	unsigned int opt_shared:1;
	unsigned int opt_dhcpv4:1;
	unsigned int opt_up:1;
	unsigned int opt_auto:1;
	unsigned int opt_ifcfg:1;
	unsigned int opt_nat:1;
	unsigned int opt_ipv6:1;
	unsigned int opt_ip_unnumbered:1;
	unsigned int need_close:1;
	unsigned int active:1;
	unsigned int vlan_mon:1;
};

struct ipoe_session {
	struct list_head entry;
	struct triton_context_t ctx;
	struct triton_timer_t timer;
	struct triton_timer_t l4_redirect_timer;
	struct ipoe_serv *serv;
	struct dhcpv4_serv *dhcpv4;
	struct ap_ctrl ctrl;
	struct ap_session ses;
	uint8_t hwaddr[ETH_ALEN];
	struct dhcpv4_option *client_id;
	struct dhcpv4_option *relay_agent;
	uint8_t *agent_circuit_id;
	uint8_t *agent_remote_id;
	uint8_t *link_selection;
	uint32_t xid;
	uint32_t giaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t router;
	uint32_t relay_server_id;
	int l4_redirect_table;
	char *l4_redirect_ipset;
	int mask;
	int lease_time;
	int renew_time;
	int rebind_time;
	uint8_t *data;
	struct dhcpv4_packet *dhcpv4_request;
	struct dhcpv4_packet *dhcpv4_relay_reply;
	struct _arphdr *arph;
	int relay_retransmit;
	int ifindex;
	char *username;
	struct ipv4db_item_t ipv4;
	unsigned int weight;
#ifdef RADIUS
	struct rad_plugin_t radius;
#endif
	unsigned int started:1;
	unsigned int terminating:1;
	unsigned int dhcp_addr:1;
	unsigned int relay_addr:1;
	unsigned int l4_redirect:1;
	unsigned int l4_redirect_set:1;
	unsigned int terminate:1;
	unsigned int UP:1;
	unsigned int wait_start:1;
};

struct ipoe_session_info {
	struct list_head entry;
	int ifindex;
	uint32_t addr;
	uint32_t peer_addr;
};

int ipoe_ipv6_nd_start(struct ipoe_serv *serv);

#ifdef USE_LUA
char *ipoe_lua_get_username(struct ipoe_session *, const char *func);
int ipoe_lua_make_vlan_name(const char *func, const char *parent, int svid, int cvid, char *name);
#endif

struct iphdr;
struct ethhdr;

void ipoe_recv_up(int ifindex, struct ethhdr *eth, struct iphdr *iph, struct _arphdr *arph);

struct ipoe_session *ipoe_session_alloc(const char *ifname);

struct ipoe_serv *ipoe_find_serv(const char *ifname);
void ipoe_serv_recv_arp(struct ipoe_serv *s, struct _arphdr *arph);

void ipoe_nl_add_interface(int ifindex, uint8_t mode);
void ipoe_nl_del_interface(int ifindex);
void ipoe_nl_delete_interfaces(void);
int ipoe_nl_create();
void ipoe_nl_delete(int ifindex);
int ipoe_nl_modify(int ifindex, uint32_t peer_addr, uint32_t addr, uint32_t gw, int link_ifindex, uint8_t *hwaddr);
void ipoe_nl_get_sessions(struct list_head *list);
int ipoe_nl_add_exclude(uint32_t addr, int mask);
void ipoe_nl_del_exclude(uint32_t addr);
int ipoe_nl_add_net(uint32_t addr, int mask);
void ipoe_nl_del_net(uint32_t addr);

void *arpd_start(struct ipoe_serv *ipoe);
void arpd_stop(void *arp);
void arp_send(int ifindex, struct _arphdr *arph, int bc);

int ipoe_check_localnet(in_addr_t addr);

#endif

