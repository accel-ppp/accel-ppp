#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/route.h>

#include <pcre.h>

#include "events.h"
#include "list.h"
#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "utils.h"
#include "cli.h"
#include "ap_session.h"
#include "pwdb.h"
#include "ipdb.h"
#include "dhcp_attr_defs.h"

#include "iputils.h"
#include "ipset.h"

#include "connlimit.h"
#include "vlan_mon.h"

#include "ipoe.h"

#include "memdebug.h"

#define USERNAME_UNSET 0
#define USERNAME_IFNAME 1
#define USERNAME_LUA 2

#define MODE_L2 2
#define MODE_L3 3

#define LEASE_TIME 600

#define SESSION_TERMINATED "Session was terminated"

struct iplink_arg {
	pcre *re;
	const char *opt;
	long *arg1;
};

struct unit_cache {
	struct list_head entry;
	int ifindex;
};

struct l4_redirect {
	struct list_head entry;
	in_addr_t addr;
	time_t timeout;
};

struct gw_addr {
	struct list_head entry;
	in_addr_t addr;
	int mask;
	int mask1;
};

struct disc_item {
	struct list_head entry;
	struct dhcpv4_packet *pack;
	struct timespec ts;
};

struct arp_item {
	struct list_head entry;
	struct timespec ts;
	struct _arphdr arph;
};

struct delay {
	struct list_head entry;
	unsigned int conn_cnt;
	int delay;
};

struct request_item {
	struct list_head entry;
	uint32_t xid;
	time_t expire;
	int cnt;
};

struct local_net {
	struct list_head entry;
	in_addr_t addr;
	int mask;
	int active;
};

enum {SID_MAC, SID_IP};

static int conf_check_exists;
static int conf_dhcpv4 = 1;
static int conf_up;
static int conf_auto;
static int conf_mode;
static int conf_shared = 1;
static int conf_ifcfg = 1;
static int conf_nat;
static int conf_arp;
static int conf_ipv6;
static uint32_t conf_src;
static const char *conf_ip_pool;
static const char *conf_ipv6_pool;
static const char *conf_dpv6_pool;
static const char *conf_l4_redirect_pool;
//static int conf_dhcpv6;
static int conf_username;
static const char *conf_password;
static int conf_unit_cache;
static int conf_noauth;
#ifdef RADIUS
static int conf_vendor;
static const char *conf_vendor_str;
static int conf_attr_dhcp_client_ip;
static int conf_attr_dhcp_router_ip;
static int conf_attr_dhcp_mask;
static int conf_attr_dhcp_lease_time;
static int conf_attr_dhcp_renew_time;
static int conf_attr_dhcp_rebind_time;
static int conf_attr_l4_redirect;
static int conf_attr_l4_redirect_table;
static int conf_attr_l4_redirect_ipset;
static const char *conf_attr_dhcp_opt82;
static const char *conf_attr_dhcp_opt82_remote_id;
static const char *conf_attr_dhcp_opt82_circuit_id;
#endif
static int conf_l4_redirect_table;
static int conf_l4_redirect_on_reject;
static const char *conf_l4_redirect_ipset;
static int conf_vlan_timeout;
static int conf_max_request = 3;
static int conf_session_timeout;
static int conf_idle_timeout;
static int conf_weight;

static const char *conf_relay;

#ifdef USE_LUA
static const char *conf_lua_username_func;
#endif

static int conf_offer_timeout = 10;
static int conf_relay_timeout = 3;
static int conf_relay_retransmit = 3;
static LIST_HEAD(conf_gw_addr);
static int conf_netmask = 24;
static int conf_lease_time = LEASE_TIME;
static int conf_lease_timeout = LEASE_TIME + LEASE_TIME/10;
static int conf_renew_time = LEASE_TIME/2;
static int conf_rebind_time = LEASE_TIME/2 + LEASE_TIME/4 + LEASE_TIME/8;
static int conf_verbose;
static const char *conf_agent_remote_id;
static const char *conf_link_selection;
static int conf_proto;
static LIST_HEAD(conf_offer_delay);
static const char *conf_vlan_name;
static int conf_ip_unnumbered;
static int conf_check_mac_change;
static int conf_soft_terminate;
static int conf_calling_sid = SID_MAC;

static unsigned int stat_starting;
static unsigned int stat_active;
static unsigned int stat_delayed_offer;

static mempool_t ses_pool;
static mempool_t disc_item_pool;
static mempool_t arp_item_pool;
static mempool_t req_item_pool;

static int connlimit_loaded;
static int radius_loaded;

static LIST_HEAD(serv_list);
static pthread_mutex_t serv_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t uc_lock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(uc_list);
static int uc_size;
static mempool_t uc_pool;

static LIST_HEAD(local_nets);

static pthread_rwlock_t l4_list_lock = PTHREAD_RWLOCK_INITIALIZER;
static LIST_HEAD(l4_redirect_list);
static struct triton_timer_t l4_redirect_timer;
static struct triton_context_t l4_redirect_ctx;

static void ipoe_session_finished(struct ap_session *s);
static void ipoe_drop_sessions(struct ipoe_serv *serv, struct ipoe_session *skip);
static void ipoe_serv_release(struct ipoe_serv *serv);
static void __ipoe_session_activate(struct ipoe_session *ses);
static void ipoe_ses_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack);
static void __ipoe_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack, int force);
static void ipoe_session_keepalive(struct dhcpv4_packet *pack);
static void add_interface(const char *ifname, int ifindex, const char *opt, int parent_ifindex, int vid, int vlan_mon);
static int get_offer_delay();
static void __ipoe_session_start(struct ipoe_session *ses);
static int ipoe_rad_send_auth_request(struct rad_plugin_t *rad, struct rad_packet_t *pack);
static int ipoe_rad_send_acct_request(struct rad_plugin_t *rad, struct rad_packet_t *pack);
static void ipoe_session_create_auto(struct ipoe_serv *serv);
static void ipoe_serv_timeout(struct triton_timer_t *t);
static struct ipoe_session *ipoe_session_create_up(struct ipoe_serv *serv, struct ethhdr *eth, struct iphdr *iph, struct _arphdr *arph);
static void __terminate(struct ap_session *ses);
static void ipoe_ipv6_disable(struct ipoe_serv *serv);
static struct conf_option_t *ipoe_find_opt(const char *name);

static void ipoe_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	if (arg) {
		struct ap_session *s = arg;
		net = s->net;
	} else
		net = def_net;

	log_switch(ctx, arg);
}

int ipoe_check_localnet(in_addr_t addr)
{
	struct local_net *n;

	if (list_empty(&local_nets))
		return 1;

	list_for_each_entry(n, &local_nets, entry) {
		if ((addr & n->mask) == n->addr)
			return 1;
	}

	return 0;
}

static struct ipoe_session *ipoe_session_lookup(struct ipoe_serv *serv, struct dhcpv4_packet *pack, struct ipoe_session **opt82_ses)
{
	struct ipoe_session *ses, *res = NULL;

	uint8_t *agent_circuit_id = NULL;
	uint8_t *agent_remote_id = NULL;
	uint8_t *link_selection = NULL;
	int opt82_match;

	if (opt82_ses)
		*opt82_ses = NULL;

	if (list_empty(&serv->sessions))
		return NULL;

	if (!serv->opt_shared) {
		ses = list_entry(serv->sessions.next, typeof(*ses), entry);
		ses->UP = 0;
		if (opt82_ses)
			*opt82_ses = ses;
		return ses;
	}

	if (!conf_check_mac_change || (pack->relay_agent && dhcpv4_parse_opt82(pack->relay_agent, &agent_circuit_id, &agent_remote_id, &link_selection))) {
		agent_circuit_id = NULL;
		agent_remote_id = NULL;
		link_selection = NULL;
	}

	list_for_each_entry(ses, &serv->sessions, entry) {
		opt82_match = conf_check_mac_change && pack->relay_agent != NULL;

		if (agent_circuit_id && !ses->agent_circuit_id)
			opt82_match = 0;

		if (opt82_match && agent_remote_id && !ses->agent_remote_id)
			opt82_match = 0;

		if (opt82_match && link_selection && !ses->link_selection)
			opt82_match = 0;

		if (opt82_match && !agent_circuit_id && ses->agent_circuit_id)
			opt82_match = 0;

		if (opt82_match && !agent_remote_id && ses->agent_remote_id)
			opt82_match = 0;

		if (opt82_match && !link_selection && ses->link_selection)
			opt82_match = 0;

		if (opt82_match && agent_circuit_id) {
			if (*agent_circuit_id != *ses->agent_circuit_id)
				opt82_match = 0;

			if (memcmp(agent_circuit_id + 1, ses->agent_circuit_id + 1, *agent_circuit_id))
				opt82_match = 0;
		}

		if (opt82_match && agent_remote_id) {
			if (*agent_remote_id != *ses->agent_remote_id)
				opt82_match = 0;

			if (memcmp(agent_remote_id + 1, ses->agent_remote_id + 1, *agent_remote_id))
				opt82_match = 0;
		}

		if (opt82_match && link_selection) {
			if (*link_selection != *ses->link_selection)
				opt82_match = 0;

			if (memcmp(link_selection + 1, ses->link_selection + 1, *link_selection))
				opt82_match = 0;
		}

		if (opt82_match && opt82_ses)
			*opt82_ses = ses;

		if (memcmp(pack->hdr->chaddr, ses->hwaddr, ETH_ALEN))
			continue;

		res = ses;
		break;

		/*if (pack->client_id && !ses->client_id)
			continue;

		if (!pack->client_id && ses->client_id)
			continue;

		if (pack->client_id) {
			if (pack->client_id->len != ses->client_id->len)
				continue;
			if (memcmp(pack->client_id->data, ses->client_id->data, pack->client_id->len))
				continue;
		}

		ses1 = ses;

		if (pack->hdr->xid != ses->xid)
			continue;

		return ses;*/
	}

	if (!res || !pack->relay_agent || !opt82_ses || *opt82_ses)
		return res;

	list_for_each_entry(ses, &serv->sessions, entry) {
		if (agent_circuit_id && !ses->agent_circuit_id)
			continue;

		if (opt82_match && agent_remote_id && !ses->agent_remote_id)
			continue;

		if (opt82_match && link_selection && !ses->link_selection)
			continue;

		if (opt82_match && !agent_circuit_id && ses->agent_circuit_id)
			continue;

		if (opt82_match && !agent_remote_id && ses->agent_remote_id)
			continue;

		if (opt82_match && !link_selection && ses->link_selection)
			continue;

		if (opt82_match && agent_circuit_id) {
			if (*agent_circuit_id != *ses->agent_circuit_id)
				continue;

			if (memcmp(agent_circuit_id + 1, ses->agent_circuit_id + 1, *agent_circuit_id))
				continue;
		}

		if (opt82_match && agent_remote_id) {
			if (*agent_remote_id != *ses->agent_remote_id)
				continue;

			if (memcmp(agent_remote_id + 1, ses->agent_remote_id + 1, *agent_remote_id))
				continue;
		}

		if (opt82_match && link_selection) {
			if (*link_selection != *ses->link_selection)
				continue;

			if (memcmp(link_selection + 1, ses->link_selection + 1, *link_selection))
				continue;
		}

		*opt82_ses = ses;
		break;
	}

	return res;
}

static void ipoe_session_timeout(struct triton_timer_t *t)
{
	struct ipoe_session *ses = container_of(t, typeof(*ses), timer);

	triton_timer_del(t);

	log_ppp_info2("ipoe: session timed out\n");

	ap_session_terminate(&ses->ses, TERM_LOST_CARRIER, 1);
}

static void ipoe_session_l4_redirect_timeout(struct triton_timer_t *t)
{
	struct ipoe_session *ses = container_of(t, typeof(*ses), l4_redirect_timer);

	triton_timer_del(t);

	log_ppp_info2("ipoe: session timed out\n");

	ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
}

static void ipoe_relay_timeout(struct triton_timer_t *t)
{
	struct ipoe_session *ses = container_of(t, typeof(*ses), timer);

	if (!ses->serv->dhcpv4_relay || !ses->dhcpv4_request) {
		triton_timer_del(t);
		return;
	}

	if (++ses->relay_retransmit > conf_relay_retransmit) {
		triton_timer_del(t);

		log_ppp_info2("ipoe: relay timed out\n");

		ap_session_terminate(&ses->ses, TERM_LOST_CARRIER, 1);
	} else
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, ses->dhcpv4_request, ses->relay_server_id, ses->serv->ifname, conf_agent_remote_id, conf_link_selection);
}


static char *ipoe_session_get_username(struct ipoe_session *ses)
{
	if (ses->username)
		return ses->username;

#ifdef USE_LUA
	if (ses->serv->opt_username == USERNAME_LUA)
		return ipoe_lua_get_username(ses, ses->serv->opt_lua_username_func ? : conf_lua_username_func);
	else
#endif
	if (!ses->dhcpv4_request)
		return _strdup(ses->ctrl.calling_station_id);

	return _strdup(ses->serv->ifname);
}

static void l4_redirect_list_add(in_addr_t addr)
{
	struct l4_redirect *n = _malloc(sizeof(*n));
	struct timespec ts;

	if (!n)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	memset(n, 0, sizeof(*n));
	n->addr = addr;
	n->timeout = ts.tv_sec + conf_l4_redirect_on_reject;

	ipoe_nl_add_exclude(addr, 32);

	if (conf_l4_redirect_table)
		iprule_add(addr, conf_l4_redirect_table);

	if (conf_l4_redirect_ipset)
		ipset_add(conf_l4_redirect_ipset, addr);

	pthread_rwlock_wrlock(&l4_list_lock);

	list_add_tail(&n->entry, &l4_redirect_list);

	if (!l4_redirect_timer.tpd)
		triton_timer_add(&l4_redirect_ctx, &l4_redirect_timer, 0);

	pthread_rwlock_unlock(&l4_list_lock);
}

static int l4_redirect_list_check(in_addr_t addr)
{
	struct l4_redirect *n;

	pthread_rwlock_rdlock(&l4_list_lock);
	list_for_each_entry(n, &l4_redirect_list, entry) {
		if (n->addr == addr) {
			pthread_rwlock_unlock(&l4_list_lock);
			return 1;
		}
	}
	pthread_rwlock_unlock(&l4_list_lock);
	return 0;
}

static void l4_redirect_list_timer(struct triton_timer_t *t)
{
	struct l4_redirect *n;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	pthread_rwlock_wrlock(&l4_list_lock);
	while (!list_empty(&l4_redirect_list)) {
		n = list_entry(l4_redirect_list.next, typeof(*n), entry);
		if (ts.tv_sec > n->timeout) {
			list_del(&n->entry);
			pthread_rwlock_unlock(&l4_list_lock);

			if (conf_l4_redirect_table)
				iprule_del(n->addr, conf_l4_redirect_table);

			if (conf_l4_redirect_ipset)
				ipset_del(conf_l4_redirect_ipset, n->addr);

			ipoe_nl_del_exclude(n->addr);

			_free(n);
			pthread_rwlock_wrlock(&l4_list_lock);
		} else
			break;
	}

	if (list_empty(&l4_redirect_list) && l4_redirect_timer.tpd)
		triton_timer_del(&l4_redirect_timer);

	pthread_rwlock_unlock(&l4_list_lock);
}

static void ipoe_change_l4_redirect(struct ipoe_session *ses, int del)
{
	in_addr_t addr;

	if (ses->ses.ipv4)
		addr = ses->ses.ipv4->peer_addr;
	else
		addr = ses->yiaddr;

	if (ses->l4_redirect_table) {
		if (del) {
			iprule_del(addr, ses->l4_redirect_table);
			ses->l4_redirect_set = 0;
		} else {
			iprule_add(addr, ses->l4_redirect_table);
			ses->l4_redirect_set = 1;
		}
	}

	if (conf_l4_redirect_ipset || ses->l4_redirect_ipset) {
		if (del) {
			ipset_del(ses->l4_redirect_ipset ?: conf_l4_redirect_ipset, addr);
			ses->l4_redirect_set = 0;
		} else {
			ipset_add(ses->l4_redirect_ipset ?: conf_l4_redirect_ipset, addr);
			ses->l4_redirect_set = 1;
		}
	}

	if (del && ses->l4_redirect_timer.tpd)
		triton_timer_del(&ses->l4_redirect_timer);
}

static void ipoe_change_addr(struct ipoe_session *ses, in_addr_t newaddr)
{

}

static int ipoe_create_interface(struct ipoe_session *ses)
{
	struct unit_cache *uc;
	struct ifreq ifr;

	pthread_mutex_lock(&uc_lock);
	if (!list_empty(&uc_list)) {
		uc = list_entry(uc_list.next, typeof(*uc), entry);
		ses->ifindex = uc->ifindex;
		list_del(&uc->entry);
		--uc_size;
		pthread_mutex_unlock(&uc_lock);
		mempool_free(uc);
	} else {
		pthread_mutex_unlock(&uc_lock);

		ses->ifindex = ipoe_nl_create();
		if (ses->ifindex == -1) {
			log_ppp_error("ipoe: failed to create interface\n");
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
			return -1;
		}
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ses->ifindex;
	if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
		log_ppp_error("ipoe: failed to get interface name\n");
		ses->ifindex = -1;
		ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
		return -1;
	}

	strncpy(ses->ses.ifname, ifr.ifr_name, AP_IFNAME_LEN);
	ses->ses.ifindex = ses->ifindex;
	ses->ses.unit_idx = ses->ifindex;

	if (ses->serv->opt_mtu)
		iplink_set_mtu(ses->ses.ifindex, ses->serv->opt_mtu);

	log_ppp_info2("create interface %s parent %s\n", ifr.ifr_name, ses->serv->ifname);

	return 0;
}

static int check_exists(struct ipoe_session *self_ipoe, in_addr_t addr)
{
	struct ap_session *ses;
	int r = 0;

	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		if (!ses->terminating && ses->ipv4 && ses->ipv4->peer_addr == addr && ses != &self_ipoe->ses) {
			log_ppp_warn("ipoe: IPv4 address already assigned to %s\n", ses->ifname);
			r = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&ses_lock);

	return r;
}

static void auth_result(struct ipoe_session *ses, int r)
{
	char *username = ses->username;

	ses->username = NULL;

	if (r == PWDB_DENIED) {
		if (conf_l4_redirect_on_reject && ses->dhcpv4_request) {
			ses->l4_redirect = 1;
			if (conf_l4_redirect_pool) {
				if (ses->ses.ipv4_pool_name)
					_free(ses->ses.ipv4_pool_name);
				ses->ses.ipv4_pool_name = _strdup(conf_l4_redirect_pool);
			}

			ses->l4_redirect_timer.expire = ipoe_session_l4_redirect_timeout;
			ses->l4_redirect_timer.expire_tv.tv_sec = conf_l4_redirect_on_reject;
			triton_timer_add(&ses->ctx, &ses->l4_redirect_timer, 0);

			if (ap_session_set_username(&ses->ses, username)) {
				ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
				return;
			}
			log_ppp_info1("%s: authentication failed\n", ses->ses.username);
			log_ppp_info1("%s: start temporary session (l4-redirect)\n", ses->ses.username);
			goto cont;
		}

		pthread_rwlock_wrlock(&ses_lock);
		ses->ses.username = username;
		ses->ses.terminate_cause = TERM_AUTH_ERROR;
		pthread_rwlock_unlock(&ses_lock);
		if (conf_ppp_verbose)
			log_ppp_warn("authentication failed\n");
		if (conf_l4_redirect_on_reject && !ses->dhcpv4_request)
			l4_redirect_list_add(ses->yiaddr);
		ap_session_terminate(&ses->ses, TERM_AUTH_ERROR, 1);
		return;
	}

	if (ap_session_set_username(&ses->ses, username)) {
		ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
		return;
	}
	log_ppp_info1("%s: authentication succeeded\n", ses->ses.username);

	if (conf_check_exists && check_exists(ses, ses->yiaddr)) {
		ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
		return;
	}

cont:
	triton_event_fire(EV_SES_AUTHORIZED, &ses->ses);

	if (ses->serv->opt_nat)
		ses->ses.ipv4 = ipdb_get_ipv4(&ses->ses);

	if (ses->serv->opt_shared == 0 && ses->ses.ipv4 && ses->ses.ipv4->peer_addr != ses->yiaddr) {
		if (ipoe_create_interface(ses))
			return;
	}

	ap_session_set_ifindex(&ses->ses);

	if (ses->dhcpv4_request && ses->serv->dhcpv4_relay) {
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, ses->dhcpv4_request, ses->relay_server_id, ses->serv->ifname, conf_agent_remote_id, conf_link_selection);

		ses->timer.expire = ipoe_relay_timeout;
		ses->timer.period = conf_relay_timeout * 1000;
		triton_timer_add(&ses->ctx, &ses->timer, 0);
	} else
		__ipoe_session_start(ses);
}

static void ipoe_session_start(struct ipoe_session *ses)
{
	int r;
	char *passwd;
	char *username;
	const char *pass;

	if (conf_verbose) {
		if (ses->dhcpv4_request) {
			log_ppp_info2("recv ");
			dhcpv4_print_packet(ses->dhcpv4_request, 0, log_ppp_info2);
		} else if (ses->arph) {
			char addr1[64], addr2[64];
			u_inet_ntoa(ses->arph->ar_tpa, addr1);
			u_inet_ntoa(ses->arph->ar_spa, addr2);
			log_ppp_info2("recv [ARP Request who-has %s tell %s]\n", addr1, addr2);
		}
	}

	__sync_add_and_fetch(&stat_starting, 1);

	assert(!ses->ses.username);

	username = ipoe_session_get_username(ses);

	if (!username) {
		ipoe_session_finished(&ses->ses);
		return;
	}

	ses->ses.unit_idx = ses->serv->ifindex;

	triton_event_fire(EV_CTRL_STARTING, &ses->ses);
	triton_event_fire(EV_CTRL_STARTED, &ses->ses);

	ap_session_starting(&ses->ses);

	if (ses->serv->opt_shared && ipoe_create_interface(ses))
		return;

	if (conf_noauth)
		r = PWDB_SUCCESS;
	else {
#ifdef RADIUS
		if (radius_loaded) {
			ses->radius.send_access_request = ipoe_rad_send_auth_request;
			ses->radius.send_accounting_request = ipoe_rad_send_acct_request;
			rad_register_plugin(&ses->ses, &ses->radius);
		}
#endif

		if (conf_password) {
			if (!strcmp(conf_password, "csid"))
				pass = ses->ctrl.calling_station_id;
			else
				pass = conf_password;
		} else
			pass = username;

		ses->username = username;
		r = pwdb_check(&ses->ses, (pwdb_callback)auth_result, ses, username, PPP_PAP, pass);

		if (r == PWDB_WAIT)
			return;

		if (r == PWDB_NO_IMPL) {
			passwd = pwdb_get_passwd(&ses->ses, username);
			if (!passwd || strcmp(passwd, pass))
				r = PWDB_DENIED;
			else {
				r = PWDB_SUCCESS;
				_free(passwd);
			}
		}
	}

	auth_result(ses, r);
}

static void find_gw_addr(struct ipoe_session *ses)
{
	struct gw_addr *a;

	list_for_each_entry(a, &conf_gw_addr, entry) {
		if ((ntohl(ses->yiaddr) & (a->mask1)) == (ntohl(a->addr) & (a->mask1))) {
			ses->router = a->addr;
			if (!ses->mask)
				ses->mask = a->mask;
			return;
		}
	}
}

static int check_server_id(in_addr_t addr)
{
	struct gw_addr *a;

	list_for_each_entry(a, &conf_gw_addr, entry) {
		if (a->addr == addr)
			return 1;
	}

	return 0;
}

static void send_arp_reply(struct ipoe_serv *serv, struct _arphdr *arph)
{
	__be32 tpa = arph->ar_tpa;

	if (conf_verbose) {
		char addr[64];
		u_inet_ntoa(arph->ar_tpa, addr);
		log_ppp_info2("send [ARP Reply %s is-at %02x:%02x:%02x:%02x:%02x:%02x]\n", addr,
			serv->hwaddr[0], serv->hwaddr[1], serv->hwaddr[2], serv->hwaddr[3], serv->hwaddr[4], serv->hwaddr[5]);
	}

	memcpy(arph->ar_tha, arph->ar_sha, ETH_ALEN);
	memcpy(arph->ar_sha, serv->hwaddr, ETH_ALEN);
	arph->ar_tpa = arph->ar_spa;
	arph->ar_spa = tpa;
	arp_send(serv->ifindex, arph, 1);
}

static void __ipoe_session_start(struct ipoe_session *ses)
{
	if (!ses->yiaddr && ses->serv->dhcpv4) {
		dhcpv4_get_ip(ses->serv->dhcpv4, &ses->yiaddr, &ses->router, &ses->mask);
		if (ses->yiaddr)
			ses->dhcp_addr = 1;
	}

	if (!ses->yiaddr && (ses->UP || !ses->serv->opt_nat)) {
		ses->ses.ipv4 = ipdb_get_ipv4(&ses->ses);

		if (ses->UP && !ses->ses.ipv4) {
			log_ppp_error("ipoe: no address specified\n");
			ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
		}
	}

	if (ses->ses.ipv4) {
		if (!ses->mask)
			ses->mask = ses->ses.ipv4->mask;

		if (!ses->yiaddr)
			ses->yiaddr = ses->ses.ipv4->peer_addr;

		if (!ses->router)
			ses->router = ses->ses.ipv4->addr;
	} /*else if (ses->yiaddr) {
		ses->ses.ipv4 = &ses->ipv4;
		ses->ipv4.addr = ses->siaddr;
		ses->ipv4.peer_addr = ses->yiaddr;
		ses->ipv4.mask = ses->mask;
		ses->ipv4.owner = NULL;
	}*/

	if (ses->dhcpv4_request) {
		if (!ses->yiaddr) {
			log_ppp_error("no free IPv4 address\n");
			ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
			return;
		}

		if (!ses->router)
			find_gw_addr(ses);

		if (!ses->mask)
			ses->mask = conf_netmask;

		if (!ses->mask)
			ses->mask = 32;

		if (ses->dhcpv4_request->hdr->giaddr) {
			/*uint32_t mask = ses->mask == 32 ? 0xffffffff : (((1 << ses->mask) - 1) << (32 - ses->mask));

			ses->siaddr = iproute_get(ses->dhcpv4_request->hdr->giaddr);
			if ((ntohl(ses->router) & mask) == (ntohl(ses->siaddr) & mask))
				ses->siaddr = ses->router;
			else if (!ses->router)
				ses->router = ses->dhcpv4_request->hdr->giaddr;*/
			if (ses->serv->opt_mode == MODE_L2)
				ses->siaddr = ses->router;
			else {
				ses->siaddr = iproute_get(ses->dhcpv4_request->hdr->giaddr, NULL);
				if (!ses->router)
					ses->router = ses->dhcpv4_request->hdr->giaddr;
			}
		}

		if (!ses->router) {
			log_ppp_error("can't determine router address\n");
			ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
			return;
		}

		if (!ses->siaddr && ses->router != ses->yiaddr)
			ses->siaddr = ses->router;

		if (!ses->siaddr)
			ses->siaddr = ses->serv->opt_src;

		if (!ses->siaddr && ses->serv->dhcpv4_relay)
			ses->siaddr = ses->serv->dhcpv4_relay->giaddr;

		if (!ses->siaddr) {
			log_ppp_error("can't determine Server-ID\n");
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
			return;
		}

		if (ses->ses.ipv4 && !ses->ses.ipv4->addr)
			ses->ses.ipv4->addr = ses->siaddr;

		dhcpv4_send_reply(DHCPOFFER, ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask,
				  ses->lease_time, ses->renew_time, ses->rebind_time, ses->dhcpv4_relay_reply);

		dhcpv4_packet_free(ses->dhcpv4_request);
		ses->dhcpv4_request = NULL;
	} else {
		if (!ses->router)
			find_gw_addr(ses);

		if (!ses->router)
			ses->router = ses->serv->opt_src;

		if (!ses->router)
			ses->router = iproute_get(ses->yiaddr, NULL);

		if (!ses->router) {
			log_ppp_error("can't determine router address\n");
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
			return;
		}

		if (ses->ses.ipv4 && !ses->ses.ipv4->addr)
			ses->ses.ipv4->addr = ses->router;

		ses->siaddr = ses->router;

		if (ses->arph) {
			if (ses->serv->opt_shared)
				ses->wait_start = 1;

			send_arp_reply(ses->serv, ses->arph);
			_free(ses->arph);
			ses->arph = NULL;
		}

		if (!ses->wait_start) {
			__ipoe_session_activate(ses);
			return;
		}
	}

	ses->timer.expire = ipoe_session_timeout;
	ses->timer.period = 0;
	ses->timer.expire_tv.tv_sec = conf_offer_timeout;
	triton_timer_add(&ses->ctx, &ses->timer, 0);
}

static void make_ipv6_intfid(uint64_t *intfid, const uint8_t *hwaddr)
{
	uint8_t *a = (uint8_t *)intfid;

	memcpy(a, hwaddr, 3);
	a[3] = 0xff;
	a[4] = 0xfe;
	memcpy(a + 5, hwaddr + 3, 3);
	a[0] ^= 0x02;
}

static void __ipoe_session_activate(struct ipoe_session *ses)
{
	uint32_t addr, gw = 0;
	struct ipoe_serv *serv = ses->serv;

	if (ses->terminating || ses->started)
		return;

	log_ppp_debug("ipoe: activate session\n");

	if (ses->ifindex != -1) {
		addr = 0;
		/*if (!ses->ses.ipv4) {
			if (ses->serv->opt_mode == MODE_L3) {
				addr = 1;
				ses->ctrl.dont_ifcfg = 1;
			}
		} else*/
		if (ses->ses.ipv4 && ses->ses.ipv4->peer_addr != ses->yiaddr)
			addr = ses->ses.ipv4->peer_addr;

		/*if (ses->dhcpv4_request && ses->serv->opt_mode == MODE_L3) {
			in_addr_t gw;
			iproute_get(ses->router, &gw, NULL);
			if (gw)
				iproute_add(0, ses->siaddr, ses->yiaddr, gw, conf_proto, 32);
			else
				iproute_add(0, ses->siaddr, ses->router, gw, conf_proto, 32);
		}*/

		if (serv->opt_mode == MODE_L3)
			iproute_get(ses->yiaddr, &gw);

		//if (ipoe_nl_modify(ses->ifindex, ses->yiaddr, addr, gw, gw ? 0 : ses->serv->ifindex, gw ? NULL : ses->hwaddr)) {
		if (ipoe_nl_modify(ses->ifindex, ses->yiaddr, addr, gw, serv->ifindex, ses->hwaddr)) {
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
			return;
		}
	}

	if (!ses->ses.ipv4) {
		ses->ses.ipv4 = &ses->ipv4;
		ses->ipv4.owner = NULL;
		ses->ipv4.peer_addr = ses->yiaddr;
		ses->ipv4.addr = ses->siaddr;
	}

	ses->ses.ipv4->mask = serv->opt_ip_unnumbered ? 32 : ses->mask;

	if (ses->ifindex != -1 || serv->opt_ifcfg)
		ses->ctrl.dont_ifcfg = 0;

	if (ses->serv->opt_mode == MODE_L2 && ses->serv->opt_ipv6 && sock6_fd != -1) {
		ses->ses.ipv6 = ipdb_get_ipv6(&ses->ses);
		if (!ses->ses.ipv6)
			log_ppp_warn("ipoe: no free IPv6 address\n");
		else {
			if (!ses->ses.ipv6->peer_intf_id)
				make_ipv6_intfid(&ses->ses.ipv6->peer_intf_id, ses->hwaddr);
			make_ipv6_intfid(&ses->ses.ipv6->intf_id, ses->serv->hwaddr);
		}
	}

	__sync_sub_and_fetch(&stat_starting, 1);
	__sync_add_and_fetch(&stat_active, 1);
	ses->started = 1;

	ap_session_activate(&ses->ses);

	if (ses->ifindex == -1 && !serv->opt_ifcfg) {
		if (!serv->opt_ip_unnumbered)
			iproute_add(serv->ifindex, ses->router, ses->yiaddr, 0, conf_proto, ses->mask, 0);
		else
			iproute_add(serv->ifindex, serv->opt_src ?: ses->router, ses->yiaddr, 0, conf_proto, 32, 0);
	}

	if (ses->l4_redirect)
		ipoe_change_l4_redirect(ses, 0);

	if (ses->dhcpv4_request) {
		if (ses->ses.state == AP_STATE_ACTIVE)
			dhcpv4_send_reply(DHCPACK, ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask,
					  ses->lease_time, ses->renew_time, ses->rebind_time, ses->dhcpv4_relay_reply);
		else
			dhcpv4_send_nak(ses->serv->dhcpv4, ses->dhcpv4_request, SESSION_TERMINATED);

		dhcpv4_packet_free(ses->dhcpv4_request);
		ses->dhcpv4_request = NULL;
	}

	ses->timer.expire = ipoe_session_timeout;
	ses->timer.period = 0;
	ses->timer.expire_tv.tv_sec = conf_lease_timeout > ses->lease_time ? conf_lease_timeout : ses->lease_time;
	if (ses->timer.tpd)
		triton_timer_mod(&ses->timer, 0);
}

static void ipoe_session_activate(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (ses->ses.state == AP_STATE_ACTIVE) {
		ipoe_session_keepalive(pack);
		return;
	}

	if (ses->dhcpv4_request)
		dhcpv4_packet_free(ses->dhcpv4_request);

	ses->dhcpv4_request = pack;

	if (ses->serv->dhcpv4_relay)
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, ses->dhcpv4_request, ses->relay_server_id, ses->serv->ifname, conf_agent_remote_id, conf_link_selection);
	else
		__ipoe_session_activate(ses);
}

static void ipoe_session_keepalive(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (ses->dhcpv4_request)
		dhcpv4_packet_free(ses->dhcpv4_request);

	ses->dhcpv4_request = pack;

	if (ses->timer.tpd)
		triton_timer_mod(&ses->timer, 0);

	ses->xid = ses->dhcpv4_request->hdr->xid;

	if (/*ses->ses.state == AP_STATE_ACTIVE &&*/ ses->serv->dhcpv4_relay) {
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, ses->dhcpv4_request, ses->relay_server_id, ses->serv->ifname, conf_agent_remote_id, conf_link_selection);
		return;
	}

	if (ses->ses.state == AP_STATE_ACTIVE) {
		dhcpv4_send_reply(DHCPACK, ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask,
				  ses->lease_time, ses->renew_time, ses->rebind_time, ses->dhcpv4_relay_reply);
	} else
		dhcpv4_send_nak(ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, SESSION_TERMINATED);

	dhcpv4_packet_free(ses->dhcpv4_request);
	ses->dhcpv4_request = NULL;
}

static void ipoe_session_decline(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	if (pack->msg_type == DHCPDECLINE && ses->serv->dhcpv4_relay)
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, pack, 0, ses->serv->ifname, conf_agent_remote_id, conf_link_selection);

	dhcpv4_packet_free(pack);

	ap_session_terminate(&ses->ses, TERM_USER_REQUEST, 1);
}

static void ipoe_session_started(struct ap_session *s)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);

	log_ppp_info1("ipoe: session started\n");

	if (ses->timer.tpd)
		triton_timer_mod(&ses->timer, 0);

	if (ses->ses.ipv4->peer_addr != ses->yiaddr)
		//ipaddr_add_peer(ses->ses.ifindex, ses->router, ses->yiaddr); // breaks quagga
		iproute_add(ses->ses.ifindex, ses->router, ses->yiaddr, 0, conf_proto, 32, 0);

	if (ses->ifindex != -1 && ses->xid) {
		ses->dhcpv4 = dhcpv4_create(ses->ctrl.ctx, ses->ses.ifname, "");
		if (!ses->dhcpv4) {
			//terminate
			return;
		}
		ses->dhcpv4->recv = ipoe_ses_recv_dhcpv4;
	}
}

static void ipoe_session_free(struct ipoe_session *ses)
{
	if (ses->started)
		__sync_sub_and_fetch(&stat_active, 1);
	else
		__sync_sub_and_fetch(&stat_starting, 1);

	if (ses->timer.tpd)
		triton_timer_del(&ses->timer);

	if (ses->l4_redirect_timer.tpd)
		triton_timer_del(&ses->l4_redirect_timer);

	if (ses->dhcpv4_request)
		dhcpv4_packet_free(ses->dhcpv4_request);

	if (ses->dhcpv4_relay_reply)
		dhcpv4_packet_free(ses->dhcpv4_relay_reply);

	if (ses->arph)
		_free(ses->arph);

	if (ses->ctrl.called_station_id && ses->ctrl.called_station_id != ses->ses.ifname)
		_free(ses->ctrl.called_station_id);

	if (ses->ctrl.calling_station_id && ses->ctrl.calling_station_id != ses->ses.ifname)
		_free(ses->ctrl.calling_station_id);

	if (ses->l4_redirect_ipset)
		_free(ses->l4_redirect_ipset);

	triton_context_unregister(&ses->ctx);

	if (ses->data)
		_free(ses->data);

	mempool_free(ses);
}

static void ipoe_session_finished(struct ap_session *s)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);
	struct ipoe_serv *serv = ses->serv;
	struct unit_cache *uc;
	struct ifreq ifr;

	log_ppp_info1("ipoe: session finished\n");

	if (ses->ifindex != -1) {
		if (uc_size < conf_unit_cache) {
			strcpy(ifr.ifr_name, s->ifname);
			ioctl(sock_fd, SIOCGIFFLAGS, &ifr);
			if (ifr.ifr_flags & IFF_UP) {
				ifr.ifr_flags &= ~IFF_UP;
				ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
			}

			ipaddr_del_peer(s->ifindex, ses->router, ses->yiaddr);

			ipoe_nl_modify(ses->ifindex, 0, 0, 0, 0, NULL);

			uc = mempool_alloc(uc_pool);
			uc->ifindex = ses->ifindex;
			pthread_mutex_lock(&uc_lock);
			list_add_tail(&uc->entry, &uc_list);
			++uc_size;
			pthread_mutex_unlock(&uc_lock);
		} else
			ipoe_nl_delete(ses->ifindex);
	} else if (ses->started) {
		if (!serv->opt_ifcfg) {
			if (!serv->opt_ip_unnumbered)
				iproute_del(serv->ifindex, ses->router, ses->yiaddr, 0, conf_proto, ses->mask, 0);
			else
				iproute_del(serv->ifindex, serv->opt_src ?: ses->router, ses->yiaddr, 0, conf_proto, 32, 0);
		}
	}

	if (ses->dhcp_addr)
		dhcpv4_put_ip(ses->serv->dhcpv4, ses->yiaddr);

	if (ses->relay_addr && ses->serv->dhcpv4_relay)
		dhcpv4_relay_send_release(ses->serv->dhcpv4_relay, ses->hwaddr, ses->xid, ses->yiaddr, ses->client_id, ses->relay_agent, ses->serv->ifname, conf_agent_remote_id, conf_link_selection);

	if (ses->dhcpv4)
		dhcpv4_free(ses->dhcpv4);

	triton_event_fire(EV_CTRL_FINISHED, s);

	if (s->ifindex == ses->serv->ifindex && strcmp(s->ifname, ses->serv->ifname)) {
		int flags;

		log_info2("ipoe: rename %s to %s\n", s->ifname, ses->serv->ifname);

		strcpy(ifr.ifr_name, s->ifname);

		ioctl(sock_fd, SIOCGIFFLAGS, &ifr);
		flags = ifr.ifr_flags;
		if (flags & IFF_UP) {
			ifr.ifr_flags &= ~IFF_UP;
			ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
		}

		strcpy(ifr.ifr_newname, ses->serv->ifname);
		ioctl(sock_fd, SIOCSIFNAME, &ifr);

		strcpy(ifr.ifr_name, ses->serv->ifname);
		ifr.ifr_flags = flags | IFF_UP;
		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	pthread_mutex_lock(&ses->serv->lock);
	list_del(&ses->entry);
	ses->serv->sess_cnt--;
	if  ((ses->serv->vlan_mon || ses->serv->need_close) && list_empty(&ses->serv->sessions))
		triton_context_call(&ses->serv->ctx, (triton_event_func)ipoe_serv_release, ses->serv);
	pthread_mutex_unlock(&ses->serv->lock);

	triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_free, ses);
}

static void ipoe_session_terminated(struct ipoe_session *ses)
{
	if (ses->l4_redirect_set)
		ipoe_change_l4_redirect(ses, 1);

	if (!ses->ses.terminated)
		ap_session_finished(&ses->ses);
}

static void ipoe_session_terminated_pkt(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	dhcpv4_send_nak(ses->serv->dhcpv4, pack, SESSION_TERMINATED);

	dhcpv4_packet_free(pack);

	ipoe_session_terminated(ses);
}

static int ipoe_session_terminate(struct ap_session *s, int hard)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);

	if (ses->ifindex == -1)
		ses->ctrl.dont_ifcfg = 1;

	if (hard || !conf_soft_terminate || ses->UP || ap_shutdown)
		ipoe_session_terminated(ses);
	else
		ses->terminate = 1;

	return 0;
}


static void ipoe_session_close(struct triton_context_t *ctx)
{
	struct ipoe_session *ses = container_of(ctx, typeof(*ses), ctx);

	if (ses->ses.state)
		ap_session_terminate(&ses->ses, TERM_ADMIN_RESET, 1);
	else
		ipoe_session_finished(&ses->ses);
}

static struct ipoe_session *ipoe_session_create_dhcpv4(struct ipoe_serv *serv, struct dhcpv4_packet *pack)
{
	struct conf_option_t *opt;
	struct ipoe_session *ses;
	int dlen = 0;
	uint8_t *ptr = NULL;

	if (ap_shutdown)
		return NULL;

	if (conf_max_starting && ap_session_stat.starting >= conf_max_starting)
		return NULL;

	if (conf_max_sessions && ap_session_stat.active + ap_session_stat.starting >= conf_max_sessions)
		return NULL;

	ses = ipoe_session_alloc(serv->ifname);
	if (!ses)
		return NULL;

	ses->serv = serv;
	ses->dhcpv4_request = pack;

	if (ses->serv->dhcpv4_relay == NULL || ses->serv->dhcpv4_relay->hnd.read == NULL) {
		log_error("%s: no socket to the DHCPv4 server. Trying again to connect\n", ses->serv->ifname);
		opt = ipoe_find_opt(serv->ifname);
		if (opt)
			add_interface(serv->ifname, serv->ifindex, opt->val, 0, 0, 0);
	}

	if (!serv->opt_shared)
		strncpy(ses->ses.ifname, serv->ifname, AP_IFNAME_LEN);

	ses->xid = pack->hdr->xid;
	memcpy(ses->hwaddr, pack->hdr->chaddr, 6);
	ses->giaddr = pack->hdr->giaddr;

	if (pack->client_id)
		dlen += sizeof(struct dhcpv4_option) + pack->client_id->len;

	if (pack->relay_agent)
		dlen += sizeof(struct dhcpv4_option) + pack->relay_agent->len;

	if (dlen) {
		ses->data = _malloc(dlen);
		if (!ses->data) {
			log_emerg("out of memery\n");
			mempool_free(ses);
			return NULL;
		}
		ptr = ses->data;
	}

	if (pack->client_id) {
		ses->client_id = (struct dhcpv4_option *)ptr;
		ses->client_id->len = pack->client_id->len;
		ses->client_id->data = (uint8_t *)(ses->client_id + 1);
		memcpy(ses->client_id->data, pack->client_id->data, pack->client_id->len);
		ptr += sizeof(struct dhcpv4_option) + pack->client_id->len;
	}

	if (pack->relay_agent) {
		ses->relay_agent = (struct dhcpv4_option *)ptr;
		ses->relay_agent->len = pack->relay_agent->len;
		ses->relay_agent->data = (uint8_t *)(ses->relay_agent + 1);
		memcpy(ses->relay_agent->data, pack->relay_agent->data, pack->relay_agent->len);
		ptr += sizeof(struct dhcpv4_option) + pack->relay_agent->len;
		if (dhcpv4_parse_opt82(ses->relay_agent, &ses->agent_circuit_id, &ses->agent_remote_id, &ses->link_selection))
			ses->relay_agent = NULL;
	}

	ses->ctrl.dont_ifcfg = 1;

	ses->ctrl.calling_station_id = _malloc(19);
	ses->ctrl.called_station_id = _strdup(serv->ifname);

	ptr = ses->hwaddr;
	sprintf(ses->ctrl.calling_station_id, "%02x:%02x:%02x:%02x:%02x:%02x",
		ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

	ses->ses.ctrl = &ses->ctrl;
	ses->ses.chan_name = ses->ctrl.calling_station_id;

	if (conf_ip_pool)
		ses->ses.ipv4_pool_name = _strdup(conf_ip_pool);
	if (conf_ipv6_pool)
		ses->ses.ipv6_pool_name = _strdup(conf_ipv6_pool);
	if (conf_dpv6_pool)
		ses->ses.dpv6_pool_name = _strdup(conf_dpv6_pool);

	triton_context_register(&ses->ctx, &ses->ses);

	triton_context_wakeup(&ses->ctx);

	//pthread_mutex_lock(&serv->lock);
	list_add_tail(&ses->entry, &serv->sessions);
	serv->sess_cnt++;
	//pthread_mutex_unlock(&serv->lock);

	if (serv->timer.tpd)
		triton_timer_del(&serv->timer);

	dhcpv4_packet_ref(pack);

	triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_start, ses);

	return ses;
}

static void __ipoe_session_terminate(struct ap_session *s)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);

	if (ses->terminate)
		ipoe_session_terminated(ses);
	else
		ap_session_terminate(s, TERM_USER_REQUEST, 1);
}

static void ipoe_ses_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(dhcpv4->ctx, typeof(*ses), ctx);
	int opt82_match;
	uint8_t *agent_circuit_id = NULL;
	uint8_t *agent_remote_id = NULL;
	uint8_t *link_selection = NULL;

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	if (ses->terminate) {
		if (pack->msg_type != DHCPDISCOVER)
			dhcpv4_send_nak(dhcpv4, pack, SESSION_TERMINATED);
		triton_context_call(ses->ctrl.ctx, (triton_event_func)ipoe_session_terminated, ses);
		return;
	}

	if (pack->relay_agent && dhcpv4_parse_opt82(pack->relay_agent, &agent_circuit_id, &agent_remote_id, &link_selection)) {
		agent_circuit_id = NULL;
		agent_remote_id = NULL;
		link_selection = NULL;
	}

	opt82_match = pack->relay_agent != NULL;

	if (agent_circuit_id && !ses->agent_circuit_id)
		opt82_match = 0;

	if (opt82_match && agent_remote_id && !ses->agent_remote_id)
		opt82_match = 0;

	if (opt82_match && !agent_circuit_id && ses->agent_circuit_id)
		opt82_match = 0;

	if (opt82_match && !agent_remote_id && ses->agent_remote_id)
		opt82_match = 0;

	if (opt82_match && agent_circuit_id) {
		if (*agent_circuit_id != *ses->agent_circuit_id)
			opt82_match = 0;

		if (memcmp(agent_circuit_id + 1, ses->agent_circuit_id + 1, *agent_circuit_id))
			opt82_match = 0;
	}

	if (opt82_match && agent_remote_id) {
		if (*agent_remote_id != *ses->agent_remote_id)
			opt82_match = 0;

		if (memcmp(agent_remote_id + 1, ses->agent_remote_id + 1, *agent_remote_id))
			opt82_match = 0;
	}

	if (conf_check_mac_change && pack->relay_agent && !opt82_match) {
		log_ppp_info2("port change detected\n");
		if (pack->msg_type == DHCPREQUEST)
			dhcpv4_send_nak(dhcpv4, pack, SESSION_TERMINATED);
		triton_context_call(ses->ctrl.ctx, (triton_event_func)__ipoe_session_terminate, &ses->ses);
		return;
	}

	if (pack->msg_type == DHCPDISCOVER) {
		if (ses->yiaddr) {
			if (ses->serv->dhcpv4_relay) {
				dhcpv4_packet_ref(pack);
				ipoe_session_keepalive(pack);
			} else
				dhcpv4_send_reply(DHCPOFFER, dhcpv4, pack, ses->yiaddr, ses->siaddr, ses->router, ses->mask,
						  ses->lease_time, ses->renew_time, ses->rebind_time, ses->dhcpv4_relay_reply);
		}
	} else if (pack->msg_type == DHCPREQUEST) {
		ses->xid = pack->hdr->xid;
		if (pack->hdr->ciaddr == ses->yiaddr && pack->hdr->xid != ses->xid)
			ses->xid = pack->hdr->xid;
		if ((pack->server_id && (pack->server_id != ses->siaddr || pack->request_ip != ses->yiaddr)) ||
			(pack->hdr->ciaddr && (pack->hdr->xid != ses->xid || pack->hdr->ciaddr != ses->yiaddr))) {

			if (pack->server_id == ses->siaddr)
				dhcpv4_send_nak(dhcpv4, pack, "Wrong session");
			else if (ses->serv->dhcpv4_relay)
				dhcpv4_relay_send(ses->serv->dhcpv4_relay, pack, 0, ses->serv->ifname, conf_agent_remote_id, conf_link_selection);

			triton_context_call(ses->ctrl.ctx, (triton_event_func)__ipoe_session_terminate, &ses->ses);
		} else {
			dhcpv4_packet_ref(pack);
			ipoe_session_keepalive(pack);
		}
	} else if (pack->msg_type == DHCPDECLINE || pack->msg_type == DHCPRELEASE) {
		dhcpv4_packet_ref(pack);
		triton_context_call(ses->ctrl.ctx, (triton_event_func)ipoe_session_decline, pack);
	}
}

static void ipoe_ses_recv_dhcpv4_discover(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	if (ses->yiaddr)
		dhcpv4_send_reply(DHCPOFFER, ses->dhcpv4 ?: ses->serv->dhcpv4, pack, ses->yiaddr, ses->siaddr, ses->router, ses->mask,
				  ses->lease_time, ses->renew_time, ses->rebind_time, ses->dhcpv4_relay_reply);

	dhcpv4_packet_free(pack);
}

static void ipoe_ses_recv_dhcpv4_request(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	ses->xid = pack->hdr->xid;

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	if ((pack->server_id && (pack->server_id != ses->siaddr || pack->request_ip != ses->yiaddr)) ||
		(pack->hdr->ciaddr && (pack->hdr->ciaddr != ses->yiaddr))) {

		if (pack->server_id == ses->siaddr)
			dhcpv4_send_nak(ses->serv->dhcpv4, pack, "Wrong session");

		ap_session_terminate(&ses->ses, TERM_USER_REQUEST, 1);

		dhcpv4_packet_free(pack);
		return;
	}

	if (ses->ses.state == AP_STATE_STARTING && ses->yiaddr)
		ipoe_session_activate(pack);
	else if (ses->ses.state == AP_STATE_ACTIVE)
		ipoe_session_keepalive(pack);
	else
		dhcpv4_packet_free(pack);
}

static void ipoe_serv_disc_timer(struct triton_timer_t *t)
{
	struct ipoe_serv *serv = container_of(t, typeof(*serv), disc_timer);
	struct timespec ts;
	int delay, delay1 = INT_MAX, delay2 = INT_MAX, offer_delay = 0;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	while (!list_empty(&serv->disc_list)) {
		struct disc_item *d = list_entry(serv->disc_list.next, typeof(*d), entry);

		delay = (ts.tv_sec - d->ts.tv_sec) * 1000 + (ts.tv_nsec - d->ts.tv_nsec) / 1000000;
		offer_delay = get_offer_delay();

		if (delay < offer_delay - 1) {
			delay1 = delay;
			break;
		}

		__ipoe_recv_dhcpv4(serv->dhcpv4, d->pack, 1);
		dhcpv4_packet_free(d->pack);

		list_del(&d->entry);
		mempool_free(d);

		__sync_sub_and_fetch(&stat_delayed_offer, 1);
	}

	while (!list_empty(&serv->arp_list)) {
		struct arp_item *d = list_entry(serv->arp_list.next, typeof(*d), entry);

		delay = (ts.tv_sec - d->ts.tv_sec) * 1000 + (ts.tv_nsec - d->ts.tv_nsec) / 1000000;
		offer_delay = get_offer_delay();

		if (delay < offer_delay - 1) {
			delay2 = delay;
			break;
		}

		ipoe_session_create_up(serv, NULL, NULL, &d->arph);

		list_del(&d->entry);
		mempool_free(d);

		__sync_sub_and_fetch(&stat_delayed_offer, 1);
	}

	if (list_empty(&serv->disc_list) && list_empty(&serv->arp_list))
		triton_timer_del(t);
	else {
		delay = delay1 < delay2 ? delay1 : delay2;
		delay = offer_delay - delay;
		t->expire_tv.tv_sec = delay / 1000;
		t->expire_tv.tv_usec = (delay % 1000) * 1000;
		triton_timer_mod(t, 0);
	}
}

static void ipoe_serv_add_disc_arp(struct ipoe_serv *serv, struct _arphdr *arph, int offer_delay)
{
	struct arp_item *d = mempool_alloc(arp_item_pool);

	if (!d)
		return;

	__sync_add_and_fetch(&stat_delayed_offer, 1);

	memcpy(&d->arph, arph, sizeof(*arph));
	clock_gettime(CLOCK_MONOTONIC, &d->ts);
	list_add_tail(&d->entry, &serv->arp_list);

	if (!serv->disc_timer.tpd) {
		serv->disc_timer.expire_tv.tv_sec = offer_delay / 1000;
		serv->disc_timer.expire_tv.tv_usec = (offer_delay % 1000) * 1000;
		triton_timer_add(&serv->ctx, &serv->disc_timer, 0);
	}
}

static void ipoe_serv_add_disc(struct ipoe_serv *serv, struct dhcpv4_packet *pack, int offer_delay)
{
	struct disc_item *d = mempool_alloc(disc_item_pool);

	if (!d)
		return;

	__sync_add_and_fetch(&stat_delayed_offer, 1);

	dhcpv4_packet_ref(pack);
	d->pack = pack;
	clock_gettime(CLOCK_MONOTONIC, &d->ts);
	list_add_tail(&d->entry, &serv->disc_list);

	if (!serv->disc_timer.tpd) {
		serv->disc_timer.expire_tv.tv_sec = offer_delay / 1000;
		serv->disc_timer.expire_tv.tv_usec = (offer_delay % 1000) * 1000;
		triton_timer_add(&serv->ctx, &serv->disc_timer, 0);
	}
}

static int ipoe_serv_check_disc(struct ipoe_serv *serv, struct dhcpv4_packet *pack)
{
	struct disc_item *d;

	list_for_each_entry(d, &serv->disc_list, entry) {
		if (d->pack->hdr->xid != pack->hdr->xid)
			continue;

		if (memcmp(d->pack->hdr->chaddr, pack->hdr->chaddr, ETH_ALEN))
			continue;

		list_del(&d->entry);
		dhcpv4_packet_free(d->pack);
		mempool_free(d);

		__sync_sub_and_fetch(&stat_delayed_offer, 1);

		return 1;
	}

	return 0;
}

static int ipoe_serv_request_check(struct ipoe_serv *serv, uint32_t xid)
{
	struct request_item *r;
	struct list_head *pos, *n;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	list_for_each_safe(pos, n, &serv->req_list) {
		r = list_entry(pos, typeof(*r), entry);
		if (ts.tv_sec > r->expire) {
			list_del(&r->entry);
			mempool_free(r);
		} else if (r->xid == xid) {
			if (++r->cnt >= conf_max_request) {
				list_del(&r->entry);
				mempool_free(r);
				return 1;
			}

			r->expire = ts.tv_sec + 30;
			return 0;
		}
	}

	r = mempool_alloc(req_item_pool);
	r->xid = xid;
	r->expire = ts.tv_sec + 30;
	r->cnt = 1;
	list_add_tail(&r->entry, &serv->req_list);

	return 0;
}

static void port_change_detected(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	dhcpv4_packet_free(pack);

	log_ppp_warn("port change detected\n");

	ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
}

static void mac_change_detected(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	dhcpv4_packet_free(pack);

	log_ppp_warn("mac change detected\n");

	ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
}

static int check_notify(struct ipoe_serv *serv, struct dhcpv4_packet *pack)
{
	struct dhcpv4_option *opt = dhcpv4_packet_find_opt(pack, 43);
	struct ipoe_session *ses;
	unsigned int w;

	if (!opt)
		return 0;

	if (opt->len != 8 + ETH_ALEN)
		return 0;

	if (*(uint32_t *)opt->data != htonl(ACCEL_PPP_MAGIC))
		return 0;

	w = htonl(*(uint32_t *)(opt->data + 4));

	list_for_each_entry(ses, &serv->sessions, entry) {
		if (ses->xid == pack->hdr->xid && memcmp(pack->hdr->chaddr, ses->hwaddr, ETH_ALEN) == 0) {
			if (w < ses->weight || ses->weight == 0 || (w == ses->weight && memcmp(serv->hwaddr, opt->data + 8, ETH_ALEN) < 0)) {
				log_debug("ipoe: terminate %s by weight %u (%u)\n", ses->ses.ifname, w, ses->weight);
				triton_context_call(&ses->ctx, (triton_event_func)__terminate, &ses->ses);
			}
			break;
		}
	}

	return 1;
}

static void __ipoe_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack, int force)
{
	struct ipoe_serv *serv = container_of(dhcpv4->ctx, typeof(*serv), ctx);
	struct ipoe_session *ses, *opt82_ses;
	int offer_delay;
	unsigned int weight = 0;
	//struct dhcpv4_packet *reply;

	if (connlimit_loaded && pack->msg_type == DHCPDISCOVER && connlimit_check(serv->opt_shared ? cl_key_from_mac(pack->hdr->chaddr) : serv->ifindex))
		return;

	pthread_mutex_lock(&serv->lock);
	if (serv->timer.tpd)
		triton_timer_mod(&serv->timer, 0);

	if (pack->msg_type == DHCPDISCOVER) {
		if (check_notify(serv, pack))
			goto out;

		ses = ipoe_session_lookup(serv, pack, &opt82_ses);
		if (!ses) {
			if (serv->opt_shared == 0)
				ipoe_drop_sessions(serv, NULL);
			else if (opt82_ses) {
				dhcpv4_packet_ref(pack);
				triton_context_call(&opt82_ses->ctx, (triton_event_func)mac_change_detected, pack);
			}

			if (ap_shutdown)
				goto out;

			offer_delay = get_offer_delay();
			if (offer_delay == -1)
				goto out;

			if (offer_delay && !force) {
				ipoe_serv_add_disc(serv, pack, offer_delay);
				goto out;
			}

			ses = ipoe_session_create_dhcpv4(serv, pack);
			if (!ses)
				goto out;

			ses->weight = weight = serv->opt_weight >= 0 ? serv->sess_cnt * serv->opt_weight : (stat_active + 1) * conf_weight;
		}	else {
			if (ses->terminate) {
				triton_context_call(ses->ctrl.ctx, (triton_event_func)ipoe_session_terminated, ses);
				goto out;
			}

			if (conf_check_mac_change) {
				if ((opt82_ses && ses != opt82_ses) || (!opt82_ses && pack->relay_agent)) {
					dhcpv4_packet_ref(pack);
					triton_context_call(&ses->ctx, (triton_event_func)port_change_detected, pack);
					if (opt82_ses)
						triton_context_call(&opt82_ses->ctx, (triton_event_func)__ipoe_session_terminate, &opt82_ses->ses);
					goto out;
				}

				if (memcmp(ses->hwaddr, pack->hdr->chaddr, ETH_ALEN)) {
					dhcpv4_packet_ref(pack);
					triton_context_call(&ses->ctx, (triton_event_func)mac_change_detected, pack);
					goto out;
				}
			}

			dhcpv4_packet_ref(pack);
			triton_context_call(&ses->ctx, (triton_event_func)ipoe_ses_recv_dhcpv4_discover, pack);
		}
	} else if (pack->msg_type == DHCPREQUEST) {
		if (ipoe_serv_check_disc(serv, pack))
			goto out;

		ses = ipoe_session_lookup(serv, pack, &opt82_ses);

		if (!ses) {
			if (conf_verbose) {
				log_debug("%s: recv ", serv->ifname);
				dhcpv4_print_packet(pack, 0, log_debug);
			}

			if (pack->src_addr) {
				dhcpv4_send_nak(dhcpv4, pack, "Session dosn't exist");
				goto out;
			}

			if (pack->server_id) {
				if (check_server_id(pack->server_id)) {
					dhcpv4_send_nak(dhcpv4, pack, "Wrong server id");
					goto out;
				}
			}

			if (serv->opt_shared == 0)
				ipoe_drop_sessions(serv, NULL);
			else if (opt82_ses) {
				dhcpv4_packet_ref(pack);
				triton_context_call(&opt82_ses->ctx, (triton_event_func)mac_change_detected, pack);
			}

			if (ap_shutdown)
				goto out;

			if (ipoe_serv_request_check(serv, pack->hdr->xid))
				dhcpv4_send_nak(dhcpv4, pack, "Session doesn't exist");
		} else {
			if (ses->terminate) {
				dhcpv4_packet_ref(pack);
				triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_terminated_pkt, pack);
				goto out;
			}

			if (conf_check_mac_change) {
				if ((opt82_ses && ses != opt82_ses) || (!opt82_ses && pack->relay_agent)) {
					dhcpv4_packet_ref(pack);
					triton_context_call(&ses->ctx, (triton_event_func)port_change_detected, pack);
					if (opt82_ses)
						triton_context_call(&opt82_ses->ctx, (triton_event_func)__ipoe_session_terminate, &opt82_ses->ses);
					goto out;
				}

				if (memcmp(ses->hwaddr, pack->hdr->chaddr, ETH_ALEN)) {
					dhcpv4_packet_ref(pack);
					triton_context_call(&ses->ctx, (triton_event_func)mac_change_detected, pack);
					goto out;
				}
			}

			if (serv->opt_shared == 0)
				ipoe_drop_sessions(serv, ses);

			dhcpv4_packet_ref(pack);
			triton_context_call(&ses->ctx, (triton_event_func)ipoe_ses_recv_dhcpv4_request, pack);
		}
	} else if (pack->msg_type == DHCPDECLINE || pack->msg_type == DHCPRELEASE) {
		ses = ipoe_session_lookup(serv, pack, &opt82_ses);
		if (ses) {
			ses->xid = pack->hdr->xid;
			dhcpv4_packet_ref(pack);
			triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_decline, pack);
		}
	}

out:
	pthread_mutex_unlock(&serv->lock);

	if (weight)
		dhcpv4_send_notify(serv->dhcpv4, pack, weight);
}

static void ipoe_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack)
{
	__ipoe_recv_dhcpv4(dhcpv4, pack, 0);
}

static int parse_dhcpv4_mask(uint32_t mask)
{
	int i;

	for (i = 31; i >= 0 && (mask & (1 << i)); i--);

	return 32 - (i + 1);
}

static void ipoe_ses_recv_dhcpv4_relay(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);
	struct dhcpv4_option *opt;

	if (ses->dhcpv4_relay_reply)
		dhcpv4_packet_free(ses->dhcpv4_relay_reply);

	if (!ses->dhcpv4_request) {
		ses->dhcpv4_relay_reply = NULL;
		return;
	}

	ses->dhcpv4_relay_reply = pack;

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 1, log_ppp_info2);
	}

	opt = dhcpv4_packet_find_opt(pack, 51);
	if (opt)
		ses->lease_time = ntohl(*(uint32_t *)opt->data);

	opt = dhcpv4_packet_find_opt(pack, 58);
	if (opt)
		ses->renew_time = ntohl(*(uint32_t *)opt->data);

	opt = dhcpv4_packet_find_opt(pack, 59);
	if (opt)
		ses->rebind_time = ntohl(*(uint32_t *)opt->data);

	opt = dhcpv4_packet_find_opt(pack, 1);
	if (opt)
		ses->mask = parse_dhcpv4_mask(ntohl(*(uint32_t *)opt->data));

	opt = dhcpv4_packet_find_opt(pack, 3);
	if (opt)
		ses->router = *(uint32_t *)opt->data;

	if (pack->msg_type == DHCPOFFER) {
		if (ses->ses.state == AP_STATE_STARTING) {
			triton_timer_del(&ses->timer);

			ses->relay_server_id = pack->server_id;

			if (!ses->yiaddr) {
				ses->yiaddr = pack->hdr->yiaddr;
				ses->relay_addr = 1;
			}

			__ipoe_session_start(ses);
		} else
			dhcpv4_send_reply(DHCPOFFER, ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask,
					  ses->lease_time, ses->renew_time, ses->rebind_time, ses->dhcpv4_relay_reply);
	} else if (pack->msg_type == DHCPACK) {
		if (ses->ses.state == AP_STATE_STARTING)
			__ipoe_session_activate(ses);
		else
			dhcpv4_send_reply(DHCPACK, ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask,
					  ses->lease_time, ses->renew_time, ses->rebind_time, ses->dhcpv4_relay_reply);

	} else if (pack->msg_type == DHCPNAK) {
		dhcpv4_send_nak(ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, "Session is terminated");
		ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
		return;
	}

	dhcpv4_packet_free(ses->dhcpv4_relay_reply);
	ses->dhcpv4_relay_reply = NULL;
}

static void ipoe_recv_dhcpv4_relay(struct dhcpv4_packet *pack)
{
	struct ipoe_serv *serv = container_of(triton_context_self(), typeof(*serv), ctx);
	struct ipoe_session *ses;
	int found = 0;
	//struct dhcpv4_packet *reply;

	pthread_mutex_lock(&serv->lock);
	list_for_each_entry(ses, &serv->sessions, entry) {
		if (ses->xid != pack->hdr->xid)
			continue;
		if (memcmp(ses->hwaddr, pack->hdr->chaddr, 6))
			continue;

		found = 1;
		break;
	}

	if (found) {
		triton_context_call(&ses->ctx, (triton_event_func)ipoe_ses_recv_dhcpv4_relay, pack);
	} else
		dhcpv4_packet_free(pack);

	pthread_mutex_unlock(&serv->lock);
}


static struct ipoe_session *ipoe_session_create_up(struct ipoe_serv *serv, struct ethhdr *eth, struct iphdr *iph, struct _arphdr *arph)
{
	struct ipoe_session *ses;
	uint8_t *hwaddr;
	in_addr_t saddr;

	if (arph) {
		hwaddr = arph->ar_sha;
		saddr = arph->ar_spa;
	} else if (eth && iph) {
		hwaddr = eth->h_source;
		saddr = iph->saddr;
	} else
		return NULL;

	if (ap_shutdown)
		return NULL;

	if (conf_max_starting && ap_session_stat.starting >= conf_max_starting)
		return NULL;

	if (conf_max_sessions && ap_session_stat.active + ap_session_stat.starting >= conf_max_sessions)
		return NULL;

	if (connlimit_loaded && connlimit_check(serv->opt_shared ? cl_key_from_ipv4(saddr) : serv->ifindex))
		return NULL;

	if (l4_redirect_list_check(saddr))
		return NULL;

	ses = ipoe_session_alloc(serv->ifname);
	if (!ses)
		return NULL;

	ses->serv = serv;
	memcpy(ses->hwaddr, hwaddr, ETH_ALEN);
	ses->yiaddr = saddr;
	ses->UP = 1;

	if (!serv->opt_shared)
		strncpy(ses->ses.ifname, serv->ifname, AP_IFNAME_LEN);

	ses->ctrl.called_station_id = _strdup(serv->ifname);

	if (conf_calling_sid == SID_MAC) {
		ses->ctrl.calling_station_id = _malloc(19);
		sprintf(ses->ctrl.calling_station_id, "%02x:%02x:%02x:%02x:%02x:%02x",
				hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	} else {
		ses->ctrl.calling_station_id = _malloc(17);
		u_inet_ntoa(saddr, ses->ctrl.calling_station_id);
	}

	if (ses->serv->opt_username == USERNAME_IFNAME)
		ses->username = _strdup(serv->ifname);
#ifdef USE_LUA
	else if (ses->serv->opt_username == USERNAME_LUA)
		ses->username = ipoe_lua_get_username(ses, ses->serv->opt_lua_username_func ? : conf_lua_username_func);
#endif
	else {
		ses->username = _malloc(17);
		u_inet_ntoa(saddr, ses->username);
	}

	ses->ses.chan_name = ses->ctrl.calling_station_id;

	if (conf_ip_pool)
		ses->ses.ipv4_pool_name = _strdup(conf_ip_pool);
	if (conf_ipv6_pool)
		ses->ses.ipv6_pool_name = _strdup(conf_ipv6_pool);
	if (conf_dpv6_pool)
		ses->ses.dpv6_pool_name = _strdup(conf_dpv6_pool);

	ses->ctrl.dont_ifcfg = 1;

	triton_context_register(&ses->ctx, &ses->ses);

	list_add_tail(&ses->entry, &serv->sessions);
	serv->sess_cnt++;

	if (serv->timer.tpd)
		triton_timer_del(&serv->timer);

	if (arph) {
		ses->arph = _malloc(sizeof(*arph));
		memcpy(ses->arph, arph, sizeof(*arph));
	}

	triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_start, ses);

	triton_context_wakeup(&ses->ctx);

	return ses;
}

static void ipoe_session_create_auto(struct ipoe_serv *serv)
{
	struct ipoe_session *ses;

	if (ap_shutdown)
		return;

	ses = ipoe_session_alloc(serv->ifname);
	if (!ses)
		return;

	ses->serv = serv;
	ses->UP = 1;

	strncpy(ses->ses.ifname, serv->ifname, AP_IFNAME_LEN);
	ses->ctrl.called_station_id = ses->ses.ifname;
	ses->ctrl.calling_station_id = ses->ses.ifname;
	ses->username = _strdup(serv->ifname);
	ses->ses.chan_name = ses->ctrl.calling_station_id;

	if (conf_ip_pool)
		ses->ses.ipv4_pool_name = _strdup(conf_ip_pool);
	if (conf_ipv6_pool)
		ses->ses.ipv6_pool_name = _strdup(conf_ipv6_pool);
	if (conf_dpv6_pool)
		ses->ses.dpv6_pool_name = _strdup(conf_dpv6_pool);

	ses->ctrl.dont_ifcfg = 1;

	triton_context_register(&ses->ctx, &ses->ses);

	list_add_tail(&ses->entry, &serv->sessions);
	serv->sess_cnt++;

	triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_start, ses);

	triton_context_wakeup(&ses->ctx);
}

struct ipoe_session *ipoe_session_alloc(const char *ifname)
{
	struct ipoe_session *ses;

	ses = mempool_alloc(ses_pool);
	if (!ses) {
		log_emerg("out of memery\n");
		return NULL;
	}

	memset(ses, 0, sizeof(*ses));

	ap_session_init(&ses->ses);

	ses->ifindex = -1;

	ses->ctx.before_switch = ipoe_ctx_switch;
	ses->ctx.close = ipoe_session_close;
	ses->ctrl.ctx = &ses->ctx;
	ses->ctrl.started = ipoe_session_started;
	ses->ctrl.finished = ipoe_session_finished;
	ses->ctrl.terminate = ipoe_session_terminate;
	ses->ctrl.type = CTRL_TYPE_IPOE;
	ses->ctrl.name = "ipoe";
	ses->ctrl.ifname = ifname;
	ses->l4_redirect_table = conf_l4_redirect_table;

	ses->ses.ctrl = &ses->ctrl;

	ses->ses.idle_timeout = conf_idle_timeout;
	ses->ses.session_timeout = conf_session_timeout;

	ses->lease_time = conf_lease_time;
	ses->renew_time = conf_renew_time;
	ses->rebind_time = conf_rebind_time;

	return ses;
}

void ipoe_recv_up(int ifindex, struct ethhdr *eth, struct iphdr *iph, struct _arphdr *arph)
{
	struct ipoe_serv *serv;
	struct ipoe_session *ses;
	in_addr_t saddr = arph ? arph->ar_spa : iph->saddr;

	pthread_mutex_lock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->ifindex != ifindex)
			continue;

		if (!serv->opt_up) {
			pthread_mutex_unlock(&serv_lock);
			return;
		}

		pthread_mutex_lock(&serv->lock);

		list_for_each_entry(ses, &serv->sessions, entry) {
			if (ses->yiaddr == saddr) {
				if (ses->wait_start) {
					ses->wait_start = 0;
					triton_context_call(&ses->ctx, (triton_event_func)__ipoe_session_activate, ses);
				}

				pthread_mutex_unlock(&serv->lock);
				pthread_mutex_unlock(&serv_lock);
				return;
			}
		}

		ipoe_session_create_up(serv, eth, iph, arph);

		pthread_mutex_unlock(&serv->lock);

		break;
	}
	pthread_mutex_unlock(&serv_lock);
}

void ipoe_serv_recv_arp(struct ipoe_serv *serv, struct _arphdr *arph)
{
	struct arp_item *d;

	if (arph->ar_op == htons(ARPOP_REQUEST)) {
		int offer_delay = get_offer_delay();

		if (offer_delay == -1)
			return;

		list_for_each_entry(d, &serv->arp_list, entry) {
			if (d->arph.ar_spa == arph->ar_spa)
				return;
		}

		if (offer_delay)
			ipoe_serv_add_disc_arp(serv, arph, offer_delay);
		else
			ipoe_session_create_up(serv, NULL, NULL, arph);
	} else {
		list_for_each_entry(d, &serv->arp_list, entry) {
			if (d->arph.ar_spa == arph->ar_tpa) {
				list_del(&d->entry);
				mempool_free(d);

				__sync_sub_and_fetch(&stat_delayed_offer, 1);

				break;
			}
		}
	}
}

#ifdef RADIUS

static int ipaddr_to_prefix(in_addr_t ipaddr)
{
	if (ipaddr == 0)
		return 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	return 33 - ffs(htonl(ipaddr));
#else
	return 33 - ffs(ipaddr);
#endif
}

static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct ipoe_session *ses = container_of(ev->ses, typeof(*ses), ses);
	struct rad_attr_t *attr;
	int lease_time_set = 0, renew_time_set = 0, rebind_time_set = 0, has_dhcp = 0;
	in_addr_t server_id = 0;

	if (ev->ses->ctrl->type != CTRL_TYPE_IPOE)
		return;

	list_for_each_entry(attr, &ev->reply->attrs, entry) {
		int vendor_id = attr->vendor ? attr->vendor->id : 0;

		if (vendor_id == VENDOR_DHCP) {
			has_dhcp = 1;

			switch (attr->attr->id) {
				case DHCP_Your_IP_Address:
					ses->yiaddr = attr->val.ipaddr;
					break;
				case DHCP_Server_IP_Address:
					ses->siaddr = attr->val.ipaddr;
					break;
				case DHCP_Router_Address:
					ses->router = *(in_addr_t *)attr->raw;
					break;
				case DHCP_Subnet_Mask:
					ses->mask = ipaddr_to_prefix(attr->val.ipaddr);
					break;
				case DHCP_IP_Address_Lease_Time:
					ses->lease_time = attr->val.integer;
					lease_time_set = 1;
					break;
				case DHCP_Renewal_Time:
					ses->renew_time = attr->val.integer;
					renew_time_set = 1;
					break;
				case DHCP_Rebinding_Time:
					ses->rebind_time = attr->val.integer;
					rebind_time_set = 1;
					break;
				case DHCP_DHCP_Server_Identifier:
					server_id = attr->val.ipaddr;
					break;
			}

			continue;
		}

		if (conf_vendor != vendor_id)
			continue;

		if (attr->attr->id == conf_attr_dhcp_client_ip)
			ses->yiaddr = attr->val.ipaddr;
		else if (attr->attr->id == conf_attr_dhcp_router_ip)
			ses->router = attr->val.ipaddr;
		else if (attr->attr->id == conf_attr_dhcp_mask) {
			if (attr->attr->type == ATTR_TYPE_INTEGER) {
				if (attr->val.integer > 0 && attr->val.integer <= 32)
					ses->mask = attr->val.integer;
			} else if (attr->attr->type == ATTR_TYPE_IPADDR)
				ses->mask = ipaddr_to_prefix(attr->val.ipaddr);
		} else if (attr->attr->id == conf_attr_l4_redirect) {
			if (attr->attr->type == ATTR_TYPE_STRING) {
				if (attr->len && attr->val.string[0] != '0')
					ses->l4_redirect = 1;
			} else if (attr->val.integer != 0)
				ses->l4_redirect = 1;
		} else if (attr->attr->id == conf_attr_dhcp_lease_time) {
			ses->lease_time = attr->val.integer;
			lease_time_set = 1;
		} else if (attr->attr->id == conf_attr_dhcp_renew_time) {
			ses->renew_time = attr->val.integer;
			renew_time_set = 1;
		} else if (attr->attr->id == conf_attr_dhcp_rebind_time) {
			ses->rebind_time = attr->val.integer;
			rebind_time_set = 1;
		} else if (attr->attr->id == conf_attr_l4_redirect_table)
			ses->l4_redirect_table = attr->val.integer;
		else if (attr->attr->id == conf_attr_l4_redirect_ipset) {
			if (attr->attr->type == ATTR_TYPE_STRING)
				ses->l4_redirect_ipset = _strdup(attr->val.string);
		}
	}

	if (lease_time_set && !renew_time_set)
		ses->renew_time = ses->lease_time/2;
	else if (renew_time_set && ses->renew_time > ses->lease_time) {
		log_ppp_warn("ipoe: overriding renew time\n");
		ses->renew_time = ses->lease_time/2;
	}

	if (lease_time_set && !rebind_time_set)
		ses->rebind_time = ses->lease_time/2 + ses->lease_time/4 + ses->lease_time/8;
	else if (rebind_time_set && ses->rebind_time > ses->lease_time) {
		log_ppp_warn("ipoe: overriding rebind time\n");
		ses->rebind_time = ses->lease_time/2 + ses->lease_time/4 + ses->lease_time/8;
	}

	if (ses->renew_time && ses->rebind_time && ses->renew_time > ses->rebind_time) {
		if (renew_time_set)
			log_ppp_warn("ipoe: overriding renew time\n");
		ses->renew_time = ses->rebind_time*4/7;
	}

	if (!ses->siaddr)
		ses->siaddr = server_id;

	if (has_dhcp)
		ses->dhcpv4_relay_reply = dhcpv4_clone_radius(ev->reply);
}

static void ev_radius_coa(struct ev_radius_t *ev)
{
	struct ipoe_session *ses = container_of(ev->ses, typeof(*ses), ses);
	struct rad_attr_t *attr;
	int l4_redirect = -1;
	int lease_time_set = 0, renew_time_set = 0, rebind_time_set = 0;
	char *ipset = NULL;

	if (ev->ses->ctrl->type != CTRL_TYPE_IPOE)
		return;

	l4_redirect = ses->l4_redirect;

	list_for_each_entry(attr, &ev->request->attrs, entry) {
		int vendor_id = attr->vendor ? attr->vendor->id : 0;

		if (conf_vendor != vendor_id)
			continue;

		if (attr->attr->id == conf_attr_l4_redirect) {
			if (attr->attr->type == ATTR_TYPE_STRING)
				l4_redirect = attr->len && attr->val.string[0] != '0';
			else
				l4_redirect = ((unsigned int)attr->val.integer) > 0;
		} else if (strcmp(attr->attr->name, "Framed-IP-Address") == 0) {
			if (ses->ses.ipv4 && ses->ses.ipv4->peer_addr != attr->val.ipaddr)
				ipoe_change_addr(ses, attr->val.ipaddr);
		} else if (attr->attr->id == conf_attr_dhcp_lease_time) {
			ses->lease_time = attr->val.integer;
			lease_time_set = 1;
		} else if (attr->attr->id == conf_attr_dhcp_renew_time) {
			ses->renew_time = attr->val.integer;
			renew_time_set = 1;
		} else if (attr->attr->id == conf_attr_dhcp_rebind_time) {
			ses->rebind_time = attr->val.integer;
			rebind_time_set = 1;
		} else if (attr->attr->id == conf_attr_l4_redirect_table)
			ses->l4_redirect_table = attr->val.integer;
		else if (attr->attr->id == conf_attr_l4_redirect_ipset) {
			if (attr->attr->type == ATTR_TYPE_STRING) {
				if (!ses->l4_redirect_ipset || strcmp(ses->l4_redirect_ipset, attr->val.string))
					ipset = attr->val.string;
			}
		}
	}

	if (lease_time_set && !renew_time_set)
		ses->renew_time = ses->lease_time/2;
	else if (renew_time_set && ses->renew_time > ses->lease_time) {
		log_ppp_warn("ipoe: overriding renew time\n");
		ses->renew_time = ses->lease_time/2;
	}

	if (lease_time_set && !rebind_time_set)
		ses->rebind_time = ses->lease_time/2 + ses->lease_time/4 + ses->lease_time/8;
	else if (rebind_time_set && ses->rebind_time > ses->lease_time) {
		log_ppp_warn("ipoe: overriding rebind time\n");
		ses->rebind_time = ses->lease_time/2 + ses->lease_time/4 + ses->lease_time/8;
	}

	if (ses->renew_time && ses->rebind_time && ses->renew_time > ses->rebind_time) {
		if (renew_time_set)
			log_ppp_warn("ipoe: overriding renew time\n");
		ses->renew_time = ses->rebind_time*4/7;
	}

	if (l4_redirect >= 0 && ev->ses->state == AP_STATE_ACTIVE) {
		if (ses->l4_redirect && l4_redirect && ipset) {
			ipoe_change_l4_redirect(ses, 1);
			ses->l4_redirect = 0;
		}

		if (ipset) {
			if (ses->l4_redirect_ipset)
				_free(ses->l4_redirect_ipset);
			ses->l4_redirect_ipset = _strdup(ipset);
		}

		if (l4_redirect != ses->l4_redirect ) {
			ipoe_change_l4_redirect(ses, l4_redirect == 0);
			ses->l4_redirect = l4_redirect;
		}
	}
}

static int ipoe_rad_send_acct_request(struct rad_plugin_t *rad, struct rad_packet_t *pack)
{
	struct ipoe_session *ses = container_of(rad, typeof(*ses), radius);

	if (!ses->relay_agent)
		return 0;

	if (conf_attr_dhcp_opt82 &&
		rad_packet_add_octets(pack, conf_vendor_str, conf_attr_dhcp_opt82, ses->relay_agent->data, ses->relay_agent->len))
		return -1;

	if (conf_attr_dhcp_opt82_remote_id && ses->agent_remote_id &&
		rad_packet_add_octets(pack, conf_vendor_str, conf_attr_dhcp_opt82_remote_id, ses->agent_remote_id + 1, *ses->agent_remote_id))
		return -1;

	if (conf_attr_dhcp_opt82_circuit_id && ses->agent_circuit_id &&
		rad_packet_add_octets(pack, conf_vendor_str, conf_attr_dhcp_opt82_circuit_id, ses->agent_circuit_id + 1, *ses->agent_circuit_id))
		return -1;

	return 0;
}

static int ipoe_rad_send_auth_request(struct rad_plugin_t *rad, struct rad_packet_t *pack)
{
	struct ipoe_session *ses = container_of(rad, typeof(*ses), radius);

	if (ipoe_rad_send_acct_request(rad, pack))
		return -1;

	if (ses->yiaddr)
		rad_packet_add_ipaddr(pack, NULL, "Framed-IP-Address", ses->yiaddr);

	return 0;
}
#endif

static void ipoe_serv_release(struct ipoe_serv *serv)
{
	pthread_mutex_lock(&serv->lock);
	if (!list_empty(&serv->sessions)) {
		pthread_mutex_unlock(&serv->lock);
		return;
	}

	if (serv->vlan_mon && !serv->need_close && !ap_shutdown && !serv->opt_auto) {
		if (serv->timer.tpd)
			triton_timer_mod(&serv->timer, 0);
		else
			triton_timer_add(&serv->ctx, &serv->timer, 0);

		pthread_mutex_unlock(&serv->lock);
		return;
	}
	pthread_mutex_unlock(&serv->lock);

	log_info2("ipoe: stop interface %s\n", serv->ifname);

	pthread_mutex_lock(&serv_lock);
	list_del(&serv->entry);
	pthread_mutex_unlock(&serv_lock);

	if (serv->dhcpv4)
		dhcpv4_free(serv->dhcpv4);

	if (serv->dhcpv4_relay)
		dhcpv4_relay_free(serv->dhcpv4_relay, &serv->ctx);

	if (serv->arp)
		arpd_stop(serv->arp);

	if (serv->opt_ipv6)
		ipoe_ipv6_disable(serv);

	while (!list_empty(&serv->disc_list)) {
		struct disc_item *d = list_entry(serv->disc_list.next, typeof(*d), entry);
		list_del(&d->entry);
		dhcpv4_packet_free(d->pack);
		mempool_free(d);
		__sync_sub_and_fetch(&stat_delayed_offer, 1);
	}

	while (!list_empty(&serv->arp_list)) {
		struct arp_item *d = list_entry(serv->arp_list.next, typeof(*d), entry);
		list_del(&d->entry);
		mempool_free(d);
		__sync_sub_and_fetch(&stat_delayed_offer, 1);
	}

	while (!list_empty(&serv->req_list)) {
		struct request_item *r = list_first_entry(&serv->req_list, typeof(*r), entry);
		list_del(&r->entry);
		mempool_free(r);
	}

	if (serv->disc_timer.tpd)
		triton_timer_del(&serv->disc_timer);

	if (serv->timer.tpd)
		triton_timer_del(&serv->timer);

	if (!serv->opt_auto)
		ipoe_nl_del_interface(serv->ifindex);

	if (serv->vlan_mon) {
		log_info2("ipoe: remove vlan %s\n", serv->ifname);
		iplink_vlan_del(serv->ifindex);
		vlan_mon_add_vid(serv->parent_ifindex, ETH_P_IP, serv->vid);
	}

	triton_context_unregister(&serv->ctx);

	_free(serv);
}

static void ipoe_serv_close(struct triton_context_t *ctx)
{
	struct ipoe_serv *serv = container_of(ctx, typeof(*serv), ctx);

	pthread_mutex_lock(&serv->lock);
	serv->need_close = 1;
	if (!list_empty(&serv->sessions)) {
		pthread_mutex_unlock(&serv->lock);
		return;
	}
	pthread_mutex_unlock(&serv->lock);

	ipoe_serv_release(serv);
}

static void l4_redirect_ctx_close(struct triton_context_t *ctx)
{
	struct l4_redirect *n;

	pthread_rwlock_wrlock(&l4_list_lock);
	while (!list_empty(&l4_redirect_list)) {
		n = list_entry(l4_redirect_list.next, typeof(*n), entry);
		list_del(&n->entry);

		if (conf_l4_redirect_table)
			iprule_del(n->addr, conf_l4_redirect_table);

		if (conf_l4_redirect_ipset)
			ipset_del(conf_l4_redirect_ipset, n->addr);

		ipoe_nl_del_exclude(n->addr);

		_free(n);
	}
	pthread_rwlock_unlock(&l4_list_lock);

	if (l4_redirect_timer.tpd)
		triton_timer_del(&l4_redirect_timer);

	triton_context_unregister(&l4_redirect_ctx);
}

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "ipoe:\r\n");
	cli_sendv(client,"  starting: %u\r\n", stat_starting);
	cli_sendv(client,"  active: %u\r\n", stat_active);
	cli_sendv(client,"  delayed: %u\r\n", stat_delayed_offer);

	return CLI_CMD_OK;
}

static void print_session_type(struct ap_session *s, char *buf)
{
	if (s->ctrl->type == CTRL_TYPE_IPOE) {
		struct ipoe_session *ses = container_of(s, typeof(*ses), ses);

		if (ses->UP)
			strcpy(buf, "up");
		else
			strcpy(buf, "dhcp");
	} else
		*buf = 0;
}

void __export ipoe_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static void __terminate(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_NAS_REQUEST, 1);
}

static void ipoe_drop_sessions(struct ipoe_serv *serv, struct ipoe_session *skip)
{
	struct ipoe_session *ses;

	list_for_each_entry(ses, &serv->sessions, entry) {
		if (ses == skip)
			continue;

		ses->terminating = 1;

		if (ses->ses.state == AP_STATE_ACTIVE)
			ap_session_ifdown(&ses->ses);

		triton_context_call(&ses->ctx, (triton_event_func)__terminate, &ses->ses);
	}
}

struct ipoe_serv *ipoe_find_serv(const char *ifname)
{
	struct ipoe_serv *serv;

	list_for_each_entry(serv, &serv_list, entry) {
		if (strcmp(serv->ifname, ifname) == 0)
			return serv;
	}

	return NULL;
}

static struct conf_option_t *ipoe_find_opt(const char *ifname)
{
	struct conf_sect_t *sect = conf_get_section("ipoe");
	struct conf_option_t *opt;
	const char *pcre_err;
	struct ifreq ifr;
	int pcre_offset;
	const char *ptr;
	pcre *re = NULL;
	char *pattern;

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "interface"))
			continue;
		if (!opt->val)
			continue;

		for (ptr = opt->val; *ptr && *ptr != ','; ptr++);

		if (strlen(opt->val) > 3 && memcmp(opt->val, "re:", 3) == 0) {
			pattern = _malloc(ptr - (opt->val + 3) + 1);
			memcpy(pattern, opt->val + 3, ptr - (opt->val + 3));
			pattern[ptr - (opt->val + 3)] = 0;

			re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

			_free(pattern);

			if (!re) {
				log_error("ipoe: '%s': %s at %i\r\n", pattern, pcre_err, pcre_offset);
				pcre_free(re);
				continue;
			}

			if (pcre_exec(re, NULL, ifname, strlen(ifname), 0, 0, NULL, 0) < 0) {
				pcre_free(re);
				continue;
			}

			pcre_free(re);
		} else {
			if (ptr - opt->val >= sizeof(ifr.ifr_name))
				continue;

			memcpy(ifr.ifr_name, opt->val, ptr - opt->val);
			ifr.ifr_name[ptr - opt->val] = 0;

			if (strcmp(ifr.ifr_name, ifname) != 0)
				continue;
		}
		return opt;
	}

	return NULL;
}

static int get_offer_delay()
{
	struct delay *r, *prev = NULL;

	list_for_each_entry(r, &conf_offer_delay, entry) {
		if (!prev || stat_active >= r->conn_cnt) {
			prev = r;
			continue;
		}
		break;
	}

	if (prev)
		return prev->delay;

	return 0;
}

static void set_vlan_timeout(struct ipoe_serv *serv)
{
	serv->timer.expire = ipoe_serv_timeout;
	serv->timer.expire_tv.tv_sec = conf_vlan_timeout;

	if (list_empty(&serv->sessions))
		triton_timer_add(&serv->ctx, &serv->timer, 0);
}

void ipoe_vlan_mon_notify(int ifindex, int vid, int vlan_ifindex)
{
	struct conf_sect_t *sect = conf_get_section("ipoe");
	struct conf_option_t *opt;
	struct ifreq ifr;
	char *ptr;
	int len, r, svid;
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	int pcre_offset;
	char ifname[IFNAMSIZ];

	if (!sect)
		return;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;
	if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
		log_error("ipoe: vlan-mon: failed to get interface name, ifindex=%i\n", ifindex);
		return;
	}

	svid = iplink_vlan_get_vid(ifindex, NULL);

#ifdef USE_LUA
	if (!memcmp(conf_vlan_name, "lua:", 4))
		r = ipoe_lua_make_vlan_name(conf_vlan_name + 4, ifr.ifr_name, svid, vid, ifname);
	else
#endif
	r = make_vlan_name(conf_vlan_name, ifr.ifr_name, svid, vid, ifname);
	if (r) {
		log_error("ipoe: vlan-mon: %s.%i: interface name is too long\n", ifr.ifr_name, vid);
		return;
	}

	if (vlan_ifindex) {
		struct ipoe_serv *serv;

		pthread_mutex_lock(&serv_lock);
		list_for_each_entry(serv, &serv_list, entry) {
			if (serv->ifindex == vlan_ifindex) {
				if (!serv->vlan_mon) {
					serv->vlan_mon = 1;
					set_vlan_timeout(serv);
				}
				pthread_mutex_unlock(&serv_lock);
				return;
			}
		}
		pthread_mutex_unlock(&serv_lock);

		log_info2("ipoe: create vlan %s parent %s\n", ifname, ifr.ifr_name);

		ifr.ifr_ifindex = vlan_ifindex;
		if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
			log_error("ipoe: vlan-mon: failed to get interface name, ifindex=%i\n", ifindex);
			return;
		}

		if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr, sizeof(ifr)))
			return;

		if (ifr.ifr_flags & IFF_UP) {
			ifr.ifr_flags &= ~IFF_UP;

			if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr, sizeof(ifr)))
				return;
		}

		if (strcmp(ifr.ifr_name, ifname)) {
			strcpy(ifr.ifr_newname, ifname);
			if (ioctl(sock_fd, SIOCSIFNAME, &ifr, sizeof(ifr))) {
				log_error("ipoe: vlan-mon: failed to rename interface %s to %s\n", ifr.ifr_name, ifr.ifr_newname);
				return;
			}
			strcpy(ifr.ifr_name, ifname);
		}
	} else {
		log_info2("ipoe: create vlan %s parent %s\n", ifname, ifr.ifr_name);

		if (iplink_vlan_add(ifname, ifindex, vid))
			return;
	}

	len = strlen(ifname);
	memcpy(ifr.ifr_name, ifname, len + 1);

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr, sizeof(ifr))) {
		log_error("ipoe: vlan-mon: %s: failed to get interface index\n", ifr.ifr_name);
		return;
	}

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "interface"))
			continue;
		if (!opt->val)
			continue;

		ptr = strchr(opt->val, ',');
		if (!ptr)
			ptr = strchr(opt->val, 0);

		if (ptr - opt->val > 3 && memcmp(opt->val, "re:", 3) == 0) {
			pattern = _malloc(ptr - (opt->val + 3) + 1);
			memcpy(pattern, opt->val + 3, ptr - (opt->val + 3));
			pattern[ptr - (opt->val + 3)] = 0;

			re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

			_free(pattern);

			if (!re)
				continue;

			r = pcre_exec(re, NULL, ifname, len, 0, 0, NULL, 0);
			pcre_free(re);

			if (r < 0)
				continue;

			add_interface(ifname, ifr.ifr_ifindex, opt->val, ifindex, vid, 1);
			return;
		} else if (ptr - opt->val == len && memcmp(opt->val, ifname, len) == 0) {
			add_interface(ifname, ifr.ifr_ifindex, opt->val, ifindex, vid, 1);
			return;
		}
	}

	log_warn("ipoe: vlan %s not started\n", ifname);
	iplink_vlan_del(ifr.ifr_ifindex);
	vlan_mon_del_vid(ifindex, ETH_P_IP, vid);
}

static void ipoe_serv_timeout(struct triton_timer_t *t)
{
	struct ipoe_serv *serv = container_of(t, typeof(*serv), timer);

	serv->need_close = 1;

	ipoe_serv_release(serv);
}

static void ipoe_ipv6_enable(struct ipoe_serv *serv)
{
	struct ifreq ifr;

	strcpy(ifr.ifr_name, serv->ifname);

	ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
	ifr.ifr_hwaddr.sa_data[0] = 0x33;
	ifr.ifr_hwaddr.sa_data[1] = 0x33;
	*(uint32_t *)(ifr.ifr_hwaddr.sa_data + 2) = htonl(0x02);
	ioctl(sock_fd, SIOCADDMULTI, &ifr);

	*(uint32_t *)(ifr.ifr_hwaddr.sa_data + 2) = htonl(0x010002);
	ioctl(sock_fd, SIOCADDMULTI, &ifr);
}

static void ipoe_ipv6_disable(struct ipoe_serv *serv)
{
	struct ifreq ifr;

	strcpy(ifr.ifr_name, serv->ifname);

	ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
	ifr.ifr_hwaddr.sa_data[0] = 0x33;
	ifr.ifr_hwaddr.sa_data[1] = 0x33;
	*(uint32_t *)(ifr.ifr_hwaddr.sa_data + 2) = htonl(0x02);
	ioctl(sock_fd, SIOCDELMULTI, &ifr);

	*(uint32_t *)(ifr.ifr_hwaddr.sa_data + 2) = htonl(0x010002);
	ioctl(sock_fd, SIOCDELMULTI, &ifr);
}


static void add_interface(const char *ifname, int ifindex, const char *opt, int parent_ifindex, int vid, int vlan_mon)
{
	char *str0 = NULL, *str, *ptr1, *ptr2;
	int end;
	struct ipoe_serv *serv;
	int opt_shared = conf_shared;
	int opt_dhcpv4 = 0;
	int opt_up = 0;
	int opt_mode = conf_mode;
	int opt_ifcfg = conf_ifcfg;
	int opt_nat = conf_nat;
	int opt_username = conf_username;
	int opt_ipv6 = conf_ipv6;
	int opt_auto = conf_auto;
	int opt_mtu = 0;
	int opt_weight = -1;
	int opt_ip_unnumbered = conf_ip_unnumbered;
#ifdef USE_LUA
	char *opt_lua_username_func = NULL;
#endif
	const char *opt_relay = conf_relay;
	in_addr_t relay_addr = conf_relay ? inet_addr(conf_relay) : 0;
	in_addr_t opt_giaddr = 0;
	in_addr_t opt_src = conf_src;
	int opt_arp = conf_arp;
	struct ifreq ifr;
	uint8_t hwaddr[ETH_ALEN];

	str0 = strchr(opt, ',');
	if (str0) {
		str0 = _strdup(str0 + 1);
		str = str0;

		while (1) {
			for (ptr1 = str + 1; *ptr1 && *ptr1 != '='; ptr1++);

			if (!*ptr1)
				goto parse_err;

			*ptr1 = 0;

			for (ptr2 = ++ptr1; *ptr2 && *ptr2 != ','; ptr2++);

			end = *ptr2 == 0;

			if (!end)
				*ptr2 = 0;

			if (ptr2 == ptr1)
				goto parse_err;

			if (strcmp(str, "start") == 0) {
				if (!strcmp(ptr1, "up"))
					opt_up = 1;
				else if (!strcmp(ptr1, "dhcpv4"))
					opt_dhcpv4 = 1;
				else if (!strcmp(ptr1, "auto"))
					opt_auto = 1;
				else
					goto parse_err;
			} else if (strcmp(str, "shared") == 0) {
				opt_shared = atoi(ptr1);
			} else if (strcmp(str, "mode") == 0) {
				if (!strcmp(ptr1, "L2"))
					opt_mode = MODE_L2;
				else if (!strcmp(ptr1, "L3"))
					opt_mode = MODE_L3;
				else
					goto parse_err;
			} else if (strcmp(str, "ifcfg") == 0) {
				opt_ifcfg = atoi(ptr1);
			} else if (strcmp(str, "relay") == 0) {
				opt_relay = ptr1;
				relay_addr = inet_addr(ptr1);
			} else if (strcmp(str, "giaddr") == 0) {
				opt_giaddr = inet_addr(ptr1);
			} else if (strcmp(str, "nat") == 0) {
				opt_nat = atoi(ptr1);
			} else if (strcmp(str, "src") == 0) {
				opt_src = inet_addr(ptr1);
			} else if (strcmp(str, "proxy-arp") == 0) {
				opt_arp = atoi(ptr1);
			} else if (strcmp(str, "ipv6") == 0) {
				opt_ipv6 = atoi(ptr1);
			} else if (strcmp(str, "mtu") == 0) {
				opt_mtu = atoi(ptr1);
			} else if (strcmp(str, "weight") == 0) {
				opt_weight = atoi(ptr1);
			} else if (strcmp(str, "ip-unnumbered") == 0) {
				opt_ip_unnumbered = atoi(ptr1);
			} else if (strcmp(str, "username") == 0) {
				if (strcmp(ptr1, "ifname") == 0)
					opt_username = USERNAME_IFNAME;
#ifdef USE_LUA
				else if (strlen(ptr1) > 4 && memcmp(ptr1, "lua:", 4) == 0) {
					opt_username = USERNAME_LUA;
					opt_lua_username_func = _strdup(ptr1 + 4);
				}
#endif
				else
					log_error("ipoe: unknown username value '%s'\n", ptr1);
			}

			if (end)
				break;

			str = ptr2 + 1;
		}
	}

	if (!opt_up && !opt_dhcpv4 && !opt_auto) {
		opt_up = conf_up;
		opt_dhcpv4 = conf_dhcpv4;
		opt_auto = conf_auto;
	}

	 if (!opt_arp && opt_up && opt_mode == MODE_L2)
                opt_arp = 1;

	opt_auto &= !opt_shared;

	if (opt_relay && !opt_giaddr && opt_dhcpv4) {
		struct sockaddr_in addr;
		int sock;
		socklen_t len = sizeof(addr);

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = relay_addr;
		addr.sin_port = htons(DHCP_SERV_PORT);

		sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

		if (connect(sock, &addr, sizeof(addr))) {
			log_error("dhcpv4: relay: %s: connect: %s\n", opt_relay, strerror(errno));
			goto out_err;
		}

		getsockname(sock, &addr, &len);
		opt_giaddr = addr.sin_addr.s_addr;

		close(sock);
	}

	pthread_mutex_lock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		if (strcmp(ifname, serv->ifname))
			continue;

		serv->active = 1;
		serv->ifindex = ifindex;

		if ((opt_shared && !serv->opt_shared) || (!opt_shared && serv->opt_shared)) {
			ipoe_drop_sessions(serv, NULL);
			serv->opt_shared = opt_shared;
		}

		if (opt_dhcpv4 && !serv->dhcpv4) {
			serv->dhcpv4 = dhcpv4_create(&serv->ctx, serv->ifname, opt);
			if (serv->dhcpv4)
				serv->dhcpv4->recv = ipoe_recv_dhcpv4;
		} else if (!opt_dhcpv4 && serv->dhcpv4) {
			dhcpv4_free(serv->dhcpv4);
			serv->dhcpv4 = NULL;
		}

		if (serv->dhcpv4_relay &&
				(serv->dhcpv4_relay->addr != relay_addr || serv->dhcpv4_relay->giaddr != opt_giaddr)) {
			dhcpv4_relay_free(serv->dhcpv4_relay, &serv->ctx);
			serv->dhcpv4_relay = NULL;
		}

		if (!serv->dhcpv4_relay && serv->opt_dhcpv4 && opt_relay)
			serv->dhcpv4_relay = dhcpv4_relay_create(opt_relay, opt_giaddr, &serv->ctx, (triton_event_func)ipoe_recv_dhcpv4_relay);

		if (serv->arp && !opt_arp) {
			arpd_stop(serv->arp);
			serv->arp = NULL;
		} else if (!serv->arp && opt_arp)
			serv->arp = arpd_start(serv);

		if (serv->opt_mtu != opt_mtu && opt_mtu) {
			iplink_set_mtu(serv->ifindex, opt_mtu);
			serv->opt_mtu = opt_mtu;
		}

		serv->opt_up = opt_up;
		serv->opt_auto = opt_auto;
		serv->opt_mode = opt_mode;
		serv->opt_ifcfg = opt_ifcfg;
		serv->opt_nat = opt_nat;
		serv->opt_src = opt_src;
		serv->opt_arp = opt_arp;
		serv->opt_username = opt_username;
		serv->opt_ipv6 = opt_ipv6;
		serv->opt_weight = opt_weight;
		serv->opt_ip_unnumbered = opt_ip_unnumbered;
#ifdef USE_LUA
		if (serv->opt_lua_username_func && (!opt_lua_username_func || strcmp(serv->opt_lua_username_func, opt_lua_username_func))) {
			_free(serv->opt_lua_username_func);
			serv->opt_lua_username_func = NULL;
		}

		if (!serv->opt_lua_username_func && opt_lua_username_func)
			serv->opt_lua_username_func = opt_lua_username_func;
		else if (opt_lua_username_func)
			_free(opt_lua_username_func);
#endif

		if (str0)
			_free(str0);

		pthread_mutex_unlock(&serv_lock);
		return;
	}
	pthread_mutex_unlock(&serv_lock);

	if (vid && !vlan_mon && vlan_mon_check_busy(parent_ifindex, vid))
		return;

	if (!opt_auto) {
		if (opt_up)
			ipoe_nl_add_interface(ifindex, opt_mode);
		else
			ipoe_nl_add_interface(ifindex, 0);
	}

	opt = strchr(opt, ',');
	if (opt)
		opt++;

	log_info2("ipoe: start interface %s (%s)\n", ifname, opt ? opt : "");

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr)) {
		log_error("ipoe: '%s': ioctl(SIOCGIFHWADDR): %s\n", ifname, strerror(errno));
		return;
	}

	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr);

	if ((ifr.ifr_flags & IFF_UP) && opt_shared == 0 && opt_ifcfg) {
		int flags = ifr.ifr_flags;

		ifr.ifr_flags &= ~IFF_UP;
		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);

		flags = ifr.ifr_flags;

		((struct sockaddr_in *)&ifr.ifr_addr)->sin_family = AF_INET;
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = 0;
		ioctl(sock_fd, SIOCSIFADDR, &ifr, sizeof(ifr));

		ifr.ifr_flags = flags;
	}

	ifr.ifr_flags |= IFF_UP;
	ioctl(sock_fd, SIOCSIFFLAGS, &ifr);

	serv = _malloc(sizeof(*serv));
	memset(serv, 0, sizeof(*serv));
	serv->ctx.close = ipoe_serv_close;
	serv->ctx.before_switch = ipoe_ctx_switch;
	pthread_mutex_init(&serv->lock, NULL);
	strcpy(serv->ifname, ifname);
	serv->ifindex = ifindex;
	serv->opt_shared = opt_shared;
	serv->opt_dhcpv4 = opt_dhcpv4;
	serv->opt_up = opt_up;
	serv->opt_auto = opt_auto;
	serv->opt_mode = opt_mode;
	serv->opt_ifcfg = opt_ifcfg;
	serv->opt_nat = opt_nat;
	serv->opt_src = opt_src;
	serv->opt_arp = opt_arp;
	serv->opt_username = opt_username;
	serv->opt_ipv6 = opt_ipv6;
	serv->opt_mtu = opt_mtu;
	serv->opt_weight = opt_weight;
	serv->opt_ip_unnumbered = opt_ip_unnumbered;
#ifdef USE_LUA
	serv->opt_lua_username_func = opt_lua_username_func;
#endif
	serv->parent_ifindex = parent_ifindex;
	serv->parent_vid = parent_ifindex ? iplink_vlan_get_vid(parent_ifindex, NULL) : 0;
	serv->vid = vid;
	serv->active = 1;
	INIT_LIST_HEAD(&serv->sessions);
	INIT_LIST_HEAD(&serv->disc_list);
	INIT_LIST_HEAD(&serv->arp_list);
	INIT_LIST_HEAD(&serv->req_list);
	memcpy(serv->hwaddr, hwaddr, ETH_ALEN);
	serv->disc_timer.expire = ipoe_serv_disc_timer;

	triton_context_register(&serv->ctx, NULL);

	if (serv->opt_dhcpv4) {
		serv->dhcpv4 = dhcpv4_create(&serv->ctx, serv->ifname, opt);
		if (serv->dhcpv4)
			serv->dhcpv4->recv = ipoe_recv_dhcpv4;

		if (opt_relay)
			serv->dhcpv4_relay = dhcpv4_relay_create(opt_relay, opt_giaddr, &serv->ctx, (triton_event_func)ipoe_recv_dhcpv4_relay);
	}

	if (serv->opt_arp)
		serv->arp = arpd_start(serv);

	if (serv->opt_ipv6 && serv->opt_shared)
		ipoe_ipv6_enable(serv);

	if (vlan_mon) {
		serv->vlan_mon = 1;
		set_vlan_timeout(serv);
	}

	if (opt_mtu)
		iplink_set_mtu(ifindex, opt_mtu);

	if (serv->opt_auto && !serv->opt_shared)
		triton_context_call(&serv->ctx, (triton_event_func)ipoe_session_create_auto, serv);

	pthread_mutex_lock(&serv_lock);
	list_add_tail(&serv->entry, &serv_list);
	pthread_mutex_unlock(&serv_lock);

	triton_context_wakeup(&serv->ctx);

	if (str0)
		_free(str0);

	return;

parse_err:
	log_error("ipoe: failed to parse '%s'\n", opt);
out_err:
	_free(str0);
}

static void load_interface(const char *opt)
{
	const char *ptr;
	struct ifreq ifr;
	struct ipoe_serv *serv;
	int vid, iflink = 0;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	if (ptr - opt >= sizeof(ifr.ifr_name))
		return;

	memcpy(ifr.ifr_name, opt, ptr - opt);
	ifr.ifr_name[ptr - opt] = 0;

	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->active)
			continue;

		if (!strcmp(serv->ifname, ifr.ifr_name)) {
			add_interface(serv->ifname, serv->ifindex, opt, 0, 0, 0);
			return;
		}
	}

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_error("ipoe: '%s': ioctl(SIOCGIFINDEX): %s\n", ifr.ifr_name, strerror(errno));
		return;
	}

	vid = iplink_vlan_get_vid(ifr.ifr_ifindex, &iflink);

	add_interface(ifr.ifr_name, ifr.ifr_ifindex, opt, iflink, vid, 0);
}

static int __load_interface_re(int index, int flags, const char *name, int iflink, int vid, struct iplink_arg *arg)
{
	if (pcre_exec(arg->re, NULL, name, strlen(name), 0, 0, NULL, 0) < 0)
		return 0;

	add_interface(name, index, arg->opt, iflink, vid, 0);

	return 0;
}

static void load_interface_re(const char *opt)
{
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	const char *ptr;
	int pcre_offset;
	struct iplink_arg arg;
	struct ipoe_serv *serv;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	pattern = _malloc(ptr - (opt + 3) + 1);
	memcpy(pattern, opt + 3, ptr - (opt + 3));
	pattern[ptr - (opt + 3)] = 0;

	re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

	if (!re) {
		log_error("ipoe: '%s': %s at %i\r\n", pattern, pcre_err, pcre_offset);
		return;
	}

	arg.re = re;
	arg.opt = opt;

	iplink_list((iplink_list_func)__load_interface_re, &arg);

	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->active)
			continue;

		if (pcre_exec(re, NULL, serv->ifname, strlen(serv->ifname), 0, 0, NULL, 0) >= 0)
			add_interface(serv->ifname, serv->ifindex, opt, 0, 0, 0);
	}

	pcre_free(re);
	_free(pattern);
}

static void load_interfaces(struct conf_sect_t *sect)
{
	struct ipoe_serv *serv;
	struct conf_option_t *opt;

	list_for_each_entry(serv, &serv_list, entry)
		serv->active = 0;

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "interface"))
			continue;
		if (!opt->val)
			continue;

		if (strlen(opt->val) > 3 && memcmp(opt->val, "re:", 3) == 0)
			load_interface_re(opt->val);
		else
			load_interface(opt->val);
	}

	list_for_each_entry(serv, &serv_list, entry) {
		if (!serv->active) {
			if (!serv->opt_auto)
				ipoe_nl_del_interface(serv->ifindex);
			ipoe_drop_sessions(serv, NULL);
			serv->need_close = 1;
			triton_context_call(&serv->ctx, (triton_event_func)ipoe_serv_release, serv);
		}
	}
}

static void load_gw_addr(struct conf_sect_t *sect)
{
	struct conf_option_t *opt;
	struct gw_addr *a;
	char addr[17];
	char *ptr;

	while (!list_empty(&conf_gw_addr)) {
		a = list_entry(conf_gw_addr.next, typeof(*a), entry);
		list_del(&a->entry);
		_free(a);
	}

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "gw-ip-address"))
			continue;
		if (!opt->val)
			continue;

		a = _malloc(sizeof(*a));
		ptr = strchr(opt->val, '/');
		if (ptr) {
			memcpy(addr, opt->val, ptr - opt->val);
			addr[ptr - opt->val] = 0;
			a->addr = inet_addr(addr);
			a->mask = atoi(ptr + 1);
		} else {
			a->addr = inet_addr(opt->val);
			a->mask = 32;
		}

		if (a->addr == 0xffffffff || a->mask < 1 || a->mask > 32) {
			log_error("ipoe: failed to parse '%s=%s'\n", opt->name, opt->val);
			_free(a);
			continue;
		}

		a->mask1 = ((1 << a->mask) - 1) << (32 - a->mask);
		list_add_tail(&a->entry, &conf_gw_addr);
	}
}

#ifdef RADIUS
static void parse_conf_rad_attr(const char *opt, int *val)
{
	struct rad_dict_attr_t *attr;

	*val = 0;

	opt = conf_get_opt("ipoe", opt);
	if (!opt)
		return;

	if (conf_vendor) {
		struct rad_dict_vendor_t *vendor = rad_dict_find_vendor_id(conf_vendor);
		attr = rad_dict_find_vendor_attr(vendor, opt);
	} else
		attr = rad_dict_find_attr(opt);

	if (attr)
		*val = attr->id;
	else if (atoi(opt) > 0)
		*val = atoi(opt);
	else
		log_emerg("ipoe: couldn't find '%s' in dictionary\n", opt);
}

static void load_radius_attrs(void)
{
	const char *vendor = conf_get_opt("ipoe", "vendor");

	conf_vendor_str = NULL;
	if (vendor) {
		struct rad_dict_vendor_t *v = rad_dict_find_vendor_name(vendor);
		if (v) {
			conf_vendor = v->id;
			conf_vendor_str = vendor;
		} else {
			conf_vendor = atoi(vendor);
			if (!rad_dict_find_vendor_id(conf_vendor)) {
				conf_vendor = 0;
				log_emerg("ipoe: vendor '%s' not found\n", vendor);
			}
		}
	}

	parse_conf_rad_attr("attr-dhcp-client-ip", &conf_attr_dhcp_client_ip);
	parse_conf_rad_attr("attr-dhcp-router-ip", &conf_attr_dhcp_router_ip);
	parse_conf_rad_attr("attr-dhcp-mask", &conf_attr_dhcp_mask);
	parse_conf_rad_attr("attr-dhcp-lease-time", &conf_attr_dhcp_lease_time);
	parse_conf_rad_attr("attr-dhcp-renew-time", &conf_attr_dhcp_renew_time);
	parse_conf_rad_attr("attr-dhcp-rebind-time", &conf_attr_dhcp_rebind_time);
	parse_conf_rad_attr("attr-l4-redirect", &conf_attr_l4_redirect);
	parse_conf_rad_attr("attr-l4-redirect-table", &conf_attr_l4_redirect_table);
	parse_conf_rad_attr("attr-l4-redirect-ipset", &conf_attr_l4_redirect_ipset);
	conf_attr_dhcp_opt82 = conf_get_opt("ipoe", "attr-dhcp-opt82");
	conf_attr_dhcp_opt82_remote_id = conf_get_opt("ipoe", "attr-dhcp-opt82-remote-id");
	conf_attr_dhcp_opt82_circuit_id = conf_get_opt("ipoe", "attr-dhcp-opt82-circuit-id");
}
#endif

static void strip(char *str)
{
	char *ptr = str;
	char *endptr = strchr(str, 0);
	while (1) {
		ptr = strchr(ptr, ' ');
		if (ptr)
			memmove(ptr, ptr + 1, endptr - ptr - 1);
		else
			break;
	}
}

int parse_offer_delay(const char *str)
{
	char *str1;
	char *ptr1, *ptr2, *ptr3, *endptr;
	struct delay *r;

	while (!list_empty(&conf_offer_delay)) {
		r = list_entry(conf_offer_delay.next, typeof(*r), entry);
		list_del(&r->entry);
		_free(r);
	}

	if (!str)
		return 0;

	str1 = _strdup(str);
	strip(str1);

	ptr1 = str1;

	while (1) {
		ptr2 = strchr(ptr1, ',');
		if (ptr2)
			*ptr2 = 0;
		ptr3 = strchr(ptr1, ':');
		if (ptr3)
			*ptr3 = 0;

		r = _malloc(sizeof(*r));
		memset(r, 0, sizeof(*r));

		r->delay = strtol(ptr1, &endptr, 10);
		if (*endptr)
			goto out_err;

		if (list_empty(&conf_offer_delay))
			r->conn_cnt = 0;
		else {
			if (!ptr3)
				goto out_err;
			r->conn_cnt = strtol(ptr3 + 1, &endptr, 10);
			if (*endptr)
				goto out_err;
		}

		list_add_tail(&r->entry, &conf_offer_delay);

		if (!ptr2)
			break;

		ptr1 = ptr2 + 1;
	}

	_free(str1);
	return 0;

out_err:
	_free(str1);
	log_error("ipoe: failed to parse offer-delay\n");
	return -1;
}

static void add_vlan_mon(const char *opt, long *mask)
{
	const char *ptr;
	struct ifreq ifr;
	int ifindex;
	long mask1[4096/8/sizeof(long)];
	struct ipoe_serv *serv;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	if (ptr - opt >= IFNAMSIZ) {
		log_error("ipoe: vlan-mon=%s: interface name is too long\n", opt);
		return;
	}

	memset(&ifr, 0, sizeof(ifr));

	memcpy(ifr.ifr_name, opt, ptr - opt);
	ifr.ifr_name[ptr - opt] = 0;

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_error("ipoe: '%s': ioctl(SIOCGIFINDEX): %s\n", ifr.ifr_name, strerror(errno));
		return;
	}

	ifindex = ifr.ifr_ifindex;

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr);

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	memcpy(mask1, mask, sizeof(mask1));
	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->parent_ifindex == ifindex &&
		    !(mask1[serv->vid / (8*sizeof(long))] & 1lu << (serv->vid % (8*sizeof(long))))) {
			mask1[serv->vid / (8*sizeof(long))] |= 1lu << (serv->vid % (8*sizeof(long)));

			if (!serv->vlan_mon) {
				serv->vlan_mon = 1;
				set_vlan_timeout(serv);
			}
		}
	}

	vlan_mon_add(ifindex, ETH_P_IP, mask1, sizeof(mask1));
}

static int __load_vlan_mon_re(int index, int flags, const char *name, int iflink, int vid, struct iplink_arg *arg)
{
	struct ifreq ifr;
	long mask1[4096/8/sizeof(long)];
	struct ipoe_serv *serv;

	if (pcre_exec(arg->re, NULL, name, strlen(name), 0, 0, NULL, 0) < 0)
		return 0;

	if (!(flags & IFF_UP)) {
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, name);
		ifr.ifr_flags = flags | IFF_UP;

		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	memcpy(mask1, arg->arg1, sizeof(mask1));
	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->parent_ifindex == index &&
		    !(mask1[serv->vid / (8*sizeof(long))] & (1lu << (serv->vid % (8*sizeof(long)))))) {
			mask1[serv->vid / (8*sizeof(long))] |= 1lu << (serv->vid % (8*sizeof(long)));

			if (!serv->vlan_mon) {
				serv->vlan_mon = 1;
				set_vlan_timeout(serv);
			}
		}
	}

	vlan_mon_add(index, ETH_P_IP,  mask1, sizeof(mask1));

	return 0;
}

static void load_vlan_mon_re(const char *opt, long *mask, int len)
{
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	const char *ptr;
	int pcre_offset;
	struct iplink_arg arg;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	pattern = _malloc(ptr - (opt + 3) + 1);
	memcpy(pattern, opt + 3, ptr - (opt + 3));
	pattern[ptr - (opt + 3)] = 0;

	re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

	if (!re) {
		log_error("ipoe: '%s': %s at %i\r\n", pattern, pcre_err, pcre_offset);
		return;
	}

	arg.re = re;
	arg.opt = opt;
	arg.arg1 = mask;

	iplink_list((iplink_list_func)__load_vlan_mon_re, &arg);

	pcre_free(re);
	_free(pattern);

}

static void load_vlan_mon(struct conf_sect_t *sect)
{
	struct conf_option_t *opt;
	long mask[4096/8/sizeof(long)];
	static int registered = 0;

	if (!registered) {
		vlan_mon_register_proto(ETH_P_IP, ipoe_vlan_mon_notify);
		registered = 1;
	}

	vlan_mon_del(-1, ETH_P_IP);

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "vlan-mon"))
			continue;

		if (!opt->val)
			continue;

		if (parse_vlan_mon(opt->val, mask))
			continue;

		if (strlen(opt->val) > 3 && !memcmp(opt->val, "re:", 3))
			load_vlan_mon_re(opt->val, mask, sizeof(mask));
		else
			add_vlan_mon(opt->val, mask);
	}
}

static void parse_local_net(const char *opt)
{
	const char *ptr;
	char str[17];
	in_addr_t addr;
	int mask;
	char *endptr;
	struct local_net *n;

	ptr = strchr(opt, '/');
	if (ptr) {
		memcpy(str, opt, ptr - opt);
		str[ptr - opt] = 0;
		addr = inet_addr(str);
		if (addr == INADDR_NONE)
			goto out_err;
		mask = strtoul(ptr + 1, &endptr, 10);
		if (mask > 32)
			goto out_err;
	} else {
		addr = inet_addr(opt);
		if (addr == INADDR_NONE)
			goto out_err;
		mask = 24;
	}

	mask = htonl(mask ? ~0 << (32 - mask) : 0);
	addr = addr & mask;

	list_for_each_entry(n, &local_nets, entry) {
		if (n->addr == addr && n->mask == mask) {
			n->active = 1;
			return;
		}
	}

	n = _malloc(sizeof(*n));
	n->addr = addr;
	n->mask = mask;
	n->active = 1;
	list_add_tail(&n->entry, &local_nets);

	ipoe_nl_add_net(addr, ntohl(mask));

	return;

out_err:
	log_error("ipoe: failed to parse 'local-net=%s'\n", opt);
}

static void load_local_nets(struct conf_sect_t *sect)
{
	struct conf_option_t *opt;
	struct local_net *n;
	struct list_head *pos, *t;

	list_for_each_entry(n, &local_nets, entry)
		n->active = 0;

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "local-net"))
			continue;
		if (!opt->val)
			continue;
		parse_local_net(opt->val);
	}

	list_for_each_safe(pos, t, &local_nets) {
		n = list_entry(pos, typeof(*n), entry);
		if (!n->active) {
			ipoe_nl_del_net(n->addr);
			list_del(&n->entry);
			_free(n);
		}
	}
}

static void load_config(void)
{
	const char *opt;
	struct conf_sect_t *s = conf_get_section("ipoe");
	struct conf_option_t *opt1;
	struct in_addr dummy;

	if (!s)
		return;

	net = def_net;

	opt = conf_get_opt("ipoe", "username");
	if (opt) {
		if (strcmp(opt, "ifname") == 0)
			conf_username = USERNAME_IFNAME;
#ifdef USE_LUA
		else if (strlen(opt) > 4 && memcmp(opt, "lua:", 4) == 0) {
			conf_username = USERNAME_LUA;
			conf_lua_username_func = opt + 4;
		}
#endif
		else
			log_emerg("ipoe: unknown username value '%s'\n", opt);
	} else
		conf_username = USERNAME_UNSET;

	opt = conf_get_opt("ipoe", "password");
	if (opt) {
		if (!strcmp(opt, "username"))
			conf_password = NULL;
		else if (!strcmp(opt, "empty"))
			conf_password = "";
		else
			conf_password = opt;
	} else
		conf_password = NULL;

	opt = conf_get_opt("ipoe", "netmask");
	if (opt) {
		conf_netmask = atoi(opt);
		if (conf_netmask <= 0 || conf_netmask > 32) {
			log_error("ipoe: invalid netmask %s\n", opt);
			conf_netmask = 0;
		}
	} else
		conf_netmask = 0;

	opt = conf_get_opt("ipoe", "verbose");
	if (opt)
		conf_verbose = atoi(opt);
	else
		conf_verbose = 0;

	opt = conf_get_opt("ipoe", "lease-time");
	if (opt)
		conf_lease_time = atoi(opt);
	else
		conf_lease_time = LEASE_TIME;

	opt = conf_get_opt("ipoe", "renew-time");
	if (opt)
		conf_renew_time = atoi(opt);
	if (!opt || conf_renew_time > conf_lease_time)
		conf_renew_time = conf_lease_time/2;

	opt = conf_get_opt("ipoe", "rebind-time");
	if (opt)
		conf_rebind_time = atoi(opt);
	if (!opt || conf_rebind_time > conf_lease_time)
		conf_rebind_time = conf_lease_time/2 + conf_lease_time/4 + conf_lease_time/8;

	if (conf_renew_time && conf_rebind_time && conf_renew_time > conf_rebind_time)
		conf_renew_time = conf_rebind_time*4/7;

	opt = conf_get_opt("ipoe", "max-lease-time");
	if (opt)
		conf_lease_timeout = atoi(opt);
	else
		conf_lease_timeout = conf_lease_time + conf_lease_time/10;

	opt = conf_get_opt("ipoe", "unit-cache");
	if (opt)
		conf_unit_cache = atoi(opt);
	else
		conf_unit_cache = 0;

	opt = conf_get_opt("ipoe", "l4-redirect-table");
	if (opt && atoi(opt) > 0)
		conf_l4_redirect_table = atoi(opt);
	else
		conf_l4_redirect_table = 0;

	conf_l4_redirect_ipset = conf_get_opt("ipoe", "l4-redirect-ipset");

	opt = conf_get_opt("ipoe", "l4-redirect-on-reject");
	if (opt) {
		conf_l4_redirect_on_reject = atoi(opt);
	} else
		conf_l4_redirect_on_reject = 0;

	if (conf_l4_redirect_on_reject) {
		l4_redirect_timer.period = conf_l4_redirect_on_reject / 10 * 1000;
		if (l4_redirect_timer.tpd)
			triton_timer_mod(&l4_redirect_timer, 0);
	}

	opt = conf_get_opt("ipoe", "shared");
	if (opt)
		conf_shared = atoi(opt);
	else
		conf_shared = 1;

	opt = conf_get_opt("ipoe", "ifcfg");
	if (opt)
		conf_ifcfg = atoi(opt);
	else
		conf_ifcfg = 1;

	opt = conf_get_opt("ipoe", "nat");
	if (opt)
		conf_nat = atoi(opt);
	else
		conf_nat = 0;

	opt = conf_get_opt("ipoe", "src");
	if (opt)
		conf_src = inet_addr(opt);
	else
		conf_src = 0;

	opt = conf_get_opt("ipoe", "proxy-arp");
	if (opt)
		conf_arp = atoi(opt);
	else
		conf_arp = 0;

	if (conf_arp < 0 || conf_arp > 2) {
		log_error("ipoe: arp=%s: invalid value\n", opt);
		conf_arp = 0;
	}

	opt = conf_get_opt("ipoe", "mode");
	if (opt) {
		if (!strcmp(opt, "L2"))
			conf_mode = MODE_L2;
		else if (!strcmp(opt, "L3"))
			conf_mode = MODE_L3;
		else
			log_emerg("ipoe: failed to parse 'mode=%s'\n", opt);
	} else
		conf_mode = MODE_L2;

	conf_relay = conf_get_opt("ipoe", "relay");

	opt = conf_get_opt("ipoe", "relay-timeout");
	if (opt && atoi(opt) > 0)
		conf_relay_timeout = atoi(opt);
	else
		conf_relay_timeout = 3;

	opt = conf_get_opt("ipoe", "relay-retransmit");
	if (opt && atoi(opt) > 0)
		conf_relay_retransmit = atoi(opt);
	else
		conf_relay_retransmit = 3;

	opt = conf_get_opt("ipoe", "agent-remote-id");
	if (opt)
		conf_agent_remote_id = opt;
	else
		conf_agent_remote_id = NULL;

	opt = conf_get_opt("ipoe", "link-selection");
	if (opt && inet_pton(AF_INET, opt, &dummy) > 0)
		conf_link_selection = opt;

	opt = conf_get_opt("ipoe", "ipv6");
	if (opt)
		conf_ipv6 = atoi(opt);
	else
		conf_ipv6 = 0;

	opt = conf_get_opt("ipoe", "noauth");
	if (!opt)
		opt = conf_get_opt("auth", "noauth");
	if (opt)
		conf_noauth = atoi(opt);
	else
		conf_noauth = 0;

	conf_dhcpv4 = 0;
	conf_up = 0;

	list_for_each_entry(opt1, &s->items, entry) {
		if (strcmp(opt1->name, "start"))
			continue;
		if (!strcmp(opt1->val, "dhcpv4"))
			conf_dhcpv4 = 1;
		else if (!strcmp(opt1->val, "up"))
			conf_up = 1;
		else if (!strcmp(opt1->val, "auto"))
			conf_auto = 1;
		else
			log_error("ipoe: failed to parse 'start=%s'\n", opt1->val);
	}

	if (!conf_dhcpv4 && !conf_up)
		conf_dhcpv4 = 1;

	opt = conf_get_opt("ipoe", "proto");
	if (opt && atoi(opt) > 0)
		conf_proto = atoi(opt);
	else
		conf_proto = 3;

	opt = conf_get_opt("ipoe", "vlan-timeout");
	if (opt && atoi(opt) > 0)
		conf_vlan_timeout = atoi(opt);
	else
		conf_vlan_timeout = 60;

	opt = conf_get_opt("ipoe", "offer-timeout");
	if (opt && atoi(opt) > 0)
		conf_offer_timeout = atoi(opt);
	else
		conf_offer_timeout = 10;

	conf_ip_pool = conf_get_opt("ipoe", "ip-pool");
	conf_ipv6_pool = conf_get_opt("ipoe", "ipv6-pool");
	conf_dpv6_pool = conf_get_opt("ipoe", "ipv6-pool-delegate");
	conf_l4_redirect_pool = conf_get_opt("ipoe", "l4-redirect-ip-pool");

	conf_vlan_name = conf_get_opt("ipoe", "vlan-name");
	if (!conf_vlan_name)
		conf_vlan_name = "%I.%N";

	opt = conf_get_opt("ipoe", "ip-unnumbered");
	if (opt)
		conf_ip_unnumbered = atoi(opt);
	else
		conf_ip_unnumbered = 1;

	opt = conf_get_opt("ipoe", "idle-timeout");
	if (opt)
		conf_idle_timeout = atoi(opt);
	else
		conf_idle_timeout = 0;

	opt = conf_get_opt("ipoe", "session-timeout");
	if (opt)
		conf_session_timeout = atoi(opt);
	else
		conf_session_timeout = 0;

	opt = conf_get_opt("ipoe", "soft-terminate");
	if (opt)
		conf_soft_terminate = atoi(opt);
	else
		conf_soft_terminate = 0;

	opt = conf_get_opt("ipoe", "check-mac-change");
	if (opt)
		conf_check_mac_change = atoi(opt);
	else
		conf_check_mac_change = 1;

	opt = conf_get_opt("ipoe", "calling-sid");
	if (opt) {
		if (!strcmp(opt, "mac"))
			conf_calling_sid = SID_MAC;
		else if (!strcmp(opt, "ip"))
			conf_calling_sid = SID_IP;
		else
			log_error("ipoe: failed to parse 'calling-sid=%s'\n", opt);
	} else
		conf_calling_sid = SID_MAC;

	opt = conf_get_opt("ipoe", "weight");
	if (opt)
		conf_weight = atoi(opt);
	else
		conf_weight = 0;

	opt = conf_get_opt("ipoe", "check-ip");
	if (!opt)
		opt = conf_get_opt("common", "check-ip");
	if (opt && atoi(opt) >= 0)
		conf_check_exists = atoi(opt) > 0;

#ifdef RADIUS
	if (triton_module_loaded("radius"))
		load_radius_attrs();
#endif

	parse_offer_delay(conf_get_opt("ipoe", "offer-delay"));

	load_interfaces(s);
	load_vlan_mon(s);
	load_gw_addr(s);
	load_local_nets(s);
}

static struct triton_context_t l4_redirect_ctx = {
	.close = l4_redirect_ctx_close,
};

static struct triton_timer_t l4_redirect_timer = {
	.expire = l4_redirect_list_timer,
};

static void ipoe_init(void)
{
	ses_pool = mempool_create(sizeof(struct ipoe_session));
	disc_item_pool = mempool_create(sizeof(struct disc_item));
	arp_item_pool = mempool_create(sizeof(struct arp_item));
	req_item_pool = mempool_create(sizeof(struct request_item));
	uc_pool = mempool_create(sizeof(struct unit_cache));

	triton_context_register(&l4_redirect_ctx, NULL);
	triton_context_wakeup(&l4_redirect_ctx);

	load_config();

	if (conf_l4_redirect_ipset)
		ipset_flush(conf_l4_redirect_ipset);

	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");
	cli_show_ses_register("ipoe-type", "IPoE session type", print_session_type);

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	}
#endif

	connlimit_loaded = triton_module_loaded("connlimit");
	radius_loaded = triton_module_loaded("radius");
}

DEFINE_INIT(52, ipoe_init);
