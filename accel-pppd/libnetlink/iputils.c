#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <pthread.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>
#ifdef HAVE_VRF
#include <linux/if_link.h>
#endif
//#include <linux/if_addr.h>
//#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>

#include "log.h"

#include "libnetlink.h"
#include "iputils.h"
#include "ap_net.h"
#ifdef HAVE_VRF
#include "rt_names.h"
#endif

#ifdef ACCEL_DP
#define _malloc(x) malloc(x)
#define _free(x) free(x)
#include "init.h"
#include "common.h"
#else
#include "triton.h"
#include "memdebug.h"
#endif

struct arg
{
	iplink_list_func func;
	void *arg;
};

static int store_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtattr *tb2[IFLA_MAX + 1];
	struct arg *a = arg;
	int vid = 0, iflink = 0;

	if (n->nlmsg_type != RTM_NEWLINK)
		return 0;

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
		return -1;

	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));

	if (tb[IFLA_IFNAME] == NULL)
		return 0;

	if (tb[IFLA_LINKINFO]) {
		parse_rtattr_nested(tb2, IFLA_MAX, tb[IFLA_LINKINFO]);
		if (tb2[IFLA_INFO_KIND] && !strcmp(RTA_DATA(tb2[IFLA_INFO_KIND]), "vlan")) {
			parse_rtattr_nested(tb2, IFLA_MAX, tb2[IFLA_INFO_DATA]);
			vid = *(uint16_t *)RTA_DATA(tb2[IFLA_VLAN_ID]);
		}
	}

	if (tb[IFLA_LINK])
		iflink = *(int *)RTA_DATA(tb[IFLA_LINK]);
	//printf("%i %s\n", ifi->ifi_index, RTA_DATA(tb[IFLA_IFNAME]));

	return a->func(ifi->ifi_index, ifi->ifi_flags, RTA_DATA(tb[IFLA_IFNAME]), iflink, vid, a->arg);
}

int __export iplink_list(iplink_list_func func, void *arg)
{
	struct rtnl_handle rth;
	struct arg a = { .func = func, .arg = arg };

	if (rtnl_open(&rth, 0)) {
		log_emerg("iplink: cannot open rtnetlink\n");
		return -1;
	}

	if (rtnl_wilddump_request(&rth, AF_PACKET, RTM_GETLINK) < 0) {
		log_emerg("iplink: cannot send dump request\n");
		goto out_err;
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, &a, NULL, NULL) < 0) {
		log_emerg("iplink: dump terminated\n");
		goto out_err;
	}

	rtnl_close(&rth);

	return 0;

out_err:
	rtnl_close(&rth);

	return -1;
}

int __export iplink_get_stats(int ifindex, struct rtnl_link_stats64 *stats)
{
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[4096];
	} req;
	struct ifinfomsg *ifi;
	int len;
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtnl_handle *rth = net->rtnl_get();
	int r = -1;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_GETLINK;
	req.i.ifi_family = AF_PACKET;
	req.i.ifi_index = ifindex;

	if (rtnl_talk(rth, &req.n, 0, 0, &req.n, NULL, NULL, 0) < 0)
		goto out;

	if (req.n.nlmsg_type != RTM_NEWLINK)
		goto out;

	ifi = NLMSG_DATA(&req.n);

	len = req.n.nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		goto out;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_STATS64]) {
		memcpy(stats, RTA_DATA(tb[IFLA_STATS64]), sizeof(*stats));
		r = 0;
	}

out:
	net->rtnl_put(rth);

	return r;
}

int __export iplink_set_mtu(int ifindex, int mtu)
{
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[1024];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 1024);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_SETLINK;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_index = ifindex;

	addattr_l(&req.n, 1024, IFLA_MTU, &mtu, 4);

	r = rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0);

	net->rtnl_put(rth);

	return r;
}

int __export iplink_vlan_add(const char *ifname, int ifindex, int vid)
{
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[4096];
	} req;
	struct rtattr *linkinfo, *data;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;

	addattr_l(&req.n, 4096, IFLA_LINK, &ifindex, 4);
	addattr_l(&req.n, 4096, IFLA_IFNAME, ifname, strlen(ifname));

	linkinfo = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, 4096, IFLA_LINKINFO, NULL, 0);
	addattr_l(&req.n, 4096, IFLA_INFO_KIND, "vlan", 4);

	data = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, 4096, IFLA_INFO_DATA, NULL, 0);
	uint16_t vid_16b = (uint16_t)vid;
	addattr_l(&req.n, 4096, IFLA_VLAN_ID, &vid_16b, 2);
	data->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)data;

	linkinfo->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)linkinfo;

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export iplink_vlan_del(int ifindex)
{
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[4096];
	} req;
	struct rtattr *linkinfo;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELLINK;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_index = ifindex;

	linkinfo = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, 4096, IFLA_LINKINFO, NULL, 0);
	addattr_l(&req.n, 4096, IFLA_INFO_KIND, "vlan", 4);

	/*data = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, 4096, IFLA_VLAN_ID, &vid, 2);
	data->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)data;*/

	linkinfo->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)linkinfo;

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export iplink_vlan_get_vid(int ifindex, int *iflink)
{
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[4096];
	} req;
	struct ifinfomsg *ifi;
	int len;
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_GETLINK;
	req.i.ifi_family = AF_PACKET;
	req.i.ifi_index = ifindex;

	if (rtnl_talk(rth, &req.n, 0, 0, &req.n, NULL, NULL, 0) < 0)
		goto out;

	if (req.n.nlmsg_type != RTM_NEWLINK)
		goto out;

	ifi = NLMSG_DATA(&req.n);

	len = req.n.nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		goto out;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	if (!tb[IFLA_LINKINFO])
		goto out;

	if (iflink && tb[IFLA_LINK])
		*iflink = *(int *)RTA_DATA(tb[IFLA_LINK]);

	parse_rtattr_nested(tb, IFLA_MAX, tb[IFLA_LINKINFO]);

	if (!tb[IFLA_INFO_KIND] || strcmp(RTA_DATA(tb[IFLA_INFO_KIND]), "vlan"))
		goto out;

	parse_rtattr_nested(tb, IFLA_MAX, tb[IFLA_INFO_DATA]);
	r = *(uint16_t *)RTA_DATA(tb[IFLA_VLAN_ID]);

out:
	net->rtnl_put(rth);

	return r;
}


int __export ipaddr_add(int ifindex, in_addr_t addr, int mask)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWADDR;
	req.i.ifa_family = AF_INET;
	req.i.ifa_index = ifindex;
	req.i.ifa_prefixlen = mask;

	addattr32(&req.n, sizeof(req), IFA_LOCAL, addr);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export ipaddr_add_peer(int ifindex, in_addr_t addr, in_addr_t peer_addr)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWADDR;
	req.i.ifa_family = AF_INET;
	req.i.ifa_index = ifindex;
	req.i.ifa_prefixlen = 32;

	addattr32(&req.n, sizeof(req), IFA_LOCAL, addr);
	addattr32(&req.n, sizeof(req), IFA_ADDRESS, peer_addr);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export ipaddr_del(int ifindex, in_addr_t addr, int mask)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELADDR;
	req.i.ifa_family = AF_INET;
	req.i.ifa_index = ifindex;
	req.i.ifa_prefixlen = mask;

	addattr32(&req.n, sizeof(req), IFA_LOCAL, addr);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export ipaddr_del_peer(int ifindex, in_addr_t addr, in_addr_t peer)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELADDR;
	req.i.ifa_family = AF_INET;
	req.i.ifa_index = ifindex;
	req.i.ifa_prefixlen = 32;

	addattr32(&req.n, sizeof(req), IFA_LOCAL, addr);
	addattr32(&req.n, sizeof(req), IFA_ADDRESS, peer);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

#ifdef HAVE_VRF
uint32_t ipvrf_get_table(const char *vrf_name)
{
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	struct rtattr *tb[IFLA_MAX+1];
	struct rtattr *li[IFLA_INFO_MAX+1];
	struct rtattr *vrf_attr[IFLA_VRF_MAX + 1];
	struct ifinfomsg *ifi;
	int len;
	uint32_t tb_id = RT_TABLE_MAIN;

	log_ppp_info2("utils: getting route table for %s\n", vrf_name);

	if (!vrf_name)
		return tb_id;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETLINK;
	req.i.ifi_family = AF_UNSPEC;

	addattr_l(&req.n, 4096, IFLA_IFNAME, vrf_name, strlen(vrf_name));

	if (rtnl_talk(rth, &req.n, 0, 0, &req.n, NULL, NULL, 0) < 0) {
    if (errno == ENODEV && !strncmp(vrf_name, "default", strlen("default")))
			if (rtnl_rttable_a2n(&tb_id, "main"))
				log_ppp_error(
					"BUG: route table \"main\" not found.\n");
		return tb_id;
	}

	ifi = NLMSG_DATA(&req.n);

	len = req.n.nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		goto out;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	if (!tb[IFLA_LINKINFO])
		goto out;

	parse_rtattr_nested(li, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

	if (!li[IFLA_INFO_KIND] || !li[IFLA_INFO_DATA])
		goto out;

	if (strncmp(RTA_DATA(li[IFLA_INFO_KIND]), "vrf", strlen("vrf")))
		goto out;

	parse_rtattr_nested(vrf_attr, IFLA_VRF_MAX, li[IFLA_INFO_DATA]);
	if (vrf_attr[IFLA_VRF_TABLE])
		tb_id = *(__u32 *)RTA_DATA(vrf_attr[IFLA_VRF_TABLE]);

	if (!tb_id)
		log_ppp_error("BUG: VRF %s is missing table id\n", vrf_name);

out:
	return tb_id;
}
#endif

int __export iproute_add(int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct rtmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;
	uint32_t rt_table = RT_TABLE_MAIN;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

#ifdef HAVE_VRF
	rt_table = ipvrf_get_table(vrf_name);
#endif

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWROUTE;
	req.i.rtm_family = AF_INET;
	req.i.rtm_table = rt_table;
	req.i.rtm_scope = gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
	req.i.rtm_protocol = proto;
	req.i.rtm_type = RTN_UNICAST;
	req.i.rtm_dst_len = mask;

	if (ifindex)
		addattr32(&req.n, sizeof(req), RTA_OIF, ifindex);
	if (src)
		addattr32(&req.n, sizeof(req), RTA_PREFSRC, src);
	if (gw)
		addattr32(&req.n, sizeof(req), RTA_GATEWAY, gw);
	if (prio)
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, prio);
	addattr32(&req.n, sizeof(req), RTA_DST, dst);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export iproute_del(int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct rtmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;
	uint32_t rt_table = RT_TABLE_MAIN;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

#ifdef HAVE_VRF
	rt_table = ipvrf_get_table(vrf_name);
#endif

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELROUTE;
	req.i.rtm_family = AF_INET;
	req.i.rtm_table = rt_table;
	req.i.rtm_scope = gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
	req.i.rtm_protocol = proto;
	req.i.rtm_type = RTN_UNICAST;
	req.i.rtm_dst_len = mask;

	if (ifindex)
		addattr32(&req.n, sizeof(req), RTA_OIF, ifindex);
	if (src)
		addattr32(&req.n, sizeof(req), RTA_PREFSRC, src);
	if (gw)
		addattr32(&req.n, sizeof(req), RTA_GATEWAY, gw);
	if (prio)
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, prio);
	addattr32(&req.n, sizeof(req), RTA_DST, dst);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export ip6route_add(int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct rtmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;
	uint32_t rt_table = RT_TABLE_MAIN;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

#ifdef HAVE_VRF
	rt_table = ipvrf_get_table(vrf_name);
#endif

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWROUTE;
	req.i.rtm_family = AF_INET6;
	req.i.rtm_table = rt_table;
	req.i.rtm_scope = RT_SCOPE_UNIVERSE;
	req.i.rtm_protocol = proto;
	req.i.rtm_type = RTN_UNICAST;
	req.i.rtm_dst_len = pref_len;

	addattr_l(&req.n, sizeof(req), RTA_DST, dst, sizeof(*dst));
	if (ifindex)
		addattr32(&req.n, sizeof(req), RTA_OIF, ifindex);
	if (gw)
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, gw, sizeof(*gw));
	if (prio)
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, prio);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export ip6route_del(int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct rtmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;
	uint32_t rt_table = RT_TABLE_MAIN;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

#ifdef HAVE_VRF
	rt_table = ipvrf_get_table(vrf_name);
#endif

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELROUTE;
	req.i.rtm_family = AF_INET6;
	req.i.rtm_table = rt_table;
	req.i.rtm_scope = RT_SCOPE_UNIVERSE;
	req.i.rtm_protocol = proto;
	req.i.rtm_type = RTN_UNICAST;
	req.i.rtm_dst_len = pref_len;

	addattr_l(&req.n, sizeof(req), RTA_DST, dst, sizeof(*dst));
	if (ifindex)
		addattr32(&req.n, sizeof(req), RTA_OIF, ifindex);
	if (gw)
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, gw, sizeof(*gw));
	if (prio)
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, prio);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export ip6addr_add(int ifindex, struct in6_addr *addr, int prefix_len)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWADDR;
	req.i.ifa_family = AF_INET6;
	req.i.ifa_index = ifindex;
	req.i.ifa_prefixlen = prefix_len;
	req.i.ifa_flags = IFA_F_NODAD;

	addattr_l(&req.n, sizeof(req), IFA_ADDRESS, addr, 16);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export ip6addr_add_peer(int ifindex, struct in6_addr *addr, struct in6_addr *peer)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWADDR;
	req.i.ifa_family = AF_INET6;
	req.i.ifa_index = ifindex;
	req.i.ifa_prefixlen = 128;
	req.i.ifa_flags = IFA_F_NODAD;

	addattr_l(&req.n, sizeof(req), IFA_LOCAL, addr, 16);
	addattr_l(&req.n, sizeof(req), IFA_ADDRESS, peer, 16);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export ip6addr_del(int ifindex, struct in6_addr *addr, int prefix_len)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELADDR;
	req.i.ifa_family = AF_INET6;
	req.i.ifa_index = ifindex;
	req.i.ifa_prefixlen = prefix_len;

	addattr_l(&req.n, sizeof(req), IFA_ADDRESS, addr, 16);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

in_addr_t __export iproute_get(in_addr_t dst, in_addr_t *gw)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[4096];
	} req;
	struct rtmsg *r;
	struct rtattr *tb[RTA_MAX+1];
	int len;
	in_addr_t res = 0;
	struct rtnl_handle *rth = net->rtnl_get();

	if (gw)
		*gw = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = AF_INET;
	req.r.rtm_table = 0;
	req.r.rtm_protocol = 0;
	req.r.rtm_scope = 0;
	req.r.rtm_type = 0;
	req.r.rtm_tos = 0;
	req.r.rtm_src_len = 0;
	req.r.rtm_dst_len = 32;

	addattr32(&req.n, 4096, RTA_DST, dst);

	if (rtnl_talk(rth, &req.n, 0, 0, &req.n, NULL, NULL, 0) < 0) {
		log_error("failed to detect route to server\n");
		goto out;
	}

	r = NLMSG_DATA(&req.n);
	len = req.n.nlmsg_len;

	if (req.n.nlmsg_type != RTM_NEWROUTE) {
		log_error("failed to detect route to server (wrong netlink message type)");
		goto out;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		log_error("failed to detect route to server (wrong netlink message length)");
		goto out;
	}

	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

	if (tb[RTA_PREFSRC])
		res = *(uint32_t *)RTA_DATA(tb[RTA_PREFSRC]);

	if (gw && tb[RTA_GATEWAY])
		*gw = *(uint32_t *)RTA_DATA(tb[RTA_GATEWAY]);

out:
	net->rtnl_put(rth);

	return res;
}

int __export iprule_add(uint32_t addr, int table)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWRULE;
	req.i.rtm_family = AF_INET;
	req.i.rtm_table = table < 256 ? table : RT_TABLE_UNSPEC;
	req.i.rtm_scope = RT_SCOPE_UNIVERSE;
	req.i.rtm_protocol = RTPROT_BOOT;
	req.i.rtm_type = RTN_UNICAST;
	req.i.rtm_src_len = 32;

	addattr32(&req.n, sizeof(req), FRA_SRC, addr);
	if (table >= 256)
		addattr32(&req.n, sizeof(req), FRA_TABLE, table);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}

int __export iprule_del(uint32_t addr, int table)
{
	struct ipaddr_req {
		struct nlmsghdr n;
		struct rtmsg i;
		char buf[4096];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELRULE;
	req.i.rtm_family = AF_INET;
	req.i.rtm_table = table < 256 ? table : RT_TABLE_UNSPEC;
	req.i.rtm_scope = RT_SCOPE_UNIVERSE;
	req.i.rtm_protocol = RTPROT_BOOT;
	req.i.rtm_type = RTN_UNICAST;
	req.i.rtm_src_len = 32;

	addattr32(&req.n, sizeof(req), FRA_SRC, addr);
	if (table >= 256)
		addattr32(&req.n, sizeof(req), FRA_TABLE, table);

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
}
