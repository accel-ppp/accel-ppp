#ifndef __IPLINK_H
#define __IPLINK_H

#include <linux/if_link.h>
#include <netinet/in.h>
#include <stdint.h>
#include <config.h>

typedef int (*iplink_list_func)(int index, int flags, const char *name, int iflink, int vid, void *arg);

int iplink_list(iplink_list_func func, void *arg);
int iplink_get_stats(int ifindex, struct rtnl_link_stats64 *stats);
int iplink_set_mtu(int ifindex, int mtu);

int iplink_vlan_add(const char *ifname, int ifindex, int vid);
int iplink_vlan_del(int ifindex);
int iplink_vlan_get_vid(int ifindex, int *iflink);

int ipaddr_add(int ifindex, in_addr_t addr, int mask);
int ipaddr_add_peer(int ifindex, in_addr_t addr, in_addr_t peer_addr);
int ipaddr_del(int ifindex, in_addr_t addr, int mask);
int ipaddr_del_peer(int ifindex, in_addr_t addr, in_addr_t peer);

#ifdef HAVE_VRF
int iproute_add(int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name);
int iproute_del(int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name);
#else
int iproute_add(int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio);
int iproute_del(int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio);
#endif
in_addr_t iproute_get(in_addr_t dst, in_addr_t *gw);

#ifdef HAVE_VRF
int ip6route_add(int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name);
int ip6route_del(int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name);
#else
int ip6route_add(int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio);
int ip6route_del(int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio);
#endif
int ip6addr_add(int ifindex, struct in6_addr *addr, int prefix_len);
int ip6addr_add_peer(int ifindex, struct in6_addr *addr, struct in6_addr *peer_addr);
int ip6addr_del(int ifindex, struct in6_addr *addr, int prefix_len);

int iprule_add(uint32_t addr, int table);
int iprule_del(uint32_t addr, int table);
#endif
