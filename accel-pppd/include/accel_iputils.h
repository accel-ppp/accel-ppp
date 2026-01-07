/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#ifndef ACCEL_IPUTILS_H
#define ACCEL_IPUTILS_H

int accel_ipaddr_add(struct ap_session *ses, int ifindex, in_addr_t addr, int mask);
int accel_ipaddr_add_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer_addr);
int accel_ipaddr_del(struct ap_session *ses, int ifindex, in_addr_t addr, int mask);
int accel_ipaddr_del_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer);
int accel_iproute_add(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name);
int accel_iproute_del(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name);
int accel_ip6route_add(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name);
int accel_ip6route_del(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name);
int accel_ip6addr_add(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len);
int accel_ip6addr_add_peer(struct ap_session *ses, int ifindex, struct in6_addr *addr, struct in6_addr *peer_addr);
int accel_ip6addr_del(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len);

#endif /* ACCEL_IPUTILS_H */