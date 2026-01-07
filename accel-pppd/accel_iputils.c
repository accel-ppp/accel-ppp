/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include "ap_session.h"
#include "iputils.h"

#include "accel_iputils.h"

/* TODO: refactore & redesign */

__export int accel_ipaddr_add(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->ipaddr_add)
		return ses->hooks->ipaddr_add(ses, ifindex, addr, mask);
	else
#endif /* HAVE_SESSION_HOOKS */
		return ipaddr_add(ifindex, addr, mask);
}

__export int accel_ipaddr_add_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer_addr)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->ipaddr_add_peer)
		return ses->hooks->ipaddr_add_peer(ses, ifindex, addr, peer_addr);
	else
#endif /* HAVE_SESSION_HOOKS */
		return ipaddr_add_peer(ifindex, addr, peer_addr);
}

__export int accel_ipaddr_del(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->ipaddr_del)
		return ses->hooks->ipaddr_del(ses, ifindex, addr, mask);
	else
#endif /* HAVE_SESSION_HOOKS */
		return ipaddr_del(ifindex, addr, mask);
}

__export int accel_ipaddr_del_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->ipaddr_del_peer)
		return ses->hooks->ipaddr_del_peer(ses, ifindex, addr, peer);
	else
#endif /* HAVE_SESSION_HOOKS */
		return ipaddr_del_peer(ifindex, addr, peer);
}

__export int accel_iproute_add(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->iproute_add)
		return ses->hooks->iproute_add(ses, ifindex, src, dst, gw, proto, mask, prio, vrf_name);
	else
#endif /* HAVE_SESSION_HOOKS */
		return iproute_add(ifindex, src, dst, gw, proto, mask, prio, vrf_name);
}

__export int accel_iproute_del(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->iproute_del)
		return ses->hooks->iproute_del(ses, ifindex, src, dst, gw, proto, mask, prio, vrf_name);
	else
#endif /* HAVE_SESSION_HOOKS */
		return iproute_del(ifindex, src, dst, gw, proto, mask, prio, vrf_name);
}

__export int accel_ip6route_add(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->ip6route_add)
		return ses->hooks->ip6route_add(ses, ifindex, dst, pref_len, gw, proto, prio, vrf_name);
	else
#endif /* HAVE_SESSION_HOOKS */
		return ip6route_add(ifindex, dst, pref_len, gw, proto, prio, vrf_name);
}

__export int accel_ip6route_del(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->ip6route_del)
		return ses->hooks->ip6route_del(ses, ifindex, dst, pref_len, gw, proto, prio, vrf_name);
	else
#endif /* HAVE_SESSION_HOOKS */
		return ip6route_del(ifindex, dst, pref_len, gw, proto, prio, vrf_name);
}

__export int accel_ip6addr_add(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->ip6addr_add)
		return ses->hooks->ip6addr_add(ses, ifindex, addr, prefix_len);
	else
#endif /* HAVE_SESSION_HOOKS */
		return ip6addr_add(ifindex, addr, prefix_len);
}

__export int accel_ip6addr_add_peer(struct ap_session *ses, int ifindex, struct in6_addr *addr, struct in6_addr *peer_addr)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->ip6addr_add_peer)
		return ses->hooks->ip6addr_add_peer(ses, ifindex, addr, peer_addr);
	else
#endif /* HAVE_SESSION_HOOKS */
		return ip6addr_add_peer(ifindex, addr, peer_addr);
}

__export int accel_ip6addr_del(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
#ifdef HAVE_SESSION_HOOKS
	if (ses->hooks && ses->hooks->ip6addr_del)
		return ses->hooks->ip6addr_del(ses, ifindex, addr, prefix_len);
	else
#endif /* HAVE_SESSION_HOOKS */
		return ip6addr_del(ifindex, addr, prefix_len);
}