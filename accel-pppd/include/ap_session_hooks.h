/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#ifndef AP_SESSION_HOOKS_H
#define AP_SESSION_HOOKS_H

#include <netinet/in.h>

#include "list.h"

struct ap_session;
/*
 * Hooks are presented mostly for VPP and are designed
 * to present the VPP routine as a separate plugin.
 */
struct ap_session_hooks_t {
	int (*get)(); /* 0 - OK, called to "init" hooks if required, currently called by pppoe server on server start */
	void (*put)(); /* deinit the hooks */

	/* init hook per session - on session create, init hook's "private" structures etc. */
	int (*session_hook_init)(struct ap_session *ses);
	/* per session - on session free, deinit hook's structures etc. */
	void (*session_hook_deinit)(struct ap_session *ses);

	/*
	 * hooks to create a proper session interface
	 * in case of "non-dev" ppp(/dev/ppp)
	 * called from ap_session_activate()
	 */
	int (*pppoe_create_session_interface)(struct ap_session *ses);
	int (*pppoe_terminate)(struct ap_session *ses, int hard);

	/* route related hooks called from accel_iputils */
	int (*ipaddr_add)(struct ap_session *ses, int ifindex, in_addr_t addr, int mask);
	int (*ipaddr_add_peer)(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer_addr);
	int (*ipaddr_del)(struct ap_session *ses, int ifindex, in_addr_t addr, int mask);
	int (*ipaddr_del_peer)(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer);
	int (*iproute_add)(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name);
	int (*iproute_del)(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name);
	int (*ip6route_add)(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name);
	int (*ip6route_del)(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name);
	int (*ip6addr_add)(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len);
	int (*ip6addr_add_peer)(struct ap_session *ses, int ifindex, struct in6_addr *addr, struct in6_addr *peer_addr);
	int (*ip6addr_del)(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len);

	/* limiter related, check shaper/limiter.c */
	int (*install_limiter)(struct ap_session *ses, int down_speed, int down_burst, int up_speed, int up_burst);
	int (*remove_limiter)(struct ap_session *ses);

	/* flags */
	uint8_t is_non_dev_ppp:1; /* do not create the ppp device with /dev/ppp */
	uint8_t is_non_socket_dhcpv6_nd:1; /* do not create a sockets for DHCPv6 and ND - use chanel socket */

	/**/
	struct list_head entry;
	const char *hooks_name; /* g.e. "vpp" */
};

int ap_session_hooks_register(struct ap_session_hooks_t *h);
void ap_session_hooks_unregister(struct ap_session_hooks_t *h);
struct ap_session_hooks_t * ap_session_hooks_find(const char *name);



#endif /* AP_SESSION_HOOKS_H */