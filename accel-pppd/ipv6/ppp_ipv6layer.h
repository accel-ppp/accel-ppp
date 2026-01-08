/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#ifndef VPPIPV6LAYER_H
#define VPPIPV6LAYER_H

void ipv6layer_unit_enable_nd(struct ap_session *ses, int (*nd_recv)(struct ap_session *, const void *, size_t, struct in6_addr *));
void ipv6layer_unit_disable_nd(struct ap_session *ses);

void ipv6layer_unit_enable_dhcpv6(struct ap_session *ses, int (*dhcpv6_recv)(struct ap_session *, const void *, size_t, struct in6_addr *, unsigned short));
void ipv6layer_unit_disable_dhcpv6(struct ap_session *ses);

void ipv6layer_unit_icmpv6_send(struct ap_session *ses, const void *buf, size_t size, struct sockaddr *addr, socklen_t addrlen);
void ipv6layer_unit_dhcpv6_send(struct ap_session *ses, const void *buf, size_t size, struct sockaddr *addr, socklen_t addrlen);

#endif /* VPPIPV6LAYER_H */