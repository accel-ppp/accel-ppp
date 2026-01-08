/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>

#include "ppp.h"
#include "triton.h"
#include "ap_session.h"
#include "ipdb.h"
#include "log.h"

static const unsigned short sc_dhcpv6_client_port = 546;
static const unsigned short sc_dhcpv6_serv_port = 547;

void ppp_unit_ipv6_recv(struct ppp_handler_t *h);
void ppp_unit_ipv6_recv_proto_rej(struct ppp_handler_t *h);

void ipv6layer_add_unit_layer(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);

	ppp->vpp_ipv6_hnd.proto = PPP_IPV6;
	ppp->vpp_ipv6_hnd.recv = ppp_unit_ipv6_recv;
	ppp->vpp_ipv6_hnd.recv_proto_rej = ppp_unit_ipv6_recv_proto_rej;

	ppp_register_unit_handler(ppp, &ppp->vpp_ipv6_hnd);
}

void ipv6layer_del_unit_layer(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	ppp_unregister_handler(ppp, &ppp->vpp_ipv6_hnd);
}

__export void ipv6layer_unit_enable_nd(struct ap_session *ses, int (*nd_recv)(struct ap_session *, const void *, size_t, struct in6_addr *))
{
	ses->ppp_ipv6_nd_recv = nd_recv;

	/* If there is no ppp_ipv6_dhcpv6_recv - then the layer is not installed and needs to be installed */
	if (ses->ppp_ipv6_dhcpv6_recv == NULL)
		ipv6layer_add_unit_layer(ses);
}

__export void ipv6layer_unit_disable_nd(struct ap_session *ses)
{
	ses->ppp_ipv6_nd_recv = NULL;

	if (ses->ppp_ipv6_dhcpv6_recv == NULL)
		ipv6layer_del_unit_layer(ses);
}

__export void ipv6layer_unit_enable_dhcpv6(struct ap_session *ses, int (*dhcpv6_recv)(struct ap_session *, const void *, size_t, struct in6_addr *, unsigned short))
{
	ses->ppp_ipv6_dhcpv6_recv = dhcpv6_recv;

	/* If there is no ppp_ipv6_nd_recv - then the layer is not installed and needs to be installed */
	if (ses->ppp_ipv6_nd_recv == NULL)
		ipv6layer_add_unit_layer(ses);
}

__export void ipv6layer_unit_disable_dhcpv6(struct ap_session *ses)
{
	ses->ppp_ipv6_dhcpv6_recv = NULL;

	if (ses->ppp_ipv6_nd_recv == NULL)
		ipv6layer_del_unit_layer(ses);
}

static inline uint32_t partial_csum(uint32_t sum, const uint16_t *buf, int len)
{
	for (; len > 1;) {
		sum += *buf++;
		len -= 2;
	}

	if (len == 1) {
		sum += *((const uint8_t *)buf);
	}

	return sum;
}

static inline uint16_t finish_csum(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (uint16_t)(~sum);
}

static inline uint16_t ipv6_calc_csum(uint8_t proto, const void *buf, uint32_t len,
							   struct in6_addr *src, struct in6_addr *dst)
{
	uint32_t sum = 0;
	struct
	{
		struct in6_addr src;
		struct in6_addr dst;
		uint32_t plen;
		uint8_t zeros[3];
		uint8_t next_header;
	} pseudo_hdr;

	memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));
	pseudo_hdr.src = *src;
	pseudo_hdr.dst = *dst;
	pseudo_hdr.plen = htonl(len);
	pseudo_hdr.next_header = proto;

	sum = partial_csum(sum, (const uint16_t *)&pseudo_hdr, sizeof(pseudo_hdr));
	sum = partial_csum(sum, (const uint16_t *)buf, len);

	return finish_csum(sum);
}

__export void ipv6layer_unit_icmpv6_send(struct ap_session *ses, const void *buf, size_t size, struct sockaddr *addr, socklen_t addrlen)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	size_t send_size = size + sizeof(struct ip6_hdr) + 2;
	unsigned char send_buf[2048];
	struct ip6_hdr *ip6 = (struct ip6_hdr *)(send_buf + 2);
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(ip6 + 1);

	if (send_size > 2048) {
		log_warn("VPP_IPV6_ICMP: Issue while sending ICMPv6 packet - the packet is too big - size: %ld", send_size);
		return;
	}

	*(unsigned short *)(send_buf) = htons(PPP_IPV6);

	/* fill ipv6 */
	memset(ip6, 0, sizeof(*ip6));
	ip6->ip6_flow = htonl(0x60000000);
	ip6->ip6_plen = htons(size);
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 0xff;
	memcpy(&ip6->ip6_dst, &((struct sockaddr_in6 *)(addr))->sin6_addr, sizeof(struct in6_addr));
	if (ses->ipv6 != NULL) {
		ip6->ip6_src.s6_addr32[0] = htonl(0xfe800000);
		*(uint64_t *)(ip6->ip6_src.s6_addr + 8) = ses->ipv6->intf_id;
	}

	memcpy(icmp6, buf, size);

	/* calculate crc */
	icmp6->icmp6_cksum = ipv6_calc_csum(IPPROTO_ICMPV6, icmp6, size, &ip6->ip6_src, &ip6->ip6_dst);

	ppp_unit_send(ppp, send_buf, send_size);
}

__export void ipv6layer_unit_dhcpv6_send(struct ap_session *ses, const void *buf, size_t size, struct sockaddr *addr, socklen_t addrlen)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	size_t send_size = size + sizeof(struct udphdr) + sizeof(struct ip6_hdr) + 2;
	unsigned char send_buf[2048];
	struct ip6_hdr *ip6 = (struct ip6_hdr *)(send_buf + 2);
	struct udphdr *udp = (struct udphdr *)(ip6 + 1);

	if (send_size > 2048) {
		log_warn("VPP_IPV6_DHCP: Issue while sending DHCPv6 packet - the packet is too big - size: %ld", send_size);
		return;
	}

	*(unsigned short *)(send_buf) = htons(PPP_IPV6);

	/* fill ipv6 */
	memset(ip6, 0, sizeof(*ip6));
	ip6->ip6_flow = htonl(0x60000000);
	ip6->ip6_plen = htons(size + sizeof(struct udphdr));
	ip6->ip6_nxt = IPPROTO_UDP;
	ip6->ip6_hlim = 0x01;
	memcpy(&ip6->ip6_dst, &((struct sockaddr_in6 *)(addr))->sin6_addr, sizeof(struct in6_addr));
	if (ses->ipv6 != NULL) {
		ip6->ip6_src.s6_addr32[0] = htonl(0xfe800000);
		*(uint64_t *)(ip6->ip6_src.s6_addr + 8) = ses->ipv6->intf_id;
	}

	/* fill udp */
	udp->source = htons(sc_dhcpv6_serv_port);
	udp->dest = ((struct sockaddr_in6 *)(addr))->sin6_port;
	udp->len = htons(size + sizeof(struct udphdr));
	udp->check = 0;

	memcpy(udp + 1, buf, size);

	udp->check = ipv6_calc_csum(IPPROTO_UDP, udp, size + sizeof(struct udphdr), &ip6->ip6_src, &ip6->ip6_dst);

	ppp_unit_send(ppp, send_buf, send_size);
}

void ppp_unit_ipv6_recv(struct ppp_handler_t *ppp_h)
{
	struct ip6_hdr *ip6 = NULL;
	struct ppp_t *ppp = container_of(ppp_h, typeof(*ppp), vpp_ipv6_hnd);

	ip6 = (struct ip6_hdr *)((unsigned char *)(ppp->buf) + 2);
	if (ip6->ip6_nxt == IPPROTO_ICMPV6 && ppp->ses.ppp_ipv6_nd_recv != NULL) {
		struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(ip6 + 1);

		if (icmp6->icmp6_type == ND_ROUTER_SOLICIT) {
			/* nd routine */
			ppp->ses.ppp_ipv6_nd_recv(&ppp->ses, icmp6, ppp->buf_size - sizeof(*ip6) - 2, &ip6->ip6_src);
		}
	}
	else if (ip6->ip6_nxt == IPPROTO_UDP && ppp->ses.ppp_ipv6_dhcpv6_recv != NULL) {
		struct udphdr *udp = (struct udphdr *)(ip6 + 1);
		if (udp->source == htons(sc_dhcpv6_client_port) && udp->dest == htons(sc_dhcpv6_serv_port)) {
			/* dhcpd6 routine */
			ppp->ses.ppp_ipv6_dhcpv6_recv(&ppp->ses, udp + 1, ppp->buf_size - sizeof(*udp) - sizeof(*ip6) - 2, &ip6->ip6_src, udp->source);
		}
	}
}

void ppp_unit_ipv6_recv_proto_rej(struct ppp_handler_t *h)
{
}