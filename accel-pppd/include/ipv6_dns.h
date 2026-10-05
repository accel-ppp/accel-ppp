#ifndef __IPV6_DNS_H
#define __IPV6_DNS_H

#include <netinet/in.h>

#include "ap_session.h"

#define IPV6_DNS_INITIAL_CAPACITY 4

struct ipv6_dns_t {
	struct in6_addr *addr;
	unsigned int count;
	unsigned int capacity;
};

int ipv6_dns_reserve(struct ipv6_dns_t *dns, unsigned int count);

/*
 * Pick the IPv6 DNS servers to advertise to a session.
 *
 * A session may have been assigned its own servers (currently by the radius
 * module, from the DNS-Server-IPv6-Address attribute of RFC 6911); those take
 * precedence. Sessions without any fall back to the globally configured ones,
 * which is what every session got before per session servers existed.
 *
 * The selected array is returned and its length is written to 'count'.
 * Callers advertise nothing when the returned count is 0.
 */
static inline const struct in6_addr *ipv6_dns_get(const struct ap_session *ses,
					  const struct in6_addr *conf_dns,
					  int conf_dns_count, int *count)
{
	if (ses && ses->ipv6_dns && ses->ipv6_dns->count) {
		*count = ses->ipv6_dns->count;
		return ses->ipv6_dns->addr;
	}

	*count = conf_dns_count;
	return conf_dns;
}

#endif
