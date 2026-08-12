#ifndef __IPV6_DNS_H
#define __IPV6_DNS_H

#include <netinet/in.h>

#include "list.h"
#include "ipdb.h"
#include "ap_session.h"

/*
 * Pick the IPv6 DNS servers to advertise to a session.
 *
 * A session may have been assigned its own servers (currently by the radius
 * module, from the DNS-Server-IPv6-Address attribute of RFC 6911); those take
 * precedence. Sessions without any fall back to the globally configured ones,
 * which is what every session got before per session servers existed.
 *
 * Up to 'max' addresses are written to 'dns', the number written is returned.
 * Callers advertise nothing when that is 0.
 */
static inline int ipv6_dns_get(const struct ap_session *ses,
			       const struct in6_addr *conf_dns, int conf_dns_count,
			       struct in6_addr *dns, int max)
{
	struct ipv6db_addr_t *a;
	int count = 0;

	if (ses && ses->ipv6_dns) {
		list_for_each_entry(a, &ses->ipv6_dns->addr_list, entry) {
			if (count == max)
				break;
			dns[count++] = a->addr;
		}

		/* An empty list means "nothing assigned", not "no DNS at all" */
		if (count)
			return count;
	}

	while (count < conf_dns_count && count < max) {
		dns[count] = conf_dns[count];
		count++;
	}

	return count;
}

#endif
