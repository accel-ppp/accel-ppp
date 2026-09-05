#include <limits.h>

#include "triton.h"
#include "ipv6_dns.h"

#include "memdebug.h"

int __export ipv6_dns_reserve(struct ipv6_dns_t *dns, unsigned int count)
{
	struct in6_addr *addr;
	unsigned int capacity;

	if (count <= dns->capacity)
		return 0;

	capacity = dns->capacity;
	if (!capacity)
		capacity = IPV6_DNS_INITIAL_CAPACITY;
	while (capacity < count) {
		/* Doubling past this would wrap around and spin forever */
		if (capacity > UINT_MAX / 2)
			return -1;
		capacity *= 2;
	}

	addr = _realloc(dns->addr, capacity * sizeof(*addr));
	if (!addr)
		return -1;

	dns->addr = addr;
	dns->capacity = capacity;
	return 0;
}
