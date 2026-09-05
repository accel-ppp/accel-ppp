/*
 * Standalone test for the IPv6 DNS server selection shared by the ipv6_nd and
 * ipv6_dhcp modules.
 *
 * Not part of the cmake build. Compile and run from the top of the tree, with
 * a configured build directory around for config.h:
 *   gcc -O2 -Wall -D_GNU_SOURCE -DAP_SESSIONID_LEN=16 \
 *       -I accel-pppd/include -I accel-pppd/triton -I build \
 *       -o /tmp/ipv6_dns_test accel-pppd/ipv6/ipv6_dns_test.c \
 *       accel-pppd/ipv6_dns.c && /tmp/ipv6_dns_test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ipv6_dns.h"

static int failures;
#define CHECK(cond) do { if (!(cond)) { \
	fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static struct in6_addr a6(const char *str)
{
	struct in6_addr addr;

	if (inet_pton(AF_INET6, str, &addr) != 1) {
		fprintf(stderr, "bad address %s\n", str);
		exit(1);
	}

	return addr;
}

static int is(const struct in6_addr *addr, const char *str)
{
	struct in6_addr expect = a6(str);

	return memcmp(addr, &expect, sizeof(expect)) == 0;
}

/* A session carrying 'count' DNS servers taken from 'str' */
static struct ap_session *session_with(const char **str, int count)
{
	struct ap_session *ses = calloc(1, sizeof(*ses));
	struct ipv6_dns_t *item = calloc(1, sizeof(*item));
	int i;

	item->addr = calloc(count, sizeof(*item->addr));
	for (i = 0; i < count; i++)
		item->addr[i] = a6(str[i]);
	item->count = count;
	item->capacity = count;

	ses->ipv6_dns = item;

	return ses;
}

static void session_free(struct ap_session *ses)
{
	if (ses->ipv6_dns) {
		free(ses->ipv6_dns->addr);
		free(ses->ipv6_dns);
	}

	free(ses);
}

int main(void)
{
	static const char *four[] = { "2001:db8::1", "2001:db8::2",
				      "2001:db8::3", "2001:db8::4" };
	struct in6_addr conf_dns[4];
	struct ipv6_dns_t dynamic_dns = {};
	const struct in6_addr *dns;
	struct ap_session *ses;
	int n;

	conf_dns[0] = a6("fc00::53");
	conf_dns[1] = a6("fc00::54");
	conf_dns[2] = a6("fc00::55");
	conf_dns[3] = a6("fc00::56");

	/* Shared storage grows geometrically and retains existing entries. */
	CHECK(ipv6_dns_reserve(&dynamic_dns, 1) == 0);
	CHECK(dynamic_dns.capacity == IPV6_DNS_INITIAL_CAPACITY);
	dynamic_dns.addr[0] = a6("2001:db8::53");
	CHECK(ipv6_dns_reserve(&dynamic_dns, IPV6_DNS_INITIAL_CAPACITY + 1) == 0);
	CHECK(dynamic_dns.capacity == IPV6_DNS_INITIAL_CAPACITY * 2);
	CHECK(is(&dynamic_dns.addr[0], "2001:db8::53"));
	free(dynamic_dns.addr);

	/* No session at all: the configured servers, as before the feature */
	dns = ipv6_dns_get(NULL, conf_dns, 2, &n);
	CHECK(n == 2);
	CHECK(is(&dns[0], "fc00::53"));
	CHECK(is(&dns[1], "fc00::54"));

	/* Session without assigned servers: same fallback */
	ses = calloc(1, sizeof(*ses));
	dns = ipv6_dns_get(ses, conf_dns, 2, &n);
	CHECK(n == 2);
	CHECK(is(&dns[0], "fc00::53"));
	free(ses);

	/* Nothing configured and nothing assigned: advertise nothing */
	dns = ipv6_dns_get(NULL, conf_dns, 0, &n);
	CHECK(n == 0);

	/* Assigned servers win over the configured ones */
	ses = session_with(four, 2);
	dns = ipv6_dns_get(ses, conf_dns, 2, &n);
	CHECK(n == 2);
	CHECK(is(&dns[0], "2001:db8::1"));
	CHECK(is(&dns[1], "2001:db8::2"));

	/* ... and win even when nothing is configured */
	dns = ipv6_dns_get(ses, conf_dns, 0, &n);
	CHECK(n == 2);
	CHECK(is(&dns[0], "2001:db8::1"));

	session_free(ses);

	/* An empty assigned set is "nothing assigned", not "no DNS" */
	ses = session_with(four, 0);
	dns = ipv6_dns_get(ses, conf_dns, 2, &n);
	CHECK(n == 2);
	CHECK(is(&dns[0], "fc00::53"));
	session_free(ses);

	/* Assigned sets are not restricted to the configured-server limit */
	ses = session_with(four, 4);
	dns = ipv6_dns_get(ses, conf_dns, 2, &n);
	CHECK(n == 4);
	CHECK(is(&dns[0], "2001:db8::1"));
	CHECK(is(&dns[1], "2001:db8::2"));
	CHECK(is(&dns[2], "2001:db8::3"));

	/* Configured sets are not restricted to three servers either */
	dns = ipv6_dns_get(NULL, conf_dns, 4, &n);
	CHECK(n == 4);
	CHECK(is(&dns[2], "fc00::55"));
	CHECK(is(&dns[3], "fc00::56"));

	session_free(ses);

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}

	printf("all tests passed\n");

	return 0;
}
