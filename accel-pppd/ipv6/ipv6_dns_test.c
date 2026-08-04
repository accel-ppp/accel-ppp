/*
 * Standalone test for the IPv6 DNS server selection shared by the ipv6_nd and
 * ipv6_dhcp modules.
 *
 * Not part of the cmake build. Compile and run from the top of the tree, with
 * a configured build directory around for config.h:
 *   gcc -O2 -Wall -D_GNU_SOURCE -DAP_SESSIONID_LEN=16 \
 *       -I accel-pppd/include -I accel-pppd/triton -I build \
 *       -o /tmp/ipv6_dns_test accel-pppd/ipv6/ipv6_dns_test.c && /tmp/ipv6_dns_test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ipv6_dns.h"

static int failures;
#define CHECK(cond) do { if (!(cond)) { \
	fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

#define MAX_DNS_COUNT 3		/* as in nd.c and dhcpv6.c */

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
	struct ipv6db_item_t *item = calloc(1, sizeof(*item));
	int i;

	INIT_LIST_HEAD(&item->addr_list);
	for (i = 0; i < count; i++) {
		struct ipv6db_addr_t *a = calloc(1, sizeof(*a));

		a->addr = a6(str[i]);
		a->prefix_len = 128;
		list_add_tail(&a->entry, &item->addr_list);
	}

	ses->ipv6_dns = item;

	return ses;
}

static void session_free(struct ap_session *ses)
{
	if (ses->ipv6_dns) {
		while (!list_empty(&ses->ipv6_dns->addr_list)) {
			struct ipv6db_addr_t *a = list_entry(ses->ipv6_dns->addr_list.next,
							     typeof(*a), entry);

			list_del(&a->entry);
			free(a);
		}
		free(ses->ipv6_dns);
	}

	free(ses);
}

int main(void)
{
	static const char *four[] = { "2001:db8::1", "2001:db8::2",
				      "2001:db8::3", "2001:db8::4" };
	struct in6_addr conf_dns[MAX_DNS_COUNT];
	struct in6_addr dns[MAX_DNS_COUNT];
	struct ap_session *ses;
	int n;

	conf_dns[0] = a6("fc00::53");
	conf_dns[1] = a6("fc00::54");

	/* No session at all: the configured servers, as before the feature */
	n = ipv6_dns_get(NULL, conf_dns, 2, dns, MAX_DNS_COUNT);
	CHECK(n == 2);
	CHECK(is(&dns[0], "fc00::53"));
	CHECK(is(&dns[1], "fc00::54"));

	/* Session without assigned servers: same fallback */
	ses = calloc(1, sizeof(*ses));
	n = ipv6_dns_get(ses, conf_dns, 2, dns, MAX_DNS_COUNT);
	CHECK(n == 2);
	CHECK(is(&dns[0], "fc00::53"));
	free(ses);

	/* Nothing configured and nothing assigned: advertise nothing */
	n = ipv6_dns_get(NULL, conf_dns, 0, dns, MAX_DNS_COUNT);
	CHECK(n == 0);

	/* Assigned servers win over the configured ones */
	ses = session_with(four, 2);
	n = ipv6_dns_get(ses, conf_dns, 2, dns, MAX_DNS_COUNT);
	CHECK(n == 2);
	CHECK(is(&dns[0], "2001:db8::1"));
	CHECK(is(&dns[1], "2001:db8::2"));

	/* ... and win even when nothing is configured */
	n = ipv6_dns_get(ses, conf_dns, 0, dns, MAX_DNS_COUNT);
	CHECK(n == 2);
	CHECK(is(&dns[0], "2001:db8::1"));

	session_free(ses);

	/* An empty assigned list is "nothing assigned", not "no DNS" */
	ses = session_with(four, 0);
	n = ipv6_dns_get(ses, conf_dns, 2, dns, MAX_DNS_COUNT);
	CHECK(n == 2);
	CHECK(is(&dns[0], "fc00::53"));
	session_free(ses);

	/* More assigned than fit: keep the first max, never overrun */
	ses = session_with(four, 4);
	memset(dns, 0, sizeof(dns));
	n = ipv6_dns_get(ses, conf_dns, 2, dns, MAX_DNS_COUNT);
	CHECK(n == MAX_DNS_COUNT);
	CHECK(is(&dns[0], "2001:db8::1"));
	CHECK(is(&dns[1], "2001:db8::2"));
	CHECK(is(&dns[2], "2001:db8::3"));

	/* Same for the configured ones, should they ever exceed max */
	n = ipv6_dns_get(NULL, conf_dns, 99, dns, MAX_DNS_COUNT);
	CHECK(n == MAX_DNS_COUNT);

	/* A caller with no room gets nothing rather than a stomped buffer */
	n = ipv6_dns_get(ses, conf_dns, 2, dns, 0);
	CHECK(n == 0);

	session_free(ses);

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}

	printf("all tests passed\n");

	return 0;
}
