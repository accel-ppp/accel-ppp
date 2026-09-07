/* Standalone tests of the production parser and reply builders. See run_safeguards.sh. */
#include <assert.h>
#include "triton.h"
#undef DEFINE_INIT
#define DEFINE_INIT(o, f)
#include "../../accel-pppd/ipv6/dhcpv6_packet.c"
#undef BUF_SIZE
#include "../../accel-pppd/ipv6/dhcpv6.c"

__thread struct ap_net *net;
static unsigned int sent;
static unsigned char response[4096];
static size_t response_len;
void log_warn(const char *fmt, ...) {}
void log_emerg(const char *fmt, ...) {}
void log_ppp_error(const char *fmt, ...) {}
void log_ppp_info2(const char *fmt, ...) {}
int ip6addr_add_peer(int i, struct in6_addr *a, struct in6_addr *p) { return 0; }
int ip6route_add(int i, const struct in6_addr *a, int p, const struct in6_addr *g, int m, uint32_t prio, const char *v) { return 0; }
struct ipv6db_prefix_t *ipdb_get_ipv6_prefix(struct ap_session *s) { return NULL; }

static ssize_t capture_send(int fd, const void *buf, size_t len, int flags,
		       const struct sockaddr *addr, socklen_t addrlen)
{
	assert(len <= sizeof(response));
	memcpy(response, buf, len);
	response_len = len;
	sent++;
	return len;
}

static size_t option(unsigned char *p, unsigned int code, const void *data, size_t len)
{
	u_write_be16(p, code);
	u_write_be16(p + 2, len);
	if (len)
		memcpy(p + 4, data, len);
	return len + 4;
}

static size_t request(unsigned char *buf)
{
	static const unsigned char duid[] = {0, 3, 0, 1, 1, 2, 3, 4, 5, 6};
	size_t len = 4;
	memset(buf, 0, 4);
	buf[0] = D6_SOLICIT;
	len += option(buf + len, D6_OPTION_CLIENTID, duid, sizeof(duid));
	len += option(buf + len, D6_OPTION_SERVERID, duid, sizeof(duid));
	return len;
}

static size_t relay(unsigned char *buf, size_t len)
{
	size_t hdrlen = sizeof(struct dhcpv6_relay_hdr);
	memmove(buf + hdrlen + 4, buf, len);
	memset(buf, 0, hdrlen);
	buf[0] = D6_RELAY_FORW;
	u_write_be16(buf + hdrlen, D6_OPTION_RELAY_MSG);
	u_write_be16(buf + hdrlen + 2, len);
	return len + hdrlen + 4;
}

int main(void)
{
	unsigned char buf[16000], oro[4000], name[256];
	const unsigned char valid_name[] = {2, 'g', 'w', 0};
	struct dhcpv6_packet *pkt, *reply;
	struct dhcpv6_option *opt;
	struct ap_session ses = {0};
	struct dhcpv6_pd pd = {0};
	struct ap_net test_net = {.sendto = capture_send};
	size_t len, base, avail;
	int i;

	net = &test_net;
	base = request(buf);
	len = base + option(buf + base, D6_OPTION_RAPID_COMMIT, NULL, 0);
	pkt = dhcpv6_packet_parse(buf, len);
	assert(pkt && pkt->rapid_commit);
	pkt->ses = &ses;
	dhcpv6_send_reply(pkt, &pd, D6_REPLY);
	assert(sent == 1);
	reply = dhcpv6_packet_parse(response, response_len);
	assert(reply && reply->rapid_commit);
	dhcpv6_packet_free(reply);
	dhcpv6_packet_free(pkt);
	len += option(buf + len, D6_OPTION_RAPID_COMMIT, NULL, 0);
	assert(!dhcpv6_packet_parse(buf, len));
	len = base + option(buf + base, D6_OPTION_RAPID_COMMIT, "x", 1);
	assert(!dhcpv6_packet_parse(buf, len));

	len = base + option(buf + base, D6_OPTION_AFTR_NAME, valid_name, sizeof(valid_name));
	pkt = dhcpv6_packet_parse(buf, len);
	assert(pkt);
	dhcpv6_packet_free(pkt);
	len += option(buf + len, D6_OPTION_AFTR_NAME, valid_name, sizeof(valid_name));
	assert(!dhcpv6_packet_parse(buf, len));
	memset(name, 'x', sizeof(name));
	for (i = 0; i < 5; i++) {
		const unsigned char invalid[][4] = {{0,0,0,0}, {0xc0,1,1,0}, {4,'a','b',0}, {2,'a','b',1}, {1,'a',0,1}};
		len = base + option(buf + base, D6_OPTION_AFTR_NAME, invalid[i], 4);
		assert(!dhcpv6_packet_parse(buf, len));
	}
	len = base + option(buf + base, D6_OPTION_AFTR_NAME, name, sizeof(name));
	assert(!dhcpv6_packet_parse(buf, len));

	len = request(buf);
	for (i = 0; i <= DHCPV6_HOP_COUNT_LIMIT; i++) {
		pkt = dhcpv6_packet_parse(buf, len);
		assert(pkt);
		reply = dhcpv6_packet_alloc_reply(pkt, D6_REPLY);
		assert(reply);
		/* The last legal byte is writable; both allocators reject overflow. */
		avail = (char *)(reply + 1) + 4096 - (char *)reply->endptr;
		opt = dhcpv6_option_alloc(reply, 65000, avail - 4);
		assert(opt);
		memset(opt->hdr->data, 1, avail - 4);
		assert(!dhcpv6_option_alloc(reply, 65000, 0));
		assert(!dhcpv6_nested_option_alloc(reply, opt, 65000, 0));
		assert(!dhcpv6_option_alloc(reply, 65000, -1));
		dhcpv6_fill_relay_info(reply);
		assert((char *)reply->endptr == (char *)(reply + 1) + 4096);
		/* Verify Relay-Message wire length in every enclosing layer. */
		if (i) {
			struct dhcpv6_relay_hdr *h = (void *)reply->hdr;
			struct dhcpv6_opt_hdr *o = (void *)h->data;
			assert(ntohs(o->len) == (char *)reply->endptr - (char *)o->data);
		}
		dhcpv6_packet_free(reply);
		dhcpv6_packet_free(pkt);
		len = relay(buf, len);
	}
	assert(!dhcpv6_packet_parse(buf, len));

	/* An ORO can amplify a small request into more than 4096 response bytes. */
	conf_dns_count = 1;
	for (i = 0; i < sizeof(oro); i += 2)
		u_write_be16(oro + i, D6_OPTION_DNS_SERVERS);
	len = request(buf);
	len += option(buf + len, D6_OPTION_ORO, oro, sizeof(oro));
	pkt = dhcpv6_packet_parse(buf, len);
	assert(pkt);
	pkt->ses = &ses;
	sent = 0;
	dhcpv6_send_reply(pkt, &pd, D6_REPLY);
	assert(!sent);
	dhcpv6_send_reply2(pkt, &pd, D6_REPLY);
	assert(!sent);
	dhcpv6_packet_free(pkt);
	puts("DHCPv6 safeguards: PASS");
	return 0;
}
void build_ip6_addr(struct ipv6db_addr_t *a, uint64_t id, struct in6_addr *addr) { *addr = a->addr; }
int ip6addr_add(int i, struct in6_addr *a, int p) { return 0; }
