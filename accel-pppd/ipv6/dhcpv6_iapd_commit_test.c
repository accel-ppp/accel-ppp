/*
 * Standalone regression test for the IA_PD IAID commit bug in dhcpv6.c:
 * dhcpv6_send_reply() used to write pd->dp_iaid unconditionally whenever a
 * prefix was available, including for a non-committing ADVERTISE reply to a
 * plain SOLICIT. A stray SOLICIT carrying a different IA_PD IAID would then
 * silently steal the binding, so a later RENEW for the real IAID was
 * rejected with NoBinding.
 *
 * This pulls in dhcpv6.c itself (not just its header) to reach its static
 * dhcpv6_recv_solicit()/dhcpv6_recv_renew() and 'struct dhcpv6_pd', and
 * reuses the real dhcpv6_packet_parse()/dhcpv6_packet_alloc_reply() wire
 * format so the test drives the exact code path a real client exchange
 * would. Everything dhcpv6.c would otherwise reach into triton/ppp/ipdb/
 * iputils for is stubbed below.
 *
 * Not part of the cmake build. Compile and run from the top of the tree,
 * with a configured build directory around for config.h:
 *   gcc -O2 -Wall -D_GNU_SOURCE -DAP_SESSIONID_LEN=16 \
 *       -I accel-pppd/include -I accel-pppd/triton -I accel-pppd -I build \
 *       -o /tmp/dhcpv6_iapd_commit_test \
 *       accel-pppd/ipv6/dhcpv6_iapd_commit_test.c \
 *       accel-pppd/ipv6/dhcpv6_packet.c && /tmp/dhcpv6_iapd_commit_test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>

/* Pull in the real production logic, including its file-local internals. */
#include "dhcpv6.c"

static int failures;
#define CHECK(cond) do { if (!(cond)) { \
	fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

/* ---------------------------------------------------------------------
 * Stubs for the triton/ppp/ipdb/iputils environment dhcpv6.c normally
 * runs under. None of this test's code paths need them to do anything
 * beyond not crashing and (for net.sendto) capturing the outgoing reply.
 * --------------------------------------------------------------------- */

void log_ppp_error(const char *fmt, ...) { }
void log_ppp_warn(const char *fmt, ...) { }
void log_ppp_info2(const char *fmt, ...) { }
void log_warn(const char *fmt, ...) { }
void log_error(const char *fmt, ...) { }
void log_emerg(const char *fmt, ...) { }

void triton_md_register_handler(struct triton_context_t *ctx, struct triton_md_handler_t *h) { }
void triton_md_unregister_handler(struct triton_md_handler_t *h, int close) { }
int triton_md_enable_handler(struct triton_md_handler_t *h, int mode) { return 0; }
int triton_event_register_handler(int ev_id, triton_event_func func) { return 0; }
void triton_event_fire(int ev_id, void *arg) { }
int triton_module_loaded(const char *name) { return 1; }
void triton_register_init(int order, void (*func)(void)) { }
char *conf_get_opt(const char *sect, const char *name) { return NULL; }
struct conf_sect_t *conf_get_section(const char *name) { return NULL; }

int ip6route_add(int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name) { return 0; }
int ip6route_del(int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name) { return 0; }
int ip6addr_add(int ifindex, struct in6_addr *addr, int prefix_len) { return 0; }
int ip6addr_add_peer(int ifindex, struct in6_addr *addr, struct in6_addr *peer_addr) { return 0; }
void build_ip6_addr(struct ipv6db_addr_t *a, uint64_t intf_id, struct in6_addr *addr) { memset(addr, 0, sizeof(*addr)); }

/* Fabricated delegated-prefix pool: one /64, handed out once per session. */
static struct ipv6db_prefix_t test_dp;
static struct ipv6db_addr_t test_dp_prefix;

struct ipv6db_prefix_t *ipdb_get_ipv6_prefix(struct ap_session *ses)
{
	INIT_LIST_HEAD(&test_dp.prefix_list);
	inet_pton(AF_INET6, "2001:db8:1::", &test_dp_prefix.addr);
	test_dp_prefix.prefix_len = 64;
	list_add_tail(&test_dp_prefix.entry, &test_dp.prefix_list);
	return &test_dp;
}
void ipdb_put_ipv6_prefix(struct ap_session *ses, struct ipv6db_prefix_t *it) { }

/* Captures whatever dhcpv6_send_reply() sends back, for inspection. */
static uint8_t sent_buf[4096];
static size_t sent_len;

static ssize_t stub_sendto(int sock, const void *buf, size_t len, int flags,
			    const struct sockaddr *dest_addr, socklen_t addrlen)
{
	sent_len = len > sizeof(sent_buf) ? sizeof(sent_buf) : len;
	memcpy(sent_buf, buf, sent_len);
	return len;
}

static struct ap_net test_net = { .sendto = stub_sendto };
__thread struct ap_net *net = &test_net;

/* ---------------------------------------------------------------------
 * Request builder: assembles a well-formed DHCPv6 client message
 * (Client-ID + optionally Server-ID/Rapid-Commit + an IA_PD carrying the
 * given IAID) and hands it through the real dhcpv6_packet_parse().
 * --------------------------------------------------------------------- */

static void put_opt_hdr(uint8_t *buf, size_t *off, uint16_t code, uint16_t len)
{
	struct dhcpv6_opt_hdr *h = (struct dhcpv6_opt_hdr *)(buf + *off);
	h->code = htons(code);
	h->len = htons(len);
	*off += sizeof(*h);
}

static void put_clientid(uint8_t *buf, size_t *off, uint64_t id)
{
	put_opt_hdr(buf, off, D6_OPTION_CLIENTID, 12);
	struct dhcpv6_duid *duid = (struct dhcpv6_duid *)(buf + *off);
	duid->type = htons(DUID_LL);
	duid->u.ll.htype = htons(27);
	memcpy(duid->u.ll.addr, &id, sizeof(id));
	*off += 12;
}

static void put_serverid_from_conf(uint8_t *buf, size_t *off)
{
	uint16_t len = ntohs(conf_serverid->hdr.len);

	put_opt_hdr(buf, off, D6_OPTION_SERVERID, len);
	memcpy(buf + *off, &conf_serverid->duid, len);
	*off += len;
}

static void put_ia_pd(uint8_t *buf, size_t *off, uint32_t iaid)
{
	put_opt_hdr(buf, off, D6_OPTION_IA_PD, 12);
	struct dhcpv6_opt_ia_na tmp;
	tmp.iaid = iaid;
	tmp.T1 = 0;
	tmp.T2 = 0;
	memcpy(buf + *off, &tmp.iaid, 12);
	*off += 12;
}

static struct dhcpv6_packet *build_request(int type, int with_serverid, int rapid_commit,
					    uint64_t client_id, uint32_t pd_iaid)
{
	uint8_t buf[512];
	size_t off = sizeof(struct dhcpv6_msg_hdr);
	struct dhcpv6_msg_hdr *hdr = (struct dhcpv6_msg_hdr *)buf;

	hdr->type = type;
	hdr->trans_id = 0x123456;

	put_clientid(buf, &off, client_id);
	if (with_serverid)
		put_serverid_from_conf(buf, &off);
	if (rapid_commit)
		put_opt_hdr(buf, &off, D6_OPTION_RAPID_COMMIT, 0);
	put_ia_pd(buf, &off, pd_iaid);

	return dhcpv6_packet_parse(buf, off);
}

/* True if the last captured reply's IA_PD carries a NoBinding status. */
static int reply_is_nobinding(void)
{
	struct dhcpv6_packet *reply = dhcpv6_packet_parse(sent_buf, sent_len);
	struct dhcpv6_option *opt, *opt2;
	int found = 0;

	CHECK(reply != NULL);

	list_for_each_entry(opt, &reply->opt_list, entry) {
		if (ntohs(opt->hdr->code) != D6_OPTION_IA_PD)
			continue;

		list_for_each_entry(opt2, &opt->opt_list, entry) {
			struct dhcpv6_opt_status *st;

			if (ntohs(opt2->hdr->code) != D6_OPTION_STATUS_CODE)
				continue;

			st = (struct dhcpv6_opt_status *)opt2->hdr;
			if (ntohs(st->code) == D6_STATUS_NoBinding)
				found = 1;
		}
	}

	dhcpv6_packet_free(reply);
	return found;
}

int main(void)
{
	struct ap_session ses;
	struct dhcpv6_pd pd;
	struct dhcpv6_packet *req;
	const uint64_t client_id = 0x1122334455667788ULL;

	load_config(); /* sets up conf_serverid with conf_get_opt() stubbed out */

	memset(&ses, 0, sizeof(ses));
	INIT_LIST_HEAD(&ses.pd_list);

	memset(&pd, 0, sizeof(pd));
	pd.ses = &ses;
	pd.hnd.fd = -1;

	/* Step 1: rapid-commit SOLICIT establishes the binding at IAID 5. */
	req = build_request(D6_SOLICIT, 0, 1, client_id, 5);
	CHECK(req != NULL);
	req->ses = &ses;
	req->pd = &pd;
	dhcpv6_recv_solicit(req);
	dhcpv6_packet_free(req);

	CHECK(pd.dp_iaid == 5);
	CHECK(pd.dp_active == 1);

	/* Step 2: a stray, non-committing SOLICIT for a different IAID (6)
	 * must not steal the binding. */
	req = build_request(D6_SOLICIT, 0, 0, client_id, 6);
	CHECK(req != NULL);
	req->ses = &ses;
	req->pd = &pd;
	dhcpv6_recv_solicit(req);
	dhcpv6_packet_free(req);

	CHECK(pd.dp_iaid == 5);

	/* Step 3: RENEW for the original IAID (5) must still be honored. */
	req = build_request(D6_RENEW, 1, 0, client_id, 5);
	CHECK(req != NULL);
	req->ses = &ses;
	req->pd = &pd;
	dhcpv6_recv_renew(req);
	dhcpv6_packet_free(req);

	CHECK(!reply_is_nobinding());

	/* dhcpv6_recv_solicit() allocated the client DUID copy; keep LSan quiet. */
	_free(pd.clientid);

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}

	printf("all tests passed\n");
	return 0;
}
