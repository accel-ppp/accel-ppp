/* Exercise peer option parsing and ConfNak construction in both NCPs. */
#include <assert.h>
#include "triton.h"
#undef DEFINE_INIT
#define DEFINE_INIT(o, f)
#ifdef TEST_IPV6CP
#include "../../accel-pppd/ppp/ppp_ipv6cp.c"
#define ncp_t ppp_ipv6cp_t
#define option_t ipv6cp_option_t
#define handler_t ipv6cp_option_handler_t
#define header_t ipv6cp_hdr_t
#define opt_header_t ipv6cp_opt_hdr_t
#define recv_request ipv6cp_recv_conf_req
#define free_request ipv6cp_free_conf_req
#define PROTOCOL PPP_IPV6CP
#define OPTION_ID CI_INTFID
#define OPTION_LEN 10
#else
#include "../../accel-pppd/ppp/ppp_ipcp.c"
#define ncp_t ppp_ipcp_t
#define option_t ipcp_option_t
#define handler_t ipcp_option_handler_t
#define header_t ipcp_hdr_t
#define opt_header_t ipcp_opt_hdr_t
#define recv_request ipcp_recv_conf_req
#define free_request ipcp_free_conf_req
#define PROTOCOL PPP_IPCP
#define OPTION_ID CI_ADDR
#define OPTION_LEN 6
#endif

int conf_ppp_verbose;
static int sent, expected_options;
void log_ppp_info2(const char *fmt, ...) {}
void log_ppp_warn(const char *fmt, ...) {}
void log_ppp_error(const char *fmt, ...) {}
void ap_session_terminate(struct ap_session *ses, int cause, int hard) { assert(0); }
void lcp_send_proto_rej(struct ppp_t *ppp, uint16_t proto) { assert(0); }
int ppp_unit_send(struct ppp_t *ppp, void *data, int size)
{
	struct header_t *hdr = data;
	unsigned char *option = (void *)(hdr + 1);
	int i, j;
	assert(hdr->proto == htons(PROTOCOL) && hdr->code == CONFNAK && hdr->id == 7);
	assert(size == sizeof(*hdr) + OPTION_LEN * expected_options);
	assert(ntohs(hdr->len) == size - 2);
	for (i = 0; i < expected_options; i++, option += OPTION_LEN) {
		assert(option[0] == OPTION_ID && option[1] == OPTION_LEN);
		for (j = 2; j < OPTION_LEN; j++)
			assert(option[j] == 0x42);
	}
	sent++;
	return 0;
}

/* The existing option handlers accept and emit exactly this wire size. */
static int receive_option(struct ncp_t *ncp, struct option_t *opt, uint8_t *data)
{
	if (data[1] != OPTION_LEN)
		return -2; /* REJ */
	return data[2] == 0x42 ? 1 : -1; /* ACK or NAK */
}
static int write_option(struct ncp_t *ncp, struct option_t *opt, uint8_t *data)
{
	memset(data, 0x42, OPTION_LEN);
	data[0] = OPTION_ID;
	data[1] = OPTION_LEN;
	return OPTION_LEN;
}

int main(void)
{
	struct ppp_t ppp = {0};
	struct ncp_t ncp = {.ppp = &ppp, .fsm = {.recv_id = 7}};
	struct handler_t handler = {.recv_conf_req = receive_option, .send_conf_nak = write_option};
	struct option_t option = {.id = OPTION_ID, .len = OPTION_LEN, .h = &handler};
	unsigned char data[OPTION_LEN * 2];
	INIT_LIST_HEAD(&ncp.options);
	INIT_LIST_HEAD(&ncp.ropt_list);
	list_add_tail(&option.entry, &ncp.options);
	ncp.conf_req_len = sizeof(struct header_t) + OPTION_LEN;
#ifndef TEST_IPV6CP
	ncp.conf_req_len += 4 * OPTION_LEN; /* Address, DNS1/2 and WINS1/2. */
#endif

	/* A single mismatched option produces one ConfNak option. */
	memset(data, 0, OPTION_LEN);
	data[0] = OPTION_ID;
	data[1] = OPTION_LEN;
	assert(recv_request(&ncp, data, OPTION_LEN) == -1);
	expected_options = 1;
	send_conf_nak(&ncp.fsm);
	free_request(&ncp);
	assert(sent == 1);

	/* The same option id must not appear more than once. */
	memcpy(data + OPTION_LEN, data, OPTION_LEN);
	assert(recv_request(&ncp, data, OPTION_LEN * 2) == -5);
	free_request(&ncp);

	/* ACK value is accepted; malformed lengths stay rejected. */
	memset(data, 0x42, OPTION_LEN);
	data[0] = OPTION_ID;
	data[1] = OPTION_LEN;
	assert(recv_request(&ncp, data, OPTION_LEN) == 1);
	free_request(&ncp);
	data[1] = 2;
	assert(recv_request(&ncp, data, 2) == -2);
	free_request(&ncp);
	assert(recv_request(&ncp, data, 1) == -5);
	free_request(&ncp);

	puts("NCP safeguards: PASS");
	return 0;
}
