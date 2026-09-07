/* Exercise production Echo-Reply handling at the negotiated MTU. */
#include <assert.h>
#include "triton.h"
#undef DEFINE_INIT
#define DEFINE_INIT(o, f)
#include "../../accel-pppd/ppp/ppp_lcp.c"

int conf_ppp_verbose;
static int sent, sent_len;
void log_ppp_debug(const char *fmt, ...) {}
int ppp_chan_send(struct ppp_t *ppp, void *buf, int size)
{
	const struct lcp_hdr_t *hdr = buf;
	assert(size == ntohs(hdr->len) + 2);
	assert(hdr->code == ECHOREP);
	sent++;
	sent_len = size;
	return 0;
}
int main(void)
{
	unsigned char buf[1502] = {0};
	struct ppp_t ppp = {.buf = buf, .buf_size = sizeof(buf), .mtu = 1492};
	struct ppp_lcp_t lcp = {.ppp = &ppp, .magic = 0x12345678};
	struct lcp_hdr_t *hdr = (void *)buf;

	hdr->len = htons(1493);
	hdr->code = ECHOREQ;
	send_echo_reply(&lcp);
	assert(!sent && hdr->code == ECHOREQ);
	hdr->len = htons(1492);
	send_echo_reply(&lcp);
	assert(sent == 1 && sent_len == 1494);
	assert(u_read_be32(hdr + 1) == lcp.magic);
	hdr->len = htons(8);
	send_echo_reply(&lcp);
	assert(sent == 2 && sent_len == 10);
	puts("LCP safeguards: PASS");
	return 0;
}
