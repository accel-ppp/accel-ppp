#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ppp.h"
#include "ppp_lcp.h"
#include "log.h"

#include "memdebug.h"

static struct lcp_option_t *magic_init(struct ppp_lcp_t *lcp);
static void magic_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int magic_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int magic_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int magic_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int magic_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int magic_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void magic_print(void (*print)(const char *fmt, ...), struct lcp_option_t*, uint8_t *ptr);

struct magic_option_t
{
	struct lcp_option_t opt;
	int magic;
};

static struct lcp_option_handler_t magic_opt_hnd=
{
	.init = magic_init,
	.send_conf_req = magic_send_conf_req,
	.send_conf_nak = magic_send_conf_nak,
	.recv_conf_req = magic_recv_conf_req,
	.recv_conf_rej = magic_recv_conf_rej,
	.recv_conf_nak = magic_recv_conf_nak,
	.free = magic_free,
	.print = magic_print,
};

static int nzmagic(int old)
{
	int magic;

	do {
		magic = random();
	} while (magic == old || !magic);

	return magic;
}

static struct lcp_option_t *magic_init(struct ppp_lcp_t *lcp)
{
	struct magic_option_t *magic_opt = _malloc(sizeof(*magic_opt));

	memset(magic_opt, 0, sizeof(*magic_opt));
	magic_opt->magic = nzmagic(0);
	magic_opt->opt.id = CI_MAGIC;
	magic_opt->opt.len = 6;

	lcp->magic = magic_opt->magic;

	return &magic_opt->opt;
}

static void magic_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct magic_option_t *magic_opt = container_of(opt,typeof(*magic_opt),opt);

	_free(magic_opt);
}

static int magic_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct magic_option_t *magic_opt = container_of(opt, typeof(*magic_opt), opt);
	struct lcp_opt32_t *opt32 = (struct lcp_opt32_t *)ptr;

	if (!magic_opt->magic)
		return 0;

	opt32->hdr.id = CI_MAGIC;
	opt32->hdr.len = 6;
	opt32->val = htonl(magic_opt->magic);
	return 6;
}

static int magic_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct magic_option_t *magic_opt = container_of(opt, typeof(*magic_opt), opt);
	struct lcp_opt32_t *opt32 = (struct lcp_opt32_t *)ptr;

	opt32->hdr.id = CI_MAGIC;
	opt32->hdr.len = 6;
	opt32->val = htonl(nzmagic(magic_opt->magic));
	return 6;
}

static int magic_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct magic_option_t *magic_opt = container_of(opt, typeof(*magic_opt), opt);
	struct lcp_opt32_t *opt32 = (struct lcp_opt32_t *)ptr;

	/*if (!ptr)
		return LCP_OPT_NAK;*/

	if (opt32->hdr.len != 6)
		return LCP_OPT_REJ;

	if (magic_opt->magic && magic_opt->magic == ntohl(opt32->val))
		return LCP_OPT_NAK;

	return LCP_OPT_ACK;
}

static int magic_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct magic_option_t *magic_opt = container_of(opt, typeof(*magic_opt), opt);

	magic_opt->magic = 0;
	lcp->magic = 0;

	return 0;
}

static int magic_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct magic_option_t *magic_opt = container_of(opt, typeof(*magic_opt), opt);
	struct lcp_opt32_t *opt32 = (struct lcp_opt32_t *)ptr;

	if (opt32->hdr.len != 6)
		return -1;

	/* Loop-back detected */
	if (magic_opt->magic && magic_opt->magic == ntohl(opt32->val))
		return -1;

	magic_opt->magic = ntohl(opt32->val) ? : nzmagic(magic_opt->magic);
	lcp->magic = magic_opt->magic;

	return 0;
}

static void magic_print(void (*print)(const char *fmt, ...), struct lcp_option_t *opt, uint8_t *ptr)
{
	struct magic_option_t *magic_opt = container_of(opt, typeof(*magic_opt), opt);
	struct lcp_opt32_t *opt32 = (struct lcp_opt32_t *)ptr;

	if (ptr && opt32->hdr.len >= sizeof(*opt32))
		print("<magic %08x>", ntohl(opt32->val));
	else if (!ptr)
		print("<magic %08x>", magic_opt->magic);
	else
		print("<magic>");
}

static void magic_opt_init()
{
	lcp_option_register(&magic_opt_hnd);
}

DEFINE_INIT(4, magic_opt_init);
