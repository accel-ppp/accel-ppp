#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "linux_ppp.h"

#include "ppp.h"
#include "ppp_lcp.h"
#include "log.h"
#include "events.h"

#include "memdebug.h"

static int conf_pcomp = 0;

static struct lcp_option_t *pcomp_init(struct ppp_lcp_t *lcp);
static void pcomp_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int pcomp_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int pcomp_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int pcomp_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int pcomp_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int pcomp_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void pcomp_print(void (*print)(const char *fmt, ...), struct lcp_option_t *opt, uint8_t *ptr);

struct pcomp_option_t
{
	struct lcp_option_t opt;
	int pcomp; // 0 - disabled, 1 - enabled, 2 - allow,disabled, 3 - allow,enabled
};

static struct lcp_option_handler_t pcomp_opt_hnd =
{
	.init = pcomp_init,
	.send_conf_req = pcomp_send_conf_req,
	.recv_conf_req = pcomp_recv_conf_req,
	.recv_conf_rej = pcomp_recv_conf_rej,
	.recv_conf_nak = pcomp_recv_conf_nak,
	.recv_conf_ack = pcomp_recv_conf_ack,
	.free = pcomp_free,
	.print = pcomp_print,
};

static struct lcp_option_t *pcomp_init(struct ppp_lcp_t *lcp)
{
	struct pcomp_option_t *pcomp_opt = _malloc(sizeof(*pcomp_opt));

	memset(pcomp_opt, 0, sizeof(*pcomp_opt));
	pcomp_opt->pcomp = conf_pcomp;
	pcomp_opt->opt.id = CI_PCOMP;
	pcomp_opt->opt.len = 2;

	return &pcomp_opt->opt;
}

static void pcomp_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct pcomp_option_t *pcomp_opt = container_of(opt, typeof(*pcomp_opt), opt);

	_free(pcomp_opt);
}

static int pcomp_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct pcomp_option_t *pcomp_opt = container_of(opt, typeof(*pcomp_opt), opt);
	struct lcp_opt_hdr_t *opt0 = (struct lcp_opt_hdr_t*)ptr;

	if (pcomp_opt->pcomp & 1) {
		opt0->id = CI_PCOMP;
		opt0->len = 2;
		return 2;
	}
	return 0;
}

static int pcomp_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct pcomp_option_t *pcomp_opt = container_of(opt, typeof(*pcomp_opt), opt);
	struct lcp_opt_hdr_t *opt0 = (struct lcp_opt_hdr_t*)ptr;

	if (opt0->len != 2)
		return LCP_OPT_REJ;

	if (pcomp_opt->pcomp & 2)
		return LCP_OPT_ACK;
	else
		return LCP_OPT_REJ;
}

static int pcomp_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct pcomp_option_t *pcomp_opt = container_of(opt, typeof(*pcomp_opt), opt);

	pcomp_opt->pcomp &= ~1;
	return 0;
}

static int pcomp_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct pcomp_option_t *pcomp_opt = container_of(opt, typeof(*pcomp_opt), opt);
	struct lcp_opt_hdr_t *opt0 = (struct lcp_opt_hdr_t*)ptr;

	if (opt0->len != 2)
		return -1;

	/* treat as reject */
	return pcomp_recv_conf_rej(lcp, opt, ptr);
}

static int pcomp_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct pcomp_option_t *pcomp_opt = container_of(opt, typeof(*pcomp_opt), opt);
	int flags;

	if (net->ppp_ioctl(lcp->ppp->chan_fd, PPPIOCGFLAGS, &flags))
		goto err;

	flags &= ~SC_COMP_PROT;
	if (pcomp_opt->pcomp & 1)
		flags |= SC_COMP_PROT;

	if (net->ppp_ioctl(lcp->ppp->chan_fd, PPPIOCSFLAGS, &flags))
		goto err;

	return 0;

err:
	if (errno != EIO)
		log_ppp_error("lcp:pcomp: failed to set channel ACCOMP: %s\n", strerror(errno));
	return -1;
}

static void pcomp_print(void (*print)(const char *fmt, ...), struct lcp_option_t *opt, uint8_t *ptr)
{
	print("<pcomp>");
}

static void load_config(void)
{
	char *opt;

	opt = conf_get_opt("ppp", "pcomp");
	if (opt) {
		if (!strcmp(opt, "deny"))
			conf_pcomp = 0;
		else if (!strcmp(opt, "allow"))
			conf_pcomp = 1 | 2;
		else
			conf_pcomp = atoi(opt);
	}

}

static void pcomp_opt_init()
{
	lcp_option_register(&pcomp_opt_hnd);

	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(4, pcomp_opt_init);
