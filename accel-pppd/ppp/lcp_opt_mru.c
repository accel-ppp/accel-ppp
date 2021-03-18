#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "linux_ppp.h"

#include "ppp.h"
#include "ppp_lcp.h"
#include "log.h"
#include "events.h"

#include "memdebug.h"

static int conf_mtu;
static int conf_mru;
static int conf_min_mtu = 100;
static int conf_max_mtu = 1500;

static struct lcp_option_t *mru_init(struct ppp_lcp_t *lcp);
static void mru_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int mru_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void mru_print(void (*print)(const char *fmt, ...), struct lcp_option_t*, uint8_t *ptr);

struct mru_option_t
{
	struct lcp_option_t opt;
	int mru;
	int mtu;
	unsigned int naked:1;
	unsigned int rejected:1;
};

static struct lcp_option_handler_t mru_opt_hnd=
{
	.init = mru_init,
	.send_conf_req = mru_send_conf_req,
	.send_conf_nak = mru_send_conf_nak,
	.recv_conf_req = mru_recv_conf_req,
	.recv_conf_ack = mru_recv_conf_ack,
	.recv_conf_nak = mru_recv_conf_nak,
	.recv_conf_rej = mru_recv_conf_rej,
	.free = mru_free,
	.print = mru_print,
};

static struct lcp_option_t *mru_init(struct ppp_lcp_t *lcp)
{
	struct mru_option_t *mru_opt = _malloc(sizeof(*mru_opt));

	memset(mru_opt, 0, sizeof(*mru_opt));
	mru_opt->mru = (conf_mru && conf_mru <= lcp->ppp->ses.ctrl->max_mtu) ? conf_mru : lcp->ppp->ses.ctrl->max_mtu;
	if (mru_opt->mru > conf_max_mtu)
		mru_opt->mru = conf_max_mtu;
	mru_opt->mtu = (conf_mtu && conf_mtu <= lcp->ppp->ses.ctrl->max_mtu) ? conf_mtu : lcp->ppp->ses.ctrl->max_mtu;
	if (mru_opt->mtu > conf_max_mtu)
		mru_opt->mtu = conf_max_mtu;
	mru_opt->opt.id = CI_MRU;
	mru_opt->opt.len = 4;

	lcp->ppp->mru = PPP_MTU;
	lcp->ppp->mtu = mru_opt->mtu;

	return &mru_opt->opt;
}

static void mru_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);

	_free(mru_opt);
}

static int mru_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;

	if (mru_opt->naked || mru_opt->rejected)
		return 0;

	opt16->hdr.id = CI_MRU;
	opt16->hdr.len = 4;
	opt16->val = htons(mru_opt->mru);
	return 4;
}

static int mru_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;

	opt16->hdr.id = CI_MRU;
	opt16->hdr.len = 4;
	opt16->val = htons(mru_opt->mtu);
	return 4;
}

static int mru_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;

	/*if (!ptr)
		return LCP_OPT_NAK;*/

	if (opt16->hdr.len != 4)
		return LCP_OPT_REJ;

	if (ntohs(opt16->val) < conf_min_mtu || ntohs(opt16->val) > lcp->ppp->ses.ctrl->max_mtu || ntohs(opt16->val) > conf_max_mtu)
		return LCP_OPT_NAK;

	mru_opt->mtu = ntohs(opt16->val);
	lcp->ppp->mtu = mru_opt->mtu;

	return LCP_OPT_ACK;
}

static int mru_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);

	lcp->ppp->mru = mru_opt->mru;

	return 0;
}

static int mru_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);

	mru_opt->naked = 1;
	return 0;
}
static int mru_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);

	mru_opt->rejected = 1;
	return 0;
}

static void mru_print(void (*print)(const char *fmt, ...), struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;

	if (ptr)
		print("<mru %i>", ntohs(opt16->val));
	else
		print("<mru %i>", mru_opt->mru);
}

static void load_config(void)
{
	char *opt;

	opt = conf_get_opt("ppp", "mtu");
	if (opt && atoi(opt) > 0)
		conf_mtu = atoi(opt);

	opt = conf_get_opt("ppp", "mru");
	if (opt && atoi(opt) > 0)
		conf_mru = atoi(opt);

	opt = conf_get_opt("ppp", "min-mtu");
	if (opt && atoi(opt) > 0)
		conf_min_mtu = atoi(opt);

	opt = conf_get_opt("ppp", "max-mtu");
	if (opt && atoi(opt) > 0)
		conf_max_mtu = atoi(opt);

	if (conf_mru && conf_min_mtu > conf_mru) {
		log_emerg("min-mtu cann't be greater then mtu/mru\n");
		conf_min_mtu = conf_mru;
	}
}

static void mru_opt_init()
{
	load_config();
	lcp_option_register(&mru_opt_hnd);
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(4, mru_opt_init);
