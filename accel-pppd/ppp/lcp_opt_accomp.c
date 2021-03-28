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

static int conf_accomp = 0;

static struct lcp_option_t *accomp_init(struct ppp_lcp_t *lcp);
static void accomp_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int accomp_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int accomp_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int accomp_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int accomp_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int accomp_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void accomp_print(void (*print)(const char *fmt, ...), struct lcp_option_t *opt, uint8_t *ptr);

struct accomp_option_t
{
	struct lcp_option_t opt;
	int accomp; // 0 - disabled, 1 - enabled, 2 - allow,disabled, 3 - allow,enabled
};

static struct lcp_option_handler_t accomp_opt_hnd =
{
	.init = accomp_init,
	.send_conf_req = accomp_send_conf_req,
	.recv_conf_req = accomp_recv_conf_req,
	.recv_conf_rej = accomp_recv_conf_rej,
	.recv_conf_nak = accomp_recv_conf_nak,
	.recv_conf_ack = accomp_recv_conf_ack,
	.free = accomp_free,
	.print = accomp_print,
};

static struct lcp_option_t *accomp_init(struct ppp_lcp_t *lcp)
{
	struct accomp_option_t *accomp_opt = _malloc(sizeof(*accomp_opt));

	memset(accomp_opt, 0, sizeof(*accomp_opt));
	accomp_opt->accomp = conf_accomp;
	accomp_opt->opt.id = CI_ACCOMP;
	accomp_opt->opt.len = 2;

	return &accomp_opt->opt;
}

static pthread_rwlock_t config_modify = PTHREAD_RWLOCK_INITIALIZER;

static void accomp_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct accomp_option_t *accomp_opt = container_of(opt, typeof(*accomp_opt), opt);

	_free(accomp_opt);
}

static int accomp_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct accomp_option_t *accomp_opt = container_of(opt, typeof(*accomp_opt), opt);
	struct lcp_opt_hdr_t *opt0 = (struct lcp_opt_hdr_t*)ptr;

	if (accomp_opt->accomp & 1) {
		opt0->id = CI_ACCOMP;
		opt0->len = 2;
		return 2;
	}
	return 0;
}

static int accomp_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct accomp_option_t *accomp_opt = container_of(opt, typeof(*accomp_opt), opt);
	struct lcp_opt_hdr_t *opt0 = (struct lcp_opt_hdr_t*)ptr;

	if (opt0->len != 2)
		return LCP_OPT_REJ;

	if (accomp_opt->accomp & 2)
		return LCP_OPT_ACK;
	else
		return LCP_OPT_REJ;
}

static int accomp_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct accomp_option_t *accomp_opt = container_of(opt, typeof(*accomp_opt), opt);

	accomp_opt->accomp &= ~1;
	return 0;
}

static int accomp_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct accomp_option_t *accomp_opt = container_of(opt, typeof(*accomp_opt), opt);
	struct lcp_opt_hdr_t *opt0 = (struct lcp_opt_hdr_t*)ptr;

	if (opt0->len != 2)
		return -1;

	/* treat as reject */
	return accomp_recv_conf_rej(lcp, opt, ptr);
}

static int accomp_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct accomp_option_t *accomp_opt = container_of(opt, typeof(*accomp_opt), opt);
	int flags;

	if (net->ppp_ioctl(lcp->ppp->chan_fd, PPPIOCGFLAGS, &flags))
		goto err;

	flags &= ~SC_COMP_AC;
	if (accomp_opt->accomp & 1)
		flags |= SC_COMP_AC;

	if (net->ppp_ioctl(lcp->ppp->chan_fd, PPPIOCSFLAGS, &flags))
		goto err;

	return 0;

err:
	if (errno != EIO)
		log_ppp_error("lcp:accomp: failed to set channel ACCOMP: %s\n", strerror(errno));
	return -1;
}

static void accomp_print(void (*print)(const char *fmt, ...), struct lcp_option_t *opt, uint8_t *ptr)
{
	print("<accomp>");
}

static void load_config(void)
{
	char *opt;

        config_lock();
        pthread_rwlock_wrlock(&config_modify);

	opt = conf_get_opt("ppp", "accomp");
	if (opt) {
		if (!strcmp(opt, "deny"))
			conf_accomp = 0;
		else if (!strcmp(opt, "allow"))
			conf_accomp = 1 | 2;
		else
			conf_accomp = atoi(opt);
	}

	pthread_rwlock_unlock(&config_modify);
        config_unlock();
}

static void accomp_opt_init()
{
	lcp_option_register(&accomp_opt_hnd);

	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(4, accomp_opt_init);
