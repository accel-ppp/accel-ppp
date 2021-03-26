#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ppp.h"
#include "ppp_ipcp.h"
#include "log.h"
#include "ipdb.h"
#include "events.h"

#include "memdebug.h"

static in_addr_t conf_wins1;
static in_addr_t conf_wins2;

static struct ipcp_option_t *wins1_init(struct ppp_ipcp_t *ipcp);
static struct ipcp_option_t *wins2_init(struct ppp_ipcp_t *ipcp);
static void wins_free(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt);
static int wins_send_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static int wins_send_conf_nak(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static int wins_recv_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static void wins1_print(void (*print)(const char *fmt, ...), struct ipcp_option_t *, uint8_t *ptr);
static void wins2_print(void (*print)(const char *fmt, ...), struct ipcp_option_t *, uint8_t *ptr);

struct wins_option_t
{
	struct ipcp_option_t opt;
	in_addr_t addr;
};

static struct ipcp_option_handler_t wins1_opt_hnd =
{
	.init = wins1_init,
	.send_conf_req = wins_send_conf_req,
	.send_conf_nak = wins_send_conf_nak,
	.recv_conf_req = wins_recv_conf_req,
	.free = wins_free,
	.print = wins1_print,
};

static struct ipcp_option_handler_t wins2_opt_hnd =
{
	.init = wins2_init,
	.send_conf_req = wins_send_conf_req,
	.send_conf_nak = wins_send_conf_nak,
	.recv_conf_req = wins_recv_conf_req,
	.free = wins_free,
	.print = wins2_print,
};

static struct ipcp_option_t *wins1_init(struct ppp_ipcp_t *ipcp)
{
	struct wins_option_t *wins_opt = _malloc(sizeof(*wins_opt));

	memset(wins_opt, 0, sizeof(*wins_opt));
	wins_opt->opt.id = CI_WINS1;
	wins_opt->opt.len = 6;
	wins_opt->addr = conf_wins1;

	return &wins_opt->opt;
}

static struct ipcp_option_t *wins2_init(struct ppp_ipcp_t *ipcp)
{
	struct wins_option_t *wins_opt = _malloc(sizeof(*wins_opt));

	memset(wins_opt, 0, sizeof(*wins_opt));
	wins_opt->opt.id = CI_WINS2;
	wins_opt->opt.len = 6;
	wins_opt->addr = conf_wins2;

	return &wins_opt->opt;
}

static void wins_free(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt)
{
	struct wins_option_t *wins_opt = container_of(opt, typeof(*wins_opt), opt);

	_free(wins_opt);
}

static int wins_send_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	return 0;
}

static int wins_send_conf_nak(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct wins_option_t *wins_opt = container_of(opt, typeof(*wins_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;
	opt32->hdr.id = wins_opt->opt.id;
	opt32->hdr.len = 6;
	opt32->val = wins_opt->addr;
	return 6;
}

static int wins_recv_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct wins_option_t *wins_opt = container_of(opt, typeof(*wins_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;

	if (opt32->hdr.len != 6)
		return IPCP_OPT_REJ;

	if (!wins_opt->addr)
		return IPCP_OPT_REJ;

	if (wins_opt->addr == opt32->val)
		return IPCP_OPT_ACK;

	return IPCP_OPT_NAK;
}

static void wins1_print(void (*print)(const char *fmt, ...), struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct wins_option_t *wins_opt = container_of(opt, typeof(*wins_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;
	struct in_addr in;

	if (ptr)
		in.s_addr = opt32->val;
	else
		in.s_addr = wins_opt->addr;

	print("<wins1 %s>", inet_ntoa(in));
}

static void wins2_print(void (*print)(const char *fmt, ...), struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct wins_option_t *wins_opt = container_of(opt, typeof(*wins_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;
	struct in_addr in;

	if (ptr)
		in.s_addr = opt32->val;
	else
		in.s_addr = wins_opt->addr;

	print("<wins2 %s>", inet_ntoa(in));
}

static void ev_wins(struct ev_wins_t *ev)
{
	struct wins_option_t *wins_opt;
	struct ppp_t *ppp;

	if (!ev->ses->ctrl->ppp)
		return;

	ppp = container_of(ev->ses, typeof(*ppp), ses);

	if (ev->wins1) {
		wins_opt = container_of(ipcp_find_option(ppp, &wins1_opt_hnd), typeof(*wins_opt), opt);
		wins_opt->addr = ev->wins1;
	}

	if (ev->wins2) {
		wins_opt = container_of(ipcp_find_option(ppp, &wins2_opt_hnd), typeof(*wins_opt), opt);
		wins_opt->addr = ev->wins2;
	}
}

static void load_config(void)
{
	char *opt;

	opt = conf_get_opt("wins", "wins1");
	if (opt)
		conf_wins1 = inet_addr(opt);

	opt = conf_get_opt("wins", "wins2");
	if (opt)
		conf_wins2 = inet_addr(opt);
}

static void reload_config(void)
{
        config_lock();
        load_config();
        config_unlock();
}

static void wins_opt_init()
{
	ipcp_option_register(&wins1_opt_hnd);
	ipcp_option_register(&wins2_opt_hnd);

	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_config);

	triton_event_register_handler(EV_WINS, (triton_event_func)ev_wins);
}

DEFINE_INIT(4, wins_opt_init);
