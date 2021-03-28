#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ppp.h"
#include "ppp_ipcp.h"
#include "log.h"
#include "ipdb.h"
#include "events.h"

#include "memdebug.h"

static in_addr_t conf_dns1;
static in_addr_t conf_dns2;

static struct ipcp_option_t *dns1_init(struct ppp_ipcp_t *ipcp);
static struct ipcp_option_t *dns2_init(struct ppp_ipcp_t *ipcp);
static void dns_free(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt);
static int dns_send_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static int dns_send_conf_nak(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static int dns_recv_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static void dns1_print(void (*print)(const char *fmt, ...), struct ipcp_option_t *, uint8_t *ptr);
static void dns2_print(void (*print)(const char *fmt, ...), struct ipcp_option_t *, uint8_t *ptr);

static pthread_rwlock_t config_modify = PTHREAD_RWLOCK_INITIALIZER;

struct dns_option_t
{
	struct ipcp_option_t opt;
	in_addr_t addr;
};

static struct ipcp_option_handler_t dns1_opt_hnd =
{
	.init = dns1_init,
	.send_conf_req = dns_send_conf_req,
	.send_conf_nak = dns_send_conf_nak,
	.recv_conf_req = dns_recv_conf_req,
	.free = dns_free,
	.print = dns1_print,
};

static struct ipcp_option_handler_t dns2_opt_hnd =
{
	.init = dns2_init,
	.send_conf_req = dns_send_conf_req,
	.send_conf_nak = dns_send_conf_nak,
	.recv_conf_req = dns_recv_conf_req,
	.free = dns_free,
	.print = dns2_print,
};

static struct ipcp_option_t *dns1_init(struct ppp_ipcp_t *ipcp)
{
	struct dns_option_t *dns_opt = _malloc(sizeof(*dns_opt));

	memset(dns_opt, 0, sizeof(*dns_opt));
	dns_opt->opt.id = CI_DNS1;
	dns_opt->opt.len = 6;
	dns_opt->addr = conf_dns1;

	return &dns_opt->opt;
}

static struct ipcp_option_t *dns2_init(struct ppp_ipcp_t *ipcp)
{
	struct dns_option_t *dns_opt = _malloc(sizeof(*dns_opt));

	memset(dns_opt, 0, sizeof(*dns_opt));
	dns_opt->opt.id = CI_DNS2;
	dns_opt->opt.len = 6;
	dns_opt->addr = conf_dns2;

	return &dns_opt->opt;
}

static void dns_free(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt)
{
	struct dns_option_t *dns_opt = container_of(opt, typeof(*dns_opt), opt);

	_free(dns_opt);
}

static int dns_send_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	return 0;
}

static int dns_send_conf_nak(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct dns_option_t *dns_opt = container_of(opt, typeof(*dns_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;
	opt32->hdr.id = dns_opt->opt.id;
	opt32->hdr.len = 6;
	opt32->val = dns_opt->addr;
	return 6;
}

static int dns_recv_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct dns_option_t *dns_opt = container_of(opt, typeof(*dns_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;

	if (opt32->hdr.len != 6)
		return IPCP_OPT_REJ;

	if (!dns_opt->addr)
		return IPCP_OPT_REJ;

	if (dns_opt->addr == opt32->val)
		return IPCP_OPT_ACK;

	return IPCP_OPT_NAK;
}

static void dns1_print(void (*print)(const char *fmt, ...), struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct dns_option_t *dns_opt = container_of(opt, typeof(*dns_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;
	struct in_addr in;

	if (ptr)
		in.s_addr = opt32->val;
	else
		in.s_addr = dns_opt->addr;

	print("<dns1 %s>", inet_ntoa(in));
}

static void dns2_print(void (*print)(const char *fmt, ...), struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct dns_option_t *dns_opt = container_of(opt, typeof(*dns_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;
	struct in_addr in;

	if (ptr)
		in.s_addr = opt32->val;
	else
		in.s_addr = dns_opt->addr;

	print("<dns2 %s>", inet_ntoa(in));
}

static void ev_dns(struct ev_dns_t *ev)
{
	struct dns_option_t *dns_opt;
	struct ppp_t *ppp;

	if (!ev->ses->ctrl->ppp)
		return;

	ppp = container_of(ev->ses, typeof(*ppp), ses);

	if (ev->dns1) {
		dns_opt = container_of(ipcp_find_option(ppp, &dns1_opt_hnd), typeof(*dns_opt), opt);
		dns_opt->addr = ev->dns1;
	}

	if (ev->dns2) {
		dns_opt = container_of(ipcp_find_option(ppp, &dns2_opt_hnd), typeof(*dns_opt), opt);
		dns_opt->addr = ev->dns2;
	}
}

static void load_config(void)
{
	char *opt;

        config_lock();
	pthread_rwlock_wrlock(&config_modify);

	opt = conf_get_opt("dns", "dns1");
	if (opt)
		conf_dns1 = inet_addr(opt);

	opt = conf_get_opt("dns", "dns2");
	if (opt)
		conf_dns2 = inet_addr(opt);

	pthread_rwlock_unlock(&config_modify);
        config_unlock();
}

static void dns_opt_init()
{
	ipcp_option_register(&dns1_opt_hnd);
	ipcp_option_register(&dns2_opt_hnd);

	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	triton_event_register_handler(EV_DNS, (triton_event_func)ev_dns);
}

DEFINE_INIT(4, dns_opt_init);
