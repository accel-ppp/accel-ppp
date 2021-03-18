#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "linux_ppp.h"

#include "ppp.h"
#include "ppp_ipcp.h"
#include "ppp_ccp.h"
#include "log.h"
#include "ipdb.h"
#include "iprange.h"
#include "events.h"

#include "memdebug.h"

static int conf_check_exists;

static struct ipcp_option_t *ipaddr_init(struct ppp_ipcp_t *ipcp);
static void ipaddr_free(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt);
static int ipaddr_send_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static int ipaddr_send_conf_nak(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static int ipaddr_recv_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
//static int ipaddr_recv_conf_ack(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static void ipaddr_print(void (*print)(const char *fmt,...),struct ipcp_option_t*, uint8_t *ptr);

struct ipaddr_option_t
{
	struct ipcp_option_t opt;
	struct ppp_t *ppp;
	unsigned int started:1;
};

static struct ipcp_option_handler_t ipaddr_opt_hnd = {
	.init          = ipaddr_init,
	.send_conf_req = ipaddr_send_conf_req,
	.send_conf_nak = ipaddr_send_conf_nak,
	.recv_conf_req = ipaddr_recv_conf_req,
	.free          = ipaddr_free,
	.print         = ipaddr_print,
};

static struct ipcp_option_t *ipaddr_init(struct ppp_ipcp_t *ipcp)
{
	struct ipaddr_option_t *ipaddr_opt = _malloc(sizeof(*ipaddr_opt));
	memset(ipaddr_opt, 0, sizeof(*ipaddr_opt));
	ipaddr_opt->opt.id = CI_ADDR;
	ipaddr_opt->opt.len = 6;
	ipaddr_opt->ppp = ipcp->ppp;

	return &ipaddr_opt->opt;
}

static void ipaddr_free(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);

	_free(ipaddr_opt);
}

static int check_exists(struct ppp_t *self_ppp, in_addr_t addr)
{
	struct ap_session *ses;
	int r = 0;

	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		if (!ses->terminating && ses->ipv4 && ses->ipv4->peer_addr == addr && ses != &self_ppp->ses) {
			log_ppp_warn("ppp: requested IPv4 address already assigned to %s\n", ses->ifname);
			r = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&ses_lock);

	return r;
}

static int alloc_ip(struct ppp_t *ppp)
{
	ppp->ses.ipv4 = ipdb_get_ipv4(&ppp->ses);
	if (!ppp->ses.ipv4) {
		log_ppp_warn("ppp: no free IPv4 address\n");
		return IPCP_OPT_CLOSE;
	}

	if (ppp->ses.ctrl->type != CTRL_TYPE_PPPOE &&
	    iprange_tunnel_check(ppp->ses.ipv4->peer_addr)) {
		log_ppp_warn("ppp:ipcp: to avoid kernel soft lockup requested IP cannot be assigned (%i.%i.%i.%i)\n",
			ppp->ses.ipv4->peer_addr&0xff,
			(ppp->ses.ipv4->peer_addr >> 8)&0xff,
			(ppp->ses.ipv4->peer_addr >> 16)&0xff,
			(ppp->ses.ipv4->peer_addr >> 24)&0xff);
		return IPCP_OPT_FAIL;
	}

	if (conf_check_exists && check_exists(ppp, ppp->ses.ipv4->peer_addr))
		return IPCP_OPT_FAIL;

	return 0;
}

static int ipaddr_send_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;
	int r;

	if (!ipcp->ppp->ses.ipv4) {
		r = alloc_ip(ipcp->ppp);
		if (r)
			return r;
	}

	opt32->hdr.id = CI_ADDR;
	opt32->hdr.len = 6;
	opt32->val = ipcp->ppp->ses.ipv4->addr;
	return 6;
}

static int ipaddr_send_conf_nak(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;
	opt32->hdr.id = CI_ADDR;
	opt32->hdr.len = 6;
	opt32->val = ipcp->ppp->ses.ipv4->peer_addr;
	return 6;
}

static int ipaddr_recv_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t *)ptr;
	int r;

	if (!ipcp->ppp->ses.ipv4) {
		r = alloc_ip(ipcp->ppp);
		if (r)
			return r;
	}

	if (opt32->hdr.len != 6)
		return IPCP_OPT_REJ;

	if (ipcp->ppp->ses.ipv4->peer_addr == opt32->val) {
		ipcp->delay_ack = ccp_ipcp_started(ipcp->ppp);
		return IPCP_OPT_ACK;
	}

	return IPCP_OPT_NAK;
}

static void ipaddr_print(void (*print)(const char *fmt,...),struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);
	struct ipcp_opt32_t *opt32=(struct ipcp_opt32_t*)ptr;
	struct in_addr in = { .s_addr = 0, };

	if (ptr)
		in.s_addr = opt32->val;
	else if (ipaddr_opt->ppp->ses.ipv4)
		in.s_addr = ipaddr_opt->ppp->ses.ipv4->addr;

	print("<addr %s>",inet_ntoa(in));
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("ppp", "check-ip");
	if (!opt)
		opt = conf_get_opt("common", "check-ip");
	if (opt && atoi(opt) >= 0)
		conf_check_exists = atoi(opt) > 0;
}

static void ipaddr_opt_init()
{
	ipcp_option_register(&ipaddr_opt_hnd);
	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(4, ipaddr_opt_init);

