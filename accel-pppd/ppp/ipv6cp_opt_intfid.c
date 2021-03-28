#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "linux_ppp.h"

#include "log.h"
#include "events.h"
#include "ppp.h"
#include "ppp_ccp.h"
#include "ppp_ipv6cp.h"
#include "ipdb.h"

#include "memdebug.h"

#define INTF_ID_FIXED  0
#define INTF_ID_RANDOM 1
#define INTF_ID_CSID   2
#define INTF_ID_IPV4   3

static int conf_check_exists;
static int conf_intf_id = INTF_ID_FIXED;
static uint64_t conf_intf_id_val = 1;
static int conf_peer_intf_id = INTF_ID_FIXED;
static uint64_t conf_peer_intf_id_val = 2;
static int conf_accept_peer_intf_id;

static struct ipv6cp_option_t *ipaddr_init(struct ppp_ipv6cp_t *ipv6cp);
static void ipaddr_free(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt);
static int ipaddr_send_conf_req(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr);
static int ipaddr_send_conf_nak(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr);
static int ipaddr_recv_conf_req(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr);
//static int ipaddr_recv_conf_ack(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr);
static void ipaddr_print(void (*print)(const char *fmt,...),struct ipv6cp_option_t*, uint8_t *ptr);
static void put_ipv6_item(struct ap_session *ses, struct ipv6db_item_t *ip6);

struct ipaddr_option_t
{
	struct ipv6cp_option_t opt;
	unsigned int started:1;
	struct ppp_t *ppp;
};

static struct ipv6cp_option_handler_t ipaddr_opt_hnd =
{
	.init          = ipaddr_init,
	.send_conf_req = ipaddr_send_conf_req,
	.send_conf_nak = ipaddr_send_conf_nak,
	.recv_conf_req = ipaddr_recv_conf_req,
	.free          = ipaddr_free,
	.print         = ipaddr_print,
};

static pthread_rwlock_t config_modify = PTHREAD_RWLOCK_INITIALIZER;

/* ipdb backend used for generating a link-local address when all other
 * backends (like radius and ipv6pool) failed to assign IPv6 addresses.
 * This backend isn't registered to ipdb as it's only used as a fallback
 * during IPv6CP negociation.
 */
static struct ipdb_t ipv6db = {
	.put_ipv6 = put_ipv6_item
};

static void put_ipv6_item(struct ap_session *ses, struct ipv6db_item_t *ip6)
{
	_free(ip6);
}

static int gen_ipv6_item(struct ap_session *ses)
{
	struct ipv6db_item_t *ip6 = NULL;

	ip6 = _malloc(sizeof(*ip6));
	if (ip6 == NULL) {
		log_ppp_warn("ppp: allocation of IPv6 address failed\n");
		return -1;
	}

	memset(ip6, 0, sizeof(*ip6));
	ip6->owner = &ipv6db;
	ip6->intf_id = 0;
	ip6->peer_intf_id = 0;
	INIT_LIST_HEAD(&ip6->addr_list);

	ses->ipv6 = ip6;

	return 0;
}

static struct ipv6cp_option_t *ipaddr_init(struct ppp_ipv6cp_t *ipv6cp)
{
	struct ipaddr_option_t *ipaddr_opt = _malloc(sizeof(*ipaddr_opt));

	memset(ipaddr_opt, 0, sizeof(*ipaddr_opt));

	ipaddr_opt->opt.id = CI_INTFID;
	ipaddr_opt->opt.len = 10;
	ipaddr_opt->ppp = ipv6cp->ppp;

	return &ipaddr_opt->opt;
}

static void ipaddr_free(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);

	_free(ipaddr_opt);
}

static int check_exists(struct ppp_t *self_ppp)
{
	struct ap_session *ses;
	struct ipv6db_addr_t *a1, *a2;
	int r = 0;

	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		if (ses->terminating)
			continue;
		if (!ses->ipv6)
			continue;
		if (ses == &self_ppp->ses)
			continue;

		list_for_each_entry(a1, &ses->ipv6->addr_list, entry) {
			list_for_each_entry(a2, &self_ppp->ses.ipv6->addr_list, entry) {
				if (a1->addr.s6_addr32[0] == a2->addr.s6_addr32[0] &&
						a1->addr.s6_addr32[1] == a2->addr.s6_addr32[1]) {
					log_ppp_warn("ppp: requested IPv6 address already assigned to %s\n", ses->ifname);
					r = 1;
					goto out;
				}
			}
		}
	}
out:
	pthread_rwlock_unlock(&ses_lock);

	return r;
}

static uint64_t generate_intf_id(struct ppp_t *ppp)
{
	uint64_t id = 0;

	switch (conf_intf_id) {
		case INTF_ID_FIXED:
			return conf_intf_id_val;
			break;
		//case INTF_ID_RANDOM:
		default:
			read(urandom_fd, &id, 8);
			break;
	}

	return id;
}

static uint64_t generate_peer_intf_id(struct ppp_t *ppp)
{
	char str[4];
	int i;
	unsigned int n;
	union {
		uint64_t intf_id;
		uint16_t addr16[4];
	} u;

	switch (conf_peer_intf_id) {
		case INTF_ID_FIXED:
			return conf_peer_intf_id_val;
			break;
		case INTF_ID_RANDOM:
			read(urandom_fd, &u, sizeof(u));
			break;
		case INTF_ID_CSID:
			break;
		case INTF_ID_IPV4:
			if (ppp->ses.ipv4) {
				for (i = 0; i < 4; i++) {
					sprintf(str, "%i", (ppp->ses.ipv4->peer_addr >> (i*8)) & 0xff);
					sscanf(str, "%x", &n);
					u.addr16[i] = htons(n);
				}
			} else
				return 0;
	}

	return u.intf_id;
}

static int alloc_ip(struct ppp_t *ppp)
{
	ppp->ses.ipv6 = ipdb_get_ipv6(&ppp->ses);
	if (!ppp->ses.ipv6) {
		if (gen_ipv6_item(&ppp->ses) < 0) {
			log_ppp_warn("ppp: no free IPv6 address\n");
			return IPV6CP_OPT_CLOSE;
		}
	}

	if (!ppp->ses.ipv6->intf_id)
		ppp->ses.ipv6->intf_id = generate_intf_id(ppp);

	if (conf_check_exists && check_exists(ppp))
		return IPV6CP_OPT_FAIL;

	return 0;
}

static int ipaddr_send_conf_req(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipv6cp_opt64_t *opt64 = (struct ipv6cp_opt64_t *)ptr;
	int r;

	if (!ipv6cp->ppp->ses.ipv6) {
		r = alloc_ip(ipv6cp->ppp);
		if (r)
			return r;
	}

	opt64->hdr.id = CI_INTFID;
	opt64->hdr.len = 10;
	opt64->val = ipv6cp->ppp->ses.ipv6->intf_id;
	return 10;
}

static int ipaddr_send_conf_nak(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipv6cp_opt64_t *opt64 = (struct ipv6cp_opt64_t *)ptr;
	opt64->hdr.id = CI_INTFID;
	opt64->hdr.len = 10;
	opt64->val = ipv6cp->ppp->ses.ipv6->peer_intf_id;
	return 10;
}

static int ipaddr_recv_conf_req(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipv6cp_opt64_t *opt64 = (struct ipv6cp_opt64_t* )ptr;
	int r;

	if (opt64->hdr.len != 10)
		return IPV6CP_OPT_REJ;

	if (!ipv6cp->ppp->ses.ipv6) {
		r = alloc_ip(ipv6cp->ppp);
		if (r)
			return r;
	}

	if (conf_accept_peer_intf_id && opt64->val)
		ipv6cp->ppp->ses.ipv6->peer_intf_id = opt64->val;
	else if (!ipv6cp->ppp->ses.ipv6->peer_intf_id) {
		ipv6cp->ppp->ses.ipv6->peer_intf_id = generate_peer_intf_id(ipv6cp->ppp);
		if (!ipv6cp->ppp->ses.ipv6->peer_intf_id)
			return IPV6CP_OPT_TERMACK;
	}

	if (opt64->val && ipv6cp->ppp->ses.ipv6->peer_intf_id == opt64->val && opt64->val != ipv6cp->ppp->ses.ipv6->intf_id) {
		ipv6cp->delay_ack = ccp_ipcp_started(ipv6cp->ppp);
		ipaddr_opt->started = 1;
		return IPV6CP_OPT_ACK;
	}

	return IPV6CP_OPT_NAK;
}

static void ipaddr_print(void (*print)(const char *fmt,...), struct ipv6cp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipv6cp_opt64_t *opt64 = (struct ipv6cp_opt64_t *)ptr;
	struct in6_addr a;

	if (ptr)
		*(uint64_t *)(a.s6_addr + 8) = opt64->val;
	else
		*(uint64_t *)(a.s6_addr + 8) = ipaddr_opt->ppp->ses.ipv6->intf_id;

	print("<addr %x:%x:%x:%x>", ntohs(a.s6_addr16[4]), ntohs(a.s6_addr16[5]), ntohs(a.s6_addr16[6]), ntohs(a.s6_addr16[7]));
}

static uint64_t parse_intfid(const char *opt)
{
	union {
		uint64_t u64;
		uint16_t u16[4];
	} u;

	unsigned int n[4];
	int i;

	if (sscanf(opt, "%x:%x:%x:%x", &n[0], &n[1], &n[2], &n[3]) != 4)
		goto err;

	for (i = 0; i < 4; i++) {
		if (n[i] > 0xffff)
			goto err;
		u.u16[i] = htons(n[i]);
	}

	return u.u64;

err:
	log_error("ppp:ipv6cp: failed to parse intf-id '%s'\n", opt);
	conf_intf_id = INTF_ID_RANDOM;
	return 0;
}

static void load_config(void)
{
	const char *opt;

        config_lock();
	pthread_rwlock_wrlock(&config_modify);

	opt = conf_get_opt("ppp", "check-ip");
	if (!opt)
		opt = conf_get_opt("common", "check-ip");
	if (opt && atoi(opt) >= 0)
		conf_check_exists = atoi(opt) > 0;

	opt = conf_get_opt("ppp", "ipv6-intf-id");
	if (opt) {
		if (!strcmp(opt, "random"))
			conf_intf_id = INTF_ID_RANDOM;
		else {
			conf_intf_id = INTF_ID_FIXED;
			conf_intf_id_val = parse_intfid(opt);
		}
	}

	opt = conf_get_opt("ppp", "ipv6-peer-intf-id");
	if (opt) {
		if (!strcmp(opt, "random"))
			conf_peer_intf_id = INTF_ID_RANDOM;
		else if (!strcmp(opt, "calling-sid"))
			conf_peer_intf_id = INTF_ID_CSID;
		else if (!strcmp(opt, "ipv4"))
			conf_peer_intf_id = INTF_ID_IPV4;
		else {
			conf_peer_intf_id = INTF_ID_FIXED;
			conf_peer_intf_id_val = parse_intfid(opt);
		}
	}

	opt = conf_get_opt("ppp", "ipv6-accept-peer-intf-id");
	if (opt)
		conf_accept_peer_intf_id = atoi(opt);

	pthread_rwlock_unlock(&config_modify);
        config_unlock();
}

static void init()
{
	if (sock6_fd < 0)
		return;

	ipv6cp_option_register(&ipaddr_opt_hnd);
	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(5, init);

