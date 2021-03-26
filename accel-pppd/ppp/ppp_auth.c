#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/route.h>

#include "ppp.h"
#include "ipdb.h"
#include "events.h"
#include "ppp_lcp.h"
#include "log.h"

#include "ppp_auth.h"

#include "memdebug.h"

static LIST_HEAD(auth_handlers);
static int conf_noauth = 0;

static struct lcp_option_t *auth_init(struct ppp_lcp_t *lcp);
static void auth_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int auth_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int auth_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int auth_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int auth_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int auth_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void auth_print(void (*print)(const char *fmt,...), struct lcp_option_t*, uint8_t *ptr);

static struct ppp_layer_data_t *auth_layer_init(struct ppp_t*);
static int auth_layer_start(struct ppp_layer_data_t *);
static void auth_layer_finish(struct ppp_layer_data_t *);
static void auth_layer_free(struct ppp_layer_data_t *);

static void __ppp_auth_started(struct ppp_t *ppp);

struct auth_option_t
{
	struct lcp_option_t opt;
	struct list_head auth_list;
	struct auth_data_t *auth;
	unsigned int started:1;
};

struct auth_layer_data_t
{
	struct ppp_layer_data_t ld;
	struct auth_option_t auth_opt;
	struct ppp_t *ppp;
};

static struct lcp_option_handler_t auth_opt_hnd =
{
	.init = auth_init,
	.send_conf_req = auth_send_conf_req,
	.send_conf_nak = auth_send_conf_req,
	.recv_conf_req = auth_recv_conf_req,
	.recv_conf_nak = auth_recv_conf_nak,
	.recv_conf_rej = auth_recv_conf_rej,
	.recv_conf_ack = auth_recv_conf_ack,
	.free = auth_free,
	.print = auth_print,
};

static struct ppp_layer_t auth_layer =
{
	.init = auth_layer_init,
	.start = auth_layer_start,
	.finish = auth_layer_finish,
	.free = auth_layer_free,
};

static struct lcp_option_t *auth_init(struct ppp_lcp_t *lcp)
{
	struct ppp_auth_handler_t *h;
	struct auth_data_t *d;
	struct auth_layer_data_t *ad;
	int auth_data_len = 0;

	ad = container_of(ppp_find_layer_data(lcp->ppp, &auth_layer), typeof(*ad), ld);

	ad->auth_opt.opt.id = CI_AUTH;
	ad->auth_opt.opt.len = 4;

	INIT_LIST_HEAD(&ad->auth_opt.auth_list);

	if (conf_noauth)
		return &ad->auth_opt.opt;

	list_for_each_entry(h, &auth_handlers, entry) {
		d = h->init(lcp->ppp);
		d->h = h;
		list_add_tail(&d->entry, &ad->auth_opt.auth_list);
		if (auth_data_len < d->len)
			auth_data_len = d->len;
	}

	ad->auth_opt.opt.len += auth_data_len;

	return &ad->auth_opt.opt;
}

static void auth_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct auth_option_t *auth_opt = container_of(opt, typeof(*auth_opt), opt);
	struct auth_data_t *d;

	if (auth_opt->started && auth_opt->auth) {
		auth_opt->auth->h->finish(lcp->ppp, auth_opt->auth);
		auth_opt->started = 0;
	}

	while(!list_empty(&auth_opt->auth_list)) {
		d = list_entry(auth_opt->auth_list.next, typeof(*d), entry);
		list_del(&d->entry);
		d->h->free(lcp->ppp, d);
	}
}

static int auth_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt = container_of(opt, typeof(*auth_opt), opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;
	struct auth_data_t *d;
	int n;

	if (list_empty(&auth_opt->auth_list) || conf_noauth)
		return 0;

	if (!auth_opt->auth || auth_opt->auth->state == LCP_OPT_NAK) {
		list_for_each_entry(d, &auth_opt->auth_list, entry) {
			if (d->state == LCP_OPT_NAK || d->state == LCP_OPT_REJ)
				continue;
			auth_opt->auth = d;
			break;
		}
	}

	opt16->hdr.id = CI_AUTH;
	opt16->val = htons(auth_opt->auth->proto);
	n = auth_opt->auth->h->send_conf_req(lcp->ppp, auth_opt->auth, (uint8_t*)(opt16 + 1));
	opt16->hdr.len = 4 + n;

	return 4 + n;
}

static int auth_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	return LCP_OPT_REJ;
}

static int auth_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	return 0;
}

static int auth_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt = container_of(opt, typeof(*auth_opt), opt);
	struct auth_data_t *d;

	if (!auth_opt->auth) {
		log_ppp_error("auth: unexcepcted configure-nak\n");
		return -1;
	}
	auth_opt->auth->state = LCP_OPT_NAK;

	list_for_each_entry(d, &auth_opt->auth_list, entry) {
		if (d->state != LCP_OPT_NAK)
			return 0;
	}

	log_ppp_error("cann't negotiate authentication type\n");
	return -1;
}

static int auth_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt = container_of(opt, typeof(*auth_opt), opt);
	struct auth_data_t *d;

	if (!auth_opt->auth) {
		log_ppp_error("auth: unexcepcted configure-reject\n");
		return -1;
	}

	auth_opt->auth->state = LCP_OPT_NAK;

	list_for_each_entry(d, &auth_opt->auth_list, entry) {
		if (d->state != LCP_OPT_NAK)
			return 0;
	}

	log_ppp_error("cann't negotiate authentication type\n");
	return -1;
}

static void auth_print(void (*print)(const char *fmt,...), struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt = container_of(opt, typeof(*auth_opt), opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;
	struct auth_data_t *d;

	if (ptr) {
		list_for_each_entry(d, &auth_opt->auth_list, entry) {
			if (d->proto == ntohs(opt16->val) && (!d->h->check || d->h->check((uint8_t *)(opt16 + 1))))
				goto print_d;
		}

		print("<auth %02x>", ntohs(opt16->val));
		return;
	} else if (auth_opt->auth)
		d = auth_opt->auth;
	else
		return;

print_d:
	print("<auth %s>", d->h->name);
}

static struct ppp_layer_data_t *auth_layer_init(struct ppp_t *ppp)
{
	struct auth_layer_data_t *ad = _malloc(sizeof(*ad));

	log_ppp_debug("auth_layer_init\n");

	memset(ad, 0, sizeof(*ad));

	ad->ppp = ppp;

	return &ad->ld;
}

static int auth_layer_start(struct ppp_layer_data_t *ld)
{
	struct auth_layer_data_t *ad = container_of(ld,typeof(*ad),ld);

	log_ppp_debug("auth_layer_start\n");

	if (conf_noauth && connect_ppp_channel(ad->ppp))
		return -1;

	if (ad->auth_opt.auth) {
		ad->auth_opt.started = 1;
		ad->auth_opt.auth->h->start(ad->ppp, ad->auth_opt.auth);
	} else {
		log_ppp_debug("auth_layer_started\n");
		ppp_layer_started(ad->ppp, ld);
	}

	return 0;
}

static void auth_layer_finish(struct ppp_layer_data_t *ld)
{
	struct auth_layer_data_t *ad = container_of(ld, typeof(*ad), ld);

	log_ppp_debug("auth_layer_finish\n");

	if (ad->auth_opt.auth)
		ad->auth_opt.auth->h->finish(ad->ppp, ad->auth_opt.auth);

	ad->auth_opt.started = 0;

	log_ppp_debug("auth_layer_finished\n");
	ppp_layer_finished(ad->ppp, ld);
}

static void auth_layer_free(struct ppp_layer_data_t *ld)
{
	struct auth_layer_data_t *ad = container_of(ld, typeof(*ad), ld);

	log_ppp_debug("auth_layer_free\n");

	triton_cancel_call(ad->ppp->ses.ctrl->ctx, (triton_event_func)__ppp_auth_started);

	_free(ad);
}

static void __ppp_auth_started(struct ppp_t *ppp)
{
	struct auth_layer_data_t *ad = container_of(ppp_find_layer_data(ppp, &auth_layer), typeof(*ad), ld);

	if (ppp->ses.terminating)
		return;

	log_ppp_info1("%s: authentication succeeded\n", ppp->ses.username);

	triton_event_fire(EV_SES_AUTHORIZED, &ppp->ses);

	log_ppp_debug("auth_layer_started\n");
	ppp_layer_started(ppp, &ad->ld);
}

int __export ppp_auth_succeeded(struct ppp_t *ppp, char *username)
{
	struct auth_layer_data_t *ad = container_of(ppp_find_layer_data(ppp, &auth_layer), typeof(*ad), ld);

	if (ap_session_set_username(&ppp->ses, username))
		return -1;

	if (connect_ppp_channel(ppp))
		return -1;

	triton_context_call(ppp->ses.ctrl->ctx, (triton_event_func)__ppp_auth_started, ppp);

	return 0;
}

void __export ppp_auth_failed(struct ppp_t *ppp, char *username)
{
	if (username) {
		pthread_rwlock_wrlock(&ses_lock);
		if (!ppp->ses.username)
			ppp->ses.username = username;
		else
			_free(username);
		ppp->ses.terminate_cause = TERM_AUTH_ERROR;
		pthread_rwlock_unlock(&ses_lock);
		log_ppp_info1("%s: authentication failed\n", ppp->ses.username);
		log_info1("%s: authentication failed\n", ppp->ses.username);
		triton_event_fire(EV_SES_AUTH_FAILED, ppp);
	} else
		log_ppp_info1("authentication failed\n");
	ap_session_terminate(&ppp->ses, TERM_AUTH_ERROR, 0);
}

int __export ppp_auth_register_handler(struct ppp_auth_handler_t *h)
{
	list_add_tail(&h->entry, &auth_handlers);
	return 0;
}

int __export ppp_auth_restart(struct ppp_t *ppp)
{
	struct auth_layer_data_t *ad = container_of(ppp_find_layer_data(ppp, &auth_layer), typeof(*ad), ld);
	log_ppp_debug("ppp_auth_restart\n");

	if (!ad->auth_opt.auth->h->restart)
		return -1;

	if (ad->auth_opt.auth->h->restart(ppp, ad->auth_opt.auth))
		return -1;

	return 0;
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("auth", "noauth");
	if (opt)
		conf_noauth = atoi(opt);
	else
		conf_noauth = 0;
}

static void reload_config(void)
{
        config_lock();
        load_config();
        config_unlock();
}

static void ppp_auth_init()
{
	load_config();

	ppp_register_layer("auth", &auth_layer);
	lcp_option_register(&auth_opt_hnd);

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_config);
}

DEFINE_INIT(3, ppp_auth_init);
