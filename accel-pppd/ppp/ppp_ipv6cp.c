#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "linux_ppp.h"

#include "triton.h"

#include "log.h"
#include "events.h"

#include "ppp.h"
#include "ppp_ipv6cp.h"
#include "ipdb.h"

#include "memdebug.h"

struct recv_opt_t
{
	struct list_head entry;
	struct ipv6cp_opt_hdr_t *hdr;
	int len;
	int state;
	struct ipv6cp_option_t *lopt;
};

#define IPV6_DENY 0
#define IPV6_ALLOW 1
#define IPV6_PREFERE 2
#define IPV6_REQUIRE 3

#define START_TIMEOUT 60

static int conf_ipv6 = IPV6_DENY;

static LIST_HEAD(option_handlers);
static struct ppp_layer_t ipv6cp_layer;

static void ipv6cp_layer_up(struct ppp_fsm_t*);
static void ipv6cp_layer_down(struct ppp_fsm_t*);
static void ipv6cp_layer_finished(struct ppp_fsm_t*);
static int send_conf_req(struct ppp_fsm_t*);
static void send_conf_ack(struct ppp_fsm_t*);
static void send_conf_nak(struct ppp_fsm_t*);
static void send_conf_rej(struct ppp_fsm_t*);
static void ipv6cp_recv(struct ppp_handler_t*);
static void ipv6cp_recv_proto_rej(struct ppp_handler_t*);
static void send_term_req(struct ppp_fsm_t *fsm);
static void send_term_ack(struct ppp_fsm_t *fsm);

static pthread_rwlock_t config_modify = PTHREAD_RWLOCK_INITIALIZER;

static void ipv6cp_options_init(struct ppp_ipv6cp_t *ipv6cp)
{
	struct ipv6cp_option_t *lopt;
	struct ipv6cp_option_handler_t *h;

	ipv6cp->conf_req_len = sizeof(struct ipv6cp_hdr_t);

	list_for_each_entry(h,&option_handlers,entry) {
		lopt = h->init(ipv6cp);
		if (lopt) {
			lopt->h = h;
			list_add_tail(&lopt->entry, &ipv6cp->options);
			ipv6cp->conf_req_len += lopt->len;
		}
	}
}

static void ipv6cp_options_free(struct ppp_ipv6cp_t *ipv6cp)
{
	struct ipv6cp_option_t *lopt;

	while (!list_empty(&ipv6cp->options)) {
		lopt = list_entry(ipv6cp->options.next, typeof(*lopt), entry);
		list_del(&lopt->entry);
		lopt->h->free(ipv6cp, lopt);
	}
}

static struct ppp_layer_data_t *ipv6cp_layer_init(struct ppp_t *ppp)
{
	struct ppp_ipv6cp_t *ipv6cp = _malloc(sizeof(*ipv6cp));
	memset(ipv6cp, 0, sizeof(*ipv6cp));

	log_ppp_debug("ipv6cp_layer_init\n");

	ipv6cp->ppp = ppp;
	ipv6cp->fsm.ppp = ppp;

	ipv6cp->hnd.proto = PPP_IPV6CP;
	ipv6cp->hnd.recv = ipv6cp_recv;
	ipv6cp->hnd.recv_proto_rej = ipv6cp_recv_proto_rej;

	ppp_register_unit_handler(ppp, &ipv6cp->hnd);

	ipv6cp->fsm.proto = PPP_IPV6CP;
	ppp_fsm_init(&ipv6cp->fsm);

	ipv6cp->fsm.layer_up = ipv6cp_layer_up;
	ipv6cp->fsm.layer_finished = ipv6cp_layer_finished;
	ipv6cp->fsm.layer_down = ipv6cp_layer_down;
	ipv6cp->fsm.send_conf_req = send_conf_req;
	ipv6cp->fsm.send_conf_ack = send_conf_ack;
	ipv6cp->fsm.send_conf_nak = send_conf_nak;
	ipv6cp->fsm.send_conf_rej = send_conf_rej;
	ipv6cp->fsm.send_term_req = send_term_req;
	ipv6cp->fsm.send_term_ack = send_term_ack;

	INIT_LIST_HEAD(&ipv6cp->options);
	INIT_LIST_HEAD(&ipv6cp->ropt_list);

	ipv6cp->ld.passive = conf_ipv6 == IPV6_ALLOW || conf_ipv6 == IPV6_DENY;

	return &ipv6cp->ld;
}

static void ipv6cp_start_timeout(struct triton_timer_t *t)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(t, typeof(*ipv6cp), timeout);

	triton_timer_del(t);

	if (ipv6cp->ppp->ses.state == AP_STATE_STARTING)
		ap_session_terminate(&ipv6cp->ppp->ses, TERM_USER_ERROR, 0);
}

int ipv6cp_layer_start(struct ppp_layer_data_t *ld)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(ld, typeof(*ipv6cp), ld);

	log_ppp_debug("ipv6cp_layer_start\n");

	ipv6cp_options_init(ipv6cp);

	ipv6cp->starting = 1;

	if (conf_ipv6 != IPV6_DENY) {
		if (ipv6cp->ld.passive) {
			ipv6cp->timeout.expire = ipv6cp_start_timeout;
			ipv6cp->timeout.expire_tv.tv_sec = START_TIMEOUT;
			triton_timer_add(ipv6cp->ppp->ses.ctrl->ctx, &ipv6cp->timeout, 0);
		} else {
			ppp_fsm_lower_up(&ipv6cp->fsm);
			if (ppp_fsm_open(&ipv6cp->fsm))
				return -1;
		}
	}

	return 0;
}

void ipv6cp_layer_finish(struct ppp_layer_data_t *ld)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(ld, typeof(*ipv6cp), ld);

	log_ppp_debug("ipv6cp_layer_finish\n");

	ipv6cp->fsm.fsm_state = FSM_Closed;

	log_ppp_debug("ipv6cp_layer_finished\n");
	ppp_layer_finished(ipv6cp->ppp, &ipv6cp->ld);
}

void ipv6cp_layer_free(struct ppp_layer_data_t *ld)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(ld, typeof(*ipv6cp), ld);

	log_ppp_debug("ipv6cp_layer_free\n");

	ppp_unregister_handler(ipv6cp->ppp, &ipv6cp->hnd);
	ipv6cp_options_free(ipv6cp);
	ppp_fsm_free(&ipv6cp->fsm);

	if (ipv6cp->timeout.tpd)
		triton_timer_del(&ipv6cp->timeout);

	_free(ipv6cp);
}

static void __ipv6cp_layer_up(struct ppp_ipv6cp_t *ipv6cp)
{
	log_ppp_debug("ipv6cp_layer_started\n");

	if (!ipv6cp->started) {
		ipv6cp->started = 1;
		ppp_layer_started(ipv6cp->ppp, &ipv6cp->ld);
	}
}

static void ipv6cp_layer_up(struct ppp_fsm_t *fsm)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(fsm, typeof(*ipv6cp), fsm);

	if (!ipv6cp->delay_ack)
		__ipv6cp_layer_up(ipv6cp);
}

static void ipv6cp_layer_finished(struct ppp_fsm_t *fsm)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(fsm, typeof(*ipv6cp), fsm);

	log_ppp_debug("ipv6cp_layer_finished\n");

	if (!ipv6cp->started) {
		if (conf_ipv6 == IPV6_REQUIRE)
			ap_session_terminate(&ipv6cp->ppp->ses, TERM_USER_ERROR, 0);
		else
			ppp_layer_passive(ipv6cp->ppp, &ipv6cp->ld);
	} else if (!ipv6cp->ppp->ses.terminating)
		ap_session_terminate(&ipv6cp->ppp->ses, TERM_USER_ERROR, 0);

	fsm->fsm_state = FSM_Closed;
}

static void ipv6cp_layer_down(struct ppp_fsm_t *fsm)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(fsm, typeof(*ipv6cp), fsm);

	log_ppp_debug("ipv6cp_layer_down\n");

	ppp_fsm_close(fsm);
}

static void print_ropt(struct recv_opt_t *ropt)
{
	int i;
	uint8_t *ptr = (uint8_t*)ropt->hdr;

	log_ppp_info2("<");
	for (i = 0; i < ropt->len; i++) {
		log_ppp_info2(" %x", ptr[i]);
	}
	log_ppp_info2(" >");
}

static int send_conf_req(struct ppp_fsm_t *fsm)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(fsm, typeof(*ipv6cp), fsm);
	uint8_t *buf = _malloc(ipv6cp->conf_req_len), *ptr = buf;
	struct ipv6cp_hdr_t *ipv6cp_hdr = (struct ipv6cp_hdr_t*)ptr;
	struct ipv6cp_option_t *lopt;
	int n;

	ipv6cp_hdr->proto = htons(PPP_IPV6CP);
	ipv6cp_hdr->code = CONFREQ;
	ipv6cp_hdr->id = ipv6cp->fsm.id;
	ipv6cp_hdr->len = 0;

	ptr += sizeof(*ipv6cp_hdr);

	list_for_each_entry(lopt, &ipv6cp->options, entry) {
		n = lopt->h->send_conf_req(ipv6cp, lopt, ptr);
		if (n < 0) {
			if (n == IPV6CP_OPT_TERMACK)
				goto out;
			if (n == IPV6CP_OPT_CLOSE && conf_ipv6 != IPV6_REQUIRE) {
				ppp_fsm_close2(fsm);
				goto out;
			}
			_free(buf);
			return -1;
		}
		if (n) {
			ptr += n;
			lopt->print = 1;
		} else
			lopt->print = 0;
	}

	if (conf_ppp_verbose) {
		log_ppp_info2("send [IPV6CP ConfReq id=%x", ipv6cp_hdr->id);
		list_for_each_entry(lopt,&ipv6cp->options,entry) {
			if (lopt->print) {
				log_ppp_info2(" ");
				lopt->h->print(log_ppp_info2, lopt, NULL);
			}
		}
		log_ppp_info2("]\n");
	}

	ipv6cp_hdr->len = htons(ptr - buf - 2);
	ppp_unit_send(ipv6cp->ppp, ipv6cp_hdr, ptr - buf);

out:
	_free(buf);

	return 0;
}

static void send_conf_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(fsm, typeof(*ipv6cp), fsm);
	struct ipv6cp_hdr_t *hdr = (struct ipv6cp_hdr_t*)ipv6cp->ppp->buf;

	if (ipv6cp->delay_ack) {
		send_term_ack(fsm);
		return;
	}

	hdr->code = CONFACK;

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPV6CP ConfAck id=%x]\n", ipv6cp->fsm.recv_id);

	ppp_unit_send(ipv6cp->ppp, hdr, ntohs(hdr->len) + 2);
}

static void send_conf_nak(struct ppp_fsm_t *fsm)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(fsm, typeof(*ipv6cp), fsm);
	uint8_t *buf = _malloc(ipv6cp->conf_req_len), *ptr = buf, *ptr1;
	struct ipv6cp_hdr_t *ipv6cp_hdr = (struct ipv6cp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPV6CP ConfNak id=%x", ipv6cp->fsm.recv_id);

	ipv6cp_hdr->proto = htons(PPP_IPV6CP);
	ipv6cp_hdr->code = CONFNAK;
	ipv6cp_hdr->id = ipv6cp->fsm.recv_id;
	ipv6cp_hdr->len = 0;

	ptr += sizeof(*ipv6cp_hdr);

	list_for_each_entry(ropt, &ipv6cp->ropt_list, entry) {
		if (ropt->state == IPV6CP_OPT_NAK) {
			ptr1 = ptr;
			ptr += ropt->lopt->h->send_conf_nak(ipv6cp, ropt->lopt, ptr);
			if (conf_ppp_verbose) {
				log_ppp_info2(" ");
				ropt->lopt->h->print(log_ppp_info2, ropt->lopt, ptr1);
			}
		}
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	ipv6cp_hdr->len = htons(ptr-buf-2);
	ppp_unit_send(ipv6cp->ppp, ipv6cp_hdr, ptr - buf);

	_free(buf);
}

static void send_conf_rej(struct ppp_fsm_t *fsm)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(fsm, typeof(*ipv6cp), fsm);
	uint8_t *buf = _malloc(ipv6cp->ropt_len + sizeof(struct ipv6cp_hdr_t)), *ptr = buf;
	struct ipv6cp_hdr_t *ipv6cp_hdr = (struct ipv6cp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPV6CP ConfRej id=%x", ipv6cp->fsm.recv_id);

	ipv6cp_hdr->proto = htons(PPP_IPV6CP);
	ipv6cp_hdr->code = CONFREJ;
	ipv6cp_hdr->id = ipv6cp->fsm.recv_id;
	ipv6cp_hdr->len = 0;

	ptr += sizeof(*ipv6cp_hdr);

	list_for_each_entry(ropt, &ipv6cp->ropt_list, entry) {
		if (ropt->state == IPV6CP_OPT_REJ) {
			if (conf_ppp_verbose) {
				log_ppp_info2(" ");
				if (ropt->lopt)
					ropt->lopt->h->print(log_ppp_info2, ropt->lopt, (uint8_t*)ropt->hdr);
				else
					print_ropt(ropt);
			}
			memcpy(ptr, ropt->hdr, ropt->len);
			ptr += ropt->len;
		}
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	ipv6cp_hdr->len = htons(ptr - buf - 2);
	ppp_unit_send(ipv6cp->ppp, ipv6cp_hdr, ptr-buf);

	_free(buf);
}

static int ipv6cp_recv_conf_req(struct ppp_ipv6cp_t *ipv6cp, uint8_t *data, int size)
{
	struct ipv6cp_opt_hdr_t *hdr;
	struct recv_opt_t *ropt;
	struct ipv6cp_option_t *lopt;
	int r,ret = 1;

	ipv6cp->ropt_len = size;

	while (size > 0) {
		hdr = (struct ipv6cp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		ropt = _malloc(sizeof(*ropt));
		memset(ropt, 0, sizeof(*ropt));

		ropt->hdr = hdr;
		ropt->len = hdr->len;
		ropt->state = IPV6CP_OPT_NONE;
		list_add_tail(&ropt->entry, &ipv6cp->ropt_list);

		data += hdr->len;
		size -= hdr->len;
	}

	list_for_each_entry(lopt, &ipv6cp->options, entry)
		lopt->state=IPV6CP_OPT_NONE;

	if (conf_ppp_verbose) {
		log_ppp_info2("recv [IPV6CP ConfReq id=%x", ipv6cp->fsm.recv_id);

		list_for_each_entry(ropt, &ipv6cp->ropt_list, entry) {
			list_for_each_entry(lopt, &ipv6cp->options, entry) {
				if (lopt->id == ropt->hdr->id) {
					ropt->lopt = lopt;
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2, lopt, (uint8_t*)ropt->hdr);
					break;
				}
			}
			if (!ropt->lopt) {
				log_ppp_info2(" ");
				print_ropt(ropt);
			}
		}
		log_ppp_info2("]\n");
	}

	list_for_each_entry(ropt, &ipv6cp->ropt_list, entry) {
		list_for_each_entry(lopt, &ipv6cp->options, entry) {
			if (lopt->id == ropt->hdr->id) {
				r = lopt->h->recv_conf_req(ipv6cp, lopt, (uint8_t*)ropt->hdr);
				if (r == IPV6CP_OPT_TERMACK) {
					send_term_ack(&ipv6cp->fsm);
					return 0;
				}
				if (r == IPV6CP_OPT_CLOSE) {
					if (conf_ipv6 == IPV6_REQUIRE)
						ap_session_terminate(&ipv6cp->ppp->ses, TERM_NAS_ERROR, 0);
					else
						lcp_send_proto_rej(ipv6cp->ppp, PPP_IPV6CP);
					return 0;
				}
				if (ipv6cp->ppp->ses.stop_time)
					return -1;
				lopt->state = r;
				ropt->state = r;
				ropt->lopt = lopt;
				if (r < ret)
					ret = r;
				break;
			}
		}
		if (!ropt->lopt) {
			ropt->state = IPV6CP_OPT_REJ;
			ret = IPV6CP_OPT_REJ;
		}
	}


	/*list_for_each_entry(lopt,&ipv6cp->options,entry)
	{
		if (lopt->state==IPV6CP_OPT_NONE)
		{
			r=lopt->h->recv_conf_req(ipv6cp,lopt,NULL);
			lopt->state=r;
			if (r<ret) ret=r;
		}
	}*/

	return ret;
}

static void ipv6cp_free_conf_req(struct ppp_ipv6cp_t *ipv6cp)
{
	struct recv_opt_t *ropt;

	while (!list_empty(&ipv6cp->ropt_list)) {
		ropt = list_entry(ipv6cp->ropt_list.next, typeof(*ropt), entry);
		list_del(&ropt->entry);
		_free(ropt);
	}
}

static int ipv6cp_recv_conf_rej(struct ppp_ipv6cp_t *ipv6cp, uint8_t *data, int size)
{
	struct ipv6cp_opt_hdr_t *hdr;
	struct ipv6cp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [IPV6CP ConfRej id=%x", ipv6cp->fsm.recv_id);

	/*if (ipv6cp->fsm.recv_id != ipv6cp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}*/

	while (size > 0) {
		hdr = (struct ipv6cp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &ipv6cp->options, entry) {
			if (lopt->id == hdr->id) {
				if (!lopt->h->recv_conf_rej)
					res = -1;
				else if (lopt->h->recv_conf_rej(ipv6cp, lopt, data))
					res = -1;
				break;
			}
		}

		data += hdr->len;
		size -= hdr->len;
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	return res;
}

static int ipv6cp_recv_conf_nak(struct ppp_ipv6cp_t *ipv6cp, uint8_t *data, int size)
{
	struct ipv6cp_opt_hdr_t *hdr;
	struct ipv6cp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [IPV6CP ConfNak id=%x", ipv6cp->fsm.recv_id);

	/*if (ipv6cp->fsm.recv_id != ipv6cp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}*/

	while (size > 0) {
		hdr = (struct ipv6cp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &ipv6cp->options, entry) {
			if (lopt->id == hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2,lopt,data);
				}
				if (lopt->h->recv_conf_nak && lopt->h->recv_conf_nak(ipv6cp, lopt, data))
					res =- 1;
				break;
			}
		}

		data += hdr->len;
		size -= hdr->len;
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	return res;
}

static int ipv6cp_recv_conf_ack(struct ppp_ipv6cp_t *ipv6cp, uint8_t *data, int size)
{
	struct ipv6cp_opt_hdr_t *hdr;
	struct ipv6cp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [IPV6CP ConfAck id=%x", ipv6cp->fsm.recv_id);

	/*if (ipv6cp->fsm.recv_id != ipv6cp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}*/

	while (size > 0) {
		hdr = (struct ipv6cp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &ipv6cp->options, entry) {
			if (lopt->id == hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2, lopt, data);
				}
				if (!lopt->h->recv_conf_ack)
					break;
				if (lopt->h->recv_conf_ack(ipv6cp, lopt, data))
					res = -1;
				break;
			}
		}

		data += hdr->len;
		size -= hdr->len;
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	return res;
}

static void send_term_req(struct ppp_fsm_t *fsm)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(fsm, typeof(*ipv6cp), fsm);
	struct ipv6cp_hdr_t hdr = {
		.proto = htons(PPP_IPV6CP),
		.code = TERMREQ,
		.id = ++ipv6cp->fsm.id,
		.len = htons(4),
	};

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPV6CP TermReq id=%x]\n", hdr.id);

	ppp_unit_send(ipv6cp->ppp, &hdr, 6);
}

static void send_term_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(fsm, typeof(*ipv6cp), fsm);
	struct ipv6cp_hdr_t hdr = {
		.proto = htons(PPP_IPV6CP),
		.code = TERMACK,
		.id = ipv6cp->fsm.recv_id,
		.len = htons(4),
	};

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPV6CP TermAck id=%x]\n", hdr.id);

	ppp_unit_send(ipv6cp->ppp, &hdr, 6);
}

static void ipv6cp_recv(struct ppp_handler_t*h)
{
	struct ipv6cp_hdr_t *hdr;
	struct ppp_ipv6cp_t *ipv6cp = container_of(h, typeof(*ipv6cp), hnd);
	int r;
	int delay_ack = ipv6cp->delay_ack;

	if (!ipv6cp->starting || ipv6cp->fsm.fsm_state == FSM_Closed || ipv6cp->ppp->ses.terminating || conf_ipv6 == IPV6_DENY) {
		if (conf_ppp_verbose)
			log_ppp_warn("IPV6CP: discarding packet\n");
		if (ipv6cp->ppp->ses.terminating)
			return;
		if (ipv6cp->fsm.fsm_state == FSM_Closed || conf_ipv6 == IPV6_DENY)
			lcp_send_proto_rej(ipv6cp->ppp, PPP_IPV6CP);
		return;
	}

	if (ipv6cp->ppp->buf_size < PPP_HEADERLEN + 2) {
		log_ppp_warn("IPV6CP: short packet received\n");
		return;
	}

	hdr = (struct ipv6cp_hdr_t *)ipv6cp->ppp->buf;
	if (ntohs(hdr->len) < PPP_HEADERLEN) {
		log_ppp_warn("IPV6CP: short packet received\n");
		return;
	}

	if ((hdr->code == CONFACK || hdr->code == CONFNAK || hdr->code == CONFREJ) && hdr->id != ipv6cp->fsm.id)
		return;

	ipv6cp->fsm.recv_id = hdr->id;

	switch(hdr->code) {
		case CONFREQ:
			r = ipv6cp_recv_conf_req(ipv6cp,(uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN);
			if (ipv6cp->ppp->ses.stop_time) {
				ipv6cp_free_conf_req(ipv6cp);
				return;
			}
			if (r && ipv6cp->ld.passive) {
				ipv6cp->ld.passive = 0;
				ppp_fsm_lower_up(&ipv6cp->fsm);
				ppp_fsm_open(&ipv6cp->fsm);
				triton_timer_del(&ipv6cp->timeout);
			}
			if (delay_ack && !ipv6cp->delay_ack)
				__ipv6cp_layer_up(ipv6cp);
			if (ipv6cp->started || delay_ack) {
				if (r == IPV6CP_OPT_ACK)
					send_conf_ack(&ipv6cp->fsm);
				else
					r = IPV6CP_OPT_FAIL;
			} else {
				switch(r) {
					case IPV6CP_OPT_ACK:
						ppp_fsm_recv_conf_req_ack(&ipv6cp->fsm);
						break;
					case IPV6CP_OPT_NAK:
						ppp_fsm_recv_conf_req_nak(&ipv6cp->fsm);
						break;
					case IPV6CP_OPT_REJ:
						ppp_fsm_recv_conf_req_rej(&ipv6cp->fsm);
						break;
				}
			}
			ipv6cp_free_conf_req(ipv6cp);
			if (r == IPV6CP_OPT_FAIL)
				ap_session_terminate(&ipv6cp->ppp->ses, TERM_USER_ERROR, 0);
			break;
		case CONFACK:
			if (ipv6cp_recv_conf_ack(ipv6cp,(uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN))
				ap_session_terminate(&ipv6cp->ppp->ses, TERM_USER_ERROR, 0);
			else
				ppp_fsm_recv_conf_ack(&ipv6cp->fsm);
			break;
		case CONFNAK:
			ipv6cp_recv_conf_nak(ipv6cp,(uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN);
			ppp_fsm_recv_conf_rej(&ipv6cp->fsm);
			break;
		case CONFREJ:
			if (ipv6cp_recv_conf_rej(ipv6cp, (uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN))
				ap_session_terminate(&ipv6cp->ppp->ses, TERM_USER_ERROR, 0);
			else
				ppp_fsm_recv_conf_rej(&ipv6cp->fsm);
			break;
		case TERMREQ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [IPV6CP TermReq id=%x]\n", hdr->id);
			ppp_fsm_recv_term_req(&ipv6cp->fsm);
			ap_session_terminate(&ipv6cp->ppp->ses, TERM_USER_REQUEST, 0);
			break;
		case TERMACK:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [IPV6CP TermAck id=%x]\n", hdr->id);
			//ppp_fsm_recv_term_ack(&ipv6cp->fsm);
			//ap_session_terminate(&ipv6cp->ppp->ses, 0);
			break;
		case CODEREJ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [IPV6CP CodeRej id=%x]\n", hdr->id);
			ppp_fsm_recv_code_rej_bad(&ipv6cp->fsm);
			break;
		default:
			ppp_fsm_recv_unk(&ipv6cp->fsm);
			break;
	}
}

static void ipv6cp_recv_proto_rej(struct ppp_handler_t*h)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(h, typeof(*ipv6cp), hnd);

	if (ipv6cp->fsm.fsm_state == FSM_Initial || ipv6cp->fsm.fsm_state == FSM_Closed)
		return;

	ppp_fsm_lower_down(&ipv6cp->fsm);
	ppp_fsm_close(&ipv6cp->fsm);
}

int ipv6cp_option_register(struct ipv6cp_option_handler_t *h)
{
	/*struct ipv6cp_option_drv_t *p;

	list_for_each_entry(p,option_drv_list,entry)
		if (p->id==h->id)
			return -1;*/

	list_add_tail(&h->entry, &option_handlers);

	return 0;
}

struct ipv6cp_option_t *ipv6cp_find_option(struct ppp_t *ppp, struct ipv6cp_option_handler_t *h)
{
	struct ppp_ipv6cp_t *ipv6cp = container_of(ppp_find_layer_data(ppp, &ipv6cp_layer), typeof(*ipv6cp), ld);
	struct ipv6cp_option_t *opt;

	list_for_each_entry(opt, &ipv6cp->options, entry)
		if (opt->h == h)
			return opt;

	log_emerg("ipv6cp: BUG: option not found\n");
	abort();
}

static struct ppp_layer_t ipv6cp_layer =
{
	.init   = ipv6cp_layer_init,
	.start  = ipv6cp_layer_start,
	.finish = ipv6cp_layer_finish,
	.free   = ipv6cp_layer_free,
};

static void load_config(void)
{
	const char *opt;

        config_lock();
	pthread_rwlock_wrlock(&config_modify);

	opt = conf_get_opt("ppp", "ipv6");
	if (opt) {
		if (!strcmp(opt, "deny"))
			conf_ipv6 = IPV6_DENY;
		else if (!strcmp(opt, "allow"))
			conf_ipv6 = IPV6_ALLOW;
		else if (!strcmp(opt, "prefer") || !strcmp(opt, "prefere"))
			conf_ipv6 = IPV6_PREFERE;
		else if (!strcmp(opt, "require"))
			conf_ipv6 = IPV6_REQUIRE;
		else
			conf_ipv6 = atoi(opt);
	}

	pthread_rwlock_unlock(&config_modify);
        config_unlock();
}

static void ipv6cp_init(void)
{
	if (sock6_fd < 0)
		return;

	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	ppp_register_layer("ipv6cp", &ipv6cp_layer);
}

DEFINE_INIT(5, ipv6cp_init);
