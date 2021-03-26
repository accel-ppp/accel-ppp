#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "linux_ppp.h"

#include "triton.h"

#include "log.h"
#include "events.h"

#include "ppp.h"
#include "ppp_ipcp.h"
#include "ipdb.h"

#include "memdebug.h"

struct recv_opt_t
{
	struct list_head entry;
	struct ipcp_opt_hdr_t *hdr;
	int len;
	int state;
	struct ipcp_option_t *lopt;
};

#define IPV4_DENY 0
#define IPV4_ALLOW 1
#define IPV4_PREFERE 2
#define IPV4_REQUIRE 3

#define START_TIMEOUT 60

static int conf_ipv4 = IPV4_ALLOW;

static LIST_HEAD(option_handlers);
static struct ppp_layer_t ipcp_layer;

static void ipcp_layer_up(struct ppp_fsm_t*);
static void ipcp_layer_down(struct ppp_fsm_t*);
static void ipcp_layer_finished(struct ppp_fsm_t*);
static int send_conf_req(struct ppp_fsm_t*);
static void send_conf_ack(struct ppp_fsm_t*);
static void send_conf_nak(struct ppp_fsm_t*);
static void send_conf_rej(struct ppp_fsm_t*);
static void ipcp_recv(struct ppp_handler_t*);
static void ipcp_recv_proto_rej(struct ppp_handler_t*);
static void send_term_req(struct ppp_fsm_t *fsm);
static void send_term_ack(struct ppp_fsm_t *fsm);

static void ipcp_options_init(struct ppp_ipcp_t *ipcp)
{
	struct ipcp_option_t *lopt;
	struct ipcp_option_handler_t *h;

	ipcp->conf_req_len = sizeof(struct ipcp_hdr_t);

	list_for_each_entry(h,&option_handlers,entry) {
		lopt = h->init(ipcp);
		if (lopt) {
			lopt->h = h;
			list_add_tail(&lopt->entry, &ipcp->options);
			ipcp->conf_req_len += lopt->len;
		}
	}
}

static void ipcp_options_free(struct ppp_ipcp_t *ipcp)
{
	struct ipcp_option_t *lopt;

	while (!list_empty(&ipcp->options)) {
		lopt = list_entry(ipcp->options.next, typeof(*lopt), entry);
		list_del(&lopt->entry);
		lopt->h->free(ipcp, lopt);
	}
}

static struct ppp_layer_data_t *ipcp_layer_init(struct ppp_t *ppp)
{
	struct ppp_ipcp_t *ipcp = _malloc(sizeof(*ipcp));
	memset(ipcp, 0, sizeof(*ipcp));

	log_ppp_debug("ipcp_layer_init\n");

	ipcp->ppp = ppp;
	ipcp->fsm.ppp = ppp;

	ipcp->hnd.proto = PPP_IPCP;
	ipcp->hnd.recv = ipcp_recv;
	ipcp->hnd.recv_proto_rej = ipcp_recv_proto_rej;

	ppp_register_unit_handler(ppp, &ipcp->hnd);

	INIT_LIST_HEAD(&ipcp->options);
	ipcp_options_init(ipcp);

	ipcp->fsm.proto = PPP_IPCP;
	ppp_fsm_init(&ipcp->fsm);

	ipcp->fsm.layer_up = ipcp_layer_up;
	ipcp->fsm.layer_finished = ipcp_layer_finished;
	ipcp->fsm.layer_down = ipcp_layer_down;
	ipcp->fsm.send_conf_req = send_conf_req;
	ipcp->fsm.send_conf_ack = send_conf_ack;
	ipcp->fsm.send_conf_nak = send_conf_nak;
	ipcp->fsm.send_conf_rej = send_conf_rej;
	ipcp->fsm.send_term_req = send_term_req;
	ipcp->fsm.send_term_ack = send_term_ack;

	INIT_LIST_HEAD(&ipcp->ropt_list);

	ipcp->ld.passive = conf_ipv4 == IPV4_ALLOW || conf_ipv4 == IPV4_DENY;

	return &ipcp->ld;
}

static void ipcp_start_timeout(struct triton_timer_t *t)
{
	struct ppp_ipcp_t *ipcp = container_of(t, typeof(*ipcp), timeout);

	triton_timer_del(t);

	if (ipcp->ppp->ses.state == AP_STATE_STARTING)
		ap_session_terminate(&ipcp->ppp->ses, TERM_USER_ERROR, 0);
}

int ipcp_layer_start(struct ppp_layer_data_t *ld)
{
	struct ppp_ipcp_t *ipcp = container_of(ld, typeof(*ipcp), ld);

	log_ppp_debug("ipcp_layer_start\n");

	ipcp->starting = 1;

	if (conf_ipv4 != IPV4_DENY) {
		if (ipcp->ld.passive) {
			ipcp->timeout.expire = ipcp_start_timeout;
			ipcp->timeout.expire_tv.tv_sec = START_TIMEOUT;
			triton_timer_add(ipcp->ppp->ses.ctrl->ctx, &ipcp->timeout, 0);
		} else {
			ppp_fsm_lower_up(&ipcp->fsm);
			if (ppp_fsm_open(&ipcp->fsm))
				return -1;
		}
	}

	return 0;
}

void ipcp_layer_finish(struct ppp_layer_data_t *ld)
{
	struct ppp_ipcp_t *ipcp = container_of(ld, typeof(*ipcp), ld);

	log_ppp_debug("ipcp_layer_finish\n");

	ipcp->fsm.fsm_state = FSM_Closed;

	log_ppp_debug("ipcp_layer_finished\n");
	ppp_layer_finished(ipcp->ppp, &ipcp->ld);
}

void ipcp_layer_free(struct ppp_layer_data_t *ld)
{
	struct ppp_ipcp_t *ipcp = container_of(ld, typeof(*ipcp), ld);

	log_ppp_debug("ipcp_layer_free\n");

	ppp_unregister_handler(ipcp->ppp, &ipcp->hnd);
	ipcp_options_free(ipcp);
	ppp_fsm_free(&ipcp->fsm);

	if (ipcp->timeout.tpd)
		triton_timer_del(&ipcp->timeout);

	_free(ipcp);
}

static void __ipcp_layer_up(struct ppp_ipcp_t *ipcp)
{
	log_ppp_debug("ipcp_layer_started\n");

	if (!ipcp->started) {
		ipcp->started = 1;
		ppp_layer_started(ipcp->ppp, &ipcp->ld);
	}
}

static void ipcp_layer_up(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp = container_of(fsm, typeof(*ipcp), fsm);

	if (!ipcp->delay_ack)
		__ipcp_layer_up(ipcp);
}

static void ipcp_layer_finished(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp = container_of(fsm, typeof(*ipcp), fsm);

	log_ppp_debug("ipcp_layer_finished\n");

	if (!ipcp->started) {
		if (conf_ipv4 == IPV4_REQUIRE)
			ap_session_terminate(&ipcp->ppp->ses, TERM_USER_ERROR, 0);
		else
			ppp_layer_passive(ipcp->ppp, &ipcp->ld);
	} else if (!ipcp->ppp->ses.terminating)
		ap_session_terminate(&ipcp->ppp->ses, TERM_USER_ERROR, 0);

	fsm->fsm_state = FSM_Closed;
}

static void ipcp_layer_down(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp = container_of(fsm, typeof(*ipcp), fsm);

	log_ppp_debug("ipcp_layer_down\n");

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
	struct ppp_ipcp_t *ipcp = container_of(fsm, typeof(*ipcp), fsm);
	uint8_t *buf = _malloc(ipcp->conf_req_len), *ptr = buf;
	struct ipcp_hdr_t *ipcp_hdr = (struct ipcp_hdr_t*)ptr;
	struct ipcp_option_t *lopt;
	int n;

	ipcp_hdr->proto = htons(PPP_IPCP);
	ipcp_hdr->code = CONFREQ;
	ipcp_hdr->id = ipcp->fsm.id;
	ipcp_hdr->len = 0;

	ptr += sizeof(*ipcp_hdr);

	list_for_each_entry(lopt, &ipcp->options, entry) {
		n = lopt->h->send_conf_req(ipcp, lopt, ptr);
		if (n < 0) {
			if (n == IPCP_OPT_TERMACK)
				goto out;
			if (n == IPCP_OPT_CLOSE && conf_ipv4 != IPV4_REQUIRE) {
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
		log_ppp_info2("send [IPCP ConfReq id=%x", ipcp_hdr->id);
		list_for_each_entry(lopt,&ipcp->options,entry) {
			if (lopt->print) {
				log_ppp_info2(" ");
				lopt->h->print(log_ppp_info2, lopt, NULL);
			}
		}
		log_ppp_info2("]\n");
	}

	ipcp_hdr->len = htons(ptr - buf - 2);
	ppp_unit_send(ipcp->ppp, ipcp_hdr, ptr - buf);

out:
	_free(buf);

	return 0;
}

static void send_conf_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp = container_of(fsm, typeof(*ipcp), fsm);
	struct ipcp_hdr_t *hdr = (struct ipcp_hdr_t*)ipcp->ppp->buf;

	if (ipcp->delay_ack) {
		send_term_ack(fsm);
		return;
	}

	hdr->code = CONFACK;

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPCP ConfAck id=%x]\n", ipcp->fsm.recv_id);

	ppp_unit_send(ipcp->ppp, hdr, ntohs(hdr->len) + 2);
}

static void send_conf_nak(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp = container_of(fsm, typeof(*ipcp), fsm);
	uint8_t *buf = _malloc(ipcp->conf_req_len), *ptr = buf, *ptr1;
	struct ipcp_hdr_t *ipcp_hdr = (struct ipcp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPCP ConfNak id=%x", ipcp->fsm.recv_id);

	ipcp_hdr->proto = htons(PPP_IPCP);
	ipcp_hdr->code = CONFNAK;
	ipcp_hdr->id = ipcp->fsm.recv_id;
	ipcp_hdr->len = 0;

	ptr += sizeof(*ipcp_hdr);

	list_for_each_entry(ropt, &ipcp->ropt_list, entry) {
		if (ropt->state == IPCP_OPT_NAK) {
			ptr1 = ptr;
			ptr += ropt->lopt->h->send_conf_nak(ipcp, ropt->lopt, ptr);
			if (conf_ppp_verbose) {
				log_ppp_info2(" ");
				ropt->lopt->h->print(log_ppp_info2, ropt->lopt, ptr1);
			}
		}
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	ipcp_hdr->len = htons(ptr-buf-2);
	ppp_unit_send(ipcp->ppp, ipcp_hdr, ptr - buf);

	_free(buf);
}

static void send_conf_rej(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp = container_of(fsm, typeof(*ipcp), fsm);
	uint8_t *buf = _malloc(ipcp->ropt_len + sizeof(struct ipcp_hdr_t)), *ptr = buf;
	struct ipcp_hdr_t *ipcp_hdr = (struct ipcp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPCP ConfRej id=%x", ipcp->fsm.recv_id);

	ipcp_hdr->proto = htons(PPP_IPCP);
	ipcp_hdr->code = CONFREJ;
	ipcp_hdr->id = ipcp->fsm.recv_id;
	ipcp_hdr->len = 0;

	ptr += sizeof(*ipcp_hdr);

	list_for_each_entry(ropt, &ipcp->ropt_list, entry) {
		if (ropt->state == IPCP_OPT_REJ) {
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

	ipcp_hdr->len = htons(ptr - buf - 2);
	ppp_unit_send(ipcp->ppp, ipcp_hdr, ptr-buf);

	_free(buf);
}

static int ipcp_recv_conf_req(struct ppp_ipcp_t *ipcp, uint8_t *data, int size)
{
	struct ipcp_opt_hdr_t *hdr;
	struct recv_opt_t *ropt;
	struct ipcp_option_t *lopt;
	int r,ret = 1;

	ipcp->ropt_len = size;

	while (size > 0) {
		hdr = (struct ipcp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		ropt = _malloc(sizeof(*ropt));
		memset(ropt, 0, sizeof(*ropt));

		ropt->hdr = hdr;
		ropt->len = hdr->len;
		ropt->state = IPCP_OPT_NONE;
		list_add_tail(&ropt->entry, &ipcp->ropt_list);

		data += hdr->len;
		size -= hdr->len;
	}

	list_for_each_entry(lopt, &ipcp->options, entry)
		lopt->state=IPCP_OPT_NONE;

	if (conf_ppp_verbose) {
		log_ppp_info2("recv [IPCP ConfReq id=%x", ipcp->fsm.recv_id);

		list_for_each_entry(ropt, &ipcp->ropt_list, entry) {
			list_for_each_entry(lopt, &ipcp->options, entry) {
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

	list_for_each_entry(ropt, &ipcp->ropt_list, entry) {
		list_for_each_entry(lopt, &ipcp->options, entry) {
			if (lopt->id == ropt->hdr->id) {
				r = lopt->h->recv_conf_req(ipcp, lopt, (uint8_t*)ropt->hdr);
				if (r == IPCP_OPT_TERMACK) {
					send_term_ack(&ipcp->fsm);
					return 0;
				}
				if (r == IPCP_OPT_CLOSE) {
					if (conf_ipv4 == IPV4_REQUIRE)
						ap_session_terminate(&ipcp->ppp->ses, TERM_NAS_ERROR, 0);
					else
						lcp_send_proto_rej(ipcp->ppp, PPP_IPCP);
					return 0;
				}
				if (ipcp->ppp->ses.stop_time)
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
			ropt->state = IPCP_OPT_REJ;
			ret = IPCP_OPT_REJ;
		}
	}


	/*list_for_each_entry(lopt,&ipcp->options,entry)
	{
		if (lopt->state==IPCP_OPT_NONE)
		{
			r=lopt->h->recv_conf_req(ipcp,lopt,NULL);
			lopt->state=r;
			if (r<ret) ret=r;
		}
	}*/

	return ret;
}

static void ipcp_free_conf_req(struct ppp_ipcp_t *ipcp)
{
	struct recv_opt_t *ropt;

	while (!list_empty(&ipcp->ropt_list)) {
		ropt = list_entry(ipcp->ropt_list.next, typeof(*ropt), entry);
		list_del(&ropt->entry);
		_free(ropt);
	}
}

static int ipcp_recv_conf_rej(struct ppp_ipcp_t *ipcp, uint8_t *data, int size)
{
	struct ipcp_opt_hdr_t *hdr;
	struct ipcp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [IPCP ConfRej id=%x", ipcp->fsm.recv_id);

	/*if (ipcp->fsm.recv_id != ipcp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}*/

	while (size > 0) {
		hdr = (struct ipcp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &ipcp->options, entry) {
			if (lopt->id == hdr->id) {
				if (!lopt->h->recv_conf_rej)
					res = -1;
				else if (lopt->h->recv_conf_rej(ipcp, lopt, data))
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

static int ipcp_recv_conf_nak(struct ppp_ipcp_t *ipcp, uint8_t *data, int size)
{
	struct ipcp_opt_hdr_t *hdr;
	struct ipcp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [IPCP ConfNak id=%x", ipcp->fsm.recv_id);

	/*if (ipcp->fsm.recv_id != ipcp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}*/

	while (size > 0) {
		hdr = (struct ipcp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &ipcp->options, entry) {
			if (lopt->id == hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2,lopt,data);
				}
				if (lopt->h->recv_conf_nak && lopt->h->recv_conf_nak(ipcp, lopt, data))
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

static int ipcp_recv_conf_ack(struct ppp_ipcp_t *ipcp, uint8_t *data, int size)
{
	struct ipcp_opt_hdr_t *hdr;
	struct ipcp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [IPCP ConfAck id=%x", ipcp->fsm.recv_id);

	/*if (ipcp->fsm.recv_id != ipcp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}*/

	while (size > 0) {
		hdr = (struct ipcp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &ipcp->options, entry) {
			if (lopt->id == hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2, lopt, data);
				}
				if (!lopt->h->recv_conf_ack)
					break;
				if (lopt->h->recv_conf_ack(ipcp, lopt, data))
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
	struct ppp_ipcp_t *ipcp = container_of(fsm, typeof(*ipcp), fsm);
	struct ipcp_hdr_t hdr = {
		.proto = htons(PPP_IPCP),
		.code = TERMREQ,
		.id = ++ipcp->fsm.id,
		.len = htons(4),
	};

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPCP TermReq id=%x]\n", hdr.id);

	ppp_unit_send(ipcp->ppp, &hdr, 6);
}

static void send_term_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp = container_of(fsm, typeof(*ipcp), fsm);
	struct ipcp_hdr_t hdr = {
		.proto = htons(PPP_IPCP),
		.code = TERMACK,
		.id = ipcp->fsm.recv_id,
		.len = htons(4),
	};

	if (conf_ppp_verbose)
		log_ppp_info2("send [IPCP TermAck id=%x]\n", hdr.id);

	ppp_unit_send(ipcp->ppp, &hdr, 6);
}

static void ipcp_recv(struct ppp_handler_t*h)
{
	struct ipcp_hdr_t *hdr;
	struct ppp_ipcp_t *ipcp = container_of(h, typeof(*ipcp), hnd);
	int r;
	int delay_ack = ipcp->delay_ack;

	if (!ipcp->starting || ipcp->fsm.fsm_state == FSM_Closed || ipcp->ppp->ses.terminating || conf_ipv4 == IPV4_DENY) {
		if (conf_ppp_verbose)
			log_ppp_warn("IPCP: discarding packet\n");
		if (ipcp->ppp->ses.terminating)
			return;
		if (ipcp->fsm.fsm_state == FSM_Closed || conf_ipv4 == IPV4_DENY)
			lcp_send_proto_rej(ipcp->ppp, PPP_IPCP);
		return;
	}

	if (ipcp->ppp->buf_size < PPP_HEADERLEN + 2) {
		log_ppp_warn("IPCP: short packet received\n");
		return;
	}

	hdr = (struct ipcp_hdr_t *)ipcp->ppp->buf;
	if (ntohs(hdr->len) < PPP_HEADERLEN) {
		log_ppp_warn("IPCP: short packet received\n");
		return;
	}

	if ((hdr->code == CONFACK || hdr->code == CONFNAK || hdr->code == CONFREJ) && hdr->id != ipcp->fsm.id)
		return;

	ipcp->fsm.recv_id = hdr->id;

	switch(hdr->code) {
		case CONFREQ:
			r = ipcp_recv_conf_req(ipcp,(uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN);
			if (ipcp->ppp->ses.stop_time) {
				ipcp_free_conf_req(ipcp);
				return;
			}
			if (r && ipcp->ld.passive) {
				ipcp->ld.passive = 0;
				ppp_fsm_lower_up(&ipcp->fsm);
				ppp_fsm_open(&ipcp->fsm);
				triton_timer_del(&ipcp->timeout);
			}
			if (delay_ack && !ipcp->delay_ack)
				__ipcp_layer_up(ipcp);
			if (ipcp->started || delay_ack) {
				if (r == IPCP_OPT_ACK)
					send_conf_ack(&ipcp->fsm);
				else
					r = IPCP_OPT_FAIL;
			} else {
				switch(r) {
					case IPCP_OPT_ACK:
						ppp_fsm_recv_conf_req_ack(&ipcp->fsm);
						break;
					case IPCP_OPT_NAK:
						ppp_fsm_recv_conf_req_nak(&ipcp->fsm);
						break;
					case IPCP_OPT_REJ:
						ppp_fsm_recv_conf_req_rej(&ipcp->fsm);
						break;
				}
			}
			ipcp_free_conf_req(ipcp);
			if (r == IPCP_OPT_FAIL)
				ap_session_terminate(&ipcp->ppp->ses, TERM_USER_ERROR, 0);
			break;
		case CONFACK:
			if (ipcp_recv_conf_ack(ipcp,(uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN))
				ap_session_terminate(&ipcp->ppp->ses, TERM_USER_ERROR, 0);
			else
				ppp_fsm_recv_conf_ack(&ipcp->fsm);
			break;
		case CONFNAK:
			ipcp_recv_conf_nak(ipcp,(uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN);
			ppp_fsm_recv_conf_rej(&ipcp->fsm);
			break;
		case CONFREJ:
			if (ipcp_recv_conf_rej(ipcp, (uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN))
				ap_session_terminate(&ipcp->ppp->ses, TERM_USER_ERROR, 0);
			else
				ppp_fsm_recv_conf_rej(&ipcp->fsm);
			break;
		case TERMREQ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [IPCP TermReq id=%x]\n", hdr->id);
			ppp_fsm_recv_term_req(&ipcp->fsm);
			ap_session_terminate(&ipcp->ppp->ses, TERM_USER_REQUEST, 0);
			break;
		case TERMACK:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [IPCP TermAck id=%x]\n", hdr->id);
			//ppp_fsm_recv_term_ack(&ipcp->fsm);
			//ap_session_terminate(&ipcp->ppp->ses, 0);
			break;
		case CODEREJ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [IPCP CodeRej id=%x]\n", hdr->id);
			ppp_fsm_recv_code_rej_bad(&ipcp->fsm);
			break;
		default:
			ppp_fsm_recv_unk(&ipcp->fsm);
			break;
	}
}

static void ipcp_recv_proto_rej(struct ppp_handler_t*h)
{
	struct ppp_ipcp_t *ipcp = container_of(h, typeof(*ipcp), hnd);

	if (ipcp->fsm.fsm_state == FSM_Initial || ipcp->fsm.fsm_state == FSM_Closed)
		return;

	ppp_fsm_lower_down(&ipcp->fsm);
	ppp_fsm_close(&ipcp->fsm);
}

int ipcp_option_register(struct ipcp_option_handler_t *h)
{
	/*struct ipcp_option_drv_t *p;

	list_for_each_entry(p,option_drv_list,entry)
		if (p->id==h->id)
			return -1;*/

	list_add_tail(&h->entry, &option_handlers);

	return 0;
}

struct ipcp_option_t *ipcp_find_option(struct ppp_t *ppp, struct ipcp_option_handler_t *h)
{
	struct ppp_ipcp_t *ipcp = container_of(ppp_find_layer_data(ppp, &ipcp_layer), typeof(*ipcp), ld);
	struct ipcp_option_t *opt;

	list_for_each_entry(opt, &ipcp->options, entry)
		if (opt->h == h)
			return opt;

	log_emerg("ipcp: BUG: option not found\n");
	abort();
}

static struct ppp_layer_t ipcp_layer =
{
	.init   = ipcp_layer_init,
	.start  = ipcp_layer_start,
	.finish = ipcp_layer_finish,
	.free   = ipcp_layer_free,
};

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("ppp", "ipv4");
	if (opt) {
		if (!strcmp(opt, "deny"))
			conf_ipv4 = IPV4_DENY;
		else if (!strcmp(opt, "allow"))
			conf_ipv4 = IPV4_ALLOW;
		else if (!strcmp(opt, "prefer") || !strcmp(opt, "prefere"))
			conf_ipv4 = IPV4_PREFERE;
		else if (!strcmp(opt, "require"))
			conf_ipv4 = IPV4_REQUIRE;
		else
			conf_ipv4 = atoi(opt);
	}
}

static void reload_config(void)
{
        config_lock();
        load_config();
        config_unlock();
}

static void ipcp_init(void)
{
	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_config);

	ppp_register_layer("ipcp", &ipcp_layer);
}

DEFINE_INIT(4, ipcp_init);
