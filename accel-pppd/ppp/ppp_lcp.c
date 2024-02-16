#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "linux_ppp.h"

#include "triton.h"

#include "log.h"

#include "ppp.h"
#include "ppp_lcp.h"
#include "events.h"
#include "iputils.h"

#include "memdebug.h"

struct recv_opt_t
{
	struct list_head entry;
	struct lcp_opt_hdr_t *hdr;
	int len;
	int state;
	struct lcp_option_t *lopt;
};

static int conf_echo_interval = 10;
static int conf_echo_failure = 0;
static int conf_echo_timeout = 60;

static LIST_HEAD(option_handlers);
static struct ppp_layer_t lcp_layer;

static void lcp_layer_up(struct ppp_fsm_t*);
static void lcp_layer_down(struct ppp_fsm_t*);
static void lcp_layer_finished(struct ppp_fsm_t*);
static int send_conf_req(struct ppp_fsm_t*);
static void send_conf_ack(struct ppp_fsm_t*);
static void send_conf_nak(struct ppp_fsm_t*);
static void send_conf_rej(struct ppp_fsm_t*);
static void send_code_rej(struct ppp_fsm_t*);
static void start_echo(struct ppp_lcp_t *lcp);
static void stop_echo(struct ppp_lcp_t *lcp);
static void send_term_req(struct ppp_fsm_t *fsm);
static void send_term_ack(struct ppp_fsm_t *fsm);
static void lcp_recv(struct ppp_handler_t*);

static void lcp_options_init(struct ppp_lcp_t *lcp)
{
	struct lcp_option_t *lopt;
	struct lcp_option_handler_t *h;

	INIT_LIST_HEAD(&lcp->options);

	lcp->conf_req_len = sizeof(struct lcp_hdr_t);

	list_for_each_entry(h, &option_handlers, entry) {
		lopt = h->init(lcp);
		if (lopt) {
			lopt->h = h;
			list_add_tail(&lopt->entry, &lcp->options);
			lcp->conf_req_len += lopt->len;
		}
	}
}

static void lcp_options_free(struct ppp_lcp_t *lcp)
{
	struct lcp_option_t *lopt;

	while (!list_empty(&lcp->options)) {
		lopt = list_entry(lcp->options.next, typeof(*lopt), entry);
		list_del(&lopt->entry);
		lopt->h->free(lcp, lopt);
	}
}

static struct ppp_layer_data_t *lcp_layer_init(struct ppp_t *ppp)
{
	struct ppp_lcp_t *lcp = _malloc(sizeof(*lcp));
	memset(lcp, 0, sizeof(*lcp));

	log_ppp_debug("lcp_layer_init\n");

	lcp->ppp = ppp;
	lcp->fsm.ppp = ppp;

	lcp->hnd.proto = PPP_LCP;
	lcp->hnd.recv = lcp_recv;

	ppp_register_chan_handler(ppp, &lcp->hnd);

	lcp->fsm.proto = PPP_LCP;
	ppp_fsm_init(&lcp->fsm);

	lcp->fsm.layer_up = lcp_layer_up;
	lcp->fsm.layer_down = lcp_layer_down;
	lcp->fsm.layer_finished = lcp_layer_finished;
	lcp->fsm.send_conf_req = send_conf_req;
	lcp->fsm.send_conf_ack = send_conf_ack;
	lcp->fsm.send_conf_nak = send_conf_nak;
	lcp->fsm.send_conf_rej = send_conf_rej;
	lcp->fsm.send_code_rej = send_code_rej;
	lcp->fsm.send_term_req = send_term_req;
	lcp->fsm.send_term_ack = send_term_ack;

	INIT_LIST_HEAD(&lcp->ropt_list);

	return &lcp->ld;
}

int lcp_layer_start(struct ppp_layer_data_t *ld)
{
	struct ppp_lcp_t *lcp = container_of(ld, typeof(*lcp), ld);

	log_ppp_debug("lcp_layer_start\n");

	lcp_options_init(lcp);
	ppp_fsm_lower_up(&lcp->fsm);
	if (ppp_fsm_open(&lcp->fsm))
		return -1;

	return 0;
}

static void _lcp_layer_finished(struct ppp_lcp_t *lcp)
{
	ppp_layer_finished(lcp->ppp, &lcp->ld);
}

void lcp_layer_finish(struct ppp_layer_data_t *ld)
{
	struct ppp_lcp_t *lcp = container_of(ld,typeof(*lcp),ld);

	log_ppp_debug("lcp_layer_finish\n");

	if (lcp->started) {
		stop_echo(lcp);
		ppp_fsm_close(&lcp->fsm);
	} else
		triton_context_call(lcp->ppp->ses.ctrl->ctx, (triton_event_func)_lcp_layer_finished, lcp);
}

void lcp_layer_free(struct ppp_layer_data_t *ld)
{
	struct ppp_lcp_t *lcp = container_of(ld, typeof(*lcp), ld);

	log_ppp_debug("lcp_layer_free\n");

	stop_echo(lcp);
	ppp_unregister_handler(lcp->ppp, &lcp->hnd);
	lcp_options_free(lcp);
	ppp_fsm_free(&lcp->fsm);
	triton_cancel_call(lcp->ppp->ses.ctrl->ctx, (triton_event_func)_lcp_layer_finished);

	_free(lcp);
}

static void lcp_layer_up(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp = container_of(fsm, typeof(*lcp), fsm);

	log_ppp_debug("lcp_layer_started\n");

	if (!lcp->started) {
		lcp->started = 1;
		ppp_layer_started(lcp->ppp, &lcp->ld);
	}
	start_echo(lcp);
}

static void lcp_layer_down(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp = container_of(fsm, typeof(*lcp), fsm);
	//ppp_fsm_close(&lcp->fsm);
	//stop_echo(lcp);
	//ppp_layer_finished(lcp->ppp,&lcp->ld);
}

static void lcp_layer_finished(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp = container_of(fsm, typeof(*lcp), fsm);

	log_ppp_debug("lcp_layer_finished\n");

	stop_echo(lcp);
	if (lcp->started) {
		lcp->started = 0;
		if (lcp->ppp->ses.terminating)
			ppp_layer_finished(lcp->ppp, &lcp->ld);
		else
			ap_session_terminate(&lcp->ppp->ses, TERM_NAS_ERROR, 0);
	} else
		ap_session_terminate(&lcp->ppp->ses, TERM_NAS_ERROR, 0);
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
	struct ppp_lcp_t *lcp = container_of(fsm, typeof(*lcp), fsm);
	uint8_t *buf = _malloc(lcp->conf_req_len), *ptr = buf;
	struct lcp_hdr_t *lcp_hdr = (struct lcp_hdr_t*)ptr;
	struct lcp_option_t *lopt;
	int n;

	lcp_hdr->proto = htons(PPP_LCP);
	lcp_hdr->code = CONFREQ;
	lcp_hdr->id = lcp->fsm.id;
	lcp_hdr->len = 0;

	ptr += sizeof(*lcp_hdr);

	list_for_each_entry(lopt, &lcp->options, entry) {
		n = lopt->h->send_conf_req(lcp, lopt, ptr);
		if (n < 0)
			return -1;
		if (n) {
			ptr += n;
			lopt->print = 1;
		} else
			lopt->print = 0;
	}

	if (conf_ppp_verbose) {
		log_ppp_info2("send [LCP ConfReq id=%x", lcp_hdr->id);
		list_for_each_entry(lopt,&lcp->options,entry) {
			if (lopt->print) {
				log_ppp_info2(" ");
				lopt->h->print(log_ppp_info2, lopt, NULL);
			}
		}
		log_ppp_info2("]\n");
	}

	lcp_hdr->len = htons(ptr - buf - 2);
	ppp_chan_send(lcp->ppp, lcp_hdr, ptr-buf);

	_free(buf);

	return 0;
}

static void send_conf_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp = container_of(fsm, typeof(*lcp), fsm);
	struct lcp_hdr_t *hdr = (struct lcp_hdr_t*)lcp->ppp->buf;

	hdr->code = CONFACK;

	if (conf_ppp_verbose)
		log_ppp_info2("send [LCP ConfAck id=%x]\n", lcp->fsm.recv_id);

	ppp_chan_send(lcp->ppp, hdr, ntohs(hdr->len) + 2);
}

static void send_code_rej(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp = container_of(fsm, typeof(*lcp), fsm);
	struct lcp_hdr_t *hdr = (struct lcp_hdr_t*)lcp->ppp->buf;

	hdr->code = CODEREJ;

	if (conf_ppp_verbose)
		log_ppp_info2("send [LCP CodeRej id=%x <%02x>]\n", lcp->fsm.recv_id, hdr->code);

	ppp_chan_send(lcp->ppp, hdr, ntohs(hdr->len) + 2);
}

static void send_conf_nak(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp = container_of(fsm, typeof(*lcp), fsm);
	uint8_t *buf = _malloc(lcp->conf_req_len), *ptr = buf;
	struct lcp_hdr_t *lcp_hdr = (struct lcp_hdr_t*)ptr;
	struct lcp_option_t *lopt;
	int n;

	if (conf_ppp_verbose)
		log_ppp_info2("send [LCP ConfNak id=%x", lcp->fsm.recv_id);

	lcp_hdr->proto = htons(PPP_LCP);
	lcp_hdr->code = CONFNAK;
	lcp_hdr->id = lcp->fsm.recv_id;
	lcp_hdr->len = 0;

	ptr += sizeof(*lcp_hdr);

	list_for_each_entry(lopt, &lcp->options, entry) {
		if (lopt->state == LCP_OPT_NAK) {
			n = lopt->h->send_conf_nak(lcp, lopt, ptr);

			if (conf_ppp_verbose && n) {
				log_ppp_info2(" ");
				lopt->h->print(log_ppp_info2, lopt, ptr);
			}

			ptr += n;
		}
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	lcp_hdr->len = htons(ptr - buf - 2);
	ppp_chan_send(lcp->ppp, lcp_hdr,ptr - buf);

	_free(buf);
}

static void send_conf_rej(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp = container_of(fsm, typeof(*lcp), fsm);
	uint8_t *buf = _malloc(lcp->ropt_len + sizeof(struct lcp_hdr_t)), *ptr = buf;
	struct lcp_hdr_t *lcp_hdr = (struct lcp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	if (conf_ppp_verbose)
		log_ppp_info2("send [LCP ConfRej id=%x", lcp->fsm.recv_id);

	lcp_hdr->proto = htons(PPP_LCP);
	lcp_hdr->code = CONFREJ;
	lcp_hdr->id = lcp->fsm.recv_id;
	lcp_hdr->len = 0;

	ptr += sizeof(*lcp_hdr);

	list_for_each_entry(ropt, &lcp->ropt_list, entry) {
		if (ropt->state == LCP_OPT_REJ) {
			memcpy(ptr, ropt->hdr, ropt->len);
			ptr += ropt->len;

			if (conf_ppp_verbose) {
				log_ppp_info2(" ");
				if (ropt->lopt)
					ropt->lopt->h->print(log_ppp_info2, ropt->lopt, (uint8_t*)ropt->hdr);
				else
					print_ropt(ropt);
			}
		}
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	lcp_hdr->len = htons(ptr - buf - 2);
	ppp_chan_send(lcp->ppp, lcp_hdr, ptr - buf);

	_free(buf);
}

static int lcp_recv_conf_req(struct ppp_lcp_t *lcp, uint8_t *data, int size)
{
	struct lcp_opt_hdr_t *hdr;
	struct recv_opt_t *ropt;
	struct lcp_option_t *lopt;
	int r, ret = 1;

	lcp->ropt_len = size;

	while (size > 0) {
		hdr = (struct lcp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		ropt = _malloc(sizeof(*ropt));
		memset(ropt, 0, sizeof(*ropt));

		ropt->hdr = hdr;
		ropt->len = hdr->len;
		ropt->state = LCP_OPT_NONE;
		list_add_tail(&ropt->entry, &lcp->ropt_list);

		data += hdr->len;
		size -= hdr->len;
	}

	list_for_each_entry(lopt, &lcp->options, entry)
		lopt->state = LCP_OPT_NONE;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [LCP ConfReq id=%x", lcp->fsm.recv_id);

	list_for_each_entry(ropt, &lcp->ropt_list, entry) {
		list_for_each_entry(lopt, &lcp->options, entry) {
			if (lopt->id == ropt->hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2, lopt, (uint8_t*)ropt->hdr);
				}
				r = lopt->h->recv_conf_req(lcp, lopt, (uint8_t*)ropt->hdr);
				lopt->state = r;
				ropt->state = r;
				ropt->lopt = lopt;
				if (r<ret)
					ret = r;
				break;
			}
		}
		if (!ropt->lopt) {
			if (conf_ppp_verbose) {
				log_ppp_info2(" ");
				print_ropt(ropt);
			}
			ropt->state=LCP_OPT_REJ;
			ret=LCP_OPT_REJ;
		}
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	/*list_for_each_entry(lopt,&lcp->options,entry)
	{
		if (lopt->state==LCP_OPT_NONE)
		{
			r=lopt->h->recv_conf_req(lcp,lopt,NULL);
			lopt->state=r;
			if (r<ret) ret=r;
		}
	}*/

	return ret;
}

static void lcp_free_conf_req(struct ppp_lcp_t *lcp)
{
	struct recv_opt_t *ropt;

	while (!list_empty(&lcp->ropt_list)) {
		ropt = list_entry(lcp->ropt_list.next, typeof(*ropt), entry);
		list_del(&ropt->entry);
		_free(ropt);
	}
}

static int lcp_recv_conf_rej(struct ppp_lcp_t *lcp, uint8_t *data, int size)
{
	struct lcp_opt_hdr_t *hdr;
	struct lcp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [LCP ConfRej id=%x", lcp->fsm.recv_id);

	if (lcp->fsm.recv_id != lcp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}

	while (size > 0) {
		hdr = (struct lcp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &lcp->options, entry) {
			if (lopt->id == hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2, lopt, (uint8_t*)hdr);
				}
				if (!lopt->h->recv_conf_rej)
					res = -1;
				else if (lopt->h->recv_conf_rej(lcp, lopt, data))
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

static int lcp_recv_conf_nak(struct ppp_lcp_t *lcp, uint8_t *data, int size)
{
	struct lcp_opt_hdr_t *hdr;
	struct lcp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [LCP ConfNak id=%x", lcp->fsm.recv_id);

	if (lcp->fsm.recv_id != lcp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}

	while (size > 0) {
		hdr = (struct lcp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt,&lcp->options,entry) {
			if (lopt->id == hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2, lopt, data);
				}
				if (lopt->h->recv_conf_nak && lopt->h->recv_conf_nak(lcp, lopt, data))
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

static int lcp_recv_conf_ack(struct ppp_lcp_t *lcp, uint8_t *data, int size)
{
	struct lcp_opt_hdr_t *hdr;
	struct lcp_option_t *lopt;
	int res=0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [LCP ConfAck id=%x", lcp->fsm.recv_id);

	if (lcp->fsm.recv_id != lcp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}

	while (size > 0) {
		hdr = (struct lcp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &lcp->options, entry) {
			if (lopt->id == hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2, lopt, data);
				}
				if (!lopt->h->recv_conf_ack)
					break;
				if (lopt->h->recv_conf_ack(lcp, lopt, data))
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

static void lcp_recv_echo_repl(struct ppp_lcp_t *lcp, uint8_t *data, int size)
{
	uint32_t magic;

	if (size != 4) {
		if (conf_ppp_verbose)
			log_ppp_debug("recv [LCP EchoRep id=%x]\n", lcp->fsm.recv_id);
	} else {
		magic = ntohl(*(uint32_t *)data);

		if (conf_ppp_verbose)
			log_ppp_debug("recv [LCP EchoRep id=%x <magic %08x>]\n", lcp->fsm.recv_id, magic);

		if (lcp->magic && magic == lcp->magic) {
			log_ppp_error("lcp: echo: loop-back detected\n");
			ap_session_terminate(&lcp->ppp->ses, TERM_NAS_ERROR, 0);
		}
	}

	lcp->echo_sent = 0;
	lcp->last_echo_ts = _time();
}

static void send_echo_reply(struct ppp_lcp_t *lcp)
{
	struct lcp_hdr_t *hdr = (struct lcp_hdr_t*)lcp->ppp->buf;
	//uint32_t magic = *(uint32_t *)(hdr + 1);

	lcp->echo_sent = 0;
	lcp->last_echo_ts = _time();

	hdr->code = ECHOREP;
	*(uint32_t *)(hdr + 1) = htonl(lcp->magic);

	if (conf_ppp_verbose)
		log_ppp_debug("send [LCP EchoRep id=%x <magic %08x>]\n", hdr->id, lcp->magic);

	ppp_chan_send(lcp->ppp, hdr, ntohs(hdr->len) + 2);
}

static void send_echo_request(struct triton_timer_t *t)
{
	struct ppp_lcp_t *lcp = container_of(t, typeof(*lcp), echo_timer);
	struct rtnl_link_stats64 stats;
	struct lcp_echo_req {
		struct lcp_hdr_t hdr;
		uint32_t magic;
	} __attribute__((packed)) msg;

	if (conf_echo_timeout) {
		ap_session_read_stats(&lcp->ppp->ses, &stats);

		if (lcp->last_ipackets != stats.rx_packets) {
			lcp->last_ipackets = stats.rx_packets;
			lcp->last_echo_ts = _time();
			lcp->echo_sent = 0;
			return;
		}

		if (_time() - lcp->last_echo_ts < conf_echo_timeout)
			return;
	}

	if (lcp->echo_sent > conf_echo_failure) {
		log_ppp_warn("lcp: no echo reply\n");
		ap_session_terminate(&lcp->ppp->ses, TERM_LOST_CARRIER, 1);
		return;
	}

	msg.hdr.proto = htons(PPP_LCP);
	msg.hdr.code = ECHOREQ;
	msg.hdr.id = lcp->fsm.id++;
	msg.hdr.len = htons(8);
	msg.magic = htonl(lcp->magic);

	lcp->echo_sent++;

	if (conf_ppp_verbose)
		log_ppp_debug("send [LCP EchoReq id=%x <magic %08x>]\n", msg.hdr.id, lcp->magic);

	ppp_chan_send(lcp->ppp, &msg, ntohs(msg.hdr.len) + 2);
}

static void start_echo(struct ppp_lcp_t *lcp)
{
	lcp->echo_timer.period = conf_echo_interval * 1000;
	lcp->echo_timer.expire = send_echo_request;
	if (lcp->echo_timer.period && !lcp->echo_timer.tpd)
		triton_timer_add(lcp->ppp->ses.ctrl->ctx, &lcp->echo_timer, 0);
}
static void stop_echo(struct ppp_lcp_t *lcp)
{
	if (lcp->echo_timer.tpd)
		triton_timer_del(&lcp->echo_timer);
}

static void send_term_req(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	struct lcp_hdr_t hdr = {
		.proto = htons(PPP_LCP),
		.code = TERMREQ,
		.id = ++lcp->fsm.id,
		.len = htons(4),
	};

	if (conf_ppp_verbose)
		log_ppp_info2("send [LCP TermReq id=%i]\n", hdr.id);

	ppp_chan_send(lcp->ppp, &hdr, 6);
}

static void send_term_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp = container_of(fsm, typeof(*lcp), fsm);
	struct lcp_hdr_t hdr = {
		.proto = htons(PPP_LCP),
		.code = TERMACK,
		.id = lcp->fsm.recv_id,
		.len = htons(4),
	};

	if (conf_ppp_verbose)
		log_ppp_info2("send [LCP TermAck id=%i]\n", hdr.id);

	ppp_chan_send(lcp->ppp, &hdr, 6);
}

void lcp_send_proto_rej(struct ppp_t *ppp, uint16_t proto)
{
	struct ppp_lcp_t *lcp = container_of(ppp_find_layer_data(ppp, &lcp_layer), typeof(*lcp), ld);
	struct rej_msg_t
	{
		struct lcp_hdr_t hdr;
		uint16_t proto;
	} __attribute__((packed)) msg = {
		.hdr.proto = htons(PPP_LCP),
		.hdr.code = PROTOREJ,
		.hdr.id = ++lcp->fsm.id,
		.hdr.len = htons(6),
		.proto = ntohs(proto),
	};

	if (conf_ppp_verbose)
		log_ppp_info2("send [LCP ProtoRej id=%i <%04x>]\n", msg.hdr.id, proto);

	ppp_chan_send(lcp->ppp, &msg, sizeof(msg));
}

static void lcp_recv(struct ppp_handler_t*h)
{
	struct lcp_hdr_t *hdr;
	struct ppp_lcp_t *lcp = container_of(h, typeof(*lcp), hnd);
	int r;
	char *term_msg;

	if (lcp->ppp->buf_size < PPP_HEADERLEN + 2) {
		log_ppp_warn("LCP: short packet received\n");
		return;
	}

	hdr = (struct lcp_hdr_t *)lcp->ppp->buf;
	if (ntohs(hdr->len) < PPP_HEADERLEN) {
		log_ppp_warn("LCP: short packet received\n");
		return;
	}

	if ((hdr->code == CONFACK || hdr->code == CONFNAK || hdr->code == CONFREJ) && hdr->id != lcp->fsm.id)
		return;

	if ((hdr->code == CONFACK || hdr->code == CONFNAK || hdr->code == CONFREJ) && lcp->started)
		return;

	if (lcp->fsm.fsm_state == FSM_Initial || lcp->fsm.fsm_state == FSM_Closed || (lcp->ppp->ses.terminating && (hdr->code != TERMACK && hdr->code != TERMREQ))) {
		/*if (conf_ppp_verbose)
			log_ppp_warn("LCP: discaring packet\n");
		lcp_send_proto_rej(ccp->ppp, htons(PPP_CCP));*/
		return;
	}

	lcp->fsm.recv_id = hdr->id;

	switch(hdr->code) {
		case CONFREQ:
			r = lcp_recv_conf_req(lcp, (uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN);
			if (lcp->started) {
				if (r == LCP_OPT_ACK) {
					send_conf_ack(&lcp->fsm);
					lcp_free_conf_req(lcp);
					break;
				} else
					r = LCP_OPT_FAIL;
			}
			switch(r) {
				case LCP_OPT_ACK:
					ppp_fsm_recv_conf_req_ack(&lcp->fsm);
					break;
				case LCP_OPT_NAK:
					ppp_fsm_recv_conf_req_nak(&lcp->fsm);
					break;
				case LCP_OPT_REJ:
					ppp_fsm_recv_conf_req_rej(&lcp->fsm);
					break;
			}
			lcp_free_conf_req(lcp);
			if (r == LCP_OPT_FAIL)
				ap_session_terminate(&lcp->ppp->ses, TERM_USER_ERROR, 0);
			break;
		case CONFACK:
			if (lcp_recv_conf_ack(lcp,(uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN))
				ap_session_terminate(&lcp->ppp->ses, TERM_USER_ERROR, 0);
			else {
				if (lcp->fsm.recv_id != lcp->fsm.id)
					break;
				ppp_fsm_recv_conf_ack(&lcp->fsm);
			}
			break;
		case CONFNAK:
			lcp_recv_conf_nak(lcp, (uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN);
			if (lcp->fsm.recv_id != lcp->fsm.id)
				break;
			ppp_fsm_recv_conf_rej(&lcp->fsm);
			break;
		case CONFREJ:
			if (lcp_recv_conf_rej(lcp,(uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN))
				ap_session_terminate(&lcp->ppp->ses, TERM_USER_ERROR, 0);
			else {
				if (lcp->fsm.recv_id != lcp->fsm.id)
					break;
				ppp_fsm_recv_conf_rej(&lcp->fsm);
			}
			break;
		case TERMREQ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [LCP TermReq id=%x]\n", hdr->id);
			ppp_fsm_recv_term_req(&lcp->fsm);
			ap_session_terminate(&lcp->ppp->ses, TERM_USER_REQUEST, 0);
			break;
		case TERMACK:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [LCP TermAck id=%x]\n", hdr->id);
			ppp_fsm_recv_term_ack(&lcp->fsm);
			break;
		case CODEREJ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [LCP CodeRej id=%x]\n", hdr->id);
			ppp_fsm_recv_code_rej_bad(&lcp->fsm);
			break;
		case ECHOREQ:
			if (conf_ppp_verbose)
				log_ppp_debug("recv [LCP EchoReq id=%x <magic %08x>]\n", hdr->id, ntohl(*(uint32_t*)(hdr + 1)));
			send_echo_reply(lcp);
			break;
		case ECHOREP:
			lcp_recv_echo_repl(lcp, (uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN);
			break;
		case PROTOREJ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [LCP ProtoRej id=%x <%04x>]\n", hdr->id, ntohs(*(uint16_t*)(hdr + 1)));
			ppp_recv_proto_rej(lcp->ppp, ntohs(*(uint16_t *)(hdr + 1)));
			break;
		case DISCARDREQ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [LCP DiscardReq id=%x <magic %08x>]\n", hdr->id, ntohl(*(uint32_t*)(hdr + 1)));
			break;
		case IDENT:
			if (conf_ppp_verbose) {
				term_msg = _strndup((char*)(hdr + 1) + 4, ntohs(hdr->len) - 4 - 4);
				log_ppp_info2("recv [LCP Ident id=%x <%s>]\n", hdr->id, term_msg);
				_free(term_msg);
			}
			break;
		default:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [LCP Unknown %x]\n", hdr->code);
			ppp_fsm_recv_unk(&lcp->fsm);
			break;
	}
}

int lcp_option_register(struct lcp_option_handler_t *h)
{
	/*struct lcp_option_drv_t *p;

	list_for_each_entry(p,option_drv_list,entry)
		if (p->id==h->id)
			return -1;*/

	list_add_tail(&h->entry, &option_handlers);

	return 0;
}

static struct ppp_layer_t lcp_layer=
{
	.init   = lcp_layer_init,
	.start  = lcp_layer_start,
	.finish = lcp_layer_finish,
	.free   = lcp_layer_free,
};

static void load_config(void)
{
	char *opt;

	opt = conf_get_opt("ppp", "lcp-echo-interval");
	if (opt)
		conf_echo_interval = atoi(opt);
	else
		conf_echo_interval = 0;

	opt = conf_get_opt("ppp", "lcp-echo-failure");
	if (opt)
		conf_echo_failure = atoi(opt);
	else
		conf_echo_failure = 0;

	opt = conf_get_opt("ppp", "lcp-echo-timeout");
	if (opt)
		conf_echo_timeout = atoi(opt);
	else
		conf_echo_timeout = 0;
}

static void lcp_init(void)
{
	load_config();

	ppp_register_layer("lcp", &lcp_layer);

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(3, lcp_init);
