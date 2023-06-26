#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "linux_ppp.h"

#include "triton.h"

#include "log.h"
#include "events.h"

#include "ppp.h"
#include "ppp_ccp.h"

#include "memdebug.h"

struct recv_opt_t
{
	struct list_head entry;
	struct ccp_opt_hdr_t *hdr;
	int len;
	int state;
	struct ccp_option_t *lopt;
};

static int conf_ccp = 1;
static int conf_ccp_max_configure = 3;

static struct ppp_layer_t ccp_layer;
static LIST_HEAD(option_handlers);

static void ccp_layer_up(struct ppp_fsm_t*);
static void ccp_layer_down(struct ppp_fsm_t*);
static void ccp_layer_finished(struct ppp_fsm_t*);
static int send_conf_req(struct ppp_fsm_t*);
static void send_conf_ack(struct ppp_fsm_t*);
static void send_conf_nak(struct ppp_fsm_t*);
static void send_conf_rej(struct ppp_fsm_t*);
static void send_term_req(struct ppp_fsm_t *fsm);
static void send_term_ack(struct ppp_fsm_t *fsm);
static void ccp_recv(struct ppp_handler_t*);
static void ccp_recv_proto_rej(struct ppp_handler_t*);

static void ccp_options_init(struct ppp_ccp_t *ccp)
{
	struct ccp_option_t *lopt;
	struct ccp_option_handler_t *h;

	ccp->conf_req_len = sizeof(struct ccp_hdr_t);

	list_for_each_entry(h, &option_handlers, entry) {
		lopt = h->init(ccp);
		if (lopt) {
			lopt->h = h;
			list_add_tail(&lopt->entry, &ccp->options);
			ccp->conf_req_len += lopt->len;
		}
	}
}

static void ccp_options_free(struct ppp_ccp_t *ccp)
{
	struct ccp_option_t *lopt;

	while (!list_empty(&ccp->options)) {
		lopt = list_entry(ccp->options.next, typeof(*lopt), entry);
		list_del(&lopt->entry);
		lopt->h->free(ccp, lopt);
	}
}

static int ccp_set_flags(int fd, int isopen, int isup)
{
	int flags;

	if (net->ppp_ioctl(fd, PPPIOCGFLAGS, &flags) < 0) {
		log_ppp_error("ccp: failed to get flags: %s\n", strerror(errno));
		return -1;
	}

	flags &= ~(SC_CCP_OPEN | SC_CCP_UP);
	flags |= (isopen ? SC_CCP_OPEN : 0) | (isup ? SC_CCP_UP : 0);

	if (net->ppp_ioctl(fd, PPPIOCSFLAGS, &flags) < 0) {
		log_ppp_error("ccp: failed to set flags: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static struct ppp_layer_data_t *ccp_layer_init(struct ppp_t *ppp)
{
	struct ppp_ccp_t *ccp = _malloc(sizeof(*ccp));
	memset(ccp, 0, sizeof(*ccp));

	log_ppp_debug("ccp_layer_init\n");

	ccp->ppp = ppp;
	ccp->fsm.ppp = ppp;

	ccp->hnd.proto = PPP_CCP;
	ccp->hnd.recv = ccp_recv;
	ccp->hnd.recv_proto_rej = ccp_recv_proto_rej;

	ppp_register_unit_handler(ppp, &ccp->hnd);

	ccp->ld.passive = 1;
	ccp->ld.optional = 1;

	INIT_LIST_HEAD(&ccp->options);
	ccp_options_init(ccp);

	ccp->fsm.proto = PPP_CCP;
	ppp_fsm_init(&ccp->fsm);

	ccp->fsm.max_configure = conf_ccp_max_configure;

	ccp->fsm.layer_up = ccp_layer_up;
	ccp->fsm.layer_finished = ccp_layer_finished;
	ccp->fsm.layer_down = ccp_layer_down;
	ccp->fsm.send_conf_req = send_conf_req;
	ccp->fsm.send_conf_ack = send_conf_ack;
	ccp->fsm.send_conf_nak = send_conf_nak;
	ccp->fsm.send_conf_rej = send_conf_rej;
	ccp->fsm.send_term_req = send_term_req;
	ccp->fsm.send_term_ack = send_term_ack;

	INIT_LIST_HEAD(&ccp->ropt_list);

	return &ccp->ld;
}

int ccp_layer_start(struct ppp_layer_data_t *ld)
{
	struct ppp_ccp_t *ccp = container_of(ld, typeof(*ccp), ld);

	log_ppp_debug("ccp_layer_start\n");

	ccp_set_flags(ccp->ppp->unit_fd, 0, 0);

	if (list_empty(&ccp->options) || !conf_ccp) {
		ccp->started = 1;
		ppp_layer_started(ccp->ppp, &ccp->ld);
		return 0;
	}

	ccp->starting = 1;

	if (!ccp->ld.passive) {
		ppp_fsm_lower_up(&ccp->fsm);
		if (ppp_fsm_open(&ccp->fsm))
			return -1;
	}

	if (ccp_set_flags(ccp->ppp->unit_fd, 1, 0)) {
		ppp_fsm_close(&ccp->fsm);
		return -1;
	}

	return 0;
}

void ccp_layer_finish(struct ppp_layer_data_t *ld)
{
	struct ppp_ccp_t *ccp = container_of(ld, typeof(*ccp), ld);

	log_ppp_debug("ccp_layer_finish\n");

	ccp_set_flags(ccp->ppp->unit_fd, 0, 0);

	ccp->fsm.fsm_state = FSM_Closed;

	log_ppp_debug("ccp_layer_finished\n");
	ppp_layer_finished(ccp->ppp, &ccp->ld);
}

void ccp_layer_free(struct ppp_layer_data_t *ld)
{
	struct ppp_ccp_t *ccp = container_of(ld, typeof(*ccp), ld);

	log_ppp_debug("ccp_layer_free\n");

	ppp_unregister_handler(ccp->ppp, &ccp->hnd);
	ccp_options_free(ccp);
	ppp_fsm_free(&ccp->fsm);

	_free(ccp);
}

static void ccp_layer_up(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp = container_of(fsm, typeof(*ccp), fsm);

	if (!ccp->started) {
		log_ppp_debug("ccp_layer_started\n");
		ccp->started = 1;
		if (ccp_set_flags(ccp->ppp->unit_fd, 1, 1)) {
			ap_session_terminate(&ccp->ppp->ses, TERM_NAS_ERROR, 0);
			return;
		}
		ppp_layer_started(ccp->ppp, &ccp->ld);
	}
}

static void ccp_layer_finished(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp = container_of(fsm, typeof(*ccp), fsm);

	log_ppp_debug("ccp_layer_finished\n");

	if (!ccp->started)
		ppp_layer_passive(ccp->ppp, &ccp->ld);
	else if (!ccp->ppp->ses.terminating)
		ap_session_terminate(&ccp->ppp->ses, TERM_USER_ERROR, 0);

	fsm->fsm_state = FSM_Closed;
}

static void ccp_layer_down(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp = container_of(fsm, typeof(*ccp), fsm);

	log_ppp_debug("ccp_layer_down\n");

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
	struct ppp_ccp_t *ccp = container_of(fsm, typeof(*ccp), fsm);
	uint8_t *buf, *ptr;
	struct ccp_hdr_t *ccp_hdr;
	struct ccp_option_t *lopt;
	int n;

	if (ccp->ld.passive)
		return 0;

	buf = _malloc(ccp->conf_req_len);
	ccp_hdr = (struct ccp_hdr_t*)buf;

	ccp_hdr->proto = htons(PPP_CCP);
	ccp_hdr->code = CONFREQ;
	ccp_hdr->id = ccp->fsm.id;
	ccp_hdr->len = 0;

	ptr = (uint8_t*)(ccp_hdr + 1);

	if (conf_ppp_verbose)
		log_ppp_info2("send [CCP ConfReq id=%x", ccp_hdr->id);

	list_for_each_entry(lopt, &ccp->options, entry) {
		n = lopt->h->send_conf_req(ccp, lopt, ptr);
		if (n < 0)
			return -1;
		if (n) {
			if (conf_ppp_verbose) {
				log_ppp_info2(" ");
				lopt->h->print(log_ppp_info2, lopt, NULL);
			}
		}
		ptr += n;
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	ccp_hdr->len = htons(ptr - buf - 2);
	ppp_unit_send(ccp->ppp, ccp_hdr, ptr - buf);

	_free(buf);

	return 0;
}

static void send_conf_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp = container_of(fsm, typeof(*ccp), fsm);
	struct ccp_hdr_t *hdr = (struct ccp_hdr_t*)ccp->ppp->buf;

	hdr->code = CONFACK;

	if (conf_ppp_verbose)
		log_ppp_info2("send [CCP ConfAck id=%x]\n", ccp->fsm.recv_id);

	ppp_unit_send(ccp->ppp,hdr,ntohs(hdr->len)+2);
}

static void send_conf_nak(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp = container_of(fsm, typeof(*ccp), fsm);
	uint8_t *buf = _malloc(ccp->conf_req_len), *ptr = buf;
	struct ccp_hdr_t *ccp_hdr = (struct ccp_hdr_t*)ptr;
	struct ccp_option_t *lopt;

	if (conf_ppp_verbose)
		log_ppp_info2("send [CCP ConfNak id=%x", ccp->fsm.recv_id);

	ccp_hdr->proto = htons(PPP_CCP);
	ccp_hdr->code = CONFNAK;
	ccp_hdr->id = ccp->fsm.recv_id;
	ccp_hdr->len = 0;

	ptr += sizeof(*ccp_hdr);

	list_for_each_entry(lopt, &ccp->options, entry) {
		if (lopt->state == CCP_OPT_NAK) {
			if (conf_ppp_verbose) {
				log_ppp_info2(" ");
				lopt->h->print(log_ppp_info2, lopt, NULL);
			}
			ptr += lopt->h->send_conf_nak(ccp, lopt, ptr);
		}
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	ccp_hdr->len = htons(ptr - buf - 2);
	ppp_unit_send(ccp->ppp, ccp_hdr, ptr - buf);

	_free(buf);
}

static void send_conf_rej(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp = container_of(fsm, typeof(*ccp), fsm);
	uint8_t *buf = _malloc(ccp->ropt_len + sizeof(struct ccp_hdr_t)), *ptr = buf;
	struct ccp_hdr_t *ccp_hdr = (struct ccp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	if (conf_ppp_verbose)
		log_ppp_info2("send [CCP ConfRej id=%x", ccp->fsm.recv_id);

	ccp_hdr->proto = htons(PPP_CCP);
	ccp_hdr->code = CONFREJ;
	ccp_hdr->id = ccp->fsm.recv_id;
	ccp_hdr->len = 0;

	ptr += sizeof(*ccp_hdr);

	list_for_each_entry(ropt, &ccp->ropt_list, entry) {
		if (ropt->state == CCP_OPT_REJ) {
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

	ccp_hdr->len = htons(ptr - buf - 2);
	ppp_unit_send(ccp->ppp, ccp_hdr, ptr-buf);

	_free(buf);
}

static int ccp_recv_conf_req(struct ppp_ccp_t *ccp, uint8_t *data, int size)
{
	struct ccp_opt_hdr_t *hdr;
	struct recv_opt_t *ropt;
	struct ccp_option_t *lopt;
	int r, ret = 1, ack = 0;

	ccp->ropt_len = size;

	while (size > 0) {
		hdr = (struct ccp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		ropt = _malloc(sizeof(*ropt));
		memset(ropt, 0, sizeof(*ropt));

		ropt->hdr = hdr;
		ropt->len = hdr->len;
		ropt->state = CCP_OPT_NONE;
		list_add_tail(&ropt->entry, &ccp->ropt_list);

		data += hdr->len;
		size -= hdr->len;
	}

	if (conf_ppp_verbose)
		log_ppp_info2("recv [CCP ConfReq id=%x", ccp->fsm.recv_id);

	list_for_each_entry(ropt, &ccp->ropt_list, entry) {
		list_for_each_entry(lopt, &ccp->options, entry) {
			if (lopt->id == ropt->hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2, lopt, (uint8_t*)ropt->hdr);
				}
				r = lopt->h->recv_conf_req(ccp, lopt, (uint8_t*)ropt->hdr);
				if (ack) {
					lopt->state = CCP_OPT_REJ;
					ropt->state = CCP_OPT_REJ;
				} else	{
					lopt->state = r;
					ropt->state = r;
				}
				ropt->lopt = lopt;
				if (r < ret)
					ret = r;
				break;
			}
		}
		if (ropt->state == CCP_OPT_ACK || ropt->state == CCP_OPT_NAK)
			ack = 1;
		else if (!ropt->lopt) {
			if (conf_ppp_verbose) {
				log_ppp_info2(" ");
				print_ropt(ropt);
			}
			ropt->state = CCP_OPT_REJ;
			ret = CCP_OPT_REJ;
		}
	}

	if (conf_ppp_verbose)
		log_ppp_info2("]\n");

	list_for_each_entry(lopt, &ccp->options, entry) {
		if (lopt->state == CCP_OPT_NONE) {
			r = lopt->h->recv_conf_req(ccp, lopt, NULL);
			lopt->state = r;
			if (r < ret)
				ret = r;
		}
	}

	return ret;
}

static void ccp_free_conf_req(struct ppp_ccp_t *ccp)
{
	struct recv_opt_t *ropt;

	while (!list_empty(&ccp->ropt_list)) {
		ropt = list_entry(ccp->ropt_list.next, typeof(*ropt), entry);
		list_del(&ropt->entry);
		_free(ropt);
	}
}

static int ccp_recv_conf_rej(struct ppp_ccp_t *ccp, uint8_t *data, int size)
{
	struct ccp_opt_hdr_t *hdr;
	struct ccp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [CCP ConfRej id=%x", ccp->fsm.recv_id);

	/*if (ccp->fsm.recv_id != ccp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}*/

	while (size > 0) {
		hdr = (struct ccp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &ccp->options, entry) {
			if (lopt->id == hdr->id) {
				if (!lopt->h->recv_conf_rej)
					res = -1;
				else if (lopt->h->recv_conf_rej(ccp, lopt, data))
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

static int ccp_recv_conf_nak(struct ppp_ccp_t *ccp, uint8_t *data, int size)
{
	struct ccp_opt_hdr_t *hdr;
	struct ccp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [CCP ConfNak id=%x", ccp->fsm.recv_id);

	/*if (ccp->fsm.recv_id != ccp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}*/

	while (size > 0) {
		hdr = (struct ccp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &ccp->options, entry) {
			if (lopt->id == hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2, lopt, data);
				}
				if (lopt->h->recv_conf_nak && lopt->h->recv_conf_nak(ccp, lopt, data))
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

static int ccp_recv_conf_ack(struct ppp_ccp_t *ccp, uint8_t *data, int size)
{
	struct ccp_opt_hdr_t *hdr;
	struct ccp_option_t *lopt;
	int res = 0;

	if (conf_ppp_verbose)
		log_ppp_info2("recv [CCP ConfAck id=%x", ccp->fsm.recv_id);

	/*if (ccp->fsm.recv_id != ccp->fsm.id) {
		if (conf_ppp_verbose)
			log_ppp_info2(": id mismatch ]\n");
		return 0;
	}*/

	while (size > 0) {
		hdr = (struct ccp_opt_hdr_t *)data;

		if (!hdr->len || hdr->len > size)
			break;

		list_for_each_entry(lopt, &ccp->options, entry) {
			if (lopt->id == hdr->id) {
				if (conf_ppp_verbose) {
					log_ppp_info2(" ");
					lopt->h->print(log_ppp_info2,lopt,data);
				}
				if (!lopt->h->recv_conf_ack)
					break;
				if (lopt->h->recv_conf_ack(ccp, lopt, data))
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
	struct ppp_ccp_t *ccp = container_of(fsm, typeof(*ccp), fsm);
	struct ccp_hdr_t hdr = {
		.proto = htons(PPP_CCP),
		.code = TERMREQ,
		.id = ++ccp->fsm.id,
		.len = htons(4),
	};

	if (conf_ppp_verbose)
		log_ppp_info2("send [CCP TermReq id=%i]\n", hdr.id);

	ppp_unit_send(ccp->ppp, &hdr, 6);
}

static void send_term_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp = container_of(fsm, typeof(*ccp), fsm);
	struct ccp_hdr_t hdr = {
		.proto = htons(PPP_CCP),
		.code = TERMACK,
		.id = ccp->fsm.recv_id,
		.len = htons(4),
	};

	if (conf_ppp_verbose)
		log_ppp_info2("send [CCP TermAck id=%i]\n", hdr.id);

	ppp_unit_send(ccp->ppp, &hdr, 6);
}

static void ccp_recv(struct ppp_handler_t*h)
{
	struct ccp_hdr_t *hdr;
	struct ppp_ccp_t *ccp = container_of(h, typeof(*ccp), hnd);
	int r;

	if (!ccp->starting || ccp->fsm.fsm_state == FSM_Closed || ccp->ppp->ses.terminating || ccp->ppp->ses.state == AP_STATE_ACTIVE) {
		if (conf_ppp_verbose)
			log_ppp_warn("CCP: discarding packet\n");
		if (ccp->fsm.fsm_state == FSM_Closed || !conf_ccp || ccp->ppp->ses.state == AP_STATE_ACTIVE)
			lcp_send_proto_rej(ccp->ppp, PPP_CCP);
		return;
	}

	if (ccp->ppp->buf_size < PPP_HEADERLEN + 2) {
		log_ppp_warn("CCP: short packet received\n");
		return;
	}

	hdr = (struct ccp_hdr_t *)ccp->ppp->buf;
	if (ntohs(hdr->len) < PPP_HEADERLEN) {
		log_ppp_warn("CCP: short packet received\n");
		return;
	}

	if ((hdr->code == CONFACK || hdr->code == CONFNAK || hdr->code == CONFREJ) && hdr->id != ccp->fsm.id)
		return;

	ccp->fsm.recv_id = hdr->id;

	switch(hdr->code) {
		case CONFREQ:
			r = ccp_recv_conf_req(ccp, (uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN);
			if (ccp->ld.passive) {
				ccp->ld.passive = 0;
				ppp_fsm_lower_up(&ccp->fsm);
				ppp_fsm_open(&ccp->fsm);
			}
			if (ccp->started) {
				if (r == CCP_OPT_ACK)
					send_conf_ack(&ccp->fsm);
				else
					r = CCP_OPT_FAIL;
			} else {
				switch(r) {
					case CCP_OPT_ACK:
						ppp_fsm_recv_conf_req_ack(&ccp->fsm);
						break;
					case CCP_OPT_NAK:
						ppp_fsm_recv_conf_req_nak(&ccp->fsm);
						break;
					case CCP_OPT_REJ:
						ppp_fsm_recv_conf_req_rej(&ccp->fsm);
						break;
				}
			}
			ccp_free_conf_req(ccp);

			if (r == CCP_OPT_FAIL)
				ap_session_terminate(&ccp->ppp->ses, TERM_USER_ERROR, 0);
			break;
		case CONFACK:
			if (ccp_recv_conf_ack(ccp, (uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN))
				ap_session_terminate(&ccp->ppp->ses, TERM_USER_ERROR, 0);
			else
				ppp_fsm_recv_conf_ack(&ccp->fsm);
			break;
		case CONFNAK:
			ccp_recv_conf_nak(ccp, (uint8_t*)(hdr + 1), ntohs(hdr->len) - PPP_HDRLEN);
			ppp_fsm_recv_conf_rej(&ccp->fsm);
			break;
		case CONFREJ:
			if (ccp_recv_conf_rej(ccp, (uint8_t*)(hdr + 1),ntohs(hdr->len) - PPP_HDRLEN))
				ap_session_terminate(&ccp->ppp->ses, TERM_USER_ERROR, 0);
			else
				ppp_fsm_recv_conf_rej(&ccp->fsm);
			break;
		case TERMREQ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [CCP TermReq id=%x]\n", hdr->id);
			ppp_fsm_recv_term_req(&ccp->fsm);
			ppp_fsm_close(&ccp->fsm);
			break;
		case TERMACK:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [CCP TermAck id=%x]\n", hdr->id);
			ppp_fsm_recv_term_ack(&ccp->fsm);
			break;
		case CODEREJ:
			if (conf_ppp_verbose)
				log_ppp_info2("recv [CCP CodeRej id=%x]\n", hdr->id);
			ppp_fsm_recv_code_rej_bad(&ccp->fsm);
			break;
		default:
			log_ppp_info2("recv [CCP Unknown code=%x id=%x]\n", hdr->code, hdr->id);
			ppp_fsm_recv_unk(&ccp->fsm);
			break;
	}
}

static void ccp_recv_proto_rej(struct ppp_handler_t *h)
{
	struct ppp_ccp_t *ccp = container_of(h, typeof(*ccp), hnd);

	if (!ccp->ld.optional) {
		ap_session_terminate(&ccp->ppp->ses, TERM_USER_ERROR, 0);
		return;
	}

	if (ccp->fsm.fsm_state == FSM_Initial || ccp->fsm.fsm_state == FSM_Closed)
		return;

	ppp_fsm_lower_down(&ccp->fsm);
	ppp_fsm_close(&ccp->fsm);
}

int ccp_option_register(struct ccp_option_handler_t *h)
{
	/*struct ccp_option_drv_t *p;

	list_for_each_entry(p,option_drv_list,entry)
		if (p->id==h->id)
			return -1;*/

	list_add_tail(&h->entry,&option_handlers);

	return 0;
}

struct ppp_ccp_t *ccp_find_layer_data(struct ppp_t *ppp)
{
	return container_of(ppp_find_layer_data(ppp, &ccp_layer), typeof(struct ppp_ccp_t), ld);
}
struct ccp_option_t *ccp_find_option(struct ppp_t *ppp, struct ccp_option_handler_t *h)
{
	struct ppp_ccp_t *ccp = container_of(ppp_find_layer_data(ppp, &ccp_layer), typeof(*ccp), ld);
	struct ccp_option_t *opt;

	list_for_each_entry(opt, &ccp->options, entry)
		if (opt->h == h)
			return opt;

	log_emerg("ccp: BUG: option not found\n");
	abort();
}

int ccp_ipcp_started(struct ppp_t *ppp)
{
	struct ppp_ccp_t *ccp = container_of(ppp_find_layer_data(ppp, &ccp_layer), typeof(*ccp), ld);

	return !ccp->ld.passive && !ccp->started;
}

static struct ppp_layer_t ccp_layer=
{
	.init   = ccp_layer_init,
	.start  = ccp_layer_start,
	.finish = ccp_layer_finish,
	.free   = ccp_layer_free,
};

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("ppp", "ccp");
	if (opt && atoi(opt) >= 0)
		conf_ccp = atoi(opt);

	opt = conf_get_opt("ppp", "ccp-max-configure");
	if (opt && atoi(opt) > 0)
		conf_ccp_max_configure = atoi(opt);
}

static void ccp_init(void)
{
	ppp_register_layer("ccp", &ccp_layer);

	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(3, ccp_init);
