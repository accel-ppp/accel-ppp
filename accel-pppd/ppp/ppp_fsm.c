#include <arpa/inet.h>
#include <stdlib.h>

#include "triton.h"

#include "ppp.h"
#include "ppp_fsm.h"
#include "ppp_lcp.h"
#include "log.h"
#include "events.h"

#include "memdebug.h"

static int conf_max_terminate = 2;
static int conf_max_configure = 10;
static int conf_max_failure = 10;
static int conf_timeout = 3;

void send_term_req(struct ppp_fsm_t *layer);
void send_term_ack(struct ppp_fsm_t *layer);
void send_echo_reply(struct ppp_fsm_t *layer);

static void init_req_counter(struct ppp_fsm_t *layer,int timeout);
static void zero_req_counter(struct ppp_fsm_t *layer);
static void restart_timer_func(struct triton_timer_t *t);
static void stop_timer(struct ppp_fsm_t *fsm);

void ppp_fsm_init(struct ppp_fsm_t *layer)
{
	layer->fsm_state = FSM_Initial;
	layer->restart_timer.expire = restart_timer_func;
	layer->restart_timer.period = conf_timeout * 1000;
	layer->restart_counter = 0;

	layer->max_terminate = conf_max_terminate;
	layer->max_configure = conf_max_configure;
	layer->max_failure = conf_max_failure;

	layer->id = random();
}
void ppp_fsm_free(struct ppp_fsm_t *layer)
{
	stop_timer(layer);
}

int ppp_fsm_lower_up(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Initial:
			layer->fsm_state=FSM_Closed;
			break;
		case FSM_Starting:
			//if (layer->init_req_cnt) layer->init_req_cnt(layer);
			init_req_counter(layer,layer->max_configure);
			--layer->restart_counter;
			if (layer->send_conf_req)
				if (layer->send_conf_req(layer))
					return -1;
			layer->fsm_state=FSM_Req_Sent;
			break;
		default:
			break;
	}
	return 0;
}

void ppp_fsm_lower_down(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Closed:
		case FSM_Closing:
			layer->fsm_state=FSM_Initial;
			break;
		case FSM_Stopped:
			if (layer->layer_started) layer->layer_started(layer);
			layer->fsm_state=FSM_Starting;
			break;
		case FSM_Stopping:
		case FSM_Req_Sent:
		case FSM_Ack_Rcvd:
		case FSM_Ack_Sent:
			layer->fsm_state=FSM_Starting;
			break;
		case FSM_Opened:
			if (layer->layer_down) layer->layer_down(layer);
			layer->fsm_state=FSM_Starting;
			break;
		default:
			break;
	}
}

int ppp_fsm_open(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Initial:
			//if (layer->layer_started) layer->layer_started(layer);
			layer->fsm_state=FSM_Starting;
			break;
		case FSM_Starting:
			break;
		case FSM_Closed:
			//if (layer->init_req_cnt) layer->init_req_cnt(layer);
			init_req_counter(layer,layer->max_configure);
			--layer->restart_counter;
			layer->fsm_state=FSM_Req_Sent;
			if (layer->send_conf_req)
				if (layer->send_conf_req(layer))
					return -1;
			break;
		case FSM_Closing:
		case FSM_Stopping:
		case FSM_Stopped:
		case FSM_Opened:
			ppp_fsm_lower_down(layer);
			ppp_fsm_lower_up(layer);
			break;
		default:
			break;
	}
	return 0;
}

void ppp_fsm_close(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Starting:
			stop_timer(layer);
			layer->fsm_state=FSM_Initial;
			if (layer->layer_finished) layer->layer_finished(layer);
			break;
		case FSM_Stopped:
			layer->fsm_state=FSM_Closed;
			stop_timer(layer);
			break;
		case FSM_Stopping:
			layer->fsm_state=FSM_Closing;
			break;
		case FSM_Opened:
			layer->fsm_state=FSM_Closing;
			if (layer->layer_down) layer->layer_down(layer);
		case FSM_Req_Sent:
		case FSM_Ack_Rcvd:
		case FSM_Ack_Sent:
			//if (layer->init_req_cnt) layer->init_req_cnt(layer);
			init_req_counter(layer,layer->max_terminate);
			layer->send_term_req(layer);
			layer->fsm_state=FSM_Closing;
			break;
		default:
			break;
	}
}

void ppp_fsm_close2(struct ppp_fsm_t *layer)
{
	stop_timer(layer);
	layer->fsm_state=FSM_Closed;
}

void ppp_fsm_timeout0(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Closing:
		case FSM_Stopping:
			--layer->restart_counter;
			layer->send_term_req(layer);
			break;
		case FSM_Ack_Rcvd:
			layer->fsm_state=FSM_Req_Sent;
		case FSM_Req_Sent:
		case FSM_Ack_Sent:
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			break;
		default:
			break;
	}
}

void ppp_fsm_timeout1(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Closing:
			stop_timer(layer);
			layer->fsm_state=FSM_Closed;
			if (layer->layer_finished) layer->layer_finished(layer);
			break;
		case FSM_Stopping:
			stop_timer(layer);
			layer->fsm_state=FSM_Stopped;
			if (layer->layer_finished) layer->layer_finished(layer);
			break;
		case FSM_Ack_Rcvd:
		case FSM_Req_Sent:
		case FSM_Ack_Sent:
			stop_timer(layer);
			layer->fsm_state=FSM_Stopped;
			if (layer->layer_finished) layer->layer_finished(layer);
			break;
		default:
			break;
	}
}

void ppp_fsm_recv_conf_req_ack(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Closed:
			layer->send_term_ack(layer);
			break;
		case FSM_Stopped:
			//if (layer->init_req_cnt) layer->init_req_cnt(layer);
			init_req_counter(layer,layer->max_configure);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
		case FSM_Req_Sent:
		case FSM_Ack_Sent:
			if (layer->send_conf_ack) layer->send_conf_ack(layer);
			layer->fsm_state=FSM_Ack_Sent;
			break;
		case FSM_Ack_Rcvd:
			if (layer->send_conf_ack) layer->send_conf_ack(layer);
			stop_timer(layer);
			if (layer->layer_up) layer->layer_up(layer);
			layer->fsm_state=FSM_Opened;
			break;
		case FSM_Opened:
			if (layer->layer_down) layer->layer_down(layer);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			if (layer->send_conf_ack) layer->send_conf_ack(layer);
			layer->fsm_state=FSM_Ack_Sent;
			break;
		default:
			break;
	}
}

void ppp_fsm_recv_conf_req_nak(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Closed:
			layer->send_term_ack(layer);
			break;
		case FSM_Stopped:
			//if (layer->init_req_cnt) layer->init_req_cnt(layer);
			init_req_counter(layer,layer->max_configure);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
		case FSM_Ack_Sent:
			if (layer->send_conf_nak) layer->send_conf_nak(layer);
			layer->fsm_state=FSM_Req_Sent;
			break;
		case FSM_Req_Sent:
		case FSM_Ack_Rcvd:
			if (++layer->conf_failure == layer->max_failure) {
				if (layer->layer_finished) layer->layer_finished(layer);
				return;
			}
			if (layer->send_conf_nak) layer->send_conf_nak(layer);
			break;
		case FSM_Opened:
			if (layer->layer_down) layer->layer_down(layer);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			if (layer->send_conf_nak) layer->send_conf_nak(layer);
			layer->fsm_state=FSM_Req_Sent;
			break;
		default:
			break;
	}
}

void ppp_fsm_recv_conf_req_rej(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Closed:
			layer->send_term_ack(layer);
			break;
		case FSM_Stopped:
			//if (layer->init_req_cnt) layer->init_req_cnt(layer);
			init_req_counter(layer,layer->max_configure);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
		case FSM_Ack_Sent:
			if (++layer->conf_failure == layer->max_failure) {
				if (layer->layer_down) layer->layer_down(layer);
				return;
			}
			if (layer->send_conf_rej) layer->send_conf_rej(layer);
			layer->fsm_state=FSM_Req_Sent;
			break;
		case FSM_Req_Sent:
		case FSM_Ack_Rcvd:
			if (++layer->conf_failure == layer->max_failure) {
				if (layer->layer_finished) layer->layer_finished(layer);
				return;
			}
			if (layer->send_conf_rej) layer->send_conf_rej(layer);
			break;
		case FSM_Opened:
			if (layer->layer_down) layer->layer_down(layer);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			if (layer->send_conf_rej) layer->send_conf_rej(layer);
			layer->fsm_state=FSM_Req_Sent;
			break;
		default:
			break;
	}
}

void ppp_fsm_recv_conf_ack(struct ppp_fsm_t *layer)
{
	++layer->id;
	switch(layer->fsm_state)
	{
		case FSM_Closed:
		case FSM_Stopped:
			layer->send_term_ack(layer);
			break;
		case FSM_Req_Sent:
			//if (layer->init_req_cnt) layer->init_req_cnt(layer);
			layer->fsm_state=FSM_Ack_Rcvd;
			break;
		case FSM_Ack_Rcvd:
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			layer->fsm_state=FSM_Req_Sent;
			break;
		case FSM_Ack_Sent:
			//if (layer->init_req_cnt) layer->init_req_cnt(layer);
			//init_req_counter(layer,layer->max_configure);
			//tlu
			stop_timer(layer);
			if (layer->layer_up) layer->layer_up(layer);
			layer->fsm_state=FSM_Opened;
			break;
		case FSM_Opened:
			if (layer->layer_down) layer->layer_down(layer);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			layer->fsm_state=FSM_Req_Sent;
		default:
			break;
	}
}

void ppp_fsm_recv_conf_rej(struct ppp_fsm_t *layer)
{
	++layer->id;
	switch(layer->fsm_state)
	{
		case FSM_Closed:
		case FSM_Stopped:
			layer->send_term_ack(layer);
			break;
		case FSM_Req_Sent:
			if (++layer->conf_failure == layer->max_failure) {
				if (layer->layer_down) layer->layer_down(layer);
				return;
			}
			//if (layer->init_req_cnt) layer->init_req_cnt(layer);
			init_req_counter(layer,layer->max_failure);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			break;
		case FSM_Ack_Rcvd:
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			layer->fsm_state=FSM_Req_Sent;
			break;
		case FSM_Ack_Sent:
			if (++layer->conf_failure == layer->max_failure) {
				if (layer->layer_down) layer->layer_down(layer);
				return;
			}
			init_req_counter(layer,layer->max_configure);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			break;
		case FSM_Opened:
			if (layer->layer_down) layer->layer_down(layer);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			layer->fsm_state=FSM_Req_Sent;
			break;
		default:
			break;
	}
}

void ppp_fsm_recv_term_req(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Opened:
			if (layer->layer_down) layer->layer_down(layer);
			//send_term_req(layer);
			layer->send_term_ack(layer);
			//if (layer->zero_req_cnt) layer->zero_req_cnt(layer);
			zero_req_counter(layer);
			layer->fsm_state=FSM_Stopping;
			break;
		case FSM_Req_Sent:
		case FSM_Ack_Rcvd:
		case FSM_Ack_Sent:
			layer->send_term_ack(layer);
			layer->fsm_state=FSM_Req_Sent;
			break;
		default:
			layer->send_term_ack(layer);
			break;
	}
}

void ppp_fsm_recv_term_ack(struct ppp_fsm_t *layer)
{
	stop_timer(layer);
	switch(layer->fsm_state)
	{
		case FSM_Closing:
			layer->fsm_state=FSM_Closed;
			if (layer->layer_finished) layer->layer_finished(layer);
			break;
		case FSM_Stopping:
			layer->fsm_state=FSM_Stopped;
			if (layer->layer_finished) layer->layer_finished(layer);
			break;
		case FSM_Ack_Rcvd:
			layer->fsm_state=FSM_Req_Sent;
			break;
		case FSM_Opened:
			if (layer->layer_down) layer->layer_down(layer);
			--layer->restart_counter;
			if (layer->send_conf_req) layer->send_conf_req(layer);
			layer->fsm_state=FSM_Req_Sent;
			break;
		default:
			break;
	}
}

void ppp_fsm_recv_unk(struct ppp_fsm_t *layer)
{
	if (layer->send_code_rej) layer->send_code_rej(layer);
}

void ppp_fsm_recv_code_rej_perm(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Ack_Rcvd:
			layer->fsm_state=FSM_Req_Sent;
			break;
		default:
			break;
	}
}

void ppp_fsm_recv_code_rej_bad(struct ppp_fsm_t *layer)
{
	switch(layer->fsm_state)
	{
		case FSM_Opened:
			if (layer->layer_down) layer->layer_down(layer);
			--layer->restart_counter;
			layer->send_term_req(layer);
			layer->fsm_state=FSM_Stopping;
			break;
		case FSM_Closing:
			layer->fsm_state=FSM_Closed;
			if (layer->layer_finished) layer->layer_finished(layer);
			break;
		case FSM_Stopping:
		case FSM_Req_Sent:
		case FSM_Ack_Rcvd:
		case FSM_Ack_Sent:
			layer->fsm_state=FSM_Stopped;
			if (layer->layer_finished) layer->layer_finished(layer);
			break;
		default:
			break;
	}
}

static void stop_timer(struct ppp_fsm_t *fsm)
{
	if (fsm->restart_timer.tpd)
		triton_timer_del(&fsm->restart_timer);
}
static void init_req_counter(struct ppp_fsm_t *layer,int timeout)
{
	layer->restart_counter = timeout;

	if (!layer->restart_timer.tpd)
		triton_timer_add(layer->ppp->ses.ctrl->ctx, &layer->restart_timer, 0);
}
static void zero_req_counter(struct ppp_fsm_t *layer)
{
	layer->restart_counter=0;

	if (!layer->restart_timer.tpd)
		triton_timer_add(layer->ppp->ses.ctrl->ctx, &layer->restart_timer, 0);
}

static void restart_timer_func(struct triton_timer_t *t)
{
	struct ppp_fsm_t *layer = container_of(t, typeof(*layer), restart_timer);

	log_ppp_debug("fsm timeout %i\n", layer->restart_counter);

	if (layer->restart_counter>0)
		ppp_fsm_timeout0(layer);
	else
		ppp_fsm_timeout1(layer);
}

static void load_config(void)
{
	char *opt;

	opt = conf_get_opt("ppp", "max-terminate");
	if (opt && atoi(opt) > 0)
		conf_max_terminate = atoi(opt);

	opt = conf_get_opt("ppp", "max-configure");
	if (opt && atoi(opt) > 0)
		conf_max_configure = atoi(opt);

	opt = conf_get_opt("ppp", "max-failure");
	if (opt && atoi(opt) > 0)
		conf_max_failure = atoi(opt);

	opt = conf_get_opt("ppp", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

}

static void fsm_init(void)
{
	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(3, fsm_init);
