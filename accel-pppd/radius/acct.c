#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "linux_ppp.h"

#include "crypto.h"

#include "log.h"
#include "backup.h"
#include "ap_session_backup.h"
#include "iputils.h"

#include "radius_p.h"

#include "memdebug.h"

#ifndef max
#define max(x,y) ((x) > (y) ? (x) : (y))
#endif

#define INTERIM_SAFE_TIME 10

static int req_set_RA(struct rad_req_t *req, const char *secret)
{
	MD5_CTX ctx;

	if (rad_packet_build(req->pack, req->RA))
		return -1;

	MD5_Init(&ctx);
	MD5_Update(&ctx, req->pack->buf, req->pack->len);
	MD5_Update(&ctx, secret, strlen(secret));
	MD5_Final(req->pack->buf + 4, &ctx);

	return 0;
}

static int req_set_stat(struct rad_req_t *req, struct ap_session *ses)
{
	struct timespec ts;
	int ret = 0;

	if (ses->stop_time)
		ts.tv_sec = ses->stop_time;
	else
		clock_gettime(CLOCK_MONOTONIC, &ts);

	rad_packet_change_int(req->pack, NULL, "Acct-Input-Octets", (int) (ses->acct_rx_bytes & UINT32_MAX));
	rad_packet_change_int(req->pack, NULL, "Acct-Output-Octets", (int) (ses->acct_tx_bytes & UINT32_MAX));
	rad_packet_change_int(req->pack, NULL, "Acct-Input-Packets", (int) (ses->acct_rx_packets & UINT32_MAX));
	rad_packet_change_int(req->pack, NULL, "Acct-Output-Packets", (int) (ses->acct_tx_packets & UINT32_MAX));
	rad_packet_change_int(req->pack, NULL, "Acct-Input-Gigawords", (int) (ses->acct_rx_bytes >> (sizeof(uint32_t) * 8)));
	rad_packet_change_int(req->pack, NULL, "Acct-Output-Gigawords", (int) (ses->acct_tx_bytes >> (sizeof(uint32_t) * 8)));

	rad_packet_change_int(req->pack, NULL, "Acct-Session-Time", ts.tv_sec - ses->start_time);

	return ret;
}

static void rad_acct_sent(struct rad_req_t *req, int res)
{
	if (res)
		return;

	__sync_add_and_fetch(&req->serv->stat_interim_sent, 1);

	if (!req->hnd.tpd)
		triton_md_register_handler(req->rpd->ses->ctrl->ctx, &req->hnd);

	triton_md_enable_handler(&req->hnd, MD_MODE_READ);

	if (req->timeout.tpd)
		triton_timer_mod(&req->timeout, 0);
	else
		triton_timer_add(req->rpd->ses->ctrl->ctx, &req->timeout, 0);
}

static void rad_acct_recv(struct rad_req_t *req)
{
	int dt = (req->reply->tv.tv_sec - req->pack->tv.tv_sec) * 1000 +
		(req->reply->tv.tv_nsec - req->pack->tv.tv_nsec) / 1000000;

	stat_accm_add(req->serv->stat_interim_query_1m, dt);
	stat_accm_add(req->serv->stat_interim_query_5m, dt);

	if (req->timeout.tpd)
		triton_timer_del(&req->timeout);

	triton_md_unregister_handler(&req->hnd, 1);

	rad_packet_free(req->reply);
	req->reply = NULL;
}

static void rad_acct_timeout(struct triton_timer_t *t)
{
	struct rad_req_t *req = container_of(t, typeof(*req), timeout);
	time_t dt;
	struct timespec ts;

	rad_server_req_exit(req);
	rad_server_timeout(req->serv);

	__sync_add_and_fetch(&req->serv->stat_interim_lost, 1);
	stat_accm_add(req->serv->stat_interim_lost_1m, 1);
	stat_accm_add(req->serv->stat_interim_lost_5m, 1);

	if (conf_acct_timeout == 0) {
		triton_timer_del(t);
		triton_md_unregister_handler(&req->hnd, 1);
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts);

	dt = ts.tv_sec - req->ts;

	if (dt > conf_acct_timeout) {
		log_ppp_warn("radius: server(%i) not responding, terminating session...\n", req->serv->id);
		triton_timer_del(t);
		ap_session_terminate(req->rpd->ses, TERM_NAS_ERROR, 0);
		return;
	}

	if (dt > conf_acct_timeout / 2)
		req->timeout.expire_tv.tv_sec++;
	else if (dt > conf_acct_timeout / 4) {
		if (req->timeout.expire_tv.tv_sec < conf_timeout * 2)
			req->timeout.expire_tv.tv_sec = conf_timeout * 2;
	}

	if (conf_acct_delay_time)
		req->pack->id++;

	req->try = 0;

	if (rad_req_send(req) && conf_acct_timeout) {
		log_ppp_warn("radius:acct: no servers available, terminating session...\n");
		ap_session_terminate(req->rpd->ses, TERM_NAS_ERROR, 0);
	}
}

static void rad_acct_interim_update(struct triton_timer_t *t)
{
	struct radius_pd_t *rpd = container_of(t, typeof(*rpd), acct_interim_timer);
	struct ap_session *ses = rpd->ses;
	struct timespec ts;
	int force = 0;

	if (rpd->acct_req->entry.next || rpd->acct_req->timeout.tpd)
		return;

	if (rpd->session_timeout.expire_tv.tv_sec &&
			rpd->session_timeout.expire_tv.tv_sec - (_time() - ses->start_time) < INTERIM_SAFE_TIME)
			return;

	if (req_set_stat(rpd->acct_req, rpd->ses)) {
		ap_session_terminate(rpd->ses, TERM_LOST_CARRIER, 0);
		return;
	}

	if (ses->ipv6_dp && !rpd->ipv6_dp_sent) {
		struct ipv6db_addr_t *a;
		list_for_each_entry(a, &ses->ipv6_dp->prefix_list, entry)
			rad_packet_add_ipv6prefix(rpd->acct_req->pack, NULL, "Delegated-IPv6-Prefix", &a->addr, a->prefix_len);
		rpd->ipv6_dp_sent = 1;
		force = 1;
	}

	if (!rpd->acct_interim_interval && !force)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	rpd->acct_req->ts = ts.tv_sec;
	rpd->acct_req->pack->id++;

	if (!rpd->acct_req->before_send)
		req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret);

	rpd->acct_req->timeout.expire_tv.tv_sec = conf_timeout;
	rpd->acct_req->try = 0;

	if (rad_req_send(rpd->acct_req) && conf_acct_timeout) {
		log_ppp_warn("radius:acct: no servers available, terminating session...\n");
		ap_session_terminate(rpd->ses, TERM_NAS_ERROR, 0);
	} else if (rpd->acct_interim_interval && rpd->acct_interim_jitter) {
		t->period = max(rpd->acct_interim_interval -
					rpd->acct_interim_jitter, INTERIM_SAFE_TIME) * 1000;
		t->period += ((rpd->acct_interim_interval +
					rpd->acct_interim_jitter) * 1000 - t->period) * random() / RAND_MAX;
		triton_timer_mod(t, 0);
	}
}

void rad_acct_force_interim_update(struct radius_pd_t *rpd)
{
	if (!rpd->acct_req)
		return;

	rad_acct_interim_update(&rpd->acct_interim_timer);
}

static int rad_acct_before_send(struct rad_req_t *req)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	rad_packet_change_int(req->pack, NULL, "Acct-Delay-Time", ts.tv_sec - req->ts + conf_acct_delay_start);
	req_set_RA(req, req->serv->secret);

	return 0;
}

static void rad_acct_start_sent(struct rad_req_t *req, int res)
{
	if (res) {
		ap_session_terminate(req->rpd->ses, TERM_NAS_ERROR, 0);
		return;
	}

	__sync_add_and_fetch(&req->serv->stat_acct_sent, 1);

	if (!req->hnd.tpd)
		triton_md_register_handler(req->rpd->ses->ctrl->ctx, &req->hnd);

	triton_md_enable_handler(&req->hnd, MD_MODE_READ);

	if (req->timeout.tpd)
		triton_timer_mod(&req->timeout, 0);
	else
		triton_timer_add(req->rpd->ses->ctrl->ctx, &req->timeout, 0);
}

static void rad_acct_start_recv(struct rad_req_t *req)
{
	struct radius_pd_t *rpd = req->rpd;
	int dt = (req->reply->tv.tv_sec - req->pack->tv.tv_sec) * 1000 +
					(req->reply->tv.tv_nsec - req->pack->tv.tv_nsec) / 1000000;

	stat_accm_add(req->serv->stat_acct_query_1m, dt);
	stat_accm_add(req->serv->stat_acct_query_5m, dt);

	triton_timer_del(&req->timeout);

	triton_md_unregister_handler(&req->hnd, 1);

	if (rpd->acct_interim_interval) {
		rad_packet_free(req->reply);
		req->reply = NULL;

		rad_packet_change_val(req->pack, NULL, "Acct-Status-Type", "Interim-Update");
		rpd->acct_interim_timer.expire = rad_acct_interim_update;
		if (rpd->acct_interim_jitter) {
			rpd->acct_interim_timer.period = max(rpd->acct_interim_interval -
						rpd->acct_interim_jitter, INTERIM_SAFE_TIME) * 1000;
			rpd->acct_interim_timer.period += ((rpd->acct_interim_interval +
						rpd->acct_interim_jitter) * 1000 - rpd->acct_interim_timer.period) * random() / RAND_MAX;
		} else
			rpd->acct_interim_timer.period = rpd->acct_interim_interval * 1000;
		triton_timer_add(rpd->ses->ctrl->ctx, &rpd->acct_interim_timer, 0);

		req->timeout.expire = rad_acct_timeout;
		req->recv = rad_acct_recv;
		req->sent = rad_acct_sent;
		req->log = conf_interim_verbose ? log_ppp_info2 : NULL;
		req->prio = 1;
	} else {
		rad_req_free(rpd->acct_req);
		rpd->acct_req = NULL;
	}

	rpd->acct_started = 1;

	ap_session_accounting_started(rpd->ses);
}

static void rad_acct_start_timeout(struct triton_timer_t *t)
{
	struct rad_req_t *req = container_of(t, typeof(*req), timeout);

	rad_server_timeout(req->serv);

	__sync_add_and_fetch(&req->serv->stat_acct_lost, 1);
	stat_accm_add(req->serv->stat_acct_lost_1m, 1);
	stat_accm_add(req->serv->stat_acct_lost_5m, 1);

	if (req->before_send)
		req->pack->id++;

	if (rad_req_send(req))
		ap_session_terminate(req->rpd->ses, TERM_NAS_ERROR, 0);
}

static int __rad_acct_start(struct radius_pd_t *rpd)
{
	struct rad_req_t *req = rad_req_alloc(rpd, CODE_ACCOUNTING_REQUEST, rpd->ses->username, 0);

	if (!req)
		return -1;

	if (rad_req_acct_fill(req)) {
		log_ppp_error("radius:acct: failed to fill accounting attributes\n");
		goto out_err;
	}

	if (conf_acct_delay_time)
		req->before_send = rad_acct_before_send;
	else if (req_set_RA(req, req->serv->secret))
		goto out_err;

	req->recv = rad_acct_start_recv;
	req->timeout.expire = rad_acct_start_timeout;
	req->timeout.expire_tv.tv_sec = conf_timeout;
	req->sent = rad_acct_start_sent;
	req->log = conf_verbose ? log_ppp_info1 : NULL;

	if (rad_req_send(req))
		goto out_err;

	rpd->acct_req = req;

	return 0;

out_err:
	rad_req_free(req);
	return -1;
}

static void rad_acct_start_delay(struct triton_timer_t *t)
{
	struct radius_pd_t *rpd = container_of(t, typeof(*rpd), acct_interim_timer);

	triton_timer_del(&rpd->acct_interim_timer);

	if (__rad_acct_start(rpd))
		ap_session_terminate(rpd->ses, TERM_NAS_ERROR, 0);
}

int rad_acct_start(struct radius_pd_t *rpd)
{
	if (conf_acct_delay_start) {
		log_ppp_debug("radius: acct delay start %i\n", conf_acct_delay_start);
		rpd->acct_interim_timer.expire = rad_acct_start_delay;
		rpd->acct_interim_timer.expire_tv.tv_sec = conf_acct_delay_start;
		triton_timer_add(rpd->ses->ctrl->ctx, &rpd->acct_interim_timer, 0);
		return 0;
	}

	return __rad_acct_start(rpd);
}

static void rad_acct_stop_sent(struct rad_req_t *req, int res)
{
	if (res) {
		if (ap_shutdown) {
			struct radius_pd_t *rpd = req->rpd;

			rad_req_free(req);

			if (rpd)
				rpd->acct_req = NULL;
		} else if (req->rpd)
			rad_acct_stop_defer(req->rpd);

		return;
	}

	__sync_add_and_fetch(&req->serv->stat_acct_sent, 1);

	if (!req->hnd.tpd)
		triton_md_register_handler(req->rpd ? req->rpd->ses->ctrl->ctx : NULL, &req->hnd);

	triton_md_enable_handler(&req->hnd, MD_MODE_READ);

	if (req->timeout.tpd)
		triton_timer_mod(&req->timeout, 0);
	else
		triton_timer_add(req->rpd ? req->rpd->ses->ctrl->ctx : NULL, &req->timeout, 0);
}

static void rad_acct_stop_recv(struct rad_req_t *req)
{
	struct radius_pd_t *rpd = req->rpd;
	int dt = (req->reply->tv.tv_sec - req->pack->tv.tv_sec) * 1000 +
					(req->reply->tv.tv_nsec - req->pack->tv.tv_nsec) / 1000000;

	stat_accm_add(req->serv->stat_acct_query_1m, dt);
	stat_accm_add(req->serv->stat_acct_query_5m, dt);

	rad_req_free(req);

	if (rpd)
		rpd->acct_req = NULL;
}

static void rad_acct_stop_timeout(struct triton_timer_t *t)
{
	struct rad_req_t *req = container_of(t, typeof(*req), timeout);

	log_debug("timeout %p\n", req);

	if (!req->rpd)
	    log_switch(triton_context_self(), NULL);

	if (req->active) {
		rad_server_timeout(req->serv);
		rad_server_req_exit(req);

		__sync_add_and_fetch(&req->serv->stat_acct_lost, 1);
		stat_accm_add(req->serv->stat_acct_lost_1m, 1);
		stat_accm_add(req->serv->stat_acct_lost_5m, 1);

		if (req->before_send)
			req->pack->id++;
	}

	if (req->try == conf_max_try) {
		rad_req_free(req);
		return;
	}

	if (rad_req_send(req)) {
		if (ap_shutdown) {
			rad_req_free(req);
			return;
		}
		req->try = 0;
	}
}

static void start_deferred(struct rad_req_t *req)
{
	log_switch(triton_context_self(), NULL);
	if (req->hnd.fd != -1) {
		triton_md_register_handler(NULL, &req->hnd);
		triton_md_enable_handler(&req->hnd, MD_MODE_READ);
		if (rad_req_read(&req->hnd))
			return;
	}

	triton_timer_add(NULL, &req->timeout, 0);
}

void rad_acct_stop_defer(struct radius_pd_t *rpd)
{
	struct rad_req_t *req = rpd->acct_req;

	rad_server_req_cancel(req, 1);
	if (req->hnd.tpd)
		triton_md_unregister_handler(&req->hnd, 0);
	rpd->acct_req = NULL;

	req->rpd = NULL;
	req->log = conf_verbose ? log_info1 : NULL;
	req->timeout.expire = rad_acct_stop_timeout;

	triton_context_call(NULL, (triton_event_func)start_deferred, req);
}

int rad_acct_stop(struct radius_pd_t *rpd)
{
	struct rad_req_t *req = rpd->acct_req;
	struct timespec ts;

	if (rpd->acct_interim_timer.tpd)
		triton_timer_del(&rpd->acct_interim_timer);

	if (req) {
		rad_server_req_cancel(req, 1);

		clock_gettime(CLOCK_MONOTONIC, &ts);
		req->ts = ts.tv_sec;
		req->try = 0;
	} else {
		req = rad_req_alloc(rpd, CODE_ACCOUNTING_REQUEST, rpd->ses->username, 1);
		if (!req)
			return -1;

		if (rad_req_acct_fill(req)) {
			log_ppp_error("radius:acct: failed to fill accounting attributes\n");
			rad_req_free(req);
			return -1;
		}

		rpd->acct_req = req;
	}

	switch (rpd->ses->terminate_cause) {
		case TERM_USER_REQUEST:
			rad_packet_add_val(req->pack, NULL, "Acct-Terminate-Cause", "User-Request");
			break;
		case TERM_SESSION_TIMEOUT:
			rad_packet_add_val(req->pack, NULL, "Acct-Terminate-Cause", "Session-Timeout");
			break;
		case TERM_ADMIN_RESET:
			rad_packet_add_val(req->pack, NULL, "Acct-Terminate-Cause", "Admin-Reset");
			break;
		case TERM_USER_ERROR:
		case TERM_AUTH_ERROR:
			rad_packet_add_val(req->pack, NULL, "Acct-Terminate-Cause", "User-Error");
			break;
		case TERM_NAS_ERROR:
			rad_packet_add_val(req->pack, NULL, "Acct-Terminate-Cause", "NAS-Error");
			break;
		case TERM_NAS_REQUEST:
			rad_packet_add_val(req->pack, NULL, "Acct-Terminate-Cause", "NAS-Request");
			break;
		case TERM_NAS_REBOOT:
			rad_packet_add_val(req->pack, NULL, "Acct-Terminate-Cause", "NAS-Reboot");
			break;
		case TERM_LOST_CARRIER:
			rad_packet_add_val(req->pack, NULL, "Acct-Terminate-Cause", "Lost-Carrier");
			break;
		case TERM_IDLE_TIMEOUT:
			rad_packet_add_val(req->pack, NULL, "Acct-Terminate-Cause", "Idle-Timeout");
			break;
	}

	req->pack->id++;

	rad_packet_change_val(req->pack, NULL, "Acct-Status-Type", "Stop");
	req_set_stat(req, rpd->ses);
	req_set_RA(req, req->serv->secret);

	req->recv = rad_acct_stop_recv;
	req->timeout.expire = rad_acct_start_timeout;
	req->timeout.expire_tv.tv_sec = conf_timeout;
	req->sent = rad_acct_stop_sent;
	req->log = conf_verbose ? log_ppp_info1 : NULL;

	if (rad_req_send(req)) {
		rad_acct_stop_defer(rpd);
		return -1;
	}

	return 0;
}

