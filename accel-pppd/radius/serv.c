#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/md5.h>

#include "log.h"
#include "triton.h"
#include "events.h"
#include "cli.h"
#include "utils.h"

#include "radius_p.h"

#include "memdebug.h"

static int conf_acct_on;
static int conf_fail_timeout;
static int conf_max_fail;
static int conf_req_limit;

static int num;
static LIST_HEAD(serv_list);

static void __free_server(struct rad_server_t *);
static void serv_ctx_close(struct triton_context_t *);

static struct rad_server_t *__rad_server_get(int type, struct rad_server_t *exclude, in_addr_t addr, int port)
{
	struct rad_server_t *s, *s0 = NULL, *s1 = NULL;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	list_for_each_entry(s, &serv_list, entry) {
		if (s == exclude)
			continue;

		if (s->fail_time && ts.tv_sec < s->fail_time)
			continue;

		if (type == RAD_SERV_AUTH && !s->auth_port)
			continue;
		else if (type == RAD_SERV_ACCT && !s->acct_port)
			continue;

		if (s->addr == addr) {
			if (type == RAD_SERV_AUTH && port == s->auth_port)
				s1 = s;
			else if (type == RAD_SERV_ACCT && port == s->acct_port)
				s1 = s;
			else if (!s1)
				s1 = s;
		}

		if (!s0) {
			s0 = s;
			continue;
		}

		if ((s->backup < s0->backup) ||
			((s->backup == s0->backup) &&
			((s->client_cnt[0] + s->client_cnt[1])*s0->weight < (s0->client_cnt[0] + s0->client_cnt[1])*s->weight)))
		s0 = s;
	}

	if (s1)
		s0 = s1;
	else if (!s0)
		return NULL;

	__sync_add_and_fetch(&s0->client_cnt[type], 1);

	return s0;
}

struct rad_server_t *rad_server_get(int type)
{
	return __rad_server_get(type, NULL, 0, 0);
}

struct rad_server_t *rad_server_get2(int type, in_addr_t addr, int port)
{
	return __rad_server_get(type, NULL, addr, port);
}

void rad_server_put(struct rad_server_t *s, int type)
{
	__sync_sub_and_fetch(&s->client_cnt[type], 1);

	if ((s->need_free || s->need_close) && !s->client_cnt[0] && !s->client_cnt[1]) {
		if (s->need_close)
			triton_context_call(&s->ctx, (triton_event_func)serv_ctx_close, &s->ctx);
		else
			__free_server(s);
	}
}

static void req_wakeup(struct rad_req_t *req)
{
	struct timespec ts;

	if (!req->rpd)
	    log_switch(triton_context_self(), NULL);

	log_ppp_debug("radius(%i): wakeup %p %i\n", req->serv->id, req, req->active);

	if (!req->active)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	pthread_mutex_lock(&req->serv->lock);

	if (ts.tv_sec < req->serv->fail_time || req->serv->need_free) {
		req->active = 0;
		req->serv->req_cnt[req->type]--;
		log_ppp_debug("radius(%i): server failed\n", req->serv->id);
		pthread_mutex_unlock(&req->serv->lock);

		req->send(req, -1);

		return;
	}
	pthread_mutex_unlock(&req->serv->lock);

	req->send(req, 1);
}

static void req_wakeup_failed(struct rad_req_t *req)
{
	if (!req->rpd)
	    log_switch(triton_context_self(), NULL);

	req->send(req, -1);
}

int rad_server_req_cancel(struct rad_req_t *req, int full)
{
	int r = 0;

	pthread_mutex_lock(&req->serv->lock);
	if (req->entry.next) {
		list_del(&req->entry);
		req->serv->queue_cnt[req->type]--;
		r = 1;
	}
	pthread_mutex_unlock(&req->serv->lock);

	triton_cancel_call(req->rpd ? req->rpd->ses->ctrl->ctx : NULL, (triton_event_func)req_wakeup);

	if (!full)
		return r;

	if (req->active)
		rad_server_req_exit(req);

	if (req->timeout.tpd)
		triton_timer_del(&req->timeout);

	if (req->hnd.tpd)
		triton_md_unregister_handler(&req->hnd, 0);

	return r;
}

int rad_server_req_enter(struct rad_req_t *req)
{
	struct timespec ts;
	int r = 0;

	if (req->serv->need_free)
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ts.tv_sec < req->serv->fail_time)
		return -1;

	if (!req->serv->req_limit) {
		__sync_add_and_fetch(&req->serv->req_cnt[req->type], 1);
		req->active = 1;

		if (req->send) {
			r = req->send(req, 0);
			if (r) {
				if (r == -2) {
					req->active = 0;
					__sync_sub_and_fetch(&req->serv->req_cnt[req->type], 1);
					rad_server_fail(req->serv);
				} else
					rad_server_req_exit(req);
			}
			return r;
		}
		return 0;
	}

	assert(!req->active);
	assert(!req->entry.next);

	pthread_mutex_lock(&req->serv->lock);

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ts.tv_sec < req->serv->fail_time) {
		pthread_mutex_unlock(&req->serv->lock);
		return -1;
	}

	if (req->serv->req_cnt[req->type] >= req->serv->req_limit) {
		if (req->send) {
			list_add_tail(&req->entry, &req->serv->req_queue[req->type]);
			req->serv->queue_cnt[req->type]++;
			log_ppp_debug("radius(%i): queue %p\n", req->serv->id, req);
			pthread_mutex_unlock(&req->serv->lock);

			if (req->hnd.tpd)
				triton_md_disable_handler(&req->hnd, MD_MODE_READ);

			return 0;
		}

		pthread_mutex_unlock(&req->serv->lock);
		return 1;
	}

	req->serv->req_cnt[req->type]++;
	log_ppp_debug("radius(%i): req_enter %i\n", req->serv->id, req->serv->req_cnt[req->type]);
	pthread_mutex_unlock(&req->serv->lock);

	req->active = 1;

	if (req->send) {
		r = req->send(req, 0);
		if (r) {
			if (r == -2) {
				req->active = 0;
				pthread_mutex_lock(&req->serv->lock);
				req->serv->req_cnt[req->type]--;
				pthread_mutex_unlock(&req->serv->lock);

				rad_server_fail(req->serv);
			} else
				rad_server_req_exit(req);
		}
	}

	return r;
}

void rad_server_req_exit(struct rad_req_t *req)
{
	struct rad_server_t *serv = req->serv;

	if (!req->serv->req_limit) {
		if (req->active) {
			req->active = 0;
			__sync_sub_and_fetch(&serv->req_cnt[req->type], 1);
		}
		return;
	}

	assert(req->active);

	req->active = 0;

	pthread_mutex_lock(&serv->lock);
	serv->req_cnt[req->type]--;
	log_ppp_debug("radius(%i): req_exit %i\n", serv->id, serv->req_cnt[req->type]);
	assert(serv->req_cnt[req->type] >= 0);
	if (serv->req_cnt[req->type] < serv->req_limit) {
		struct list_head *list = NULL;
		if (!list_empty(&serv->req_queue[req->type]))
			list = &serv->req_queue[req->type];

		if (list) {
			struct rad_req_t *r = list_entry(list->next, typeof(*r), entry);
			log_ppp_debug("radius(%i): wakeup %p\n", serv->id, r);
			list_del(&r->entry);
			serv->queue_cnt[req->type]--;
			serv->req_cnt[req->type]++;
			r->active = 1;
			triton_context_call(r->rpd ? r->rpd->ses->ctrl->ctx : NULL, (triton_event_func)req_wakeup, r);
		}
	}
	pthread_mutex_unlock(&serv->lock);
}

int rad_server_realloc(struct rad_req_t *req)
{
	struct rad_server_t *s = __rad_server_get(req->type, req->serv, 0, 0);

	if (!s)
		return -1;

	if (req->serv)
		rad_server_put(req->serv, req->type);

	req->serv = s;

	if (req->hnd.fd != -1) {
		if (req->hnd.tpd)
			triton_md_unregister_handler(&req->hnd, 1);
		else {
			close(req->hnd.fd);
			req->hnd.fd = -1;
		}
	}

	req->server_addr = req->serv->addr;
	if (req->type == RAD_SERV_ACCT)
		req->server_port = req->serv->acct_port;
	else
		req->server_port = req->serv->auth_port;

	return 0;
}

void rad_server_fail(struct rad_server_t *s)
{
	struct rad_req_t *r;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	pthread_mutex_lock(&s->lock);

	if (ts.tv_sec >= s->fail_time) {
		s->fail_time = ts.tv_sec + s->fail_timeout;
		log_ppp_warn("radius: server(%i) not responding\n", s->id);
		log_warn("radius: server(%i) not responding\n", s->id);
	}

	while (!list_empty(&s->req_queue[0])) {
		r = list_entry(s->req_queue[0].next, typeof(*r), entry);
		list_del(&r->entry);
		triton_context_call(r->rpd ? r->rpd->ses->ctrl->ctx : NULL, (triton_event_func)req_wakeup_failed, r);
	}

	while (!list_empty(&s->req_queue[1])) {
		r = list_entry(s->req_queue[1].next, typeof(*r), entry);
		list_del(&r->entry);
		triton_context_call(r->rpd ? r->rpd->ses->ctrl->ctx : NULL, (triton_event_func)req_wakeup_failed, r);
	}

	s->queue_cnt[0] = 0;
	s->queue_cnt[1] = 0;
	s->stat_fail_cnt++;

	pthread_mutex_unlock(&s->lock);
}

void rad_server_timeout(struct rad_server_t *s)
{
	if (!s->fail_timeout)
		return;

	if (__sync_add_and_fetch(&s->timeout_cnt, 1) >= s->max_fail)
		rad_server_fail(s);
}

void rad_server_reply(struct rad_server_t *s)
{
	__sync_synchronize();
	s->timeout_cnt = 0;
}

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

static void acct_on_sent(struct rad_req_t *req, int res)
{
	if (!res && !req->hnd.tpd) {
		triton_md_register_handler(&req->serv->ctx, &req->hnd);
		triton_md_enable_handler(&req->hnd, MD_MODE_READ);
	}
}

static void acct_on_recv(struct rad_req_t *req)
{
	struct rad_server_t *s = req->serv;

	rad_req_free(req);

	if (req->serv->starting) {
		req->serv->starting = 0;
		req->serv->acct_on = 1;
	} else
		__free_server(s);
}

static void acct_on_timeout(struct triton_timer_t *t)
{
	struct rad_req_t *req = container_of(t, typeof(*req), timeout);
	struct rad_server_t *s = req->serv;

	log_switch(triton_context_self(), NULL);

	if (req->try++ == conf_max_try) {
		rad_req_free(req);
		if (s->starting)
			s->starting = 0;
		else
			__free_server(s);
		return;
	}

	__rad_req_send(req, 0);
}

static void send_acct_on(struct rad_server_t *s)
{
	struct rad_req_t *req = rad_req_alloc_empty();

	log_switch(triton_context_self(), NULL);

	memset(req, 0, sizeof(*req));
	req->hnd.fd = -1;
	req->type = RAD_SERV_ACCT;
	req->server_addr = s->addr;
	req->server_port = s->acct_port;
	req->serv = s;
	req->sent = acct_on_sent;
	req->recv = acct_on_recv;
	req->hnd.read = rad_req_read;
	req->timeout.expire = acct_on_timeout;
	req->timeout.period = conf_timeout * 1000;
	req->try = 1;
	__sync_add_and_fetch(&s->client_cnt[req->type], 1);
	if (conf_verbose)
		req->log = log_info1;

	req->pack = rad_packet_alloc(CODE_ACCOUNTING_REQUEST);
	if (!req->pack)
		goto out_err;

	if (rad_packet_add_val(req->pack, NULL, "Acct-Status-Type", s->starting ? "Accounting-On" : "Accounting-Off"))
		goto out_err;

	if (conf_nas_identifier)
		if (rad_packet_add_str(req->pack, NULL, "NAS-Identifier", conf_nas_identifier))
			goto out_err;

	if (conf_nas_ip_address)
		if (rad_packet_add_ipaddr(req->pack, NULL, "NAS-IP-Address", conf_nas_ip_address))
			goto out_err;

	if (req_set_RA(req, s->secret))
		goto out_err;

	__rad_req_send(req, 0);

	triton_timer_add(&s->ctx, &req->timeout, 0);

	return;

out_err:
	rad_req_free(req);
}

static void serv_ctx_close(struct triton_context_t *ctx)
{
	struct rad_server_t *s = container_of(ctx, typeof(*s), ctx);

	if (s->timer.tpd)
		triton_timer_del(&s->timer);

	s->need_close = 1;

	if (!s->client_cnt[0] && !s->client_cnt[1]) {
		if (s->acct_on) {
			s->acct_on = 0;
			s->starting = 0;
			s->need_close = 0;
			send_acct_on(s);
		} else
			triton_context_unregister(ctx);
	}
}

static void show_stat(struct rad_server_t *s, void *client)
{
	char addr[INET6_ADDRSTRLEN];  // Sufficient size for both IPv4 and IPv6 addresses
	struct timespec ts;

	if (s->ipv4) {
		u_inet_ntoa(s->addr, addr);
	} else {
		inet_ntop(AF_INET6, &s->addr6, addr, sizeof(addr));
	}

	clock_gettime(CLOCK_MONOTONIC, &ts);

	cli_sendv(client, "radius(%i, %s):\r\n", s->id, addr);

	if (ts.tv_sec < s->fail_time)
		cli_send(client, "  state: failed\r\n");
	else
		cli_send(client, "  state: active\r\n");

	cli_sendv(client, "  fail count: %lu\r\n", s->stat_fail_cnt);

	cli_sendv(client, "  request count (auth/acct): %i/%i\r\n", s->req_cnt[0], s->req_cnt[1]);
	cli_sendv(client, "  queue length (auth/acct): %i/%i\r\n", s->queue_cnt[0], s->queue_cnt[1]);

	if (s->auth_port) {
		cli_sendv(client, "  auth sent: %lu\r\n", s->stat_auth_sent);
		cli_sendv(client, "  auth lost(total/5m/1m): %lu/%lu/%lu\r\n",
			s->stat_auth_lost, stat_accm_get_cnt(s->stat_auth_lost_5m), stat_accm_get_cnt(s->stat_auth_lost_1m));
		cli_sendv(client, "  auth avg query time(5m/1m): %lu/%lu ms\r\n",
			stat_accm_get_avg(s->stat_auth_query_5m), stat_accm_get_avg(s->stat_auth_query_1m));
	}

	if (s->acct_port) {
		cli_sendv(client, "  acct sent: %lu\r\n", s->stat_acct_sent);
		cli_sendv(client, "  acct lost(total/5m/1m): %lu/%lu/%lu\r\n",
			s->stat_acct_lost, stat_accm_get_cnt(s->stat_acct_lost_5m), stat_accm_get_cnt(s->stat_acct_lost_1m));
		cli_sendv(client, "  acct avg query time(5m/1m): %lu/%lu ms\r\n",
			stat_accm_get_avg(s->stat_acct_query_5m), stat_accm_get_avg(s->stat_acct_query_1m));

		cli_sendv(client, "  interim sent: %lu\r\n", s->stat_interim_sent);
		cli_sendv(client, "  interim lost(total/5m/1m): %lu/%lu/%lu\r\n",
			s->stat_interim_lost, stat_accm_get_cnt(s->stat_interim_lost_5m), stat_accm_get_cnt(s->stat_interim_lost_1m));
		cli_sendv(client, "  interim avg query time(5m/1m): %lu/%lu ms\r\n",
			stat_accm_get_avg(s->stat_interim_query_5m), stat_accm_get_avg(s->stat_interim_query_1m));
	}
}

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	struct rad_server_t *s;

	list_for_each_entry(s, &serv_list, entry)
		show_stat(s, client);

	return CLI_CMD_OK;
}

static void __add_server(struct rad_server_t *s)
{
	struct rad_server_t *s1;

	list_for_each_entry(s1, &serv_list, entry) {
		if (s1->addr == s->addr && s1->auth_port == s->auth_port && s1->acct_port == s->acct_port) {
			s1->fail_timeout = s->fail_timeout;
			s1->req_limit = s->req_limit;
			s1->max_fail = s->max_fail;
			s1->need_free = 0;
			s1->bind_default = s->bind_default;
			strcpy(s1->bind_device, s->bind_device);
			_free(s);
			return;
		}
	}

	s->id = ++num;
	INIT_LIST_HEAD(&s->req_queue[0]);
	INIT_LIST_HEAD(&s->req_queue[1]);
	pthread_mutex_init(&s->lock, NULL);
	list_add_tail(&s->entry, &serv_list);
	s->starting = conf_acct_on;

	s->stat_auth_lost_1m = stat_accm_create(60);
	s->stat_auth_lost_5m = stat_accm_create(5 * 60);
	s->stat_auth_query_1m = stat_accm_create(60);
	s->stat_auth_query_5m = stat_accm_create(5 * 60);

	s->stat_acct_lost_1m = stat_accm_create(60);
	s->stat_acct_lost_5m = stat_accm_create(5 * 60);
	s->stat_acct_query_1m = stat_accm_create(60);
	s->stat_acct_query_5m = stat_accm_create(5 * 60);

	s->stat_interim_lost_1m = stat_accm_create(60);
	s->stat_interim_lost_5m = stat_accm_create(5 * 60);
	s->stat_interim_query_1m = stat_accm_create(60);
	s->stat_interim_query_5m = stat_accm_create(5 * 60);

	s->ctx.close = serv_ctx_close;

	triton_context_register(&s->ctx, NULL);
	triton_context_set_priority(&s->ctx, 0);
	if (conf_acct_on)
		triton_context_call(&s->ctx, (triton_event_func)send_acct_on, s);
	triton_context_wakeup(&s->ctx);
}

static void __free_server(struct rad_server_t *s)
{
	log_debug("radius: free(%i)\n", s->id);

	stat_accm_free(s->stat_auth_lost_1m);
	stat_accm_free(s->stat_auth_lost_5m);
	stat_accm_free(s->stat_auth_query_1m);
	stat_accm_free(s->stat_auth_query_5m);

	stat_accm_free(s->stat_acct_lost_1m);
	stat_accm_free(s->stat_acct_lost_5m);
	stat_accm_free(s->stat_acct_query_1m);
	stat_accm_free(s->stat_acct_query_5m);

	stat_accm_free(s->stat_interim_lost_1m);
	stat_accm_free(s->stat_interim_lost_5m);
	stat_accm_free(s->stat_interim_query_1m);
	stat_accm_free(s->stat_interim_query_5m);

	triton_context_unregister(&s->ctx);

	_free(s);
}

static int parse_server_old(const char *opt, in_addr_t *addr, int *port, char **secret)
{
	char *str = _strdup(opt);
	char *p1, *p2;

	p1 = strstr(str, ":");
	p2 = strstr(str, ",");

	if (p1)
		*p1 = 0;
	if (p2)
		*p2 = 0;
	else {
		_free(str);
		return -1;
	}

	*addr = inet_addr(str);

	if (p1) {
		*port = atoi(p1 + 1);
		if (*port <=0) {
			_free(str);
			return -1;
		}
	}

	*secret = _strdup(p2 + 1);

	_free(str);

	return 0;
}

static void add_server_old(void)
{
	const char *opt;
	in_addr_t auth_addr = 0;
	int auth_port = 0;
	char *auth_secret = NULL;
	in_addr_t acct_addr = 0;
	int acct_port = 0;
	char *acct_secret = NULL;
	struct rad_server_t *s;

	opt = conf_get_opt("radius", "auth-server");
	if (opt) {
		if (parse_server_old(opt, &auth_addr, &auth_port, &auth_secret)) {
			log_emerg("radius: failed to parse 'auth-server'\n");
			return;
		}
	} else
		return;

	opt = conf_get_opt("radius", "acct-server");
	if (opt) {
		if (parse_server_old(opt, &acct_addr, &acct_port, &acct_secret)) {
			log_emerg("radius: failed to parse 'acct-server'\n");
			return;
		}
		conf_accounting = 1;
	}

	s = _malloc(sizeof(*s));
	memset(s, 0, sizeof(*s));
	s->addr = auth_addr;
	s->secret = auth_secret;
	s->auth_port = auth_port;
	s->fail_timeout = conf_fail_timeout;
	s->req_limit = conf_req_limit;
	s->max_fail = conf_max_fail;
	s->bind_default = 1;

	if (auth_addr == acct_addr && !strcmp(auth_secret, acct_secret)) {
		s->acct_port = acct_port;
		__add_server(s);
		return;
	}

	__add_server(s);

	if (acct_addr) {
		s = _malloc(sizeof(*s));
		memset(s, 0, sizeof(*s));
		s->addr = acct_addr;
		s->secret = acct_secret;
		s->acct_port = acct_port;
		s->fail_timeout = conf_fail_timeout;
		s->req_limit = conf_req_limit;
		s->max_fail = conf_max_fail;
		s->bind_default = 1;
		__add_server(s);
	}
}

static int parse_server1(const char *_opt, struct rad_server_t *s)
{
	char *opt = _strdup(_opt);
	char *ptr1, *ptr2, *ptr3, *endptr;

	ptr1 = strchr(opt, ',');
	if (!ptr1)
		goto out;

	ptr2 = strchr(ptr1 + 1, ',');

	if (ptr2)
		ptr3 = strchr(ptr2 + 1, ',');
	else
		ptr3 = NULL;

	*ptr1 = 0;
	if (ptr2)
		*ptr2 = 0;
	if (ptr3)
		*ptr3 = 0;

    struct in_addr addr4;
    if (inet_pton(AF_INET, opt, &addr4) == 1) {
        s->ipv4 = 1;
        s->addr = addr4.s_addr;
    }else {
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, opt, &addr6) == 1) {
            s->ipv4 = 0;
            s->addr6 = addr6;
        } else {
            log_error("Invalid server address");
            goto out;
        }
    }

	if (ptr2) {
		if (ptr2[1]) {
			s->auth_port = strtol(ptr2 + 1, &endptr, 10);
			if (*endptr)
				goto out;
		}
	} else
		s->auth_port = 1812;

	if (ptr3) {
		if (ptr3[1]) {
			s->acct_port = strtol(ptr3 + 1, &endptr, 10);
			if (*endptr)
				goto out;
		}
	} else
		s->acct_port = 1813;

	s->secret = _strdup(ptr1 + 1);
	s->fail_timeout = conf_fail_timeout;
	s->req_limit = conf_req_limit;
	s->max_fail = conf_max_fail;
	s->bind_default = 1;

	return 0;

out:
	_free(opt);

	return -1;
}

static int parse_server2(const char *_opt, struct rad_server_t *s)
{
	char *opt = _strdup(_opt);
	char *ptr1, *ptr2, *ptr3, *endptr;

	ptr1 = strchr(opt, ',');
	if (!ptr1)
		goto out;

	ptr2 = strchr(ptr1 + 1, ',');
	if (!ptr2)
		goto out;

	*ptr1 = 0;

    struct in_addr addr4;
    if (inet_pton(AF_INET, opt, &addr4) == 1) {
        s->ipv4 = 1;
        s->addr = addr4.s_addr;
    }else {
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, opt, &addr6) == 1) {
            s->ipv4 = 0;
            s->addr6 = addr6;
        } else {
            log_error("Invalid server address");
            goto out;
        }
    }
	ptr3 = strstr(ptr2, ",auth-port=");
	if (ptr3) {
		s->auth_port = strtol(ptr3 + 11, &endptr, 10);
		if (*endptr != ',' && *endptr != 0)
			goto out;
	} else
		s->auth_port = 1812;

	ptr3 = strstr(ptr2, ",acct-port=");
	if (ptr3) {
		s->acct_port = strtol(ptr3 + 11, &endptr, 10);
		if (*endptr != ',' && *endptr != 0)
			goto out;
	} else
		s->acct_port = 1813;

	ptr3 = strstr(ptr2, ",req-limit=");
	if (ptr3) {
		s->req_limit = strtol(ptr3 + 11, &endptr, 10);
		if (*endptr != ',' && *endptr != 0)
			goto out;
	} else
		s->req_limit = conf_req_limit;

	ptr3 = strstr(ptr2, ",fail-timeout=");
	if (ptr3) {
		s->fail_timeout = strtol(ptr3 + 14, &endptr, 10);
		if (*endptr != ',' && *endptr != 0)
			goto out;
	} else {
		ptr3 = strstr(ptr2, ",fail-time=");
		if (ptr3) {
			s->fail_timeout = strtol(ptr3 + 11, &endptr, 10);
			if (*endptr != ',' && *endptr != 0)
				goto out;
		} else
			s->fail_timeout = conf_fail_timeout;
	}

	ptr3 = strstr(ptr2, ",max-fail=");
	if (ptr3) {
		s->max_fail = strtol(ptr3 + 10, &endptr, 10);
		if (*endptr != ',' && *endptr != 0)
			goto out;
	} else
		s->max_fail = conf_max_fail;

	ptr3 = strstr(ptr2, ",weight=");
	if (ptr3) {
		s->weight = atoi(ptr3 + 8);
		if (s->weight <= 0) {
			log_error("radius: %s: invalid weight (forced to 1)\n", _opt);
			s->weight = 1;
		}
	} else
		s->weight = 1;

	ptr3 = strstr(ptr2, ",bind-device=");
	if (ptr3) {
		endptr = strchrnul(ptr3 + 13, ',');
		if (*endptr != ',' && *endptr != 0)
			goto out;
		if  ( ( endptr - ptr3 - 13 ) >  IFNAMSIZ - 1 ) {
			log_error("radius: %s: too long bind device name\n", _opt);
			s->bind_default = 1;
		} else
		{
			s->bind_default = 0;
			bzero(s->bind_device, sizeof(s->bind_device));
			strncpy(s->bind_device, ptr3 + 13, endptr - ptr3 - 13);
		}
	} else
		s->bind_default = 1;

	ptr3 = strstr(ptr2, ",backup");
	if (ptr3)
		s->backup = 1;
	else
		s->backup = 0;

	*ptr2 = 0;

	s->secret = _strdup(ptr1 + 1);

	_free(opt);

	return 0;

out:
	_free(opt);

	return -1;
}

static void add_server(const char *opt)
{
	struct rad_server_t *s = _malloc(sizeof(*s));

	memset(s, 0, sizeof(*s));

	if (!parse_server1(opt,s))
		goto add;

	if (!parse_server2(opt,s))
		goto add;

	log_emerg("radius: failed to parse '%s'\n", opt);
	_free(s);
	return;

add:
	__add_server(s);
}

static void load_config(void)
{
	struct conf_sect_t *sect = conf_get_section("radius");
	struct conf_option_t *opt;
	struct rad_server_t *s;
	struct rad_req_t *r;
	struct list_head *pos, *n;
	const char *opt1;

	list_for_each_entry(s, &serv_list, entry)
		s->need_free = 1;

	opt1 = conf_get_opt("radius", "acct-on");
	if (opt1)
		conf_acct_on = atoi(opt1);
	else
		conf_acct_on = 0;

	opt1 = conf_get_opt("radius", "fail-timeout");
	if (!opt1)
		opt1 = conf_get_opt("radius", "fail-time");
	if (opt1)
		conf_fail_timeout = atoi(opt1);
	else
		conf_fail_timeout = 0;

	opt1 = conf_get_opt("radius", "req-limit");
	if (opt1)
		conf_req_limit = atoi(opt1);
	else
		conf_req_limit = 0;

	opt1 = conf_get_opt("radius", "max-fail");
	if (opt1)
		conf_max_fail = atoi(opt1);
	else
		conf_max_fail = conf_req_limit + conf_max_try;

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "server"))
			continue;
		add_server(opt->val);
	}

	list_for_each_safe(pos, n, &serv_list) {
		s = list_entry(pos, typeof(*s), entry);
		if (s->need_free) {
			list_del(&s->entry);

			while (!list_empty(&s->req_queue[0])) {
				r = list_entry(s->req_queue[0].next, typeof(*r), entry);
				list_del(&r->entry);
				triton_context_call(r->rpd->ses->ctrl->ctx, (triton_event_func)req_wakeup, r);
			}

			while (!list_empty(&s->req_queue[1])) {
				r = list_entry(s->req_queue[1].next, typeof(*r), entry);
				list_del(&r->entry);
				triton_context_call(r->rpd->ses->ctrl->ctx, (triton_event_func)req_wakeup, r);
			}

			if (!s->client_cnt[0] && !s->client_cnt[1]) {
				if (s->acct_on)
					triton_context_call(&s->ctx, (triton_event_func)serv_ctx_close, &s->ctx);
				else
					__free_server(s);
			}
		}
	}

	add_server_old();

	conf_accounting = 0;
	list_for_each_entry(s, &serv_list, entry) {
		if (s->acct_port) {
			conf_accounting = 1;
			break;
		}
	}

	list_for_each_entry(s, &serv_list, entry) {
		if (s->starting) {
			if (!conf_accounting || !s->auth_port)
				s->starting = 0;
		}
	}
}

static void init(void)
{
	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");
}

DEFINE_INIT(52, init);
