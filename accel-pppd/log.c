#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <sys/time.h>

#include "triton/mempool.h"
#include "events.h"
#include "ppp.h"

#include "log.h"

#include "memdebug.h"

#ifndef min
#define min(x,y) ((x)<(y)?(x):(y))
#endif

#define LOG_MSG   0
#define LOG_ERROR 1
#define LOG_WARN  2
#define LOG_INFO1 3
#define LOG_INFO2 4
#define LOG_DEBUG 5

struct log_pd_t
{
	struct ap_private pd;
	struct ap_session *ses;
	struct list_head msgs;
	struct log_msg_t *msg;
	unsigned int authorized:1;
};

struct _log_msg_t
{
	struct list_head entry;
	int level;
	struct timeval timestamp;
	struct list_head chunks;
	unsigned int refs;
};

static int log_level;

static LIST_HEAD(targets);
static mempool_t msg_pool;
static mempool_t _msg_pool;
static mempool_t chunk_pool;

static __thread struct ap_session *cur_ses;
static __thread struct _log_msg_t *cur_msg;
static __thread char *stat_buf;
static pthread_key_t stat_buf_key;

static FILE *emerg_file;
static FILE *debug_file;

static void _log_free_msg(struct _log_msg_t *msg);
static struct log_msg_t *clone_msg(struct _log_msg_t *msg);
static int add_msg(struct _log_msg_t *msg, const char *buf);
//static struct log_pd_t *find_pd(struct ap_session *ses);
static void write_msg(FILE *f, struct _log_msg_t *msg, struct ap_session *ses);

static pthread_rwlock_t config_modify = PTHREAD_RWLOCK_INITIALIZER;

static void stat_buf_free(void *ptr)
{
	_free(ptr);
}

static void do_log(int level, const char *fmt, va_list ap, struct ap_session *ses)
{
	struct log_target_t *t;
	struct log_msg_t *m;

	if (!stat_buf) {
		stat_buf = _malloc(LOG_MAX_SIZE + 1);
		pthread_setspecific(stat_buf_key, stat_buf);
	}

	vsnprintf(stat_buf, LOG_MAX_SIZE, fmt, ap);

	if (!cur_msg) {
		cur_msg = mempool_alloc(_msg_pool);
		if (!cur_msg)
			return;
		INIT_LIST_HEAD(&cur_msg->chunks);
		cur_msg->refs = 1;
		cur_msg->level = level;
		gettimeofday(&cur_msg->timestamp, NULL);
	}

	if (add_msg(cur_msg, stat_buf))
		goto out;

	if (stat_buf[strlen(stat_buf) - 1] != '\n')
		return;

	if (debug_file)
		write_msg(debug_file, cur_msg, ses);

	list_for_each_entry(t, &targets, entry) {
		m = clone_msg(cur_msg);
		if (!m)
			break;
		t->log(t, m, ses);
	}

out:
	_log_free_msg(cur_msg);
	cur_msg = NULL;
}

void __export log_error(const char *fmt,...)
{
	if (log_level >= LOG_ERROR) {
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_ERROR, fmt, ap, NULL);
		va_end(ap);
	}
}

void __export log_warn(const char *fmt,...)
{
	if (log_level >= LOG_WARN) {
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_WARN, fmt, ap, NULL);
		va_end(ap);
	}
}

void __export log_info1(const char *fmt,...)
{
	if (log_level >= LOG_INFO1) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_INFO1, fmt, ap, NULL);
		va_end(ap);
	}
}

void __export log_info2(const char *fmt,...)
{
	if (log_level >= LOG_INFO2) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_INFO2, fmt, ap, NULL);
		va_end(ap);
	}
}

void __export log_debug(const char *fmt,...)
{
	if (log_level >= LOG_DEBUG) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_DEBUG, fmt, ap, NULL);
		va_end(ap);
	}
}

void __export log_debug2(const char *fmt,...)
{
	va_list ap;
	if (!debug_file)
		return;
	va_start(ap, fmt);
	vfprintf(debug_file, fmt, ap);
	va_end(ap);
	fflush(debug_file);
}
void __export log_msg(const char *fmt,...)
{
	va_list ap;
	va_start(ap, fmt);
	do_log(LOG_MSG, fmt, ap, NULL);
	va_end(ap);
}

void __export log_ppp_error(const char *fmt,...)
{
	if (log_level >= LOG_ERROR) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_ERROR, fmt, ap, cur_ses);
		va_end(ap);
	}
}

void __export log_ppp_warn(const char *fmt,...)
{
	if (log_level >= LOG_WARN) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_WARN, fmt, ap, cur_ses);
		va_end(ap);
	}
}

void __export log_ppp_info1(const char *fmt,...)
{
	if (log_level >= LOG_INFO1) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_INFO1, fmt, ap, cur_ses);
		va_end(ap);
	}
}

void __export log_ppp_info2(const char *fmt,...)
{
	if (log_level >= LOG_INFO2) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_INFO2, fmt, ap, cur_ses);
		va_end(ap);
	}
}

void __export log_ppp_debug(const char *fmt,...)
{
	if (log_level >= LOG_DEBUG) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_DEBUG, fmt, ap, cur_ses);
		va_end(ap);
	}
}

void __export log_ppp_msg(const char *fmt,...)
{
	va_list ap;
	va_start(ap, fmt);
	do_log(LOG_MSG, fmt, ap, cur_ses);
	va_end(ap);
}

void __export log_emerg(const char *fmt, ...)
{
	if (emerg_file) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(emerg_file, fmt, ap);
		va_end(ap);
		fflush(emerg_file);
	}
}

void __export log_free_msg(struct log_msg_t *m)
{
	struct _log_msg_t *msg = (struct _log_msg_t *)m->lpd;

	//printf("free msg %p\n", m);

	mempool_free(m->hdr);
	_log_free_msg(msg);

	mempool_free(m);
}


static void _log_free_msg(struct _log_msg_t *msg)
{
	struct log_chunk_t *chunk;

	if (__sync_sub_and_fetch(&msg->refs, 1))
		return;

	while(!list_empty(&msg->chunks)) {
		chunk = list_entry(msg->chunks.next, typeof(*chunk), entry);
		list_del(&chunk->entry);
		mempool_free(chunk);
	}

	mempool_free(msg);
}

static struct log_msg_t *clone_msg(struct _log_msg_t *msg)
{
	struct log_msg_t *m = mempool_alloc(msg_pool);
	if (!m) {
		log_emerg("log: out of memory\n");
		return NULL;
	}

	m->hdr = mempool_alloc(chunk_pool);
	if (!m->hdr) {
		log_emerg("log: out of memory\n");
		mempool_free(m);
		return NULL;
	}

	m->hdr->len = 0;
	m->lpd = msg;
	m->chunks = &msg->chunks;
	m->timestamp = msg->timestamp;
	m->level = msg->level;

	__sync_add_and_fetch(&msg->refs, 1);

	//printf("clone msg %p\n", m);
	return m;
}

static int add_msg(struct _log_msg_t *msg, const char *buf)
{
	struct log_chunk_t *chunk;
	int i, chunk_cnt, len = strlen(buf);

	if (!list_empty(&msg->chunks)) {
		chunk = list_entry(msg->chunks.prev, typeof(*chunk), entry);
		i = min(len, LOG_CHUNK_SIZE - chunk->len);
		memcpy(chunk->msg + chunk->len, buf, i);
		chunk->len += i;
		chunk->msg[chunk->len] = 0;

		if (i == len)
			return 0;

		buf += i;
		len -= i;
	}

	chunk_cnt = (len - 1)/LOG_CHUNK_SIZE + 1;

	for (i = 0; i < chunk_cnt; i++) {
		chunk = mempool_alloc(chunk_pool);
		if (!chunk)
			return -1;

		chunk->len = i == chunk_cnt - 1 ? len - i * LOG_CHUNK_SIZE : LOG_CHUNK_SIZE;
		memcpy(chunk->msg, buf + i * LOG_CHUNK_SIZE, chunk->len);
		chunk->msg[chunk->len] = 0;

		list_add_tail(&chunk->entry, &msg->chunks);
	}

	return 0;
}

static void write_msg(FILE *f, struct _log_msg_t *msg, struct ap_session *ses)
{
	struct log_chunk_t *chunk;
	struct timeval tv;
	struct tm tm;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);

	pthread_mutex_lock(&lock);
	fprintf(f, "[%04i-%02i-%02i %02i:%02i:%02i.%03i] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec/1000);

	if (ses)
		fprintf(f, "%s: %s: ", ses->ifname[0] ? ses->ifname : ses->ctrl->ifname, ses->sessionid);

	list_for_each_entry(chunk, &msg->chunks, entry)
		fwrite(chunk->msg, chunk->len, 1, f);

	fflush(f);
	pthread_mutex_unlock(&lock);
}

/*static struct log_pd_t *find_pd(struct ap_session *ses)
{
	struct ap_private *pd;
	struct log_pd_t *lpd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key) {
			lpd = container_of(pd, typeof(*lpd), pd);
			return lpd;
		}
	}
	log_emerg("log:BUG: pd not found\n");
	abort();
}

static void ev_ctrl_starting(struct ap_session *ses)
{
	struct log_pd_t *lpd = _malloc(sizeof(*lpd));
	if (!lpd) {
		log_emerg("log: out of memory\n");
		return;
	}

	memset(lpd, 0, sizeof(*lpd));
	lpd->pd.key = &pd_key;
	lpd->ppp = ppp;
	INIT_LIST_HEAD(&lpd->msgs);
	list_add_tail(&lpd->pd.entry, &ses->pd_list);
}

static void ev_ctrl_finished(struct ap_session *ses)
{
	struct log_pd_t *lpd = find_pd(ppp);
	struct _log_msg_t *msg;
	struct log_msg_t *m;
	struct log_target_t *t;

	if (lpd->msg) {
		log_emerg("log:BUG: lpd->msg is not NULL\n");
		abort();
	}

	if (lpd->authorized) {
		if (!list_empty(&lpd->msgs)) {
			log_emerg("log:BUG: lpd->msgs is not empty\n");
			abort();
		}
		list_for_each_entry(t, &targets, entry)
			if (t->session_stop)
				t->session_stop(ppp);
	}

	while (!list_empty(&lpd->msgs)) {
		msg = list_entry(lpd->msgs.next, typeof(*msg), entry);
		list_del(&msg->entry);

		list_for_each_entry(t, &targets, entry) {
			if (!t->log)
				continue;
			m = clone_msg(msg);
			if (!m)
				break;
			t->log(m);
		}

		_log_free_msg(msg);
	}

	list_del(&lpd->pd.entry);
	_free(lpd);
}

static void ev_ppp_authorized(struct ap_session *ses)
{
	struct log_pd_t *lpd = find_pd(ppp);
	struct _log_msg_t *msg;
	struct log_msg_t *m;
	struct log_target_t *t;

	list_for_each_entry(t, &targets, entry)
		if (t->session_start)
			t->session_start(ppp);

	while(!list_empty(&lpd->msgs)) {
		msg = list_entry(lpd->msgs.next, typeof(*msg), entry);
		list_del(&msg->entry);

		list_for_each_entry(t, &targets, entry) {
			if (!t->session_log)
				continue;
			m = clone_msg(msg);
			if (!m)
				break;
			t->session_log(lpd->ppp, m);
		}

		_log_free_msg(msg);
	}

	lpd->authorized = 1;
}*/

void __export log_switch(struct triton_context_t *ctx, void *arg)
{
	cur_ses = (struct ap_session *)arg;
}


void __export log_register_target(struct log_target_t *t)
{
	list_add_tail(&t->entry, &targets);
}

static void sighup(int n)
{
	struct log_target_t *t;

	list_for_each_entry(t, &targets, entry)
		if (t->reopen)
			t->reopen();
}

static void load_config(void)
{
	char *opt;

        config_lock();
	pthread_rwlock_wrlock(&config_modify);

	opt = conf_get_opt("log", "level");
	if (opt && atoi(opt) >= 0)
		log_level = atoi(opt);

	opt = conf_get_opt("log", "log-emerg");
	if (opt) {
		if (emerg_file)
			emerg_file = freopen(opt, "a", emerg_file);
		else
			emerg_file = fopen(opt, "a");
		if (!emerg_file)
			fprintf(stderr, "log:open: %s\n", strerror(errno));
	} else if (emerg_file) {
		fclose(emerg_file);
		emerg_file = NULL;
	}

	opt = conf_get_opt("log", "log-debug");
	if (opt) {
		if (debug_file)
			debug_file = freopen(opt, "a", debug_file);
		else
			debug_file = fopen(opt, "a");
		if (!debug_file)
			fprintf(stderr, "log:open: %s\n", strerror(errno));
	} else if (debug_file) {
		fclose(debug_file);
		debug_file = NULL;
	}

	pthread_rwlock_unlock(&config_modify);
        config_unlock();
}

static void log_init(void)
{
	struct sigaction sa = {
		.sa_handler = sighup,
	};

	pthread_key_create(&stat_buf_key, stat_buf_free);

	msg_pool = mempool_create(sizeof(struct log_msg_t));
	_msg_pool = mempool_create(sizeof(struct _log_msg_t));
	chunk_pool = mempool_create(sizeof(struct log_chunk_t) + LOG_CHUNK_SIZE + 1);

	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	sigaction(SIGHUP, &sa, NULL);
}

DEFINE_INIT(0, log_init);
