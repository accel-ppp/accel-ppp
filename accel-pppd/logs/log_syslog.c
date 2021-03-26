#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <syslog.h>

#include "triton.h"
#include "spinlock.h"
#include "log.h"
#include "list.h"
#include "events.h"
#include "ppp.h"

#include "memdebug.h"

static int conf_queue_max = 1000;

static void syslog_close(struct triton_context_t *ctx);

static struct triton_context_t syslog_ctx = {
	.close = syslog_close,
	.before_switch = log_switch,
};

static LIST_HEAD(msg_queue);
static int queue_size;
static int sleeping = 1;
static spinlock_t queue_lock;
static char *log_buf;
static int need_close;
static char *ident;
static int prio_map[] = {LOG_INFO, LOG_ERR, LOG_WARNING, LOG_INFO, LOG_INFO, LOG_DEBUG};

static void unpack_msg(struct log_msg_t *msg)
{
	struct log_chunk_t *chunk;
	int pos;

	strcpy(log_buf, msg->hdr->msg);
	pos = strlen(log_buf);

	list_for_each_entry(chunk, msg->chunks, entry) {
		memcpy(log_buf + pos, chunk->msg, chunk->len);
		pos += chunk->len;
	}

	if (pos > 1)
		log_buf[pos - 1] = 0;
	else
		log_buf[0] = 0;
}

static void set_hdr(struct log_msg_t *msg, struct ap_session *ses)
{
	if (ses) {
		if (snprintf(msg->hdr->msg, LOG_CHUNK_SIZE, "%s:%s: ", ses->ifname[0] ? ses->ifname : ses->ctrl->ifname, ses->username ? ses->username : ""))
			strcpy(msg->hdr->msg + LOG_CHUNK_SIZE - 3, ": ");
	} else
		msg->hdr->msg[0] = 0;
}

static void do_syslog(void)
{
	struct log_msg_t *msg;

	while (1) {
		spin_lock(&queue_lock);
		if (list_empty(&msg_queue)) {
			sleeping = 1;
			spin_unlock(&queue_lock);
			if (need_close)
				triton_context_unregister(&syslog_ctx);
			return;
		}

		msg = list_entry(msg_queue.next, typeof(*msg), entry);
		list_del(&msg->entry);
		--queue_size;
		spin_unlock(&queue_lock);

		unpack_msg(msg);
		syslog(prio_map[msg->level], "%s", log_buf);
		log_free_msg(msg);
	}
}

static void queue_log(struct log_msg_t *msg)
{
	int r = 0, f = 0;
	spin_lock(&queue_lock);
	if (queue_size < conf_queue_max) {
		list_add_tail(&msg->entry, &msg_queue);
		++queue_size;
		r = sleeping;
		sleeping = 0;
	} else
		f = 1;
	spin_unlock(&queue_lock);

	if (r)
		triton_context_call(&syslog_ctx, (void (*)(void*))do_syslog, NULL);
	else if (f)
		log_free_msg(msg);
}


static void general_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	set_hdr(msg, ses);

	if (syslog_ctx.tpd)
		queue_log(msg);
	else {
		unpack_msg(msg);
		syslog(prio_map[msg->level], "%s", log_buf);
		log_free_msg(msg);
	}
}

static void syslog_close(struct triton_context_t *ctx)
{
	spin_lock(&queue_lock);
	if (sleeping) {
		triton_context_unregister(&syslog_ctx);
	} else
		need_close = 1;
	spin_unlock(&queue_lock);
}

static struct log_target_t target = {
	.log = general_log,
};

static void parse_opt(const char *opt, char **ident, int *facility)
{
	char *str = _strdup(opt);
	char *ptr, *endptr;
	int n;
	const char *facility_name[] = {"daemon", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"};
	const int facility_num[] = {LOG_DAEMON, LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7};
	const int facility_total = 9;

	ptr = strchr(str, ',');
	if (ptr) {
		*ptr = 0;
		n = strtol(ptr + 1, &endptr, 10);
		if (*endptr) {
			for (n = 0; n < facility_total; n++) {
				if (!strcasecmp(ptr + 1, facility_name[n]))
					break;
			}
			if (n == facility_total) {
				log_emerg("log_syslog: unknown facility name '%s'\n", ptr + 1);
				*facility = LOG_DAEMON;
			} else
				*facility = facility_num[n];
		} else
			*facility = n;
	}

	*ident = str;
}

static void load_config()
{
	const char *opt;
	int facility = LOG_DAEMON;

	if (ident) {
		closelog();
		_free(ident);
	}

	opt = conf_get_opt("log", "syslog");
	if (opt)
		parse_opt(opt, &ident, &facility);
	else
		ident = _strdup("accel-pppd");

	openlog(ident, 0, facility);
}

static void reload_config(void)
{
        config_lock();
        load_config();
        config_unlock();
}

static void init(void)
{
	spinlock_init(&queue_lock);

	log_buf = malloc(LOG_MAX_SIZE + 1);

	load_config();

	triton_context_register(&syslog_ctx, NULL);
	triton_context_wakeup(&syslog_ctx);

	log_register_target(&target);

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_config);
}

DEFINE_INIT(1, init);
