#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include "triton.h"
#include "cli.h"
#include "cli_p.h"
#include "list.h"
#include "log.h"
#include "events.h"
#include "ppp.h"
#include "utils.h"

#include "memdebug.h"

#define CLI_LOG_LEVEL_MIN 0
#define CLI_LOG_LEVEL_MAX 5
#define CLI_LOG_LEVEL_DEFAULT 5

#define CLI_LOG_HISTORY_DEFAULT 0
#define CLI_LOG_HISTORY_MAX 5000

/* max lines queued per subscriber awaiting delivery in its context */
#define CLI_LOG_PENDING_MAX 256
/* max bytes sitting in the client transmit queue before the
 * subscription is dropped (slow consumer protection) */
#define CLI_LOG_BACKLOG_MAX (1 << 20)

struct cli_log_line_t
{
	struct list_head entry;
	char buf[0];
};

/* All fields are protected by subs_lock. sub->client is dereferenced
 * only from the client's own triton context (sub->ctx) and only while
 * !dead: the transports mark the subscription dead (via
 * cli_log_stream_on_disconnect) in that same context before freeing
 * the client, so the pointer cannot go stale under a flush. */
struct cli_log_sub_t
{
	struct list_head entry;
	struct cli_client_t *client;
	struct triton_context_t *ctx;
	int max_level;
	int ref_cnt;
	struct list_head pending;
	int pending_cnt;
	unsigned int queued:1;
	unsigned int overrun:1;
	unsigned int dead:1;
};

static pthread_mutex_t subs_lock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(subs);
static int subs_count;

static pthread_mutex_t history_lock = PTHREAD_MUTEX_INITIALIZER;
static char **history;
static int history_max = CLI_LOG_HISTORY_DEFAULT;
static int history_len;
static int history_pos;
static int history_enabled;
static int initialized = 0;

static void history_resize(int n)
{
	int i;

	if (n < 0)
		n = 0;
	else if (n > CLI_LOG_HISTORY_MAX)
		n = CLI_LOG_HISTORY_MAX;

	pthread_mutex_lock(&history_lock);

	if (history && n == history_max) {
		pthread_mutex_unlock(&history_lock);
		return;
	}

	if (history) {
		for (i = 0; i < history_max; i++)
			if (history[i])
				_free(history[i]);
		_free(history);
		history = NULL;
	}

	history_max = n;
	history_len = 0;
	history_pos = 0;

	if (history_max > 0)
		history = _malloc(sizeof(*history) * history_max);

	if (history)
		memset(history, 0, sizeof(*history) * history_max);
	else
		history_max = 0;

	__sync_lock_test_and_set(&history_enabled, history_max > 0);

	pthread_mutex_unlock(&history_lock);
}

static void history_add(const char *line)
{
	char *dup;

	pthread_mutex_lock(&history_lock);

	if (!history || history_max <= 0) {
		pthread_mutex_unlock(&history_lock);
		return;
	}

	dup = _strdup(line);
	if (!dup) {
		pthread_mutex_unlock(&history_lock);
		return;
	}

	if (history[history_pos])
		_free(history[history_pos]);

	history[history_pos] = dup;

	history_pos = (history_pos + 1) % history_max;
	if (history_len < history_max)
		history_len++;

	pthread_mutex_unlock(&history_lock);
}

/* Runs in the client's own context. Snapshots the lines under
 * history_lock and sends after releasing it: cli_send() may log on
 * error and the recursive history_add() would deadlock on
 * history_lock if it was still held here. */
static void history_send_tail(struct cli_client_t *client, int tail)
{
	char **snap;
	int i;
	int start;
	int count = 0;
	int failed = 0;

	if (tail <= 0)
		return;

	pthread_mutex_lock(&history_lock);

	if (!history || history_len == 0) {
		pthread_mutex_unlock(&history_lock);
		return;
	}

	if (tail > history_len)
		tail = history_len;

	snap = _malloc(sizeof(*snap) * tail);
	if (!snap) {
		pthread_mutex_unlock(&history_lock);
		return;
	}

	start = history_pos - tail;
	if (start < 0)
		start += history_max;

	for (i = 0; i < tail; i++) {
		const char *line = history[(start + i) % history_max];
		if (!line)
			continue;
		snap[count] = _strdup(line);
		if (snap[count])
			count++;
	}

	pthread_mutex_unlock(&history_lock);

	for (i = 0; i < count; i++) {
		if (!failed && cli_send(client, snap[i]) < 0)
			failed = 1;
		_free(snap[i]);
	}

	_free(snap);
}

/* Requires subs_lock to be held */
static inline struct cli_log_sub_t *sub_find(struct cli_client_t *client)
{
	struct cli_log_sub_t *sub;

	list_for_each_entry(sub, &subs, entry)
		if (sub->client == client)
			return sub;

	return NULL;
}

static void sub_free(struct cli_log_sub_t *sub)
{
	struct cli_log_line_t *l;

	while (!list_empty(&sub->pending)) {
		l = list_entry(sub->pending.next, typeof(*l), entry);
		list_del(&l->entry);
		_free(l);
	}

	_free(sub);
}

/* Requires subs_lock to be held. Unlinks the subscription from the
 * subscriber list; the sub itself is freed when the last reference
 * (list or in-flight flush) is dropped. */
static void sub_detach(struct cli_log_sub_t *sub)
{
	list_del(&sub->entry);
	sub->dead = 1;
	sub->client = NULL;
	__sync_sub_and_fetch(&subs_count, 1);

	sub->ref_cnt--;
	if (sub->ref_cnt == 0)
		sub_free(sub);
}

static void sub_remove_client(struct cli_client_t *client)
{
	struct list_head *pos, *n;
	struct cli_log_sub_t *sub;

	pthread_mutex_lock(&subs_lock);
	list_for_each_safe(pos, n, &subs) {
		sub = list_entry(pos, typeof(*sub), entry);
		if (sub->client == client)
			sub_detach(sub);
	}
	pthread_mutex_unlock(&subs_lock);
}

void cli_log_stream_on_disconnect(struct cli_client_t *cln)
{
	sub_remove_client(cln);
}

/* Runs in the subscriber's own triton context (scheduled with
 * triton_context_call()), so cli_send() here is serialized with the
 * rest of the client's I/O. No locks are held while sending. */
static void sub_flush(void *arg)
{
	struct cli_log_sub_t *sub = arg;
	struct cli_client_t *client;
	struct cli_log_line_t *l;
	LIST_HEAD(lines);
	int overrun;
	int failed = 0;

	pthread_mutex_lock(&subs_lock);
	sub->queued = 0;
	list_splice_init(&sub->pending, &lines);
	sub->pending_cnt = 0;
	overrun = sub->overrun;
	sub->overrun = 0;
	client = sub->dead ? NULL : sub->client;
	pthread_mutex_unlock(&subs_lock);

	while (!list_empty(&lines)) {
		l = list_entry(lines.next, typeof(*l), entry);
		list_del(&l->entry);
		if (client && !failed && cli_send(client, l->buf) < 0)
			failed = 1;
		_free(l);
	}

	if (client && !failed && overrun) {
		if (cli_send(client, "log follow: overrun, some lines were dropped\r\n") < 0)
			failed = 1;
	}

	if (client && !failed && client->queued_bytes > CLI_LOG_BACKLOG_MAX) {
		cli_send(client, "log follow: client is too slow, disabling\r\n");
		failed = 1;
	}

	pthread_mutex_lock(&subs_lock);
	if (failed && !sub->dead)
		sub_detach(sub);
	sub->ref_cnt--;
	if (sub->ref_cnt == 0)
		sub_free(sub);
	pthread_mutex_unlock(&subs_lock);
}

static int sub_set(struct cli_client_t *client, int max_level)
{
	struct cli_log_sub_t *sub;

	if (!client->ctx)
		return -1;

	if (max_level < CLI_LOG_LEVEL_MIN)
		max_level = CLI_LOG_LEVEL_MIN;
	else if (max_level > CLI_LOG_LEVEL_MAX)
		max_level = CLI_LOG_LEVEL_MAX;

	pthread_mutex_lock(&subs_lock);

	sub = sub_find(client);
	if (sub) {
		sub->max_level = max_level;
		pthread_mutex_unlock(&subs_lock);
		return 0;
	}

	sub = _malloc(sizeof(*sub));
	if (!sub) {
		pthread_mutex_unlock(&subs_lock);
		return -1;
	}
	memset(sub, 0, sizeof(*sub));
	sub->client = client;
	sub->ctx = client->ctx;
	sub->max_level = max_level;
	sub->ref_cnt = 1;
	INIT_LIST_HEAD(&sub->pending);
	list_add_tail(&sub->entry, &subs);
	__sync_add_and_fetch(&subs_count, 1);

	pthread_mutex_unlock(&subs_lock);
	return 0;
}

static void sub_unset(struct cli_client_t *client)
{
	sub_remove_client(client);
}

static void format_msg(char *out, size_t out_size, struct log_msg_t *msg, struct ap_session *ses)
{
	struct log_chunk_t *chunk;
	struct tm tm;
	int pos = 0;
	int n;

	if (!out_size)
		return;

	localtime_r(&msg->timestamp.tv_sec, &tm);

	n = snprintf(out + pos, out_size - pos,
		"[%04i-%02i-%02i %02i:%02i:%02i.%03i] ",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		(int)msg->timestamp.tv_usec / 1000);

	if (n >= 0) {
		if ((size_t)n >= out_size - pos)
			pos = out_size - 1;
		else
			pos += n;
	}

	if (ses) {
		const char *ifname = ses->ifname[0] ? ses->ifname : ses->ctrl->ifname;
		const char *ident = ses->username ? ses->username : ses->sessionid;
		n = snprintf(out + pos, out_size - pos, "%s: %s: ", ifname, ident);

		if (n >= 0) {
			if ((size_t)n >= out_size - pos)
				pos = out_size - 1;
			else
				pos += n;
		}
	}

	list_for_each_entry(chunk, msg->chunks, entry) {
		int i;
		for (i = 0; i < chunk->len && pos + 2 < (int)out_size; i++) {
			char c = chunk->msg[i];
			if (c == '\n') {
				out[pos++] = '\r';
				out[pos++] = '\n';
			} else
				out[pos++] = c;
		}
		if (pos + 2 >= (int)out_size)
			break;
	}

	if (pos >= 2 && out[pos - 2] == '\r' && out[pos - 1] == '\n') {
		out[pos] = '\0';
		return;
	}

	if (pos + 2 < (int)out_size) {
		out[pos++] = '\r';
		out[pos++] = '\n';
	}

	out[pos] = '\0';
}

/* Called synchronously from whatever thread emitted the log message.
 * Never sends to clients from here: lines are queued per subscriber
 * and delivered by sub_flush() in the client's own context. This also
 * makes recursive logging safe (e.g. cli_send() failing and calling
 * log_error()): this function only takes subs_lock/history_lock and
 * never calls back into the CLI transports. */
static void cli_log_target_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	char buf[LOG_MAX_SIZE * 2 + 512];
	struct cli_log_sub_t *sub;
	size_t len;

	(void)t;

	/* lockless fast path; the race with (un)subscribe is benign:
	 * at worst one line is dropped around the transition */
	if (!__sync_fetch_and_add(&subs_count, 0) && !__sync_fetch_and_add(&history_enabled, 0)) {
		log_free_msg(msg);
		return;
	}

	format_msg(buf, sizeof(buf), msg, ses);
	history_add(buf);

	len = strlen(buf);

	pthread_mutex_lock(&subs_lock);
	list_for_each_entry(sub, &subs, entry) {
		struct cli_log_line_t *l;

		if (msg->level > sub->max_level)
			continue;

		if (sub->pending_cnt >= CLI_LOG_PENDING_MAX) {
			sub->overrun = 1;
		} else {
			l = _malloc(sizeof(*l) + len + 1);
			if (!l) {
				sub->overrun = 1;
			} else {
				memcpy(l->buf, buf, len + 1);
				list_add_tail(&l->entry, &sub->pending);
				sub->pending_cnt++;
			}
		}

		if (!sub->queued) {
			sub->queued = 1;
			sub->ref_cnt++;
			if (triton_context_call(sub->ctx, sub_flush, sub)) {
				sub->queued = 0;
				sub->ref_cnt--;
			}
		}
	}
	pthread_mutex_unlock(&subs_lock);

	log_free_msg(msg);
}

static struct log_target_t cli_log_target = {
	.log = cli_log_target_log,
};

static void cli_log_follow_help(char * const *fields, int fields_cnt, void *client)
{
	(void)fields;
	(void)fields_cnt;
	cli_send(client, "log follow [level <0..5>] [tail <n>] - stream logs to this CLI client\r\n");
}

static int cli_log_follow_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	int i;
	int max_level = CLI_LOG_LEVEL_DEFAULT;
	int tail = 0;
	struct cli_client_t *cln = (struct cli_client_t *)client;
	long int val;

	(void)cmd;

	for (i = 2; i < fields_cnt; ) {
		if (!strcmp(fields[i], "level") && i + 1 < fields_cnt) {
			if (u_readlong(&val, fields[i + 1], CLI_LOG_LEVEL_MIN, CLI_LOG_LEVEL_MAX))
				return CLI_CMD_SYNTAX;
			max_level = (int)val;
			i += 2;
			continue;
		}
		if (!strcmp(fields[i], "tail") && i + 1 < fields_cnt) {
			if (u_readlong(&val, fields[i + 1], 0, INT_MAX))
				return CLI_CMD_SYNTAX;
			tail = (int)val;
			i += 2;
			continue;
		}
		return CLI_CMD_SYNTAX;
	}

	if (tail > 0) {
		if (__sync_fetch_and_add(&history_enabled, 0))
			history_send_tail(cln, tail);
		else
			cli_send(client, "log follow: history disabled, tail unavailable (see 'log history')\r\n");
	}

	if (sub_set(cln, max_level)) {
		cli_send(client, "log follow: not supported on this connection\r\n");
		return CLI_CMD_FAILED;
	}

	cli_send(client, "log follow: enabled\r\n");
	return CLI_CMD_OK;
}

static void cli_log_stop_help(char * const *fields, int fields_cnt, void *client)
{
	(void)fields;
	(void)fields_cnt;
	cli_send(client, "log stop - stop streaming logs to this CLI client\r\n");
}

static int cli_log_stop_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	struct cli_client_t *cln = (struct cli_client_t *)client;

	(void)cmd;
	(void)fields;

	if (fields_cnt != 2)
		return CLI_CMD_SYNTAX;

	sub_unset(cln);
	cli_send(client, "log follow: disabled\r\n");
	return CLI_CMD_OK;
}

static void cli_show_log_help(char * const *fields, int fields_cnt, void *client)
{
	(void)fields;
	(void)fields_cnt;
	cli_send(client, "log show [n] - show last N log lines seen by accel-pppd (default 50)\r\n");
}

static int cli_show_log_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	int tail = 50;
	struct cli_client_t *cln = (struct cli_client_t *)client;
	long int val;

	(void)cmd;

	if (fields_cnt == 3) {
		if (u_readlong(&val, fields[2], 0, INT_MAX))
			return CLI_CMD_SYNTAX;
		tail = (int)val;
	} else if (fields_cnt != 2)
		return CLI_CMD_SYNTAX;

	if (!__sync_fetch_and_add(&history_enabled, 0)) {
		cli_send(client, "log show: history disabled, enable with 'log history <n>' or [cli] log-history\r\n");
		return CLI_CMD_OK;
	}

	history_send_tail(cln, tail);
	return CLI_CMD_OK;
}

static void cli_log_history_help(char * const *fields, int fields_cnt, void *client)
{
	(void)fields;
	(void)fields_cnt;
	cli_send(client, "log history [n] - show/set CLI log buffer size (0 disables, max 5000)\r\n");
}

static int cli_log_history_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	int n;
	long int val;

	(void)cmd;

	if (fields_cnt == 2) {
		cli_sendv(client, "log history: %d\r\n", history_max);
		return CLI_CMD_OK;
	}

	if (fields_cnt != 3)
		return CLI_CMD_SYNTAX;

	if (!strcmp(fields[2], "off"))
		n = 0;
	else {
		if (u_readlong(&val, fields[2], 0, INT_MAX))
			return CLI_CMD_SYNTAX;
		n = (int)val;
	}

	history_resize(n);
	cli_sendv(client, "log history: %d\r\n", history_max);
	return CLI_CMD_OK;
}

static void load_config(void)
{
	const char *opt;
	int n;
	long int val;

	opt = conf_get_opt("cli", "log-history");
	if (opt && !u_readlong(&val, opt, 0, INT_MAX))
		n = (int)val;
	else
		n = CLI_LOG_HISTORY_DEFAULT;
	history_resize(n);
}

static void init(void)
{
	load_config();

	log_register_target(&cli_log_target);

	cli_register_simple_cmd2(cli_log_follow_exec, cli_log_follow_help, 2, "log", "follow");
	cli_register_simple_cmd2(cli_log_stop_exec, cli_log_stop_help, 2, "log", "stop");
	cli_register_simple_cmd2(cli_show_log_exec, cli_show_log_help, 2, "log", "show");
	cli_register_simple_cmd2(cli_log_history_exec, cli_log_history_help, 2, "log", "history");

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
	initialized = 1;
}

DEFINE_INIT(2, init);

static void __exit cleanup(void)
{
	if (initialized)
		log_unregister_target(&cli_log_target);
}
