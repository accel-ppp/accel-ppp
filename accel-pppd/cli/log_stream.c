#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "triton.h"
#include "cli.h"
#include "cli_p.h"
#include "list.h"
#include "log.h"
#include "events.h"
#include "ppp.h"

#include "memdebug.h"

#define CLI_LOG_LEVEL_MIN 0
#define CLI_LOG_LEVEL_MAX 5
#define CLI_LOG_LEVEL_DEFAULT 5

#define CLI_LOG_HISTORY_DEFAULT 0
#define CLI_LOG_HISTORY_MAX 5000

struct cli_log_sub_t
{
	struct list_head entry;
	struct cli_client_t *client;
	int max_level;
};

static pthread_mutex_t subs_lock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(subs);
static volatile int subs_count;

static pthread_mutex_t history_lock = PTHREAD_MUTEX_INITIALIZER;
static char **history;
static int history_max = CLI_LOG_HISTORY_DEFAULT;
static int history_len;
static int history_pos;
static volatile int history_enabled;

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

	history_enabled = history_max > 0;
	if (history_max > 0)
		history = _malloc(sizeof(*history) * history_max);

	if (history)
		memset(history, 0, sizeof(*history) * history_max);
	else {
		history_max = 0;
		history_enabled = 0;
	}

	pthread_mutex_unlock(&history_lock);
}

static void history_add(const char *line)
{
	pthread_mutex_lock(&history_lock);

	if (!history || history_max <= 0) {
		pthread_mutex_unlock(&history_lock);
		return;
	}

	if (history[history_pos])
		_free(history[history_pos]);
	history[history_pos] = _strdup(line);

	history_pos = (history_pos + 1) % history_max;
	if (history_len < history_max)
		history_len++;

	pthread_mutex_unlock(&history_lock);
}

static void history_send_tail(struct cli_client_t *client, int tail)
{
	int i;
	int start;

	if (tail <= 0)
		return;

	pthread_mutex_lock(&history_lock);

	if (!history || history_len == 0) {
		pthread_mutex_unlock(&history_lock);
		return;
	}

	if (tail > history_len)
		tail = history_len;

	start = history_pos - tail;
	if (start < 0)
		start += history_max;

	for (i = 0; i < tail; i++) {
		const char *line = history[(start + i) % history_max];
		if (!line)
			continue;
		if (cli_send(client, line) < 0)
			break;
	}

	pthread_mutex_unlock(&history_lock);
}

static struct cli_log_sub_t *sub_find(struct cli_client_t *client)
{
	struct cli_log_sub_t *sub;

	list_for_each_entry(sub, &subs, entry)
		if (sub->client == client)
			return sub;

	return NULL;
}

static void sub_remove_client(struct cli_client_t *client)
{
	struct list_head *pos, *n;
	struct cli_log_sub_t *sub;
	int removed = 0;

	pthread_mutex_lock(&subs_lock);
	list_for_each_safe(pos, n, &subs) {
		sub = list_entry(pos, typeof(*sub), entry);
		if (sub->client != client)
			continue;
		list_del(&sub->entry);
		_free(sub);
		removed++;
	}
	if (removed)
		__sync_sub_and_fetch(&subs_count, removed);
	pthread_mutex_unlock(&subs_lock);
}

void cli_log_stream_on_disconnect(struct cli_client_t *cln)
{
	sub_remove_client(cln);
}

static void sub_set(struct cli_client_t *client, int max_level)
{
	struct cli_log_sub_t *sub;

	if (max_level < CLI_LOG_LEVEL_MIN)
		max_level = CLI_LOG_LEVEL_MIN;
	else if (max_level > CLI_LOG_LEVEL_MAX)
		max_level = CLI_LOG_LEVEL_MAX;

	pthread_mutex_lock(&subs_lock);

	sub = sub_find(client);
	if (sub) {
		sub->max_level = max_level;
		pthread_mutex_unlock(&subs_lock);
		return;
	}

	sub = _malloc(sizeof(*sub));
	memset(sub, 0, sizeof(*sub));
	sub->client = client;
	sub->max_level = max_level;
	list_add_tail(&sub->entry, &subs);
	__sync_add_and_fetch(&subs_count, 1);

	pthread_mutex_unlock(&subs_lock);
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

	if (!out_size)
		return;

	localtime_r(&msg->timestamp.tv_sec, &tm);

	pos += snprintf(out + pos, out_size - pos,
		"[%04i-%02i-%02i %02i:%02i:%02i.%03i] ",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		(int)msg->timestamp.tv_usec / 1000);

	if (ses) {
		const char *ifname = ses->ifname[0] ? ses->ifname : ses->ctrl->ifname;
		const char *ident = ses->username ? ses->username : ses->sessionid;
		pos += snprintf(out + pos, out_size - pos, "%s: %s: ", ifname, ident);
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

static void cli_log_target_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	char buf[LOG_MAX_SIZE * 2 + 512];
	struct list_head *pos, *n;
	struct cli_log_sub_t *sub;

	(void)t;

	if (!subs_count && !history_enabled) {
		log_free_msg(msg);
		return;
	}

	format_msg(buf, sizeof(buf), msg, ses);
	history_add(buf);

	pthread_mutex_lock(&subs_lock);
	list_for_each_safe(pos, n, &subs) {
		sub = list_entry(pos, typeof(*sub), entry);
		if (msg->level > sub->max_level)
			continue;
		if (cli_send(sub->client, "\r\n") < 0 || cli_send(sub->client, buf) < 0) {
			list_del(&sub->entry);
			_free(sub);
			__sync_sub_and_fetch(&subs_count, 1);
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

	(void)cmd;

	for (i = 2; i < fields_cnt; ) {
		if (!strcmp(fields[i], "level") && i + 1 < fields_cnt) {
			max_level = atoi(fields[i + 1]);
			i += 2;
			continue;
		}
		if (!strcmp(fields[i], "tail") && i + 1 < fields_cnt) {
			tail = atoi(fields[i + 1]);
			i += 2;
			continue;
		}
		return CLI_CMD_SYNTAX;
	}

	if (tail > 0)
		history_send_tail(cln, tail);

	sub_set(cln, max_level);
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

	(void)cmd;

	if (fields_cnt == 3)
		tail = atoi(fields[2]);
	else if (fields_cnt != 2)
		return CLI_CMD_SYNTAX;

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

	(void)cmd;

	if (fields_cnt == 2) {
		cli_sendv(client, "log history: %d\r\n", history_max);
		return CLI_CMD_OK;
	}

	if (fields_cnt != 3)
		return CLI_CMD_SYNTAX;

	if (!strcmp(fields[2], "off"))
		n = 0;
	else
		n = atoi(fields[2]);

	history_resize(n);
	cli_sendv(client, "log history: %d\r\n", history_max);
	return CLI_CMD_OK;
}

static void load_config(void)
{
	const char *opt;
	int n;

	opt = conf_get_opt("cli", "log-history");
	n = opt ? atoi(opt) : CLI_LOG_HISTORY_DEFAULT;
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
}

DEFINE_INIT(2, init);
