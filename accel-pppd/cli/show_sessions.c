#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <pthread.h>

#include "triton.h"
#include "events.h"
#include "ppp.h"
#include "ipdb.h"
#include "cli.h"
#include "utils.h"
#include "log.h"
#include "memdebug.h"

#define CELL_SIZE 128
#define DEF_COLUMNS "ifname,username,calling-sid,ip,rate-limit,type,comp,state,uptime"

struct column_t
{
	struct list_head entry;
	const char *name;
	const char *desc;
	void (*print)(struct ap_session *ses, char *buf);
};

struct col_t
{
	struct list_head entry;
	struct column_t *column;
	int width;
	int hidden;
};

struct row_t
{
	struct list_head entry;
	char *match_key;
	char *order_key;
	struct list_head cell_list;
};

struct cell_t
{
	struct list_head entry;
	struct col_t *col;
	char buf[CELL_SIZE + 1];
};

static LIST_HEAD(col_list);
static char *conf_def_columns = NULL;

static __thread struct rtnl_link_stats stats;
static __thread int stats_set;

void __export cli_show_ses_register(const char *name, const char *desc, void (*print)(struct ap_session *ses, char *buf))
{
	struct column_t *c = malloc(sizeof(*c));
	c->name = name;
	c->desc = desc;
	c->print = print;
	list_add_tail(&c->entry, &col_list);
}

static void show_ses_help(char * const *f, int f_cnt, void *cli)
{
	struct column_t *col;
	char buf[129];

	cli_send(cli, "show sessions [columns] [order <column>] [match <column> <regexp>] - shows sessions\r\n");
	cli_send(cli, "\tcolumns:\r\n");

	list_for_each_entry(col, &col_list, entry) {
		snprintf(buf, 128, "\t\t%s - %s\r\n", col->name, col->desc);
		cli_send(cli, buf);
	}
}

static struct column_t *find_column(const char *name)
{
	struct column_t *col;

	list_for_each_entry(col, &col_list, entry) {
		if (strcmp(col->name, name))
			continue;
		return col;
	}

	return NULL;
}

static void free_row(struct row_t *row)
{
	struct cell_t *cell;

	while (!list_empty(&row->cell_list)) {
		cell = list_entry(row->cell_list.next, typeof(*cell), entry);
		list_del(&cell->entry);
		_free(cell);
	}

	_free(row);
}

static void insert_row(struct list_head *list, struct row_t *row)
{
	struct row_t *row2, *row3;

	row3 = NULL;
	list_for_each_entry(row2, list, entry) {
		if (strcmp(row->order_key, row2->order_key) <= 0) {
			row3 = row2;
			break;
		}
	}
	if (row3)
		list_add_tail(&row->entry, &row3->entry);
	else
		list_add_tail(&row->entry, list);
}

static int show_ses_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	char *columns = NULL;
	struct column_t *match_key = NULL;
	char *match_pattern = NULL;
	struct column_t *order_key = NULL;
	pcre *re = NULL;
	const char *pcre_err;
	int pcre_offset;
	struct column_t *column;
	struct col_t *col;
	struct row_t *row;
	struct cell_t *cell;
	char *ptr1, *ptr2;
	int i, n, total_width, def_columns = 0;
	struct ap_session *ses;
	char *buf = NULL;
	int match_key_f = 0, order_key_f = 0;
	LIST_HEAD(c_list);
	LIST_HEAD(r_list);
	LIST_HEAD(t_list);

	for (i = 2; i < f_cnt; i++) {
		if (!strcmp(f[i], "order")) {
			if (i == f_cnt - 1)
				return CLI_CMD_SYNTAX;
			order_key = find_column(f[++i]);
			if (!order_key) {
				cli_sendv(cli, "unknown column %s\r\n", f[i]);
				return CLI_CMD_OK;
			}
		} else if (!strcmp(f[i], "match")) {
			if (i >= f_cnt - 2)
				return CLI_CMD_SYNTAX;
			match_key = find_column(f[++i]);
			if (!match_key) {
				cli_sendv(cli, "unknown column %s\r\n", f[i]);
				return CLI_CMD_OK;
			}
			match_pattern = f[++i];
		} else if (!columns)
			columns = f[i];
		else
			return CLI_CMD_SYNTAX;
	}

	if (match_key) {
		re = pcre_compile2(match_pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);
		if (!re) {
			cli_sendv(cli, "match: %s at %i\r\n", pcre_err, pcre_offset);
			return CLI_CMD_OK;
		}
	}

	if (!columns) {
		columns = (conf_def_columns) ? conf_def_columns : DEF_COLUMNS;
		def_columns = 1;
	}

	columns = _strdup(columns);
	ptr1 = columns;
	while (1) {
		ptr2 = strchr(ptr1, ',');
		if (ptr2)
			*ptr2 = 0;
		column = find_column(ptr1);
		if (column == match_key)
			match_key_f = 1;
		if (column == order_key)
			order_key_f = 1;
		if (column) {
			col = _malloc(sizeof(*col));
			col->column = column;
			col->width = strlen(column->name);
			col->hidden = 0;
			list_add_tail(&col->entry, &c_list);
		} else {
			if (!def_columns) {
				cli_sendv(cli, "unknown column %s\r\n", ptr1);
				_free(columns);
				goto out;
			}
		}
		if (!ptr2)
			break;
		ptr1 = ptr2 + 1;
	}
	_free(columns);

	if (match_key && !match_key_f) {
		col = _malloc(sizeof(*col));
		col->column = match_key;
		col->width = 0;
		col->hidden = 1;
		list_add_tail(&col->entry, &c_list);
	}

	if (order_key && !order_key_f) {
		col = _malloc(sizeof(*col));
		col->column = order_key;
		col->width = 0;
		col->hidden = 1;
		list_add_tail(&col->entry, &c_list);
	}

	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		stats_set = 0;
		row = _malloc(sizeof(*row));
		if (!row)
			goto oom;
		memset(row, 0, sizeof(*row));
		INIT_LIST_HEAD(&row->cell_list);
		if (match_key || order_key)
			list_add_tail(&row->entry, &t_list);
		else
			list_add_tail(&row->entry, &r_list);
		list_for_each_entry(col, &c_list, entry) {
			cell = _malloc(sizeof(*cell));
			if (!cell)
				goto oom;
			cell->col = col;
			list_add_tail(&cell->entry, &row->cell_list);
			col->column->print(ses, cell->buf);
			n = strlen(cell->buf);
			if (n > col->width)
				col->width = n;
			if (col->column == order_key)
				row->order_key = cell->buf;
			if (col->column == match_key)
				row->match_key = cell->buf;
		}
	}
	pthread_rwlock_unlock(&ses_lock);

	if (order_key || match_key) {
		while(!list_empty(&t_list)) {
			row = list_entry(t_list.next, typeof(*row), entry);
			list_del(&row->entry);
			if (match_key) {
				if (pcre_exec(re, NULL, row->match_key, strlen(row->match_key), 0, 0, NULL, 0) < 0) {
					free_row(row);
					continue;
				}
			}
			if (order_key)
				insert_row(&r_list, row);
			else
				list_add_tail(&row->entry, &r_list);
		}
	}

	total_width = -1;
	list_for_each_entry(col, &c_list, entry) {
		if (col->hidden)
			continue;
		total_width += col->width + 3;
	}

	if (total_width < 0)
		/* No column to print */
		goto early_out;

	buf = _malloc(total_width + 3);
	if (!buf)
		goto oom;

	ptr1 = buf;
	list_for_each_entry(col, &c_list, entry) {
		if (col->hidden)
			continue;
		n = strlen(col->column->name);
		if (col->width > n + 1) {
			ptr2 = ptr1;
			memset(ptr1, ' ', col->width/2 - n/2 + 1);
			ptr1 += col->width/2 - n/2 + 1;
			sprintf(ptr1, "%s", col->column->name);
			ptr1 = strchr(ptr1, 0);
			memset(ptr1, ' ', col->width + 2 - (ptr1 - ptr2));
			ptr1 += col->width + 2 - (ptr1 - ptr2);
			*ptr1 = '|';
			ptr1++;
		} else if (col->width > n) {
			sprintf(ptr1, " %s  |", col->column->name);
			ptr1 = strchr(ptr1, 0);
		} else {
			sprintf(ptr1, " %s |", col->column->name);
			ptr1 = strchr(ptr1, 0);
		}
	}

	strcpy(ptr1 - 1, "\r\n");
	cli_send(cli, buf);

	ptr1 = buf;
	list_for_each_entry(col, &c_list, entry) {
		if (col->hidden)
			continue;
		memset(ptr1, '-', col->width + 2);
		ptr1 += col->width + 2;
		*ptr1 = '+';
		ptr1++;
	}

	strcpy(ptr1 - 1, "\r\n");
	cli_send(cli, buf);

	while (!list_empty(&r_list)) {
		row = list_entry(r_list.next, typeof(*row), entry);
		ptr1 = buf;
		list_for_each_entry(cell, &row->cell_list, entry) {
			if (cell->col->hidden)
				continue;
			ptr2 = ptr1;
			sprintf(ptr1, " %s ", cell->buf);
			ptr1 = strchr(ptr1, 0);
			n = ptr1 - ptr2;
			if (n - 2 < cell->col->width) {
				memset(ptr1, ' ', cell->col->width + 2 - (ptr1 - ptr2));
				ptr1 += cell->col->width + 2 - (ptr1 - ptr2);
			}
			*ptr1 = '|';
			ptr1++;
		}
		strcpy(ptr1 - 1, "\r\n");
		cli_send(cli, buf);
		list_del(&row->entry);
		free_row(row);
	}

	_free(buf);

out:
	while (!list_empty(&c_list)) {
		col = list_entry(c_list.next, typeof(*col), entry);
		list_del(&col->entry);
		_free(col);
	}

	if (re)
		pcre_free(re);

	return CLI_CMD_OK;

oom:
	cli_send(cli, "out of memory");
early_out:
	if (buf)
		_free(buf);

	while (!list_empty(&t_list)) {
		row = list_entry(t_list.next, typeof(*row), entry);
		list_del(&row->entry);
		free_row(row);
	}
	goto out;
}

static void print_netns(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->net->name);
}

static void print_vrf(struct ap_session *ses, char *buf)
{
	if (ses->vrf_name)
		snprintf(buf, CELL_SIZE, "%s", ses->vrf_name);
	else
		*buf = 0;
}

static void print_ifname(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->ifname);
}

static void print_username(struct ap_session *ses, char *buf)
{
	if (ses->username)
		snprintf(buf, CELL_SIZE, "%s", ses->username);
	else
		*buf = 0;
}

static void print_ip6_dp(struct ap_session *ses, char *buf)
{
	struct ipv6db_addr_t *a;
	char *ptr;

	if (!ses->ipv6_dp) {
		*buf = 0;
		return;
	}

	a = list_entry(ses->ipv6_dp->prefix_list.next, typeof(*a), entry);
	inet_ntop(AF_INET6, &a->addr, buf, 64);
	ptr = strchr(buf, 0);
	sprintf(ptr, "/%i", a->prefix_len);
}

static void print_ip6(struct ap_session *ses, char *buf)
{
	struct ipv6db_addr_t *a;
	struct in6_addr addr;
	char *ptr;

	if (!ses->ipv6 || list_empty(&ses->ipv6->addr_list)) {
		*buf = 0;
		return;
	}

	a = list_entry(ses->ipv6->addr_list.next, typeof(*a), entry);
	if (a->prefix_len == 0) {
		*buf = 0;
		return;
	}

	build_ip6_addr(a, ses->ipv6->peer_intf_id, &addr);

	inet_ntop(AF_INET6, &addr, buf, 64);
	ptr = strchr(buf, 0);
	sprintf(ptr, "/%i", a->prefix_len);
}

static void print_ip(struct ap_session *ses, char *buf)
{
	if (!ses->ipv4) {
		print_ip6(ses,buf);
		return;
	}

	u_inet_ntoa(ses->ipv4->peer_addr, buf);
}

static void print_type(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->ctrl->name);
}

static void print_state(struct ap_session *ses, char *buf)
{
	char *state;
	switch (ses->state) {
		case AP_STATE_STARTING:
			state = "start";
			break;
		case AP_STATE_ACTIVE:
			state = "active";
			break;
		case AP_STATE_FINISHING:
			state = "finish";
			break;
		default:
			state = "unk";
	}
	sprintf(buf, "%s", state);
}

static void print_uptime(struct ap_session *ses, char *buf)
{
	time_t uptime;
	int day,hour,min,sec;
	char time_str[24];

	if (ses->stop_time)
		uptime = ses->stop_time - ses->start_time;
	else {
		uptime = _time();
		uptime -= ses->start_time;
	}

	day = uptime/ (24*60*60); uptime %= (24*60*60);
	hour = uptime / (60*60); uptime %= (60*60);
	min = uptime / 60;
	sec = uptime % 60;
	if (day)
		snprintf(time_str, sizeof(time_str), "%i.%02i:%02i:%02i", day, hour, min, sec);
	else
		snprintf(time_str, sizeof(time_str), "%02i:%02i:%02i", hour, min, sec);

	sprintf(buf, "%s", time_str);
}

static void print_uptime_raw(struct ap_session *ses, char *buf)
{
	time_t uptime;

	if (ses->stop_time)
		uptime = ses->stop_time - ses->start_time;
	else
		uptime = _time() - ses->start_time;

	sprintf(buf, "%lu", (unsigned long)uptime);
}

static void print_calling_sid(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->ctrl->calling_station_id);
}

static void print_called_sid(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->ctrl->called_station_id);
}

static void print_sid(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->sessionid);
}

static void print_comp(struct ap_session *ses, char *buf)
{
	if (ses->comp)
		snprintf(buf, CELL_SIZE, "%s", ses->comp);
	else
		buf[0] = 0;
}

static void format_bytes(char *buf, unsigned long long bytes)
{
	const char *suffix;
	unsigned int m;
	double d;

	if (bytes < 1024) {
		sprintf(buf, "%u B", (unsigned)bytes);
		return;
	}

	if (bytes < 1024*1024) {
		suffix = "KiB";
		m = 1024;
	} else if (bytes < 1024*1024*1024) {
		suffix = "MiB";
		m = 1024*1024;
	} else {
		suffix = "GiB";
		m = 1024*1024*1024;
	}

	d = (double)bytes/m;
	sprintf(buf, "%.1f %s", d, suffix);
}

static void get_stats(struct ap_session *ses) {
	if(ap_session_read_stats(ses, &stats) == -1) {
		stats.rx_bytes = 0;
		stats.tx_bytes = 0;
		stats.rx_packets = 0;
		stats.tx_packets = 0;
	}
}

static void print_rx_bytes(struct ap_session *ses, char *buf)
{
	if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}
	format_bytes(buf, 4294967296ll*ses->acct_input_gigawords + stats.rx_bytes);
}

static void print_tx_bytes(struct ap_session *ses, char *buf)
{
	if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}
	format_bytes(buf, 4294967296ll*ses->acct_output_gigawords + stats.tx_bytes);
}

static void print_rx_bytes_raw(struct ap_session *ses, char *buf)
{
	if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}
	sprintf(buf, "%llu", 4294967296ll*ses->acct_input_gigawords + stats.rx_bytes);
}

static void print_tx_bytes_raw(struct ap_session *ses, char *buf)
{
	if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}
	sprintf(buf, "%llu", 4294967296ll*ses->acct_output_gigawords + stats.tx_bytes);
}

static void print_rx_pkts(struct ap_session *ses, char *buf)
{
	if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}
	sprintf(buf, "%u", stats.rx_packets);
}

static void print_tx_pkts(struct ap_session *ses, char *buf)
{
	if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}
	sprintf(buf, "%u", stats.tx_packets);
}

static void load_config()
{
	const char *opt = NULL;
	char *ptr = NULL;

	opt = conf_get_opt("cli", "sessions-columns");
	if (opt && strlen(opt) > 0) {
		ptr = _realloc(conf_def_columns, strlen(opt) + 1);
		if (ptr) {
			memcpy(ptr, opt, strlen(opt) + 1);
			conf_def_columns = ptr;
		} else
			log_error("cli: Discard option sessions-columns:"
				  " memory allocation error\n");
	}
	if (ptr == NULL && conf_def_columns) {
		_free(conf_def_columns);
		conf_def_columns = NULL;
	}
}

static void init(void)
{
	load_config();

	cli_register_simple_cmd2(show_ses_exec, show_ses_help, 2, "show", "sessions");

	cli_show_ses_register("netns", "network namespace name", print_netns);
	cli_show_ses_register("vrf", "vrf name", print_vrf);
	cli_show_ses_register("ifname", "interface name", print_ifname);
	cli_show_ses_register("username", "user name", print_username);
	cli_show_ses_register("ip", "IP address", print_ip);
	cli_show_ses_register("ip6", "IPv6 address", print_ip6);
	cli_show_ses_register("ip6-dp", "IPv6 delegated prefix", print_ip6_dp);
	cli_show_ses_register("type", "VPN type", print_type);
	cli_show_ses_register("state", "state of session", print_state);
	cli_show_ses_register("uptime", "uptime (human readable)", print_uptime);
	cli_show_ses_register("uptime-raw", "uptime (in seconds)", print_uptime_raw);
	cli_show_ses_register("calling-sid", "calling station id", print_calling_sid);
	cli_show_ses_register("called-sid", "called station id", print_called_sid);
	cli_show_ses_register("sid", "session id", print_sid);
	cli_show_ses_register("comp", "compression/encryption method", print_comp);
	cli_show_ses_register("rx-bytes", "received bytes (human readable)", print_rx_bytes);
	cli_show_ses_register("tx-bytes", "transmitted bytes (human readable)", print_tx_bytes);
	cli_show_ses_register("rx-bytes-raw", "received bytes", print_rx_bytes_raw);
	cli_show_ses_register("tx-bytes-raw", "transmitted bytes", print_tx_bytes_raw);
	cli_show_ses_register("rx-pkts", "received packets", print_rx_pkts);
	cli_show_ses_register("tx-pkts", "transmitted packets", print_tx_pkts);

	triton_event_register_handler(EV_CONFIG_RELOAD, load_config);
}

DEFINE_INIT(12, init);
