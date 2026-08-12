#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <dlfcn.h>

#include "triton.h"
#include "events.h"
#include "log.h"
#include "list.h"
#include "utils.h"
#include "ap_session.h"
#include "ipdb.h"
#include "version.h"

#include "memdebug.h"

/* Per-protocol session counters live in their respective shared modules.
 * Resolve them with dlsym(RTLD_DEFAULT, ...) lazily rather than via direct
 * (weak) references: when metrics is dlopen()ed before the protocol module
 * the loader binds undefined refs to NULL and never updates them when a
 * later RTLD_GLOBAL dlopen brings the symbols in. dlsym walks the live
 * global scope at call time, so it picks them up regardless of order.
 */
typedef unsigned int (*proto_stat_fn)(void);

struct proto_stat {
	const char *module;
	const char *starting_sym;
	const char *active_sym;
	proto_stat_fn starting;
	proto_stat_fn active;
};

static struct proto_stat proto_stats[] = {
	{ "pppoe", "pppoe_stat_starting", "pppoe_stat_active" },
	{ "l2tp",  "l2tp_stat_starting",  "l2tp_stat_active"  },
	{ "pptp",  "pptp_stat_starting",  "pptp_stat_active"  },
	{ "sstp",  "sstp_stat_starting",  "sstp_stat_active"  },
	{ "ipoe",  "ipoe_stat_starting",  "ipoe_stat_active"  },
};

static int proto_resolve(struct proto_stat *p)
{
	if (!triton_module_loaded(p->module))
		return 0;
	if (!p->starting)
		p->starting = (proto_stat_fn)(uintptr_t)dlsym(RTLD_DEFAULT, p->starting_sym);
	if (!p->active)
		p->active = (proto_stat_fn)(uintptr_t)dlsym(RTLD_DEFAULT, p->active_sym);
	return p->starting && p->active;
}

enum metrics_format {
	METRICS_FORMAT_PROMETHEUS,
	METRICS_FORMAT_JSON,
};

#define METRICS_RECV_BUF_SIZE 2048
#define METRICS_HDR_RESERVE 256		/* room reserved for the response header */
#define METRICS_DEFAULT_READ_TIMEOUT 5	/* seconds */
#define METRICS_DEFAULT_MAX_CLIENTS 64

struct metrics_client_t {
	struct list_head entry;
	struct triton_md_handler_t hnd;
	struct triton_timer_t timer;
	struct sockaddr_in addr;
	char *recv_buf;
	int recv_pos;
	char *xmit_buf;
	int xmit_pos;
	int xmit_len;
	unsigned int disconnect:1;
};

struct metrics_acl_t {
	struct list_head entry;
	uint32_t net;	/* host byte order */
	uint32_t mask;	/* host byte order */
};

static enum metrics_format conf_format = METRICS_FORMAT_PROMETHEUS;
/* TODO: Support simultaneous Prometheus and JSON output, selected by endpoint
 * (for example, /metrics and /metrics.json) instead of a process-wide format.
 */
static char *conf_address;
static LIST_HEAD(conf_allowed);
static int conf_read_timeout = METRICS_DEFAULT_READ_TIMEOUT;
static int conf_max_clients = METRICS_DEFAULT_MAX_CLIENTS;
static int conf_sessions;

#define METRICS_ACCEPT_BACKOFF 1	/* seconds */
#define METRICS_ACCEPT_BATCH 16	/* max accept()s per serv_read tick */

static struct triton_context_t serv_ctx;
static struct triton_md_handler_t serv_hnd;
static struct triton_timer_t accept_resume_timer;
static LIST_HEAD(clients);
static unsigned int client_count;
static int serv_running;
static int accept_paused;

static int parse_format(const char *opt, enum metrics_format *out)
{
	if (!strcasecmp(opt, "prometheus")) {
		*out = METRICS_FORMAT_PROMETHEUS;
		return 0;
	}
	if (!strcasecmp(opt, "json")) {
		*out = METRICS_FORMAT_JSON;
		return 0;
	}
	return -1;
}

/* TODO: IPv6 support. The listener, the ACL, and every sockaddr below are
 * IPv4-only for now; bracketed-host syntax ("[::1]:8080"), AF_INET6 sockets,
 * and IPv6 CIDRs in allowed_ips are intentionally left for a follow-up.
 */
static int parse_listen_address(const char *str, struct sockaddr_in *addr)
{
	char *buf, *colon;
	int port;
	int ret = -1;

	buf = strdup(str);
	if (!buf)
		return -1;

	colon = strrchr(buf, ':');
	if (!colon)
		goto out;

	*colon = 0;
	port = atoi(colon + 1);
	if (port <= 0 || port > 65535)
		goto out;

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	if (buf[0] == 0 || !strcmp(buf, "*") || !strcmp(buf, "0.0.0.0"))
		addr->sin_addr.s_addr = htonl(INADDR_ANY);
	else if (inet_pton(AF_INET, buf, &addr->sin_addr) != 1)
		goto out;

	ret = 0;
out:
	free(buf);
	return ret;
}

static void free_acl(struct list_head *head)
{
	struct metrics_acl_t *acl;

	while (!list_empty(head)) {
		acl = list_first_entry(head, typeof(*acl), entry);
		list_del(&acl->entry);
		_free(acl);
	}
}

/* Strip surrounding whitespace, optional matching single/double quotes,
 * and any trailing comma. Returns NULL if the token becomes empty.
 */
static char *clean_token(char *s)
{
	char *end;
	size_t len;

	while (*s == ' ' || *s == '\t')
		s++;

	len = strlen(s);
	while (len && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
		       s[len - 1] == ',' || s[len - 1] == '\r' ||
		       s[len - 1] == '\n'))
		s[--len] = 0;

	if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') ||
			 (s[0] == '\'' && s[len - 1] == '\''))) {
		s[len - 1] = 0;
		s++;
		len -= 2;
	}

	while (*s == ' ' || *s == '\t')
		s++;
	end = s + strlen(s);
	while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
		*--end = 0;

	return *s ? s : NULL;
}

/* TODO: IPv6 support. Only IPv4 CIDR or a bare IPv4 address are accepted;
 * IPv6 entries in allowed_ips are rejected at parse time. ip_allowed() and
 * struct metrics_acl_t store the network in a 32-bit host-order word, so
 * adding IPv6 here will also need the matching widening downstream.
 */
static int parse_acl_entry(const char *str, struct metrics_acl_t **out)
{
	struct metrics_acl_t *acl;
	struct in_addr addr;
	uint8_t prefix;
	uint32_t mask;

	if (!u_parse_ip4cidr(str, &addr, &prefix)) {
		/* Accept a bare IP as /32 */
		if (inet_pton(AF_INET, str, &addr) != 1)
			return -1;
		prefix = 32;
	}

	acl = _malloc(sizeof(*acl));
	if (!acl)
		return -1;

	mask = prefix ? (uint32_t)0xffffffffu << (32 - prefix) : 0;
	acl->net = ntohl(addr.s_addr) & mask;
	acl->mask = mask;
	*out = acl;
	return 0;
}

/* Parse `allowed_ips` value. Accepts:
 *   "1.2.3.4/32, 5.6.7.0/24"
 *   ["1.2.3.4/32", "5.6.7.0/24"]
 * On success the supplied list is populated and 0 is returned. Returns -1 on
 * any parse error; in that case the partial list is freed.
 */
static int parse_allowed_ips(const char *value, struct list_head *list)
{
	char *buf, *p, *tok;
	int ret = -1;

	if (!value || !*value)
		return 0;

	buf = strdup(value);
	if (!buf)
		return -1;

	p = buf;
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == '[')
		p++;
	{
		size_t len = strlen(p);
		while (len && (p[len - 1] == ' ' || p[len - 1] == '\t' ||
			       p[len - 1] == ']' || p[len - 1] == '\r' ||
			       p[len - 1] == '\n'))
			p[--len] = 0;
	}

	while ((tok = strsep(&p, ",")) != NULL) {
		struct metrics_acl_t *acl;
		char *clean = clean_token(tok);

		if (!clean)
			continue;
		if (parse_acl_entry(clean, &acl) < 0) {
			log_error("metrics: invalid entry in allowed_ips: '%s'\n", clean);
			free_acl(list);
			goto out;
		}
		list_add_tail(&acl->entry, list);
	}

	ret = 0;
out:
	free(buf);
	return ret;
}

static int ip_allowed(uint32_t addr_nbo)
{
	struct metrics_acl_t *acl;
	uint32_t addr;

	if (list_empty(&conf_allowed))
		return 1;

	addr = ntohl(addr_nbo);
	list_for_each_entry(acl, &conf_allowed, entry) {
		if ((addr & acl->mask) == acl->net)
			return 1;
	}
	return 0;
}

static int load_config(void)
{
	const char *opt;
	enum metrics_format fmt = METRICS_FORMAT_PROMETHEUS;
	char *address = NULL;
	struct sockaddr_in dummy;
	LIST_HEAD(new_allowed);

	opt = conf_get_opt("metrics", "format");
	if (opt && parse_format(opt, &fmt) < 0) {
		log_error("metrics: unknown format '%s', expected 'prometheus' or 'json'\n", opt);
		return -1;
	}

	opt = conf_get_opt("metrics", "address");
	if (!opt) {
		log_emerg("metrics: 'address' option is required (host:port)\n");
		return -1;
	}
	if (parse_listen_address(opt, &dummy) < 0) {
		log_emerg("metrics: invalid address '%s', expected host:port\n", opt);
		return -1;
	}
	address = _strdup(opt);
	if (!address) {
		log_emerg("metrics: out of memory while loading config\n");
		return -1;
	}

	opt = conf_get_opt("metrics", "allowed_ips");
	if (opt && parse_allowed_ips(opt, &new_allowed) < 0) {
		_free(address);
		return -1;
	}

	conf_format = fmt;
	if (conf_address)
		_free(conf_address);
	conf_address = address;

	free_acl(&conf_allowed);
	list_replace_init(&new_allowed, &conf_allowed);

	opt = conf_get_opt("metrics", "read_timeout");
	if (opt) {
		int n = atoi(opt);
		conf_read_timeout = n > 0 ? n : 0;
	}

	opt = conf_get_opt("metrics", "max_clients");
	if (opt) {
		int n = atoi(opt);
		conf_max_clients = n > 0 ? n : 0;
	}

	opt = conf_get_opt("metrics", "sessions");
	conf_sessions = opt ? atoi(opt) != 0 : 0;

	return 0;
}

static const char *content_type(void)
{
	switch (conf_format) {
	case METRICS_FORMAT_JSON:
		return "application/json";
	case METRICS_FORMAT_PROMETHEUS:
	default:
		return "text/plain; version=0.0.4; charset=utf-8";
	}
}

struct strbuf {
	char *data;
	size_t len;
	size_t cap;
	int oom;
};

static int strbuf_reserve(struct strbuf *sb, size_t want)
{
	size_t need = sb->len + want + 1;
	size_t ncap;
	char *p;

	if (sb->oom)
		return -1;
	if (need <= sb->cap)
		return 0;

	ncap = sb->cap ? sb->cap : 1024;
	while (ncap < need)
		ncap *= 2;

	p = _realloc(sb->data, ncap);
	if (!p) {
		sb->oom = 1;
		return -1;
	}
	sb->data = p;
	sb->cap = ncap;
	return 0;
}

static void strbuf_appendf(struct strbuf *sb, const char *fmt, ...)
	__attribute__((format(gnu_printf, 2, 3)));

static void strbuf_appendf(struct strbuf *sb, const char *fmt, ...)
{
	va_list ap;
	int n;
	char *dst;
	size_t avail;

	if (sb->oom)
		return;

	for (;;) {
		/* On the very first append sb->data is still NULL and
		 * sb->cap is zero. Computing sb->data + sb->len in that
		 * state would be NULL pointer arithmetic (UB per the C
		 * standard); pass NULL directly to vsnprintf instead,
		 * which is well-defined when the size is zero.
		 */
		avail = sb->cap - sb->len;
		dst = sb->data ? sb->data + sb->len : NULL;

		va_start(ap, fmt);
		n = vsnprintf(dst, avail, fmt, ap);
		va_end(ap);

		if (n < 0) {
			sb->oom = 1;
			return;
		}
		if ((size_t)n < avail) {
			sb->len += n;
			return;
		}
		if (strbuf_reserve(sb, n + 1) < 0)
			return;
	}
}

static void strbuf_free(struct strbuf *sb)
{
	if (sb->data)
		_free(sb->data);
	sb->data = NULL;
	sb->len = sb->cap = 0;
}

struct accel_stats {
	time_t uptime;
	unsigned int cpu;
	unsigned long rss_bytes;
	unsigned long virt_bytes;
	struct triton_stat_t core;
	struct ap_session_stat sessions;
};

static void read_proc_mem(unsigned long *rss, unsigned long *virt)
{
	char path[64];
	unsigned long vmsize = 0, vmrss = 0;
	long page_size = sysconf(_SC_PAGESIZE);
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%i/statm", getpid());
	f = fopen(path, "r");
	if (f) {
		if (fscanf(f, "%lu %lu", &vmsize, &vmrss) != 2) {
			vmsize = 0;
			vmrss = 0;
		}
		fclose(f);
	}

	*rss = (unsigned long)vmrss * (page_size > 0 ? page_size : 4096);
	*virt = (unsigned long)vmsize * (page_size > 0 ? page_size : 4096);
}

static void gather_stats(struct accel_stats *s)
{
	struct timespec ts;

	memset(s, 0, sizeof(*s));
	triton_stat_get(&s->core);
	ap_session_stat_get(&s->sessions);

	clock_gettime(CLOCK_MONOTONIC, &ts);
	s->uptime = ts.tv_sec - s->core.start_time;
	s->cpu = s->core.cpu;

	read_proc_mem(&s->rss_bytes, &s->virt_bytes);
}

static void emit_prom_gauge(struct strbuf *sb, const char *name,
			    const char *help, unsigned long long value)
{
	strbuf_appendf(sb, "# HELP %s %s\n", name, help);
	strbuf_appendf(sb, "# TYPE %s gauge\n", name);
	strbuf_appendf(sb, "%s %llu\n", name, value);
}

static const char *session_state_name(int state)
{
	switch (state) {
	case AP_STATE_STARTING:
		return "starting";
	case AP_STATE_ACTIVE:
		return "active";
	case AP_STATE_FINISHING:
		return "finishing";
	case AP_STATE_RESTORE:
		return "restore";
	default:
		return "unknown";
	}
}

static void append_prefix_len(char *buf, size_t len, int prefix_len)
{
	size_t pos = strlen(buf);

	if (pos < len)
		snprintf(buf + pos, len - pos, "/%i", prefix_len);
}

static void session_ipv6(struct ap_session *ses, char *buf, size_t len, int with_plen)
{
	struct ipv6db_addr_t *a;
	struct in6_addr addr;

	buf[0] = 0;
	if (!ses->ipv6 || list_empty(&ses->ipv6->addr_list))
		return;

	a = list_first_entry(&ses->ipv6->addr_list, typeof(*a), entry);
	if (!a->prefix_len)
		return;
	build_ip6_addr(a, ses->ipv6->peer_intf_id, &addr);
	if (!inet_ntop(AF_INET6, &addr, buf, len))
		return;
	if (with_plen)
		append_prefix_len(buf, len, a->prefix_len);
}

static void session_ipv6_dp(struct ap_session *ses, char *buf, size_t len)
{
	struct ipv6db_addr_t *a;

	buf[0] = 0;
	if (!ses->ipv6_dp || list_empty(&ses->ipv6_dp->prefix_list))
		return;

	a = list_first_entry(&ses->ipv6_dp->prefix_list, typeof(*a), entry);
	if (!inet_ntop(AF_INET6, &a->addr, buf, len))
		return;
	append_prefix_len(buf, len, a->prefix_len);
}

/* Bare peer address, no prefix length: this is the address the peer is
 * reachable at, mirroring the "ip" column of "accel-cmd show sessions". */
static void session_ip(struct ap_session *ses, char *buf, size_t len)
{
	if (ses->ipv4) {
		inet_ntop(AF_INET, &ses->ipv4->peer_addr, buf, len);
		return;
	}
	session_ipv6(ses, buf, len, 0);
}

static unsigned long long session_uptime(struct ap_session *ses, time_t now)
{
	time_t end = ses->stop_time ? ses->stop_time : now;

	return end > ses->start_time ? (unsigned long long)(end - ses->start_time) : 0;
}

static void render_prometheus(struct strbuf *sb)
{
	struct accel_stats s;

	gather_stats(&s);

	strbuf_appendf(sb, "# HELP accel_ppp_build_info accel-ppp build information\n");
	strbuf_appendf(sb, "# TYPE accel_ppp_build_info gauge\n");
	strbuf_appendf(sb, "accel_ppp_build_info{version=\"%s\"} 1\n", ACCEL_PPP_VERSION);

	emit_prom_gauge(sb, "accel_ppp_uptime_seconds",
			"Daemon uptime in seconds",
			(unsigned long long)s.uptime);
	emit_prom_gauge(sb, "accel_ppp_cpu_percent",
			"Daemon CPU usage in percent",
			(unsigned long long)s.cpu);
	emit_prom_gauge(sb, "accel_ppp_memory_rss_bytes",
			"Resident set size of the daemon in bytes",
			(unsigned long long)s.rss_bytes);
	emit_prom_gauge(sb, "accel_ppp_memory_virt_bytes",
			"Virtual memory size of the daemon in bytes",
			(unsigned long long)s.virt_bytes);

	emit_prom_gauge(sb, "accel_ppp_core_mempool_allocated_bytes",
			"Bytes currently allocated from triton mempools",
			(unsigned long long)s.core.mempool_allocated);
	emit_prom_gauge(sb, "accel_ppp_core_mempool_available_bytes",
			"Bytes currently free in triton mempools",
			(unsigned long long)s.core.mempool_available);
	emit_prom_gauge(sb, "accel_ppp_core_threads",
			"Total number of triton worker threads",
			s.core.thread_count);
	emit_prom_gauge(sb, "accel_ppp_core_threads_active",
			"Number of triton worker threads currently active",
			s.core.thread_active);
	emit_prom_gauge(sb, "accel_ppp_core_contexts",
			"Total number of triton contexts",
			s.core.context_count);
	emit_prom_gauge(sb, "accel_ppp_core_contexts_sleeping",
			"Number of triton contexts currently sleeping",
			s.core.context_sleeping);
	emit_prom_gauge(sb, "accel_ppp_core_contexts_pending",
			"Number of triton contexts waiting to run",
			s.core.context_pending);
	emit_prom_gauge(sb, "accel_ppp_core_md_handlers",
			"Total number of triton md handlers",
			s.core.md_handler_count);
	emit_prom_gauge(sb, "accel_ppp_core_md_handlers_pending",
			"Number of triton md handlers with pending events",
			s.core.md_handler_pending);
	emit_prom_gauge(sb, "accel_ppp_core_timers",
			"Total number of triton timers",
			s.core.timer_count);
	emit_prom_gauge(sb, "accel_ppp_core_timers_pending",
			"Number of triton timers pending fire",
			s.core.timer_pending);

	strbuf_appendf(sb, "# HELP accel_ppp_sessions Number of sessions in each state\n");
	strbuf_appendf(sb, "# TYPE accel_ppp_sessions gauge\n");
	strbuf_appendf(sb, "accel_ppp_sessions{state=\"starting\"} %u\n", s.sessions.starting);
	strbuf_appendf(sb, "accel_ppp_sessions{state=\"active\"} %u\n", s.sessions.active);
	strbuf_appendf(sb, "accel_ppp_sessions{state=\"finishing\"} %u\n", s.sessions.finishing);

	strbuf_appendf(sb, "# HELP accel_ppp_protocol_sessions Sessions per protocol and state\n");
	strbuf_appendf(sb, "# TYPE accel_ppp_protocol_sessions gauge\n");
	for (size_t i = 0; i < sizeof(proto_stats) / sizeof(proto_stats[0]); i++) {
		struct proto_stat *p = &proto_stats[i];

		if (!proto_resolve(p))
			continue;
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"%s\",state=\"starting\"} %u\n",
			       p->module, p->starting());
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"%s\",state=\"active\"} %u\n",
			       p->module, p->active());
	}
}

/* Length of the well formed UTF-8 sequence starting at s, 0 if the bytes
 * there are not one. Overlong forms, surrogates and out of range code
 * points are rejected. */
static int utf8_seq_len(const unsigned char *s)
{
	unsigned int cp, min;
	int n, i;

	if (s[0] < 0x80)
		return 1;

	if ((s[0] & 0xe0) == 0xc0) {
		n = 2;
		min = 0x80;
		cp = s[0] & 0x1f;
	} else if ((s[0] & 0xf0) == 0xe0) {
		n = 3;
		min = 0x800;
		cp = s[0] & 0x0f;
	} else if ((s[0] & 0xf8) == 0xf0) {
		n = 4;
		min = 0x10000;
		cp = s[0] & 0x07;
	} else
		return 0;

	for (i = 1; i < n; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return 0;
		cp = (cp << 6) | (s[i] & 0x3f);
	}

	if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
		return 0;

	return n;
}

static void append_json_string(struct strbuf *sb, const char *str)
{
	const unsigned char *s = (const unsigned char *)str;
	const char *esc;
	int n;

	strbuf_appendf(sb, "\"");
	while (*s) {
		esc = NULL;
		switch (*s) {
		case '"':
			esc = "\\\"";
			break;
		case '\\':
			esc = "\\\\";
			break;
		case '\b':
			esc = "\\b";
			break;
		case '\f':
			esc = "\\f";
			break;
		case '\n':
			esc = "\\n";
			break;
		case '\r':
			esc = "\\r";
			break;
		case '\t':
			esc = "\\t";
			break;
		}

		if (esc) {
			strbuf_appendf(sb, "%s", esc);
			s++;
			continue;
		}

		if (*s < 0x20) {
			strbuf_appendf(sb, "\\u%04x", *s);
			s++;
			continue;
		}

		/* Usernames and station ids come from the peer and are not
		 * validated anywhere, so a single malformed sequence would
		 * otherwise make the whole document undecodable. */
		n = utf8_seq_len(s);
		if (!n) {
			strbuf_appendf(sb, "\\ufffd");
			s++;
			continue;
		}

		strbuf_appendf(sb, "%.*s", n, (const char *)s);
		s += n;
	}
	strbuf_appendf(sb, "\"");
}

static void emit_json_proto(struct strbuf *sb, const char *name, int *first,
			    unsigned int starting, unsigned int active)
{
	if (!*first)
		strbuf_appendf(sb, ",");
	*first = 0;
	strbuf_appendf(sb, "\"%s\":{\"starting\":%u,\"active\":%u}",
		       name, starting, active);
}

static void append_json_field(struct strbuf *sb, int *first, const char *name,
			      const char *value)
{
	if (!*first)
		strbuf_appendf(sb, ",");
	*first = 0;
	append_json_string(sb, name);
	strbuf_appendf(sb, ":");
	append_json_string(sb, value ? value : "");
}

/* TODO: Copy a bounded snapshot of the required fields under ses_lock, then
 * serialize it after unlocking. This would shorten lock hold time and make it
 * practical to add a response-size limit or pagination for large deployments.
 */
/* The whole list is walked with ses_lock held, so nothing in here may
 * block or touch the session. In particular ap_session_read_stats() is
 * not used: it issues a synchronous netlink round trip per session,
 * which would stall every session setup and teardown for the duration
 * of a scrape, it writes back into the session while only the read lock
 * is held, and it needs the thread local "net" of the session's
 * namespace, which this context does not have. The accounting counters
 * last sampled by the session itself are reported instead. */
static void render_json_sessions(struct strbuf *sb)
{
	struct ap_session *ses;
	time_t now = _time();
	char ip[INET6_ADDRSTRLEN];
	char ipv6[INET6_ADDRSTRLEN + 5];
	char ipv6_dp[INET6_ADDRSTRLEN + 5];
	int first = 1;
	int f;

	strbuf_appendf(sb, ",\"session_details\":[");
	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		session_ip(ses, ip, sizeof(ip));
		session_ipv6(ses, ipv6, sizeof(ipv6), 1);
		session_ipv6_dp(ses, ipv6_dp, sizeof(ipv6_dp));

		strbuf_appendf(sb, "%s", first ? "{" : ",{");
		first = 0;
		f = 1;
		append_json_field(sb, &f, "session_id", ses->sessionid);
		append_json_field(sb, &f, "ifname", ses->ifname);
		append_json_field(sb, &f, "username", ses->username);
		append_json_field(sb, &f, "ip", ip);
		append_json_field(sb, &f, "ipv6", ipv6);
		append_json_field(sb, &f, "delegated_ipv6_prefix", ipv6_dp);
		append_json_field(sb, &f, "protocol", ses->ctrl ? ses->ctrl->name : NULL);
		append_json_field(sb, &f, "state", session_state_name(ses->state));
		append_json_field(sb, &f, "calling_station_id", ses->ctrl ? ses->ctrl->calling_station_id : NULL);
		append_json_field(sb, &f, "called_station_id", ses->ctrl ? ses->ctrl->called_station_id : NULL);
		append_json_field(sb, &f, "service_name", ses->ctrl ? ses->ctrl->service_name : NULL);
		append_json_field(sb, &f, "inbound_if", ses->ctrl ? ses->ctrl->ifname : NULL);
		append_json_field(sb, &f, "compression", ses->comp);
		append_json_field(sb, &f, "vrf", ses->vrf_name);
		append_json_field(sb, &f, "netns", ses->net ? ses->net->name : NULL);
		strbuf_appendf(sb,
			",\"uptime_seconds\":%llu,\"rx_bytes\":%" PRIu64
			",\"tx_bytes\":%" PRIu64 ",\"rx_packets\":%" PRIu64
			",\"tx_packets\":%" PRIu64 "}",
			session_uptime(ses, now), ses->acct_rx_bytes,
			ses->acct_tx_bytes, ses->acct_rx_packets,
			ses->acct_tx_packets);
	}
	pthread_rwlock_unlock(&ses_lock);
	strbuf_appendf(sb, "]");
}

static void render_json(struct strbuf *sb)
{
	struct accel_stats s;
	int first = 1;

	gather_stats(&s);

	strbuf_appendf(sb, "{");
	strbuf_appendf(sb, "\"build\":{\"version\":");
	append_json_string(sb, ACCEL_PPP_VERSION);
	strbuf_appendf(sb, "},");

	strbuf_appendf(sb, "\"uptime_seconds\":%llu,", (unsigned long long)s.uptime);
	strbuf_appendf(sb, "\"cpu_percent\":%u,", s.cpu);
	strbuf_appendf(sb, "\"memory\":{\"rss_bytes\":%lu,\"virt_bytes\":%lu},",
		       s.rss_bytes, s.virt_bytes);

	strbuf_appendf(sb, "\"core\":{");
	strbuf_appendf(sb, "\"mempool_allocated_bytes\":%" PRIu64 ",", s.core.mempool_allocated);
	strbuf_appendf(sb, "\"mempool_available_bytes\":%" PRIu64 ",", s.core.mempool_available);
	strbuf_appendf(sb, "\"threads\":%u,", s.core.thread_count);
	strbuf_appendf(sb, "\"threads_active\":%u,", s.core.thread_active);
	strbuf_appendf(sb, "\"contexts\":%u,", s.core.context_count);
	strbuf_appendf(sb, "\"contexts_sleeping\":%u,", s.core.context_sleeping);
	strbuf_appendf(sb, "\"contexts_pending\":%u,", s.core.context_pending);
	strbuf_appendf(sb, "\"md_handlers\":%u,", s.core.md_handler_count);
	strbuf_appendf(sb, "\"md_handlers_pending\":%u,", s.core.md_handler_pending);
	strbuf_appendf(sb, "\"timers\":%u,", s.core.timer_count);
	strbuf_appendf(sb, "\"timers_pending\":%u", s.core.timer_pending);
	strbuf_appendf(sb, "},");

	strbuf_appendf(sb,
		"\"sessions\":{\"starting\":%u,\"active\":%u,\"finishing\":%u},",
		s.sessions.starting, s.sessions.active, s.sessions.finishing);

	strbuf_appendf(sb, "\"protocols\":{");
	for (size_t i = 0; i < sizeof(proto_stats) / sizeof(proto_stats[0]); i++) {
		struct proto_stat *p = &proto_stats[i];

		if (!proto_resolve(p))
			continue;
		emit_json_proto(sb, p->module, &first, p->starting(), p->active());
	}
	strbuf_appendf(sb, "}");
	if (conf_sessions)
		render_json_sessions(sb);

	strbuf_appendf(sb, "}\n");
}

/* Try to drain cln->xmit_buf to the socket. Returns 0 if the entire
 * response was flushed, 1 if a partial write occurred and MD_MODE_WRITE
 * was enabled to finish later, -1 if the connection is broken (caller
 * should disconnect).
 */
static int xmit_flush(struct metrics_client_t *cln)
{
	int n;

	while (cln->xmit_pos < cln->xmit_len) {
		n = write(cln->hnd.fd,
			  cln->xmit_buf + cln->xmit_pos,
			  cln->xmit_len - cln->xmit_pos);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				triton_md_enable_handler(&cln->hnd, MD_MODE_WRITE);
				return 1;
			}
			return -1;
		}
		cln->xmit_pos += n;
	}
	return 0;
}

static int format_header(char *buf, size_t size, int status, const char *reason,
			 const char *ctype, size_t body_len)
{
	int hlen;

	hlen = snprintf(buf, size,
			"HTTP/1.1 %d %s\r\n"
			"Server: accel-ppp\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %zu\r\n"
			"Connection: close\r\n"
			"\r\n",
			status, reason, ctype, body_len);
	if (hlen <= 0 || hlen >= (int)size)
		return -1;

	return hlen;
}

static void start_xmit(struct metrics_client_t *cln)
{
	int rc = xmit_flush(cln);

	if (rc < 0)
		cln->disconnect = 1;
	else if (rc == 0)
		cln->disconnect = 1;	/* fully flushed, ready to close */
}

static void send_response(struct metrics_client_t *cln, int status, const char *reason,
			  const char *ctype, const char *body, int body_len)
{
	char header[METRICS_HDR_RESERVE];
	int hlen, total;

	if (cln->xmit_buf)
		return;	/* response already in flight */

	hlen = format_header(header, sizeof(header), status, reason, ctype,
			     body_len > 0 ? (size_t)body_len : 0);
	if (hlen < 0) {
		cln->disconnect = 1;
		return;
	}

	total = hlen + (body_len > 0 ? body_len : 0);
	cln->xmit_buf = _malloc(total);
	if (!cln->xmit_buf) {
		cln->disconnect = 1;
		return;
	}
	memcpy(cln->xmit_buf, header, hlen);
	if (body_len > 0)
		memcpy(cln->xmit_buf + hlen, body, body_len);
	cln->xmit_pos = 0;
	cln->xmit_len = total;

	start_xmit(cln);
}

static void send_simple(struct metrics_client_t *cln, int status, const char *reason)
{
	char body[128];
	int len;

	len = snprintf(body, sizeof(body), "%d %s\n", status, reason);
	send_response(cln, status, reason, "text/plain; charset=utf-8", body, len);
}

/* Sends a body rendered into sb and takes ownership of its buffer. The
 * first METRICS_HDR_RESERVE bytes of sb are unused padding the header is
 * written into, so a body that can be several megabytes with sessions=1
 * is not copied a second time. */
static void send_rendered(struct metrics_client_t *cln, const char *ctype,
			  struct strbuf *sb)
{
	char header[METRICS_HDR_RESERVE];
	size_t body_len = sb->len - METRICS_HDR_RESERVE;
	int hlen;

	if (cln->xmit_buf)
		return;	/* response already in flight */

	hlen = format_header(header, sizeof(header), 200, "OK", ctype, body_len);
	if (hlen < 0 || sb->len > INT_MAX) {
		send_simple(cln, 500, "Internal Server Error");
		return;
	}

	memcpy(sb->data + METRICS_HDR_RESERVE - hlen, header, hlen);
	cln->xmit_buf = sb->data;
	cln->xmit_pos = METRICS_HDR_RESERVE - hlen;
	cln->xmit_len = (int)sb->len;
	sb->data = NULL;
	sb->len = sb->cap = 0;

	start_xmit(cln);
}

static void serve_metrics(struct metrics_client_t *cln)
{
	struct strbuf sb = {0};

	/* Reserve room for the response header in front of the body so it
	 * can be handed to the client without another copy. */
	if (strbuf_reserve(&sb, METRICS_HDR_RESERVE))
		goto err;
	sb.len = METRICS_HDR_RESERVE;

	switch (conf_format) {
	case METRICS_FORMAT_PROMETHEUS:
		render_prometheus(&sb);
		break;
	case METRICS_FORMAT_JSON:
		render_json(&sb);
		break;
	}

	if (sb.oom || !sb.data)
		goto err;

	send_rendered(cln, content_type(), &sb);
	strbuf_free(&sb);
	return;

err:
	send_simple(cln, 500, "Internal Server Error");
	strbuf_free(&sb);
}

static void client_timeout(struct triton_timer_t *t);

static void disconnect_client(struct metrics_client_t *cln)
{
	if (cln->timer.tpd)
		triton_timer_del(&cln->timer);
	list_del(&cln->entry);
	client_count--;
	triton_md_unregister_handler(&cln->hnd, 1);
	if (cln->recv_buf)
		_free(cln->recv_buf);
	if (cln->xmit_buf)
		_free(cln->xmit_buf);
	_free(cln);
}

static void client_timeout(struct triton_timer_t *t)
{
	struct metrics_client_t *cln = container_of(t, typeof(*cln), timer);

	disconnect_client(cln);
}

static void handle_request(struct metrics_client_t *cln)
{
	char *line_end, *space1, *space2;
	char *method, *path;

	line_end = strstr(cln->recv_buf, "\r\n");
	if (!line_end)
		return;
	*line_end = 0;

	method = cln->recv_buf;
	space1 = strchr(method, ' ');
	if (!space1) {
		send_simple(cln, 400, "Bad Request");
		return;
	}
	*space1 = 0;
	path = space1 + 1;
	space2 = strchr(path, ' ');
	if (space2)
		*space2 = 0;

	if (strcmp(method, "GET")) {
		send_simple(cln, 405, "Method Not Allowed");
		return;
	}

	if (!strcmp(path, "/metrics"))
		serve_metrics(cln);
	else
		send_simple(cln, 404, "Not Found");
}

static int cln_read(struct triton_md_handler_t *h)
{
	struct metrics_client_t *cln = container_of(h, typeof(*cln), hnd);
	int n;

	while (1) {
		if (cln->recv_pos >= METRICS_RECV_BUF_SIZE - 1) {
			send_simple(cln, 413, "Request Entity Too Large");
			break;
		}

		n = read(h->fd, cln->recv_buf + cln->recv_pos,
			 METRICS_RECV_BUF_SIZE - 1 - cln->recv_pos);
		if (n == 0) {
			cln->disconnect = 1;
			break;
		}
		if (n < 0) {
			if (errno == EAGAIN)
				return 0;
			cln->disconnect = 1;
			break;
		}

		cln->recv_pos += n;
		cln->recv_buf[cln->recv_pos] = 0;

		if (strstr(cln->recv_buf, "\r\n\r\n")) {
			handle_request(cln);
			break;
		}
	}

	if (cln->disconnect) {
		disconnect_client(cln);
		return -1;
	}
	if (cln->xmit_buf)
		triton_md_disable_handler(&cln->hnd, MD_MODE_READ);
	return 0;
}

static int cln_write(struct triton_md_handler_t *h)
{
	struct metrics_client_t *cln = container_of(h, typeof(*cln), hnd);
	int rc;

	rc = xmit_flush(cln);
	if (rc == 1)
		return 0;	/* still partial — keep MD_MODE_WRITE enabled */
	if (rc < 0) {
		disconnect_client(cln);
		return -1;
	}
	triton_md_disable_handler(&cln->hnd, MD_MODE_WRITE);
	disconnect_client(cln);
	return -1;
}

static void accept_resume(struct triton_timer_t *t)
{
	triton_timer_del(t);
	accept_paused = 0;
	triton_md_enable_handler(&serv_hnd, MD_MODE_READ);
}

static void accept_pause(void)
{
	if (accept_paused)
		return;
	accept_paused = 1;
	triton_md_disable_handler(&serv_hnd, MD_MODE_READ);
	accept_resume_timer.expire = accept_resume;
	accept_resume_timer.expire_tv.tv_sec = METRICS_ACCEPT_BACKOFF;
	triton_timer_add(&serv_ctx, &accept_resume_timer, 0);
}

static int serv_read(struct triton_md_handler_t *h)
{
	struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int sock;
	struct metrics_client_t *cln;
	int batch;

	/* Cap the number of accepts handled per dispatch. Without this, an
	 * overflow burst (peers exceeding max_clients or denied by
	 * allowed_ips) keeps us in this loop accept()ing and immediately
	 * closing sockets, never yielding back to the triton dispatcher.
	 * Since the per-client read-timeout timers share serv_ctx, that
	 * would delay client_timeout() and let stalled clients live past
	 * read_timeout. Return after METRICS_ACCEPT_BATCH iterations; if
	 * the listening fd is still readable triton will dispatch us again
	 * on the next loop after timers have had a chance to fire.
	 */
	for (batch = 0; batch < METRICS_ACCEPT_BATCH; batch++) {
		sock = accept(h->fd, (struct sockaddr *)&addr, &size);
		if (sock < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			/* For persistent resource-exhaustion errors
			 * (EMFILE, ENFILE, ENOBUFS, ENOMEM) the kernel will
			 * keep the listening fd readable, so a bare
			 * `continue` spins the worker. Disable the listener
			 * briefly and retry via a one-shot timer.
			 */
			log_error("metrics: accept failed: %s; backing off %ds\n",
				  strerror(errno), METRICS_ACCEPT_BACKOFF);
			accept_pause();
			return 0;
		}

		if (!ip_allowed(addr.sin_addr.s_addr)) {
			close(sock);
			continue;
		}

		if (conf_max_clients && client_count >= (unsigned int)conf_max_clients) {
			close(sock);
			continue;
		}

		if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
			log_error("metrics: failed to set nonblocking mode: %s\n", strerror(errno));
			close(sock);
			continue;
		}

		cln = _malloc(sizeof(*cln));
		if (!cln) {
			close(sock);
			continue;
		}
		memset(cln, 0, sizeof(*cln));
		cln->addr = addr;
		cln->hnd.fd = sock;
		cln->hnd.read = cln_read;
		cln->hnd.write = cln_write;
		cln->recv_buf = _malloc(METRICS_RECV_BUF_SIZE);
		if (!cln->recv_buf) {
			close(sock);
			_free(cln);
			continue;
		}

		list_add_tail(&cln->entry, &clients);
		client_count++;
		triton_md_register_handler(&serv_ctx, &cln->hnd);
		triton_md_enable_handler(&cln->hnd, MD_MODE_READ);

		if (conf_read_timeout > 0) {
			cln->timer.expire = client_timeout;
			cln->timer.expire_tv.tv_sec = conf_read_timeout;
			triton_timer_add(&serv_ctx, &cln->timer, 0);
		}
	}

	return 0;
}

static void serv_close(struct triton_context_t *ctx)
{
	struct metrics_client_t *cln;

	if (accept_resume_timer.tpd)
		triton_timer_del(&accept_resume_timer);

	while (!list_empty(&clients)) {
		cln = list_entry(clients.next, typeof(*cln), entry);
		disconnect_client(cln);
	}

	triton_md_unregister_handler(&serv_hnd, 1);
	triton_context_unregister(ctx);
}

static struct triton_context_t serv_ctx = {
	.close = serv_close,
};

static struct triton_md_handler_t serv_hnd = {
	.read = serv_read,
};

static int start_server(void)
{
	struct sockaddr_in addr;
	int reuse = 1;

	if (parse_listen_address(conf_address, &addr) < 0) {
		log_emerg("metrics: invalid listen address '%s'\n", conf_address);
		return -1;
	}

	serv_hnd.fd = socket(PF_INET, SOCK_STREAM, 0);
	if (serv_hnd.fd < 0) {
		log_emerg("metrics: failed to create socket: %s\n", strerror(errno));
		return -1;
	}

	fcntl(serv_hnd.fd, F_SETFD, fcntl(serv_hnd.fd, F_GETFD) | FD_CLOEXEC);
	setsockopt(serv_hnd.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	if (bind(serv_hnd.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log_emerg("metrics: failed to bind %s: %s\n", conf_address, strerror(errno));
		goto err;
	}

	if (listen(serv_hnd.fd, 16) < 0) {
		log_emerg("metrics: failed to listen on %s: %s\n", conf_address, strerror(errno));
		goto err;
	}

	if (fcntl(serv_hnd.fd, F_SETFL, O_NONBLOCK)) {
		log_emerg("metrics: failed to set nonblocking mode: %s\n", strerror(errno));
		goto err;
	}

	triton_context_register(&serv_ctx, NULL);
	triton_context_set_priority(&serv_ctx, 0);
	triton_md_register_handler(&serv_ctx, &serv_hnd);
	triton_md_enable_handler(&serv_hnd, MD_MODE_READ);
	triton_context_wakeup(&serv_ctx);

	serv_running = 1;
	return 0;

err:
	close(serv_hnd.fd);
	serv_hnd.fd = -1;
	return -1;
}

static void init(void)
{
	/* TODO: Add optional HTTP authentication before exposing session_details;
	 * allowed_ips limits network reachability but does not identify callers.
	 */
	if (load_config() < 0)
		return;

	if (start_server() < 0)
		return;

	log_info2("metrics: listening on %s, format %s\n",
		  conf_address,
		  conf_format == METRICS_FORMAT_PROMETHEUS ? "prometheus" : "json");
}

DEFINE_INIT(100, init);
