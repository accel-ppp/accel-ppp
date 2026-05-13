#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "triton.h"
#include "events.h"
#include "log.h"
#include "list.h"
#include "utils.h"
#include "ap_session.h"
#include "version.h"

#include "memdebug.h"

/* Per-protocol session counters live in their respective shared modules.
 * They are referenced via RTLD_LAZY + RTLD_GLOBAL, so the symbols only need
 * to be resolvable at call time. Each use site below first checks
 * triton_module_loaded("<name>") so we never invoke them when the protocol
 * module isn't loaded.
 */
unsigned int pppoe_stat_starting(void);
unsigned int pppoe_stat_active(void);
unsigned int l2tp_stat_starting(void);
unsigned int l2tp_stat_active(void);
unsigned int pptp_stat_starting(void);
unsigned int pptp_stat_active(void);
unsigned int sstp_stat_starting(void);
unsigned int sstp_stat_active(void);
unsigned int ipoe_stat_starting(void);
unsigned int ipoe_stat_active(void);

enum metrics_format {
	METRICS_FORMAT_PROMETHEUS,
	METRICS_FORMAT_JSON,
};

#define METRICS_RECV_BUF_SIZE 2048

struct metrics_client_t {
	struct list_head entry;
	struct triton_md_handler_t hnd;
	struct sockaddr_in addr;
	char *recv_buf;
	int recv_pos;
	unsigned int disconnect:1;
};

struct metrics_acl_t {
	struct list_head entry;
	uint32_t net;	/* host byte order */
	uint32_t mask;	/* host byte order */
};

static enum metrics_format conf_format = METRICS_FORMAT_PROMETHEUS;
static char *conf_address;
static LIST_HEAD(conf_allowed);

static struct triton_context_t serv_ctx;
static struct triton_md_handler_t serv_hnd;
static LIST_HEAD(clients);
static int serv_running;

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
	if (triton_module_loaded("pppoe")) {
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"pppoe\",state=\"starting\"} %u\n",
			       pppoe_stat_starting());
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"pppoe\",state=\"active\"} %u\n",
			       pppoe_stat_active());
	}
	if (triton_module_loaded("l2tp")) {
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"l2tp\",state=\"starting\"} %u\n",
			       l2tp_stat_starting());
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"l2tp\",state=\"active\"} %u\n",
			       l2tp_stat_active());
	}
	if (triton_module_loaded("pptp")) {
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"pptp\",state=\"starting\"} %u\n",
			       pptp_stat_starting());
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"pptp\",state=\"active\"} %u\n",
			       pptp_stat_active());
	}
	if (triton_module_loaded("sstp")) {
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"sstp\",state=\"starting\"} %u\n",
			       sstp_stat_starting());
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"sstp\",state=\"active\"} %u\n",
			       sstp_stat_active());
	}
	if (triton_module_loaded("ipoe")) {
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"ipoe\",state=\"starting\"} %u\n",
			       ipoe_stat_starting());
		strbuf_appendf(sb, "accel_ppp_protocol_sessions{protocol=\"ipoe\",state=\"active\"} %u\n",
			       ipoe_stat_active());
	}
}

static void append_json_string(struct strbuf *sb, const char *s)
{
	strbuf_appendf(sb, "\"");
	for (; *s; s++) {
		switch (*s) {
		case '"':
			strbuf_appendf(sb, "\\\"");
			break;
		case '\\':
			strbuf_appendf(sb, "\\\\");
			break;
		case '\b':
			strbuf_appendf(sb, "\\b");
			break;
		case '\f':
			strbuf_appendf(sb, "\\f");
			break;
		case '\n':
			strbuf_appendf(sb, "\\n");
			break;
		case '\r':
			strbuf_appendf(sb, "\\r");
			break;
		case '\t':
			strbuf_appendf(sb, "\\t");
			break;
		default:
			if ((unsigned char)*s < 0x20)
				strbuf_appendf(sb, "\\u%04x", (unsigned)*s);
			else
				strbuf_appendf(sb, "%c", *s);
			break;
		}
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
	if (triton_module_loaded("pppoe"))
		emit_json_proto(sb, "pppoe", &first, pppoe_stat_starting(), pppoe_stat_active());
	if (triton_module_loaded("l2tp"))
		emit_json_proto(sb, "l2tp", &first, l2tp_stat_starting(), l2tp_stat_active());
	if (triton_module_loaded("pptp"))
		emit_json_proto(sb, "pptp", &first, pptp_stat_starting(), pptp_stat_active());
	if (triton_module_loaded("sstp"))
		emit_json_proto(sb, "sstp", &first, sstp_stat_starting(), sstp_stat_active());
	if (triton_module_loaded("ipoe"))
		emit_json_proto(sb, "ipoe", &first, ipoe_stat_starting(), ipoe_stat_active());
	strbuf_appendf(sb, "}");

	strbuf_appendf(sb, "}\n");
}

static int write_all(int fd, const char *buf, int len)
{
	int n, total = 0;

	while (total < len) {
		n = write(fd, buf + total, len - total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		total += n;
	}
	return 0;
}

static void send_response(struct metrics_client_t *cln, int status, const char *reason,
			  const char *ctype, const char *body, int body_len)
{
	char header[256];
	int hlen;

	hlen = snprintf(header, sizeof(header),
			"HTTP/1.1 %d %s\r\n"
			"Server: accel-ppp\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %d\r\n"
			"Connection: close\r\n"
			"\r\n",
			status, reason, ctype, body_len);
	if (hlen <= 0 || hlen >= (int)sizeof(header))
		return;

	if (write_all(cln->hnd.fd, header, hlen) < 0)
		return;
	if (body_len > 0)
		write_all(cln->hnd.fd, body, body_len);
}

static void send_simple(struct metrics_client_t *cln, int status, const char *reason)
{
	char body[128];
	int len;

	len = snprintf(body, sizeof(body), "%d %s\n", status, reason);
	send_response(cln, status, reason, "text/plain; charset=utf-8", body, len);
}

static void serve_metrics(struct metrics_client_t *cln)
{
	struct strbuf sb = {0};

	switch (conf_format) {
	case METRICS_FORMAT_PROMETHEUS:
		render_prometheus(&sb);
		break;
	case METRICS_FORMAT_JSON:
		render_json(&sb);
		break;
	}

	if (sb.oom || !sb.data) {
		send_simple(cln, 500, "Internal Server Error");
		goto out;
	}

	send_response(cln, 200, "OK", content_type(), sb.data, (int)sb.len);
out:
	strbuf_free(&sb);
}

static void disconnect_client(struct metrics_client_t *cln)
{
	list_del(&cln->entry);
	triton_md_unregister_handler(&cln->hnd, 1);
	if (cln->recv_buf)
		_free(cln->recv_buf);
	_free(cln);
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
			cln->disconnect = 1;
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
			cln->disconnect = 1;
			break;
		}
	}

	if (cln->disconnect) {
		disconnect_client(cln);
		return -1;
	}
	return 0;
}

static int serv_read(struct triton_md_handler_t *h)
{
	struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int sock;
	struct metrics_client_t *cln;

	while (1) {
		sock = accept(h->fd, (struct sockaddr *)&addr, &size);
		if (sock < 0) {
			if (errno == EAGAIN)
				return 0;
			log_error("metrics: accept failed: %s\n", strerror(errno));
			continue;
		}

		if (!ip_allowed(addr.sin_addr.s_addr)) {
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
		cln->recv_buf = _malloc(METRICS_RECV_BUF_SIZE);
		if (!cln->recv_buf) {
			close(sock);
			_free(cln);
			continue;
		}

		list_add_tail(&cln->entry, &clients);
		triton_md_register_handler(&serv_ctx, &cln->hnd);
		triton_md_enable_handler(&cln->hnd, MD_MODE_READ);
	}

	return 0;
}

static void serv_close(struct triton_context_t *ctx)
{
	struct metrics_client_t *cln;

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
	if (load_config() < 0)
		return;

	if (start_server() < 0)
		return;

	log_info2("metrics: listening on %s, format %s\n",
		  conf_address,
		  conf_format == METRICS_FORMAT_PROMETHEUS ? "prometheus" : "json");
}

DEFINE_INIT(100, init);
