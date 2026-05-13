#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "triton.h"
#include "events.h"
#include "log.h"
#include "list.h"

#include "memdebug.h"

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

static enum metrics_format conf_format = METRICS_FORMAT_PROMETHEUS;
static char *conf_address;

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

static int load_config(void)
{
	const char *opt;
	enum metrics_format fmt = METRICS_FORMAT_PROMETHEUS;
	char *address = NULL;
	struct sockaddr_in dummy;

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

	conf_format = fmt;
	if (conf_address)
		_free(conf_address);
	conf_address = address;

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
	const char *body = "";
	send_response(cln, 200, "OK", content_type(), body, 0);
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
