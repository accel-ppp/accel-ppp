#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "triton.h"
#include "events.h"
#include "log.h"
#include "list.h"
#include "memdebug.h"

#include "cli_p.h"

#define RECV_BUF_SIZE 1024

struct tcp_client_t {
	struct cli_client_t cli_client;
	struct list_head entry;
	struct triton_md_handler_t hnd;
	struct sockaddr_in addr;
	struct list_head xmit_queue;
	struct buffer_t *xmit_buf;
	uint8_t *cmdline;
	int xmit_pos;
	int recv_pos;
	unsigned int auth:1;
	unsigned int disconnect:1;
};

struct buffer_t {
	struct list_head entry;
	int size;
	uint8_t buf[0];
};

static int conf_verbose;

static struct triton_context_t serv_ctx;
static struct triton_md_handler_t serv_hnd;
static LIST_HEAD(clients);

static uint8_t *temp_buf;

static void disconnect(struct tcp_client_t *cln)
{
	struct buffer_t *b;

	log_debug("cli: disconnect\n");

	list_del(&cln->entry);

	triton_md_unregister_handler(&cln->hnd, 1);

	if (cln->xmit_buf)
		_free(cln->xmit_buf);

	while (!list_empty(&cln->xmit_queue)) {
		b = list_entry(cln->xmit_queue.next, typeof(*b), entry);
		list_del(&b->entry);
		_free(b);
	}

	_free(cln->cmdline);
	_free(cln);
}

static void cli_client_disconnect(struct cli_client_t *tcln)
{
	struct tcp_client_t *cln = container_of(tcln, typeof(*cln), cli_client);
	cln->disconnect = 1;
}

static void queue_buffer(struct tcp_client_t *cln, struct buffer_t *b)
{
	if (cln->xmit_buf)
		list_add_tail(&b->entry, &cln->xmit_queue);
	else
		cln->xmit_buf = b;
}

static int cli_client_send(struct cli_client_t *tcln, const void *_buf, int size)
{
	struct tcp_client_t *cln = container_of(tcln, typeof(*cln), cli_client);
	int n, k;
	struct buffer_t *b;
	const uint8_t *buf = (const uint8_t *)_buf;

	if (cln->disconnect)
		return -1;

	if (cln->xmit_buf) {
		b = _malloc(sizeof(*b) + size);
		b->size = size;
		memcpy(b->buf, buf, size);
		queue_buffer(cln, b);
		return 0;
	}

	for (n = 0; n < size; n += k) {
		k = write(cln->hnd.fd, buf + n, size - n);
		if (k < 0) {
			if (errno == EAGAIN) {
				b = _malloc(sizeof(*b) + size - n);
				b->size = size - n;
				memcpy(b->buf, buf + n, size - n);
				queue_buffer(cln, b);

				triton_md_enable_handler(&cln->hnd, MD_MODE_WRITE);
				break;
			}
			if (errno != EPIPE)
				log_error("cli: write: %s\n", strerror(errno));
			//disconnect(cln);
			cln->disconnect = 1;
			return -1;
		}
	}
	return 0;
}

static int cli_client_sendv(struct cli_client_t *tcln, const char *fmt, va_list ap)
{
	struct tcp_client_t *cln = container_of(tcln, typeof(*cln), cli_client);
	int r = vsnprintf((char *)temp_buf, RECV_BUF_SIZE, fmt, ap);

	if (r >= RECV_BUF_SIZE) {
		strcpy((char *)temp_buf + RECV_BUF_SIZE - 5, "...\n");
		r = RECV_BUF_SIZE;
	}

	return cli_client_send(tcln, temp_buf, r);
}

static int cln_read(struct triton_md_handler_t *h)
{
	struct tcp_client_t *cln = container_of(h, typeof(*cln), hnd);
	int n;
	char *d;

	while (1) {
		n = read(h->fd, cln->cmdline + cln->recv_pos, RECV_BUF_SIZE - 1 - cln->recv_pos);
		if (n == 0)
			goto disconn_soft;
		if (n < 0) {
			if (errno != EAGAIN)
				log_error("cli: read: %s\n", strerror(errno));
			return 0;
		}

		cln->recv_pos += n;
		cln->cmdline[cln->recv_pos] = '\0';

		while (cln->recv_pos) {
			d = strchr((char *)cln->cmdline, '\n');
			if (!d) {
				if (cln->recv_pos == RECV_BUF_SIZE - 1) {
					log_warn("cli: tcp: recv buffer overflow\n");
					goto disconn_hard;
				}
				break;
			}

			*d = 0;

			if (!cln->auth) {
				if (strcmp((char *)cln->cmdline, conf_cli_passwd))
					goto disconn_hard;
				cln->auth = 1;
			} else {
				if (conf_verbose == 2)
					log_info2("cli: %s: %s\n", inet_ntoa(cln->addr.sin_addr), cln->cmdline);

				cli_process_cmd(&cln->cli_client);
			}

			if (cln->disconnect)
				goto disconn_soft;

			cln->recv_pos -= (uint8_t *)d + 1 - cln->cmdline;
			memmove(cln->cmdline, d + 1, cln->recv_pos);
		}
	}

disconn_soft:
	/* Wait for pending data to be transmitted before disconnecting */
	if (cln->xmit_buf) {
		triton_md_disable_handler(&cln->hnd, MD_MODE_READ);
		cln->disconnect = 1;

		return 0;
	}

disconn_hard:
	disconnect(cln);

	return -1;
}

static int cln_write(struct triton_md_handler_t *h)
{
	struct tcp_client_t *cln = container_of(h, typeof(*cln), hnd);
	int k;

	while (cln->xmit_buf) {
		for (; cln->xmit_pos < cln->xmit_buf->size; cln->xmit_pos += k) {
			k = write(cln->hnd.fd, cln->xmit_buf->buf + cln->xmit_pos, cln->xmit_buf->size - cln->xmit_pos);
			if (k < 0) {
				if (errno == EAGAIN)
					return 0;
				if (errno != EPIPE)
					log_error("cli: tcp: write: %s\n", strerror(errno));
				goto disconn;
			}
		}

		_free(cln->xmit_buf);
		cln->xmit_pos = 0;

		if (list_empty(&cln->xmit_queue)) {
			cln->xmit_buf = NULL;
		} else {
			cln->xmit_buf = list_first_entry(&cln->xmit_queue,
							 typeof(*cln->xmit_buf),
							 entry);
			list_del(&cln->xmit_buf->entry);
		}
	}

	if (cln->disconnect)
		goto disconn;

	triton_md_disable_handler(&cln->hnd, MD_MODE_WRITE);

	return 0;

disconn:
	disconnect(cln);

	return -1;
}

static int serv_read(struct triton_md_handler_t *h)
{
  struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int sock;
	struct tcp_client_t *conn;

	while(1) {
		sock = accept(h->fd, (struct sockaddr *)&addr, &size);
		if (sock < 0) {
			if (errno == EAGAIN)
				return 0;
			log_error("cli: tcp: accept failed: %s\n", strerror(errno));
			continue;
		}

		if (conf_verbose)
			log_info2("cli: tcp: new connection from %s\n", inet_ntoa(addr.sin_addr));

		if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
			log_error("cli: tcp: failed to set nonblocking mode: %s, closing connection...\n", strerror(errno));
			close(sock);
			continue;
		}

		conn = _malloc(sizeof(*conn));
		memset(conn, 0, sizeof(*conn));
		conn->addr = addr;
		conn->hnd.fd = sock;
		conn->hnd.read = cln_read;
		conn->hnd.write = cln_write;
		conn->cmdline = _malloc(RECV_BUF_SIZE);
		INIT_LIST_HEAD(&conn->xmit_queue);

		conn->cli_client.cmdline = conn->cmdline;
		conn->cli_client.send = cli_client_send;
		conn->cli_client.sendv = cli_client_sendv;
		conn->cli_client.disconnect = cli_client_disconnect;

		triton_md_register_handler(&serv_ctx, &conn->hnd);
		triton_md_enable_handler(&conn->hnd,MD_MODE_READ);

		list_add_tail(&conn->entry, &clients);

		if (!conf_cli_passwd)
			conn->auth = 1;
	}
	return 0;
}

static void serv_close(struct triton_context_t *ctx)
{
	struct tcp_client_t *cln = NULL;

	while (!list_empty(&clients)) {
		cln = list_entry(clients.next, typeof(*cln), entry);
		disconnect(cln);
	}

	triton_md_unregister_handler(&serv_hnd, 1);
	triton_context_unregister(ctx);
}

static struct triton_context_t serv_ctx = {
	.close = serv_close,
	.before_switch = log_switch,
};

static struct triton_md_handler_t serv_hnd = {
	.read = serv_read,
};

static void start_server(const char *host, int port)
{
  struct sockaddr_in addr;

	serv_hnd.fd = socket(PF_INET, SOCK_STREAM, 0);
  if (serv_hnd.fd < 0) {
    log_emerg("cli: tcp: failed to create server socket: %s\n", strerror(errno));
    return;
  }

	fcntl(serv_hnd.fd, F_SETFD, fcntl(serv_hnd.fd, F_GETFD) | FD_CLOEXEC);

	memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
	if (host)
		addr.sin_addr.s_addr = inet_addr(host);
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

  setsockopt(serv_hnd.fd, SOL_SOCKET, SO_REUSEADDR, &serv_hnd.fd, 4);
  if (bind (serv_hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    log_emerg("cli: tcp: failed to bind socket: %s\n", strerror(errno));
		close(serv_hnd.fd);
    return;
	}

  if (listen (serv_hnd.fd, 1) < 0) {
    log_emerg("cli: tcp: failed to listen socket: %s\n", strerror(errno));
		close(serv_hnd.fd);
    return;
  }

	if (fcntl(serv_hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_emerg("cli: tcp: failed to set nonblocking mode: %s\n", strerror(errno));
		close(serv_hnd.fd);
    return;
	}

	triton_context_register(&serv_ctx, NULL);
	triton_context_set_priority(&serv_ctx, 0);
	triton_md_register_handler(&serv_ctx, &serv_hnd);
	triton_md_enable_handler(&serv_hnd, MD_MODE_READ);
	triton_context_wakeup(&serv_ctx);
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("cli", "verbose");
	if (opt)
		conf_verbose = atoi(opt);
	else
		conf_verbose = 1;
}

static void reload_config(void)
{
        config_lock();
        load_config();
        config_unlock();
}

static void init(void)
{
	const char *opt;
	char *host, *d;
	int port;

	opt = conf_get_opt("cli", "tcp");
	if (!opt)
		return;

	host = strdup(opt);
	d = strstr(host, ":");
	if (!d)
		goto err_fmt;

	*d = 0;
	port = atoi(d + 1);
	if (port <= 0)
		goto err_fmt;

	load_config();

	temp_buf = malloc(RECV_BUF_SIZE);

	start_server(host, port);

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_config);

	free(host);
	return;
err_fmt:
	log_emerg("cli: tcp: invalid format\n");
	free(host);
}

DEFINE_INIT(11, init);
