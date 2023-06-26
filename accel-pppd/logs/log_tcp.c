#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "log.h"
#include "triton.h"
#include "events.h"
#include "ppp.h"
#include "spinlock.h"
#include "mempool.h"

#include "memdebug.h"

struct tcp_target_t
{
	struct log_target_t target;
	struct list_head entry;
	struct triton_md_handler_t hnd;
	struct triton_timer_t conn_timer;
  struct sockaddr_in addr;
	char *buf;
	int buf_size;
	int buf_pos;
	spinlock_t lock;
	struct list_head queue;
	int queue_len;
	unsigned int connected:1;
	unsigned int wait:1;
};

static int conf_connect_interval = 5;
static int conf_queue_len = 1000;

static struct triton_context_t tcp_ctx;

static const char* level_name[]={"  msg", "error", " warn", " info", " info", "debug"};

static void start_connect(struct tcp_target_t *t);

static LIST_HEAD(targets);

static void disconnect(struct tcp_target_t *t)
{
	triton_md_unregister_handler(&t->hnd, 1);

	start_connect(t);
}

static void unpack_msg(struct tcp_target_t *t, struct log_msg_t *msg)
{
	struct log_chunk_t *chunk;
	int pos = strlen(msg->hdr->msg);

	strcpy(t->buf, msg->hdr->msg);

	list_for_each_entry(chunk, msg->chunks, entry) {
		memcpy(t->buf + pos, chunk->msg, chunk->len);
		pos += chunk->len;
	}

	t->buf_size = pos;
	t->buf_pos = 0;
}

static int send_log(struct tcp_target_t *t)
{
	struct log_msg_t *msg;
	int n;

	while (1) {
		spin_lock(&t->lock);
		if (!t->queue_len) {
			t->wait = 0;
			spin_unlock(&t->lock);
			return 0;
		}
		msg = list_entry(t->queue.next, typeof(*msg), entry);
		list_del(&msg->entry);
		t->queue_len--;
		spin_unlock(&t->lock);

		unpack_msg(t, msg);

		log_free_msg(msg);

		while (t->buf_pos != t->buf_size) {
			n = write(t->hnd.fd, t->buf + t->buf_pos, t->buf_size - t->buf_pos);
			if (n < 0) {
				if (errno == EAGAIN)
					return 1;
				if (errno != EPIPE)
					log_emerg("log-tcp: write: %s\n", strerror(errno));
				disconnect(t);
				return 0;
			}
			t->buf_pos += n;
		}
	}
}

static void queue_log(struct tcp_target_t *t, struct log_msg_t *msg)
{
	int r;

	spin_lock(&t->lock);
	if (t->queue_len == conf_queue_len) {
		spin_unlock(&t->lock);
		log_free_msg(msg);
		return;
	}
	list_add_tail(&msg->entry, &t->queue);
	t->queue_len++;
	if (t->connected) {
		r = t->wait;
		t->wait = 1;
	} else
		r = 1;
	spin_unlock(&t->lock);

	if (!r) {
		if (send_log(t))
			triton_md_enable_handler(&t->hnd, MD_MODE_WRITE);
	}
}

static void set_hdr(struct log_msg_t *msg, struct ap_session *ses)
{
	struct tm tm;
	char timestamp[32];

	localtime_r(&msg->timestamp.tv_sec, &tm);

	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);
	sprintf(msg->hdr->msg, "[%s]: %s: %s: ", timestamp, level_name[msg->level],	ses ? (ses->ifname[0] ? ses->ifname : ses->ctrl->ifname) : "");
	msg->hdr->len = strlen(msg->hdr->msg);
}

static void general_log(struct log_target_t *lt, struct log_msg_t *msg, struct ap_session *ses)
{
	struct tcp_target_t *t = container_of(lt, typeof(*t), target);

	set_hdr(msg, ses);
	queue_log(t, msg);
}

static int log_tcp_write(struct triton_md_handler_t *h)
{
	struct tcp_target_t *t = container_of(h, typeof(*t), hnd);

	if (!send_log(t))
		triton_md_disable_handler(h, MD_MODE_WRITE);

	return 0;
}

static int log_tcp_connect(struct triton_md_handler_t *h)
{
	struct tcp_target_t *t = container_of(h, typeof(*t), hnd);

	if (connect(t->hnd.fd, &t->addr, sizeof(t->addr)) < 0) {
		if (errno == EAGAIN)
			return 0;
		if (errno == EINPROGRESS)
			return 0;
		log_emerg("log-tcp: connect: %s\n", strerror(errno));
		triton_md_unregister_handler(&t->hnd, 1);
		triton_timer_add(&tcp_ctx, &t->conn_timer, 0);
		return 0;
	}

	t->hnd.write = log_tcp_write;

	triton_md_disable_handler(&t->hnd, MD_MODE_WRITE);

	spin_lock(&t->lock);
	t->connected = 1;
	t->wait = 1;
	spin_unlock(&t->lock);

	if (send_log(t))
		triton_md_enable_handler(&t->hnd, MD_MODE_WRITE);

	return 0;
}

static void connect_timer(struct triton_timer_t *timer)
{
	struct tcp_target_t *t = container_of(timer, typeof(*t), conn_timer);

	triton_timer_del(timer);

	start_connect(t);
}

static void start_connect(struct tcp_target_t *t)
{
	t->hnd.write = log_tcp_connect;
	t->hnd.fd = socket(PF_INET, SOCK_STREAM, 0);

	if (!t->hnd.fd) {
		log_emerg("log-tcp: socket: %s\n", strerror(errno));
		return;
	}

	fcntl(t->hnd.fd, F_SETFD, fcntl(t->hnd.fd, F_GETFD) | FD_CLOEXEC);

	if (fcntl(t->hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_emerg("log-tcp: failed to set nonblocking mode: %s\n", strerror(errno));
		close(t->hnd.fd);
    return;
	}

	if (connect(t->hnd.fd, &t->addr, sizeof(t->addr)) < 0) {
		if (errno != EINPROGRESS) {
			log_emerg("log-tcp: connect: %s\n", strerror(errno));
			close(t->hnd.fd);
			return;
		}
	}

	triton_md_register_handler(&tcp_ctx, &t->hnd);
	triton_md_enable_handler(&t->hnd, MD_MODE_WRITE);
}

static void log_tcp_close(struct triton_context_t *ctx)
{
	struct tcp_target_t *t;

	while (!list_empty(&targets)) {
		t = list_entry(targets.next, typeof(*t), entry);
		list_del(&t->entry);
		if (t->conn_timer.tpd)
			triton_timer_del(&t->conn_timer);
		else {
			t->connected = 0;
			triton_md_unregister_handler(&t->hnd, 1);
		}
	}

	triton_context_unregister(&tcp_ctx);
}

static int start_log(const char *_opt)
{
	struct tcp_target_t *t;
	char *opt = strdup(_opt);
	int port;
	char *d;

	d = strchr(opt, ':');
	if (!d)
		goto err;

	*d = 0;

	port = atoi(d + 1);
	if (port <= 0)
		goto err;

	t = _malloc(sizeof(*t));
	memset(t, 0, sizeof(*t));

	t->buf = _malloc(LOG_MAX_SIZE + 64);

	t->conn_timer.expire_tv.tv_sec = conf_connect_interval;
	t->conn_timer.expire = connect_timer;

	t->target.log = general_log;

	memset(&t->addr, 0, sizeof(t->addr));
  t->addr.sin_family = AF_INET;
  t->addr.sin_port = htons(port);
	t->addr.sin_addr.s_addr = inet_addr(opt);

	INIT_LIST_HEAD(&t->queue);

	spinlock_init(&t->lock);

	start_connect(t);

	log_register_target(&t->target);

	list_add_tail(&t->entry, &targets);

	return 0;

err:
	free(opt);
	return -1;
}

static struct triton_context_t tcp_ctx ={
	.close = log_tcp_close,
	.before_switch = log_switch,
};

static void init(void)
{
	struct conf_sect_t *s =	conf_get_section("log");
	struct conf_option_t *opt;

	if (!s)
		return;

	triton_context_register(&tcp_ctx, NULL);

	list_for_each_entry(opt, &s->items, entry) {
		if (strcmp(opt->name, "log-tcp"))
			continue;
		if (!opt->val || start_log(opt->val))
			log_emerg("log: log-tcp: invalid format: '%s'\n", opt->val);
	}

	triton_context_wakeup(&tcp_ctx);
}

DEFINE_INIT(1, init);
