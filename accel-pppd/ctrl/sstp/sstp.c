#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <termios.h>
#include <pty.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "linux_ppp.h"

/*
 * Suppress OpenSSL 3.0 deprecation warnings for DH API.
 * See crypto.h for detailed explanation.
 */
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "triton.h"
#include "events.h"
#include "list.h"
#include "log.h"
#include "ppp.h"
#include "utils.h"
#include "mempool.h"
#include "iprange.h"
#include "connlimit.h"
#include "cli.h"

#include "memdebug.h"

#include "proxy_prot.h"
#include "sstp_prot.h"

#ifndef min
#define min(x,y) ((x) < (y) ? (x) : (y))
#endif
#ifndef max
#define max(x,y) ((x) > (y) ? (x) : (y))
#endif

#define PPP_SYNC	0 /* buggy yet */
#define PPP_BUF_SIZE	8192
#define PPP_BUF_IOVEC	256
#define PPP_F_ESCAPE	1
#define PPP_F_TOSS	2

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#define ADDRSTR_MAXLEN (sizeof("unix:") + sizeof(((struct sockaddr_un *)0)->sun_path))
#define FLAG_NOPORT 1

enum {
	STATE_INIT = 0,
	STATE_STARTING,
	STATE_AUTHORIZED,
	STATE_STARTED,
	STATE_FINISHED,
};

struct sockaddr_t {
	socklen_t len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_un sun;
	} u;
};

struct hash_t {
	unsigned int len;
	union {
		uint8_t hash[0];
		uint8_t sha1[SHA_DIGEST_LENGTH];
		uint8_t sha256[SHA256_DIGEST_LENGTH];
	};
};

struct buffer_t {
	struct list_head entry;
	size_t len;
	unsigned char *head;
	unsigned char *tail;
	unsigned char *end;
	unsigned char data[0];
};

struct sstp_stream_t {
	union {
		int fd;
		SSL *ssl;
	};
	ssize_t (*read)(struct sstp_stream_t *stream, void *buf, size_t count);
	ssize_t (*recv)(struct sstp_stream_t *stream, void *buf, size_t count, int flags);
	ssize_t (*write)(struct sstp_stream_t *stream, const void *buf, size_t count);
	int (*close)(struct sstp_stream_t *stream);
	void (*free)(struct sstp_stream_t *stream);
};

struct sstp_conn_t {
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd, ppp_hnd;

	struct triton_timer_t timeout_timer;
	struct triton_timer_t hello_timer;

	struct sstp_stream_t *stream;
	int (*handler)(struct sstp_conn_t *conn, struct buffer_t *buf);

	int sstp_state;
	int nak_sent;
	int hello_sent;
	int hello_interval;

//	unsigned int bypass_auth:1;
//	char *http_cookie;
	uint8_t *nonce;
	uint8_t *hlak_key;

	struct buffer_t *in;
	struct list_head out_queue;
	struct list_head deferred_queue;

	int ppp_state;
	int ppp_flags;
	struct buffer_t *ppp_in;
	struct list_head ppp_queue;

	struct sockaddr_t addr;
	struct ppp_t ppp;
	struct ap_ctrl ctrl;
};

static struct sstp_serv_t {
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;

	struct sockaddr_t addr;

	SSL_CTX *ssl_ctx;
} serv;

static int conf_timeout = SSTP_NEGOTIOATION_TIMEOUT;
static int conf_hello_interval = SSTP_HELLO_TIMEOUT;
static int conf_verbose = 0;
static int conf_ppp_max_mtu = 1452;
static const char *conf_ip_pool;
static const char *conf_ipv6_pool;
static const char *conf_dpv6_pool;
static const char *conf_ifname;
static int conf_proxyproto = 0;
static int conf_sndbuf = 0;
static int conf_rcvbuf = 0;
static int conf_session_timeout;

static int conf_hash_protocol = CERT_HASH_PROTOCOL_SHA1 | CERT_HASH_PROTOCOL_SHA256;
static struct hash_t conf_hash_sha1 = { .len = 0 };
static struct hash_t conf_hash_sha256 = { .len = 0 };
//static int conf_bypass_auth = 0;
static const char *conf_hostname = NULL;
enum {
	HTTP_ERR_ALLOW = -1,
	HTTP_ERR_DENY = 0,
	HTTP_ERR_REDIRECT = 1,
	HTTP_ERR_REDIRECT_APPEND = 2,
};
static int conf_http_mode = HTTP_ERR_ALLOW;
static const char *conf_http_url = NULL;

static mempool_t conn_pool;

static unsigned int stat_starting;
static unsigned int stat_active;

static inline void sstp_queue(struct sstp_conn_t *conn, struct buffer_t *buf);
static int sstp_send(struct sstp_conn_t *conn, struct buffer_t *buf);
static inline void sstp_queue_deferred(struct sstp_conn_t *conn, struct buffer_t *buf);
static int sstp_write(struct triton_md_handler_t *h);
static int sstp_read_deferred(struct sstp_conn_t *conn);
static int sstp_abort(struct sstp_conn_t *conn, int disconnect);
static void sstp_disconnect(struct sstp_conn_t *conn);
static int sstp_handler(struct sstp_conn_t *conn, struct buffer_t *buf);
static int http_handler(struct sstp_conn_t *conn, struct buffer_t *buf);

/*
 * FCS lookup table as calculated by genfcstab.
 */
static const uint16_t fcstab[256] = {
	0x0000,	0x1189,	0x2312,	0x329b,	0x4624,	0x57ad,	0x6536,	0x74bf,
	0x8c48,	0x9dc1,	0xaf5a,	0xbed3,	0xca6c,	0xdbe5,	0xe97e,	0xf8f7,
	0x1081,	0x0108,	0x3393,	0x221a,	0x56a5,	0x472c,	0x75b7,	0x643e,
	0x9cc9,	0x8d40,	0xbfdb,	0xae52,	0xdaed,	0xcb64,	0xf9ff,	0xe876,
	0x2102,	0x308b,	0x0210,	0x1399,	0x6726,	0x76af,	0x4434,	0x55bd,
	0xad4a,	0xbcc3,	0x8e58,	0x9fd1,	0xeb6e,	0xfae7,	0xc87c,	0xd9f5,
	0x3183,	0x200a,	0x1291,	0x0318,	0x77a7,	0x662e,	0x54b5,	0x453c,
	0xbdcb,	0xac42,	0x9ed9,	0x8f50,	0xfbef,	0xea66,	0xd8fd,	0xc974,
	0x4204,	0x538d,	0x6116,	0x709f,	0x0420,	0x15a9,	0x2732,	0x36bb,
	0xce4c,	0xdfc5,	0xed5e,	0xfcd7,	0x8868,	0x99e1,	0xab7a,	0xbaf3,
	0x5285,	0x430c,	0x7197,	0x601e,	0x14a1,	0x0528,	0x37b3,	0x263a,
	0xdecd,	0xcf44,	0xfddf,	0xec56,	0x98e9,	0x8960,	0xbbfb,	0xaa72,
	0x6306,	0x728f,	0x4014,	0x519d,	0x2522,	0x34ab,	0x0630,	0x17b9,
	0xef4e,	0xfec7,	0xcc5c,	0xddd5,	0xa96a,	0xb8e3,	0x8a78,	0x9bf1,
	0x7387,	0x620e,	0x5095,	0x411c,	0x35a3,	0x242a,	0x16b1,	0x0738,
	0xffcf,	0xee46,	0xdcdd,	0xcd54,	0xb9eb,	0xa862,	0x9af9,	0x8b70,
	0x8408,	0x9581,	0xa71a,	0xb693,	0xc22c,	0xd3a5,	0xe13e,	0xf0b7,
	0x0840,	0x19c9,	0x2b52,	0x3adb,	0x4e64,	0x5fed,	0x6d76,	0x7cff,
	0x9489,	0x8500,	0xb79b,	0xa612,	0xd2ad,	0xc324,	0xf1bf,	0xe036,
	0x18c1,	0x0948,	0x3bd3,	0x2a5a,	0x5ee5,	0x4f6c,	0x7df7,	0x6c7e,
	0xa50a,	0xb483,	0x8618,	0x9791,	0xe32e,	0xf2a7,	0xc03c,	0xd1b5,
	0x2942,	0x38cb,	0x0a50,	0x1bd9,	0x6f66,	0x7eef,	0x4c74,	0x5dfd,
	0xb58b,	0xa402,	0x9699,	0x8710,	0xf3af,	0xe226,	0xd0bd,	0xc134,
	0x39c3,	0x284a,	0x1ad1,	0x0b58,	0x7fe7,	0x6e6e,	0x5cf5,	0x4d7c,
	0xc60c,	0xd785,	0xe51e,	0xf497,	0x8028,	0x91a1,	0xa33a,	0xb2b3,
	0x4a44,	0x5bcd,	0x6956,	0x78df,	0x0c60,	0x1de9,	0x2f72,	0x3efb,
	0xd68d,	0xc704,	0xf59f,	0xe416,	0x90a9,	0x8120,	0xb3bb,	0xa232,
	0x5ac5,	0x4b4c,	0x79d7,	0x685e,	0x1ce1,	0x0d68,	0x3ff3,	0x2e7a,
	0xe70e,	0xf687,	0xc41c,	0xd595,	0xa12a,	0xb0a3,	0x8238,	0x93b1,
	0x6b46,	0x7acf,	0x4854,	0x59dd,	0x2d62,	0x3ceb,	0x0e70,	0x1ff9,
	0xf78f,	0xe606,	0xd49d,	0xc514,	0xb1ab,	0xa022,	0x92b9,	0x8330,
	0x7bc7,	0x6a4e,	0x58d5,	0x495c,	0x3de3,	0x2c6a,	0x1ef1,	0x0f78
};

/* utils */

static int strhas(const char *s1, const char *s2, int delim)
{
	char *ptr;
	int n = strlen(s2);

	while ((ptr = strchr(s1, delim))) {
		if (ptr - s1 == n && !memcmp(s1, s2, n))
			return 1;
		s1 = ++ptr;
	}
	return !strcmp(s1, s2);
}

static int hex2bin(const char *src, uint8_t *dst, size_t size)
{
	char buf[3], *err;
	int n;

	memset(buf, 0, sizeof(buf));
	for (n = 0; n < size && src[0] && src[1]; n++) {
		buf[0] = *src++;
		buf[1] = *src++;
		dst[n] = strtoul(buf, &err, 16);
		if (err == buf || *err)
			break;
		if (*src == ':')
			src++;
	}
	return n;
}

#define vstrsep(buf, sep, args...) _vstrsep(buf, sep, args, NULL)
static int _vstrsep(char *buf, const char *sep, ...)
{
	va_list ap;
	char **arg, *val, *ptr;
	int n = 0;

	va_start(ap, sep);
	while ((arg = va_arg(ap, char **)) != NULL) {
		val = strtok_r(buf, sep, &ptr);
		if (!val)
			break;
		buf = NULL;
		*arg = val;
		n++;
	}
	va_end(ap);
	return n;
}

static in_addr_t sockaddr_ipv4(const struct sockaddr_t *addr)
{
	switch (addr->u.sa.sa_family) {
	case AF_INET:
		return addr->u.sin.sin_addr.s_addr;
	case AF_INET6:
		if (IN6_IS_ADDR_V4MAPPED(&addr->u.sin6.sin6_addr))
			return addr->u.sin6.sin6_addr.s6_addr32[3];
		/* fall through */
	default:
		return INADDR_ANY;
	}
}

static int sockaddr_ntop(const struct sockaddr_t *addr, char *dst, socklen_t size, int flags)
{
	char ipv6_buf[INET6_ADDRSTRLEN], sign;
	const char *path;

	switch (addr->u.sa.sa_family) {
	case AF_INET:
		return snprintf(dst, size, (flags & FLAG_NOPORT) ? "%s" : "%s:%d",
				inet_ntoa(addr->u.sin.sin_addr), ntohs(addr->u.sin.sin_port));
	case AF_INET6:
		if (IN6_IS_ADDR_V4MAPPED(&addr->u.sin6.sin6_addr)) {
			inet_ntop(AF_INET, &addr->u.sin6.sin6_addr.s6_addr32[3],
					ipv6_buf, sizeof(ipv6_buf));
			return snprintf(dst, size, (flags & FLAG_NOPORT) ? "%s" : "%s:%d",
					ipv6_buf, ntohs(addr->u.sin6.sin6_port));
		} else {
			inet_ntop(AF_INET6, &addr->u.sin6.sin6_addr,
					ipv6_buf, sizeof(ipv6_buf));
			return snprintf(dst, size, (flags & FLAG_NOPORT) ? "%s" : "[%s]:%d",
					ipv6_buf, ntohs(addr->u.sin6.sin6_port));
		}
	case AF_UNIX:
		if (addr->len <= offsetof(typeof(addr->u.sun), sun_path)) {
			path = "NULL";
			sign = path[0];
		} else {
			path = addr->u.sun.sun_path;
			sign = path[0] ? : '@';
		}
		return snprintf(dst, size, "unix:%c%s", sign, path + 1);
	}

	return -1;
}

/* buffer */

static inline void *buf_put(struct buffer_t *buf, int len)
{
	void *tmp = buf->tail;
	buf->tail += len;
	buf->len += len;
	return tmp;
}

static inline void *buf_put_data(struct buffer_t *buf, const void *data, int len)
{
	void *tmp = buf_put(buf, len);
	memcpy(tmp, data, len);
	return tmp;
}

static inline void *buf_put_zero(struct buffer_t *buf, int len)
{
	void *tmp = buf_put(buf, len);
	memset(tmp, 0, len);
	return tmp;
}

static inline void *buf_push(struct buffer_t *buf, int len)
{
	buf->head -= len;
	buf->len += len;
	return buf->head;
}

static inline void *buf_pull(struct buffer_t *buf, int len)
{
	buf->head += len;
	buf->len -= len;
	return buf->head;
}

static inline int buf_headroom(const struct buffer_t *buf)
{
	return buf->head - buf->data;
}

static inline int buf_tailroom(const struct buffer_t *buf)
{
	return buf->end - buf->tail;
}

static inline void buf_reserve(struct buffer_t *buf, int len)
{
	buf->head += len;
	buf->tail += len;
}

static inline void buf_set_length(struct buffer_t *buf, int len)
{
	buf->tail = buf->head + len;
	buf->len = len;
}

static inline int buf_expand_tail(struct buffer_t *buf, int tailroom)
{
	if (buf->len == 0)
		buf->head = buf->tail = buf->data;
	else if (buf_tailroom(buf) < tailroom) {
		buf->head = memmove(buf->data, buf->head, buf->len);
		buf->tail = buf->head + buf->len;
	}
	return (buf_tailroom(buf) >= tailroom);
}

static struct buffer_t *alloc_buf(size_t size)
{
	struct buffer_t *buf = _malloc(sizeof(*buf) + size);

	if (!buf)
		return NULL;

	buf->head = buf->data;
	buf->end = buf->data + size;
	buf_set_length(buf, 0);
	return buf;
}

static struct buffer_t *alloc_buf_printf(const char* format, ...)
{
	struct buffer_t *buf;
	va_list ap;
	int len;

	va_start(ap, format);
	len = vsnprintf(NULL, 0, format, ap);
	va_end(ap);
	if (len < 0)
		return NULL;

	buf = alloc_buf(len + 1);
	if (buf) {
		va_start(ap, format);
		vsnprintf(buf_put(buf, len), len + 1, format, ap);
		va_end(ap);
	}
	return buf;
}

static void free_buf(struct buffer_t *buf)
{
	_free(buf);
}

/* socket stream */

static ssize_t stream_read(struct sstp_stream_t *stream, void *buf, size_t count)
{
	return read(stream->fd, buf, count);
}

static ssize_t stream_recv(struct sstp_stream_t *stream, void *buf, size_t count, int flags)
{
	return recv(stream->fd, buf, count, flags);
}

static ssize_t stream_write(struct sstp_stream_t *stream, const void *buf, size_t count)
{
	return write(stream->fd, buf, count);
}

static int stream_close(struct sstp_stream_t *stream)
{
	return close(stream->fd);
}

static void stream_free(struct sstp_stream_t *stream)
{
	_free(stream);
}

static struct sstp_stream_t *stream_init(int fd)
{
	struct sstp_stream_t *stream = _malloc(sizeof(*stream));

	if (!stream)
		return NULL;

	stream->fd = fd;
	stream->read = stream_read;
	stream->recv = stream_recv;
	stream->write = stream_write;
	stream->close = stream_close;
	stream->free = stream_free;

	return stream;
}

/* ssl stream */

static ssize_t ssl_stream_read(struct sstp_stream_t *stream, void *buf, size_t count)
{
	int ret, err;

	ERR_clear_error();
	ret = SSL_read(stream->ssl, buf, count);
	if (ret > 0)
		return ret;

	err = SSL_get_error(stream->ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		/* fall through */
	case SSL_ERROR_SYSCALL:
		return ret;
	case SSL_ERROR_ZERO_RETURN:
		return 0;
	default:
		errno = EIO;
		return -1;
	}
}

static ssize_t ssl_stream_recv(struct sstp_stream_t *stream, void *buf, size_t count, int flags)
{
	return recv(SSL_get_fd(stream->ssl), buf, count, flags);
}

static ssize_t ssl_stream_write(struct sstp_stream_t *stream, const void *buf, size_t count)
{
	int ret, err;

	ERR_clear_error();
	ret = SSL_write(stream->ssl, buf, count);
	if (ret > 0)
		return ret;

	err = SSL_get_error(stream->ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		/* fall through */
	case SSL_ERROR_SYSCALL:
		return ret;
	case SSL_ERROR_ZERO_RETURN:
		return 0;
	default:
		errno = EIO;
		return -1;
	}
}

static int ssl_stream_close(struct sstp_stream_t *stream)
{
	SSL_shutdown(stream->ssl);
	return close(SSL_get_fd(stream->ssl));
}

static void ssl_stream_free(struct sstp_stream_t *stream)
{
	if (stream && stream->ssl)
		SSL_free(stream->ssl);
	_free(stream);
}

static struct sstp_stream_t *ssl_stream_init(int fd, SSL_CTX *ssl_ctx)
{
	struct sstp_stream_t *stream = _malloc(sizeof(*stream));

	if (!stream)
		return NULL;

	stream->ssl = SSL_new(ssl_ctx);
	if (!stream->ssl)
		goto error;

	SSL_set_verify(stream->ssl, SSL_VERIFY_NONE, NULL);
	SSL_set_accept_state(stream->ssl);
	SSL_set_fd(stream->ssl, fd);

	stream->read = ssl_stream_read;
	stream->recv = ssl_stream_recv;
	stream->write = ssl_stream_write;
	stream->close = ssl_stream_close;
	stream->free = ssl_stream_free;

	return stream;

error:
	ssl_stream_free(stream);
	return NULL;
}

/* proxy */

static int proxy_parse(const struct buffer_t *buf, struct sockaddr_t *peer, struct sockaddr_t *addr)
{
	static const uint8_t proxy_sig[] = PROXY_SIG;
	struct proxy_hdr *hdr;
	char *ptr, *proto, *src_addr, *dst_addr, *src_port, *dst_port;
	int n, count;

	if (buf->len < PROXY_MINLEN || memcmp(buf->head, proxy_sig, sizeof(proxy_sig)) != 0)
		return 0;

	ptr = memmem(buf->head, buf->len, "\r\n", 2);
	if (!ptr) {
		if (buf_tailroom(buf) > 0)
			return 0;
		log_error("sstp: proxy: %s\n", "too long header");
		return -1;
	} else
		*ptr = '\0';

	hdr = (void *)buf->head;
	n = ptr + 2 - hdr->line;

	if (conf_verbose)
		log_ppp_info2("recv [PROXY <%s>]\n", hdr->line);

	count = vstrsep(hdr->line, " ", &ptr, &proto, &src_addr, &dst_addr, &src_port, &dst_port);
	if (count < 2)
		goto error;

	if (strcasecmp(proto, PROXY_TCP4) == 0) {
		if (count < 6 ||
		    inet_pton(AF_INET, src_addr, &peer->u.sin.sin_addr) <= 0 ||
		    inet_pton(AF_INET, dst_addr, &addr->u.sin.sin_addr) <= 0) {
			goto error;
		}
		peer->len = addr->len = sizeof(addr->u.sin);
		peer->u.sin.sin_family = addr->u.sin.sin_family = AF_INET;
		peer->u.sin.sin_port = htons(atoi(src_port));
		addr->u.sin.sin_port = htons(atoi(dst_port));
	} else if (strcasecmp(proto, PROXY_TCP6) == 0) {
		if (count < 6 ||
		    inet_pton(AF_INET6, src_addr, &peer->u.sin6.sin6_addr) <= 0 ||
		    inet_pton(AF_INET6, dst_addr, &addr->u.sin6.sin6_addr) <= 0) {
			goto error;
		}
		peer->len = addr->len = sizeof(addr->u.sin6);
		peer->u.sin6.sin6_family = addr->u.sin6.sin6_family = AF_INET6;
		peer->u.sin6.sin6_port = htons(atoi(src_port));
		addr->u.sin6.sin6_port = htons(atoi(dst_port));
	} else if (strcasecmp(proto, PROXY_UNKNOWN) != 0)
		goto error;

	return n;

error:
	log_error("sstp: proxy: %s\n", "invalid header");
	return -1;
}

static int proxy_parse_v2(const struct buffer_t *buf, struct sockaddr_t *peer, struct sockaddr_t *addr)
{
	static const uint8_t proxy2_sig[] = PROXY2_SIG;
	struct proxy2_hdr *hdr;
	int n;

	if (buf->len < PROXY2_MINLEN || memcmp(buf->head, proxy2_sig, sizeof(proxy2_sig)) != 0)
		return 0;

	hdr = (void *)buf->head;

	if (conf_verbose) {
		log_ppp_info2("recv [PROXY ver/cmd=0x%02x fam/addr=0x%02x len=%d]\n",
				hdr->ver_cmd, hdr->fam, ntohs(hdr->len));
	}

	if ((hdr->ver_cmd & 0xf0) != 0x20)
		goto error;

	n = sizeof(*hdr) + ntohs(hdr->len);
	if (n > buf->len) {
		if (buf_tailroom(buf) > 0)
			return 0;
		log_error("sstp: proxy2: %s\n", "too long header");
		return -1;
	}

	switch (hdr->ver_cmd & 0x0f) {
	case PROXY2_PROXY:
		switch (hdr->fam >> 4) {
		case PROXY2_AF_INET:
			if (n < sizeof(*hdr) + sizeof(hdr->ipv4_addr))
				goto error;
			peer->len = addr->len = sizeof(addr->u.sin);
			peer->u.sin.sin_family = addr->u.sin.sin_family = AF_INET;
			peer->u.sin.sin_addr.s_addr = hdr->ipv4_addr.src_addr.s_addr;
			peer->u.sin.sin_port = hdr->ipv4_addr.src_port;
			addr->u.sin.sin_addr.s_addr = hdr->ipv4_addr.dst_addr.s_addr;
			addr->u.sin.sin_port = hdr->ipv4_addr.dst_port;
			break;
		case PROXY2_AF_INET6:
			if (n < sizeof(*hdr) + sizeof(hdr->ipv6_addr))
				goto error;
			peer->len = addr->len = sizeof(addr->u.sin6);
			peer->u.sin6.sin6_family = addr->u.sin6.sin6_family = AF_INET6;
			memcpy(&peer->u.sin6.sin6_addr, &hdr->ipv6_addr.src_addr, sizeof(peer->u.sin6.sin6_addr));
			peer->u.sin6.sin6_port = hdr->ipv6_addr.src_port;
			memcpy(&addr->u.sin6.sin6_addr, &hdr->ipv6_addr.dst_addr, sizeof(addr->u.sin6.sin6_addr));
			addr->u.sin6.sin6_port = hdr->ipv6_addr.dst_port;
			break;
		case PROXY2_AF_UNIX:
			if (n < sizeof(*hdr) + sizeof(hdr->unix_addr))
				goto error;
			peer->len = addr->len = sizeof(addr->u.sun);
			peer->u.sun.sun_family = addr->u.sun.sun_family = AF_UNIX;
			memcpy(peer->u.sun.sun_path, hdr->unix_addr.src_addr, sizeof(peer->u.sun.sun_path));
			memcpy(addr->u.sun.sun_path, hdr->unix_addr.dst_addr, sizeof(addr->u.sun.sun_path));
			break;
		case PROXY2_AF_UNSPEC:
			break;
		default:
			goto error;
		}
		/* fall through */
	case PROXY2_LOCAL:
		break;
	default:
		goto error;
	}

	return n;

error:
	log_error("sstp: proxy2: %s\n", "invalid header");
	return -1;
}

static int proxy_handler(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	struct sockaddr_t addr;
	char addr_buf[ADDRSTR_MAXLEN];
	in_addr_t ip;
	int n;

	if (conn->sstp_state != STATE_SERVER_CALL_DISCONNECTED)
		return -1;

	memset(&addr, 0, sizeof(addr));

	n = proxy_parse_v2(buf, &conn->addr, &addr);
	if (n == 0)
		n = proxy_parse(buf, &conn->addr, &addr);

	if (n == 0 && buf->len >= max(PROXY2_MINLEN, PROXY_MINLEN)) {
		log_error("sstp: proxy: %s\n", "no header found");
		return -1;
	} else if (n <= 0)
		return n;

	ip = sockaddr_ipv4(&conn->addr);
	if (ip && triton_module_loaded("connlimit") && connlimit_check(cl_key_from_ipv4(ip)))
		return -1;

	sockaddr_ntop(&conn->addr, addr_buf, sizeof(addr_buf), 0);
	log_info2("sstp: proxy: connection from %s\n", addr_buf);

	if (ip && iprange_client_check(ip)) {
		log_warn("sstp: proxy: IP is out of client-ip-range, droping connection...\n");
		return -1;
	}

	if (addr.u.sa.sa_family != AF_UNSPEC) {
		_free(conn->ppp.ses.chan_name);
		conn->ppp.ses.chan_name = _strdup(addr_buf);

		sockaddr_ntop(&conn->addr, addr_buf, sizeof(addr_buf), FLAG_NOPORT);
		_free(conn->ctrl.calling_station_id);
		conn->ctrl.calling_station_id = _strdup(addr_buf);

		sockaddr_ntop(&addr, addr_buf, sizeof(addr_buf), FLAG_NOPORT);
		_free(conn->ctrl.called_station_id);
		conn->ctrl.called_station_id = _strdup(addr_buf);
	}

	buf_pull(buf, n);

	conn->handler = http_handler;
	return n;
}

/* http */

static char *http_getline(struct buffer_t *buf, char *line, size_t size)
{
	char *src, *dst, *ptr;
	int len;

	if (buf->len == 0 || size == 0)
		return NULL;

	src = (void *)buf->head;
	ptr = memchr(src, '\n', buf->len);
	if (ptr) {
		len = ptr - src;
		buf_pull(buf, len + 1);
		if (len > 0 && src[len - 1] == '\r')
			len--;
	} else {
		len = buf->len;
		buf_pull(buf, len);
	}

	dst = line;
	while (len-- > 0 && size-- > 1)
		*dst++ = *src++;
	if (size > 0)
		*dst = '\0';

	return line;
}

static char *http_getvalue(char *line, const char *name, int len)
{
	int sep;

	if (len < 0)
		len = strlen(name);

	if (strncasecmp(line, name, len) != 0)
		return NULL;

	line += len;
	for (sep = 0; *line; line++) {
		if (!sep && *line == ':')
			sep = 1;
		else if (*line != ' ' && *line != '\t')
			break;
	}

	return sep ? line : NULL;
}

static int http_send_response(struct sstp_conn_t *conn, char *proto, char *status, char *headers)
{
	char datetime[sizeof("aaa, dd bbb yyyy HH:MM:SS GMT")];
	char linebuf[1024], *line;
	struct buffer_t *buf, tmp;
	time_t now = time(NULL);

	strftime(datetime, sizeof(datetime), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&now));
	buf = alloc_buf_printf(
		"%s %s\r\n"
		/* "Server: %s\r\n" */
		"Date: %s\r\n"
		"%s"
		"\r\n", proto, status, /* "accel-ppp",*/ datetime, headers ? : "");
	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	if (conf_verbose) {
		tmp = *buf;
		while ((line = http_getline(&tmp, linebuf, sizeof(linebuf))) != NULL) {
			if (*line == '\0')
				break;
			log_ppp_info2("send [HTTP <%s>]\n", line);
		}
	}

	return sstp_send(conn, buf) || sstp_write(&conn->hnd);
}

static int http_recv_request(struct sstp_conn_t *conn, uint8_t *data, int len)
{
	char httpbuf[1024], linebuf[1024];
	char *line, *method, *request, *proto, *host;
	struct buffer_t buf;
	int host_error;

	buf.head = data;
	buf.end = data + len;
	buf_set_length(&buf, len);

	line = http_getline(&buf, httpbuf, sizeof(httpbuf));
	if (!line)
		return -1;
	if (conf_verbose)
		log_ppp_info2("recv [HTTP <%s>]\n", line);

	if (vstrsep(line, " ", &method, &request, &proto) < 3) {
		if (conf_http_mode != HTTP_ERR_DENY)
			http_send_response(conn, "HTTP/1.1", "400 Bad Request", NULL);
		return -1;
	}
	if (strncasecmp(proto, "HTTP/1", sizeof("HTTP/1") - 1) != 0) {
		if (conf_http_mode != HTTP_ERR_DENY)
			http_send_response(conn, "HTTP/1.1", "400 Bad Request", NULL);
		return -1;
	}
	if (strcasecmp(method, SSTP_HTTP_METHOD) != 0 && strcasecmp(method, "GET") != 0) {
		if (conf_http_mode != HTTP_ERR_DENY)
			http_send_response(conn, proto, "501 Not Implemented", NULL);
		return -1;
	}

	host_error = conf_hostname ? -1 : 0;
	while ((line = http_getline(&buf, linebuf, sizeof(linebuf))) != NULL) {
		if (*line == '\0')
			break;
		if (conf_verbose)
			log_ppp_info2("recv [HTTP <%s>]\n", line);

		if (host_error < 0) {
			host = http_getvalue(line, "Host", sizeof("Host") - 1);
			if (host) {
				host = strsep(&host, ":");
				host_error = (strcasecmp(host, conf_hostname) != 0);
			}
		}
	}

	if (host_error) {
		if (conf_http_mode != HTTP_ERR_DENY)
			http_send_response(conn, proto, "404 Not Found", NULL);
		return -1;
	}

	if (strcasecmp(method, SSTP_HTTP_METHOD) != 0 || strcasecmp(request, SSTP_HTTP_URI) != 0) {
		if (conf_http_mode > 0) {
			if (_asprintf(&line, "Location: %s%s\r\n",
			    conf_http_url, (conf_http_mode == HTTP_ERR_REDIRECT_APPEND) ? request : "") < 0)
				return -1;
			http_send_response(conn, proto, "301 Moved Permanently", line);
			_free(line);
		} else if (conf_http_mode == HTTP_ERR_ALLOW)
			http_send_response(conn, proto, "404 Not Found", NULL);
		return -1;
	}

	return http_send_response(conn, proto, "200 OK",
			"Content-Length: 18446744073709551615\r\n");
}

static int http_handler(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	static const char *table[] = { "\n\r\n", "\r\r\n", NULL };
	const char **pptr;
	uint8_t *ptr, *end = NULL;
	int n, r;

	if (conn->sstp_state != STATE_SERVER_CALL_DISCONNECTED)
		return -1;

	ptr = buf->head;
	while (ptr < buf->tail && *ptr == ' ')
		ptr++;
	if (ptr == buf->tail)
		return 0;
	else if (strncasecmp((char *)ptr, SSTP_HTTP_METHOD,
			min(buf->tail - ptr, sizeof(SSTP_HTTP_METHOD) - 1)) != 0)
		end = buf->tail;
	else for (pptr = table; *pptr; pptr++) {
		ptr = memmem(buf->head, buf->len, *pptr, strlen(*pptr));
		if (ptr && (!end || ptr < end))
			end = ptr + strlen(*pptr);
	}
	if (!end) {
		if (buf_tailroom(buf) > 0)
			return 0;
		log_ppp_error("recv [HTTP too long header]\n");
		return -1;
	} else
		n = end - buf->head;

	r = http_recv_request(conn, buf->head, n);
	if (r < 0)
		return -1;
	else if (r > 0)
		return 1;
	buf_pull(buf, n);

	conn->sstp_state = STATE_SERVER_CONNECT_REQUEST_PENDING;
	conn->handler = sstp_handler;
	return sstp_handler(conn, buf);
}

/* ppp */

static int ppp_allocate_pty(int *master, int *slave, int flags)
{
	struct termios tios;
	int value, mfd, sfd;

	if (openpty(&mfd, &sfd, NULL, NULL, NULL) < 0) {
		log_ppp_error("sstp: allocate pty: %s\n", strerror(errno));
		return -1;
	}

	if (flags & O_CLOEXEC) {
		fcntl(mfd, F_SETFD, fcntl(mfd, F_GETFD) | FD_CLOEXEC);
		fcntl(sfd, F_SETFD, fcntl(sfd, F_GETFD) | FD_CLOEXEC);
		flags &= ~O_CLOEXEC;
	}

	if (tcgetattr(sfd, &tios) < 0) {
		log_ppp_error("sstp: ppp: get pty attributes: %s\n", strerror(errno));
		goto error;
	}
	tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB);
	tios.c_cflag |= CS8 | CREAD | CLOCAL;
	tios.c_iflag  = IGNBRK | IGNPAR;
	tios.c_oflag  = 0;
	tios.c_lflag  = 0;
	tios.c_cc[VMIN] = 1;
	tios.c_cc[VTIME] = 0;
	if (tcsetattr(sfd, TCSAFLUSH, &tios) < 0) {
		log_ppp_error("sstp: ppp: set pty attributes: %s\n", strerror(errno));
		goto error;
	}

#if PPP_SYNC
	value = N_SYNC_PPP;
#else
	value = N_PPP;
#endif
	if (ioctl(sfd, TIOCSETD, &value) < 0) {
		log_ppp_error("sstp: ppp: set pty line discipline: %s\n", strerror(errno));
		goto error;
	}

#if PPP_SYNC
	value = N_HDLC;
	if (ioctl(mfd, TIOCSETD, &value) < 0) {
		log_ppp_error("sstp: ppp: set pty line discipline: %s\n", strerror(errno));
		goto error;
	}
#endif

	if ((value = fcntl(mfd, F_GETFL)) < 0 || fcntl(mfd, F_SETFL, value | flags) < 0 ||
	    (value = fcntl(sfd, F_GETFL)) < 0 || fcntl(sfd, F_SETFL, value | flags) < 0) {
		log_ppp_error("sstp: ppp: set pty status flags: %s\n", strerror(errno));
		goto error;
	}

	*master = mfd;
	*slave = sfd;
	return 0;

error:
	close(mfd);
	close(sfd);
	return -1;
}

static void ppp_started(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct sstp_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	log_ppp_debug("sstp: ppp: started\n");

	switch (conn->ppp_state) {
	case STATE_STARTING:
	case STATE_AUTHORIZED:
		conn->ppp_state = STATE_STARTED;
		sstp_read_deferred(conn);
		break;
	}
}

static void ppp_finished(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct sstp_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	log_ppp_debug("sstp: ppp: finished\n");

	switch (conn->ppp_state) {
	case STATE_STARTING:
	case STATE_AUTHORIZED:
	case STATE_STARTED:
		conn->ppp_state = STATE_FINISHED;
		sstp_abort(conn, 1);
		break;
	}
}

static int ppp_read(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), ppp_hnd);
	struct buffer_t *buf;
	struct sstp_hdr *hdr;
	uint8_t pppbuf[PPP_BUF_SIZE], *src;
	int i, n;
#if !PPP_SYNC
	uint8_t byte;

	buf = conn->ppp_in;
#endif
	while (1) {
		n = read(h->fd, pppbuf, sizeof(pppbuf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;
			log_ppp_error("sstp: ppp: read: %s\n", strerror(errno));
			goto drop;
		} else if (n == 0) {
			if (conf_verbose)
				log_ppp_info2("sstp: ppp: disconnect from tty\n");
			goto drop;
		}

		switch (conn->sstp_state) {
		case STATE_SERVER_CALL_CONNECTED_PENDING:
		case STATE_SERVER_CALL_CONNECTED:
			break;
		default:
			continue;
		}

		src = pppbuf;
#if PPP_SYNC
		while (n > 0) {
			if (src[0] == PPP_ALLSTATIONS)
				i = conn->ppp.mtu + 4 - (src[2] & 1);
			else
				i = conn->ppp.mtu + 2 - (src[0] & 1);
			if (i > n)
				i = n;

			buf = alloc_buf(i + sizeof(*hdr));
			if (!buf) {
				log_ppp_error("sstp: ppp: no memory\n");
				goto drop;
			}
			hdr = buf_put(buf, sizeof(*hdr));
			buf_put_data(buf, src, i);
			INIT_SSTP_DATA_HDR(hdr, buf->len);
			sstp_queue(conn, buf);

			n -= i;
			src += i;
		}
#else
		if (!buf) {
		alloc:
			conn->ppp_in = buf = alloc_buf(SSTP_MAX_PACKET_SIZE + PPP_FCSLEN);
			if (!buf) {
				log_ppp_error("sstp: ppp: no memory\n");
				goto drop;
			}
			buf_reserve(buf, sizeof(*hdr));
		}

		while (n > 0) {
			if ((conn->ppp_flags & PPP_F_ESCAPE) && *src == PPP_ESCAPE)
				i = 1;
			else {
				for (i = 0; i < n &&
						src[i] != PPP_ESCAPE && src[i] != PPP_FLAG; i++);
			}
			if (i > 0 && (conn->ppp_flags & PPP_F_TOSS) == 0) {
				if (i <= buf_tailroom(buf)) {
					char *p = buf_put_data(buf, src, i);
					if (conn->ppp_flags & PPP_F_ESCAPE) {
						*p ^= PPP_TRANS;
						conn->ppp_flags &= ~PPP_F_ESCAPE;
					}
				} else
					conn->ppp_flags |= PPP_F_TOSS;
			}

			byte = src[i++];
			src += i;
			n -= i;

			switch (byte) {
			case PPP_FLAG:
				if (buf->len <= PPP_FCSLEN || conn->ppp_flags) {
					buf_set_length(buf, 0);
					conn->ppp_flags = 0;
					break;
				}
				buf_put(buf, -PPP_FCSLEN);
				hdr = buf_push(buf, sizeof(*hdr));
				INIT_SSTP_DATA_HDR(hdr, buf->len);
				sstp_queue(conn, buf);
				goto alloc;
			case PPP_ESCAPE:
				conn->ppp_flags |= PPP_F_ESCAPE;
				break;
			}
		}
#endif
	}
	if (!list_empty(&conn->out_queue))
		triton_md_enable_handler(&conn->hnd, MD_MODE_WRITE);
	return 0;

drop:
	sstp_disconnect(conn);
	return 1;
}

static int ppp_write(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), ppp_hnd);
	struct iovec iov[PPP_BUF_IOVEC];
	struct buffer_t *buf;
	ssize_t n;
	int i;

	if (!list_empty(&conn->ppp_queue)) {
		i = n = 0;
		list_for_each_entry(buf, &conn->ppp_queue, entry) {
			if (i < PPP_BUF_IOVEC && n < PPP_BUF_SIZE) {
				iov[i].iov_base = buf->head;
				iov[i++].iov_len = buf->len;
				n += buf->len;
			} else
				break;
		}
	again:
		n = writev(conn->ppp_hnd.fd, iov, i);
		if (n < 0) {
			if (errno == EINTR)
				goto again;
			if (errno == EAGAIN)
				goto defer;
			if (conf_verbose && errno != EPIPE)
				log_ppp_info2("sstp: ppp: write: %s\n", strerror(errno));
			goto drop;
		} else if (n == 0)
			goto defer;
		do {
			buf = list_first_entry(&conn->ppp_queue, typeof(*buf), entry);
			if (buf->len > n) {
				buf_pull(buf, n);
				break;
			}
			n -= buf->len;
			list_del(&buf->entry);
			free_buf(buf);
		} while (n > 0);

		if (!list_empty(&conn->ppp_queue))
			goto defer;
	}
	triton_md_disable_handler(h, MD_MODE_WRITE);
	return 0;

defer:
	triton_md_enable_handler(h, MD_MODE_WRITE);
	return 0;

drop:
	triton_context_call(&conn->ctx, (triton_event_func)sstp_disconnect, conn);
	return 1;
}

static inline void ppp_queue(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	list_add_tail(&buf->entry, &conn->ppp_queue);
}

static int ppp_send(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	ppp_queue(conn, buf);
	triton_md_enable_handler(&conn->ppp_hnd, MD_MODE_WRITE);
	return 0;
}

/* sstp */

static void sstp_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	if (arg) {
		struct ap_session *s = arg;
		net = s->net;
	} else
		net = def_net;
	log_switch(ctx, arg);
}

static int sstp_send_msg_call_connect_ack(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_crypto_binding_request attr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_ppp_info2("send [SSTP SSTP_MSG_CALL_CONNECT_ACK]\n");

	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	msg = buf_put_zero(buf, sizeof(*msg));

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_CONNECT_ACK, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_CRYPTO_BINDING_REQ, sizeof(msg->attr));
	msg->attr.hash_protocol_bitmask = conf_hash_protocol;
	if (conn->nonce)
		memcpy(msg->attr.nonce, conn->nonce, SSTP_NONCE_SIZE);

	return sstp_send(conn, buf);
}

static int sstp_send_msg_call_connect_nak(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_status_info attr;
		uint16_t attr_value;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_ppp_info2("send [SSTP SSTP_MSG_CALL_CONNECT_NAK]\n");

	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	msg = buf_put_zero(buf, sizeof(*msg));

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_CONNECT_NAK, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_STATUS_INFO, sizeof(msg->attr));
	msg->attr.attrib_id = SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID;
	msg->attr.status = htonl(ATTRIB_STATUS_VALUE_NOT_SUPPORTED);
	msg->attr_value = 0;

	return sstp_send(conn, buf);
}

static int sstp_send_msg_call_abort(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_status_info attr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_ppp_info2("send [SSTP SSTP_MSG_CALL_ABORT]\n");

	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	msg = buf_put_zero(buf, sizeof(*msg));

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_ABORT, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_STATUS_INFO, sizeof(msg->attr));
	msg->attr.attrib_id = SSTP_ATTRIB_STATUS_INFO;
	msg->attr.status = htonl(ATTRIB_STATUS_INVALID_FRAME_RECEIVED);

	return sstp_send(conn, buf);
}

static int sstp_send_msg_call_disconnect(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_status_info attr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_ppp_info2("send [SSTP SSTP_MSG_CALL_DISCONNECT]\n");

	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	msg = buf_put_zero(buf, sizeof(*msg));

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_DISCONNECT, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_STATUS_INFO, sizeof(msg->attr));
	msg->attr.attrib_id = SSTP_ATTRIB_NO_ERROR;
	msg->attr.status = htonl(ATTRIB_STATUS_NO_ERROR);

	return sstp_send(conn, buf);
}

static int sstp_send_msg_call_disconnect_ack(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_ppp_info2("send [SSTP SSTP_MSG_CALL_DISCONNECT_ACK]\n");

	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	msg = buf_put_zero(buf, sizeof(*msg));

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_DISCONNECT_ACK, 0, sizeof(*msg));

	return sstp_send(conn, buf);
}

static int sstp_send_msg_echo_request(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_ppp_info2("send [SSTP SSTP_MSG_ECHO_REQUEST]\n");

	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	msg = buf_put_zero(buf, sizeof(*msg));

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_ECHO_REQUEST, 0, sizeof(*msg));

	return sstp_send(conn, buf);
}

static int sstp_send_msg_echo_response(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_ppp_info2("send [SSTP SSTP_MSG_ECHO_RESPONSE]\n");

	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	msg = buf_put_zero(buf, sizeof(*msg));

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_ECHO_RESPONSE, 0, sizeof(*msg));

	return sstp_send(conn, buf);
}

static int sstp_recv_msg_call_connect_request(struct sstp_conn_t *conn, struct sstp_ctrl_hdr *hdr)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_encapsulated_protocol attr;
	} __attribute__((packed)) *msg = (void *)hdr;
	int master, slave;

	if (conf_verbose)
		log_ppp_info2("recv [SSTP SSTP_MSG_CALL_CONNECT_REQUEST]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	case STATE_SERVER_CONNECT_REQUEST_PENDING:
		break;
	default:
		return sstp_abort(conn, 0);
	}

	if (ntohs(msg->hdr.length) < sizeof(*msg) ||
	    ntohs(msg->hdr.num_attributes) < 1 ||
	    msg->attr.hdr.attribute_id != SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID ||
	    ntohs(msg->attr.hdr.length) < sizeof(msg->attr)) {
		return sstp_abort(conn, 0);
	}
	if (ntohs(msg->attr.protocol_id) != SSTP_ENCAPSULATED_PROTOCOL_PPP) {
		if (conn->nak_sent++ == 3) {
			log_ppp_error("sstp: nak limit reached\n");
			return sstp_abort(conn, 0);
		}
		return sstp_send_msg_call_connect_nak(conn);
	}

	if (ppp_allocate_pty(&master, &slave, O_CLOEXEC | O_NONBLOCK) < 0)
		return -1;

	conn->ppp_hnd.fd = master;
	conn->ppp_hnd.read = ppp_read;
	conn->ppp_hnd.write = ppp_write;

	triton_md_register_handler(&conn->ctx, &conn->ppp_hnd);
	triton_md_enable_handler(&conn->ppp_hnd, MD_MODE_READ);

	if (conn->nonce)
		read(urandom_fd, conn->nonce, SSTP_NONCE_SIZE);
	if (conn->hlak_key)
		memset(conn->hlak_key, 0, SSTP_HLAK_SIZE);
	if (sstp_send_msg_call_connect_ack(conn))
		goto error;

	conn->sstp_state = STATE_SERVER_CALL_CONNECTED_PENDING;
	__sync_sub_and_fetch(&stat_starting, 1);
	__sync_add_and_fetch(&stat_active, 1);
	triton_event_fire(EV_CTRL_STARTED, &conn->ppp.ses);

	conn->ppp_state = STATE_STARTING;
	conn->ppp.fd = slave;
	if (establish_ppp(&conn->ppp)) {
		conn->ppp_state = STATE_FINISHED;
		goto error;
	}
	return 0;

error:
	if (conn->ppp_hnd.tpd)
		triton_md_unregister_handler(&conn->ppp_hnd, 1);
	close(slave);
	return -1;
}

static int sstp_recv_msg_call_connected(struct sstp_conn_t *conn, struct sstp_ctrl_hdr *hdr)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_crypto_binding attr;
	} __attribute__((packed)) *msg = (void *)hdr;
	uint8_t hash;
	unsigned int len;
	struct npioctl np;
	typeof(*msg) buf;
	uint8_t md[EVP_MAX_MD_SIZE], *ptr;
	const EVP_MD *evp;
	unsigned int mdlen;

	if (conf_verbose)
		log_ppp_info2("recv [SSTP SSTP_MSG_CALL_CONNECTED]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	case STATE_SERVER_CALL_CONNECTED_PENDING:
		break;
	default:
		sstp_abort(conn, 0);
		return 0;
	}

	if (ntohs(msg->hdr.length) < sizeof(*msg) ||
	    ntohs(msg->hdr.num_attributes) < 1 ||
	    msg->attr.hdr.attribute_id != SSTP_ATTRIB_CRYPTO_BINDING ||
	    ntohs(msg->attr.hdr.length) < sizeof(msg->attr)) {
		return sstp_abort(conn, 0);
	}

	if (conn->nonce && memcmp(msg->attr.nonce, conn->nonce, SSTP_NONCE_SIZE) != 0) {
		log_ppp_error("sstp: invalid Nonce\n");
		return sstp_abort(conn, 0);
	}

	hash = msg->attr.hash_protocol_bitmask & conf_hash_protocol;
	if (hash & CERT_HASH_PROTOCOL_SHA256) {
		len = SHA256_DIGEST_LENGTH;
		if (conf_hash_sha256.len == len &&
		    memcmp(msg->attr.cert_hash, conf_hash_sha256.hash, len) != 0) {
			log_ppp_error("sstp: invalid SHA256 Cert Hash\n");
			return sstp_abort(conn, 0);
		}
		evp = EVP_sha256();
	} else if (hash & CERT_HASH_PROTOCOL_SHA1) {
		len = SHA_DIGEST_LENGTH;
		if (conf_hash_sha1.len == len &&
		    memcmp(msg->attr.cert_hash, conf_hash_sha1.hash, len) != 0) {
			log_ppp_error("sstp: invalid SHA1 Cert Hash\n");
			return sstp_abort(conn, 0);
		}
		evp = EVP_sha1();
	} else {
		log_ppp_error("sstp: invalid Hash Protocol 0x%02x\n",
				msg->attr.hash_protocol_bitmask);
		return sstp_abort(conn, 0);
	}

	if (conn->hlak_key) {
		/* SSTP_MSG_CALL_CONNECTED may come before auth response */
		if (conn->ppp_state < STATE_AUTHORIZED) {
			struct buffer_t *buf;

			if (conf_verbose)
				log_warn("sstp: SSTP_MSG_CALL_CONNECTED is out of order, deferring...\n");

			buf = alloc_buf(sizeof(*msg));
			if (!buf) {
				log_error("sstp: no memory\n");
				return -1;
			}
			buf_put_data(buf, msg, sizeof(*msg));
			sstp_queue_deferred(conn, buf);
			return 0;
		}

		ptr = mempcpy(md, SSTP_CMK_SEED, SSTP_CMK_SEED_SIZE);
		*ptr++ = len;
		*ptr++ = 0;
		*ptr++ = 1;
		mdlen = sizeof(md);
		HMAC(evp, conn->hlak_key, SSTP_HLAK_SIZE, md, ptr - md, md, &mdlen);

		memcpy(&buf, msg, sizeof(buf));
		memset(buf.attr.compound_mac, 0, sizeof(buf.attr.compound_mac));
		HMAC(evp, md, mdlen, (void *)&buf, sizeof(buf), buf.attr.compound_mac, &len);

		if (memcmp(msg->attr.compound_mac, buf.attr.compound_mac, len) != 0) {
			log_ppp_error("sstp: invalid Compound MAC\n");
			return sstp_abort(conn, 0);
		}
	}

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	conn->sstp_state = STATE_SERVER_CALL_CONNECTED;

	conn->ctrl.ppp_npmode = NPMODE_PASS;
	switch (conn->ppp_state) {
	case STATE_STARTED:
		if (conn->ppp.ses.ipv4) {
			np.protocol = PPP_IP;
			np.mode = conn->ctrl.ppp_npmode;
			if (net->ppp_ioctl(conn->ppp.unit_fd, PPPIOCSNPMODE, &np))
				log_ppp_error("failed to set NP (IPv4) mode: %s\n", strerror(errno));
		}
		if (conn->ppp.ses.ipv6) {
			np.protocol = PPP_IPV6;
			np.mode = conn->ctrl.ppp_npmode;
			if (net->ppp_ioctl(conn->ppp.unit_fd, PPPIOCSNPMODE, &np))
				log_ppp_error("failed to set NP (IPv6) mode: %s\n", strerror(errno));
		}
		break;
	}

	_free(conn->nonce);
	conn->nonce = NULL;
	_free(conn->hlak_key);
	conn->hlak_key = NULL;

	if (conn->hello_interval) {
		conn->hello_timer.period = conn->hello_interval * 1000;
		triton_timer_add(&conn->ctx, &conn->hello_timer, 0);
	}

	return 0;
}

static int sstp_recv_msg_call_abort(struct sstp_conn_t *conn)
{
	int ret = 0;

	if (conf_verbose)
		log_ppp_info2("recv [SSTP SSTP_MSG_CALL_ABORT]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_PENDING:
		break;
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	default:
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_2;
		ret = sstp_send_msg_call_abort(conn);
		break;
	}

	conn->timeout_timer.period = SSTP_ABORT_TIMEOUT_2 * 1000;
	if (conn->timeout_timer.tpd)
		triton_timer_mod(&conn->timeout_timer, 0);
	else
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);

	conn->sstp_state = STATE_CALL_ABORT_TIMEOUT_PENDING;

	return ret;
}

static int sstp_recv_msg_call_disconnect(struct sstp_conn_t *conn)
{
	int ret;

	if (conf_verbose)
		log_ppp_info2("recv [SSTP SSTP_MSG_CALL_DISCONNECT]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	case STATE_CALL_DISCONNECT_ACK_PENDING:
		if (conn->timeout_timer.tpd)
			triton_timer_del(&conn->timeout_timer);
		break;
	}

	conn->sstp_state = STATE_CALL_DISCONNECT_IN_PROGRESS_2;
	ret = sstp_send_msg_call_disconnect_ack(conn);

	conn->timeout_timer.period = SSTP_DISCONNECT_TIMEOUT_2 * 1000;
	if (conn->timeout_timer.tpd)
		triton_timer_mod(&conn->timeout_timer, 0);
	else
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);

	conn->sstp_state = STATE_CALL_DISCONNECT_TIMEOUT_PENDING;

	return ret;
}

static int sstp_recv_msg_call_disconnect_ack(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_ppp_info2("recv [SSTP SSTP_MSG_CALL_DISCONNECT_ACK]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_DISCONNECT_ACK_PENDING:
		break;
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	default:
		return sstp_abort(conn, 0);
	}

	conn->sstp_state = STATE_SERVER_CALL_DISCONNECTED;
	triton_context_call(&conn->ctx, (triton_event_func)sstp_disconnect, conn);

	return 0;
}

static int sstp_recv_msg_echo_request(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_ppp_info2("recv [SSTP SSTP_MSG_ECHO_REQUEST]\n");

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED:
		break;
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	default:
		return sstp_abort(conn, 0);
	}

	return sstp_send_msg_echo_response(conn);
}

static int sstp_recv_msg_echo_response(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_ppp_info2("recv [SSTP SSTP_MSG_ECHO_RESPONSE]\n");

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED:
		break;
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	default:
		return sstp_abort(conn, 0);
	}

	conn->hello_sent = 0;
	return 0;
}

static int sstp_recv_data_packet(struct sstp_conn_t *conn, struct sstp_hdr *hdr)
{
	struct buffer_t *buf;
	int size;
#if !PPP_SYNC
	uint8_t *src, *dst, byte;
	uint16_t fcs;
	int n;
#endif

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED_PENDING:
	case STATE_SERVER_CALL_CONNECTED:
		break;
	default:
		return 0;
	}

	size = ntohs(hdr->length) - sizeof(*hdr);
	if (size == 0)
		return 0;

#if PPP_SYNC
	buf = alloc_buf(size);
	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	buf_put_data(buf, hdr->data, size);
#else
	buf = alloc_buf(size*2 + 2 + PPP_FCSLEN);
	if (!buf) {
		log_error("sstp: no memory\n");
		return -1;
	}

	src = hdr->data;
	dst = buf->tail;
	fcs = PPP_INITFCS;

	*dst++ = PPP_FLAG;
	for (n = size + PPP_FCSLEN; n > 0; n--) {
		if (n > PPP_FCSLEN) {
			byte = *src++;
			fcs = (fcs >> 8) ^ fcstab[(fcs ^ byte) & 0xff];
		} else if (n == PPP_FCSLEN) {
			fcs ^= PPP_INITFCS;
			byte = fcs & 0xff;
		} else if (n == PPP_FCSLEN - 1)
			byte = fcs >> 8;
		if (byte < 0x20 || byte == PPP_FLAG || byte == PPP_ESCAPE) {
			*dst++ = PPP_ESCAPE;
			*dst++ = byte ^ PPP_TRANS;
		} else
			*dst++ = byte;
	}
	*dst++ = PPP_FLAG;

	buf_put(buf, dst - buf->tail);
#endif

	return ppp_send(conn, buf);
}

static int sstp_recv_packet(struct sstp_conn_t *conn, struct sstp_hdr *hdr)
{
	struct sstp_ctrl_hdr *msg = (struct sstp_ctrl_hdr *)hdr;

	switch (hdr->reserved) {
	case SSTP_DATA_PACKET:
		return sstp_recv_data_packet(conn, hdr);
	case SSTP_CTRL_PACKET:
		if (ntohs(hdr->length) >= sizeof(*msg))
			break;
		log_ppp_error("recv [SSTP too short message]\n");
		return -1;
	default:
		log_ppp_warn("recv [SSTP unknown packet type %02x]\n", hdr->reserved);
		return 0;
	}

	if (conn->hello_timer.tpd) {
		conn->hello_timer.period = conn->hello_interval * 1000;
		triton_timer_mod(&conn->hello_timer, 0);
	}

	switch (ntohs(msg->message_type)) {
	case SSTP_MSG_CALL_CONNECT_REQUEST:
		return sstp_recv_msg_call_connect_request(conn, msg);
	case SSTP_MSG_CALL_CONNECT_ACK:
	case SSTP_MSG_CALL_CONNECT_NAK:
		return sstp_abort(conn, 0);
	case SSTP_MSG_CALL_CONNECTED:
		return sstp_recv_msg_call_connected(conn, msg);
	case SSTP_MSG_CALL_ABORT:
		return sstp_recv_msg_call_abort(conn);
	case SSTP_MSG_CALL_DISCONNECT:
		return sstp_recv_msg_call_disconnect(conn);
	case SSTP_MSG_CALL_DISCONNECT_ACK:
		return sstp_recv_msg_call_disconnect_ack(conn);
	case SSTP_MSG_ECHO_REQUEST:
		return sstp_recv_msg_echo_request(conn);
	case SSTP_MSG_ECHO_RESPONSE:
		return sstp_recv_msg_echo_response(conn);
	default:
		log_ppp_warn("recv [SSTP unknown message type 0x%04x]\n", ntohs(msg->message_type));
		return 0;
	}
}

static int sstp_handler(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	struct sstp_hdr *hdr;
	int n;

	while (buf->len >= sizeof(*hdr)) {
		hdr = (struct sstp_hdr *)buf->head;
		if (hdr->version != SSTP_VERSION) {
			log_ppp_error("recv [SSTP invalid version 0x%02x]\n", hdr->version);
			return -1;
		}

		n = ntohs(hdr->length);
		if (n > SSTP_MAX_PACKET_SIZE) {
			log_ppp_error("recv [SSTP too long packet]\n");
			return -1;
		} else if (n > buf->len)
			break;

		if (sstp_recv_packet(conn, hdr) < 0)
			return -1;
		buf_pull(buf, n);
	};

	return 0;
}

static int sstp_read(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct buffer_t *buf = conn->in;
	int n;

	while ((n = buf_tailroom(buf)) > 0) {
		n = conn->stream->read(conn->stream, buf->tail, n);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return 0;
			log_ppp_error("sstp: read: %s\n", strerror(errno));
			goto drop;
		} else if (n == 0) {
			if (conf_verbose)
				log_ppp_info2("sstp: disconnect by peer\n");
			goto drop;
		}
		buf_put(buf, n);

		n = conn->handler(conn, buf);
		if (n < 0)
			goto drop;
		else if (n > 0)
			return 1;

		buf_expand_tail(buf, SSTP_MAX_PACKET_SIZE);
	}
	return 0;

drop:
	sstp_disconnect(conn);
	return 1;
}

static inline void sstp_queue_deferred(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	list_add_tail(&buf->entry, &conn->deferred_queue);
}

static int sstp_read_deferred(struct sstp_conn_t *conn)
{
	struct buffer_t *buf;
	int n;

	while (!list_empty(&conn->deferred_queue)) {
		buf = list_first_entry(&conn->deferred_queue, typeof(*buf), entry);

		n = conn->handler(conn, buf);
		if (n < 0)
			goto drop;

		list_del(&buf->entry);
		free_buf(buf);
	}
	return 0;

drop:
	sstp_disconnect(conn);
	return 1;
}

static int sstp_recv(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct buffer_t *buf = conn->in;
	int n, len;

	while ((n = buf_tailroom(buf)) > 0) {
		n = conn->stream->recv(conn->stream, buf->tail, n, MSG_PEEK);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return 0;
			log_ppp_error("sstp: recv: %s\n", strerror(errno));
			goto drop;
		} else if (n == 0) {
			if (conf_verbose)
				log_ppp_info2("sstp: disconnect by peer\n");
			goto drop;
		}
		len = buf->len;
		buf_put(buf, n);

		n = conn->handler(conn, buf);
		if (n < 0)
			goto drop;
		else if (n == 0) {
			buf_set_length(buf, len);
			buf_expand_tail(buf, buf_tailroom(buf) + 1);
			return 0;
		}

		buf_set_length(buf, 0);
		buf_pull(buf, -n);
		while (buf->len > 0) {
			n = conn->stream->recv(conn->stream, buf->head, buf->len, 0);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				log_ppp_error("sstp: recv: %s\n", strerror(errno));
					goto drop;
			} else if (n == 0) {
				if (conf_verbose)
					log_ppp_info2("sstp: disconnect by peer\n");
				goto drop;
			}
			buf_pull(buf, n);
		}

		buf_expand_tail(buf, SSTP_MAX_PACKET_SIZE);

		conn->hnd.read = sstp_read;
		return sstp_read(h);
	}

	return 0;

drop:
	sstp_disconnect(conn);
	return 1;
}

static int sstp_write(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct buffer_t *buf;
	int n;

	while (!list_empty(&conn->out_queue)) {
		buf = list_first_entry(&conn->out_queue, typeof(*buf), entry);
		while (buf->len) {
			n = conn->stream->write(conn->stream, buf->head, buf->len);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN)
					goto defer;
				if (conf_verbose && errno != EPIPE)
					log_ppp_info2("sstp: write: %s\n", strerror(errno));
				goto drop;
			} else if (n == 0)
				goto defer;
			buf_pull(buf, n);
		}
		list_del(&buf->entry);
		free_buf(buf);
	}

	triton_md_disable_handler(h, MD_MODE_WRITE);
	return 0;

defer:
	triton_md_enable_handler(h, MD_MODE_WRITE);
	return 0;

drop:
	triton_context_call(&conn->ctx, (triton_event_func)sstp_disconnect, conn);
	return 1;
}

static inline void sstp_queue(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	list_add_tail(&buf->entry, &conn->out_queue);
}

static int sstp_send(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	sstp_queue(conn, buf);
	triton_md_enable_handler(&conn->hnd, MD_MODE_WRITE);
	return 0;
}

static void sstp_msg_echo(struct triton_timer_t *t)
{
	struct sstp_conn_t *conn = container_of(t, typeof(*conn), hello_timer);
	struct ppp_idle idle;

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED:
		if (ioctl(conn->ppp.unit_fd, PPPIOCGIDLE, &idle) >= 0 &&
		    idle.recv_idle < conn->hello_interval) {
			t->period = (conn->hello_interval - idle.recv_idle) * 1000;
			triton_timer_mod(t, 0);
			break;
		}
		if (conn->hello_sent++) {
			log_ppp_warn("sstp: no echo reply\n");
			sstp_abort(conn, 0);
		} else
			sstp_send_msg_echo_request(conn);
		break;
	}
}

static void sstp_timeout(struct triton_timer_t *t)
{
	struct sstp_conn_t *conn = container_of(t, typeof(*conn), timeout_timer);

	triton_timer_del(t);

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
		triton_context_call(&conn->ctx, (triton_event_func)sstp_disconnect, conn);
		break;
	case STATE_SERVER_CONNECT_REQUEST_PENDING:
	case STATE_SERVER_CALL_CONNECTED_PENDING:
		log_ppp_warn("sstp: negotiation timeout\n");
		/* fall through */
	default:
		sstp_abort(conn, 0);
		break;
	}
}

static void sstp_close(struct triton_context_t *ctx)
{
	struct sstp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	switch (conn->ppp_state) {
	case STATE_STARTING:
	case STATE_AUTHORIZED:
	case STATE_STARTED:
		conn->ppp_state = STATE_FINISHED;
		ap_session_terminate(&conn->ppp.ses, TERM_ADMIN_RESET, 1);
		sstp_abort(conn, 1);
		break;
	default:
		sstp_abort(conn, 0);
		break;
	}
}

static int sstp_abort(struct sstp_conn_t *conn, int disconnect)
{
	static const struct {
		int send_state;
		int exit_state;
		int timeout;
	} modes[2] = {
		{ STATE_CALL_ABORT_IN_PROGRESS_1, STATE_CALL_ABORT_PENDING, SSTP_ABORT_TIMEOUT_1 },
		{ STATE_CALL_DISCONNECT_IN_PROGRESS_1, STATE_CALL_DISCONNECT_ACK_PENDING, SSTP_DISCONNECT_TIMEOUT_1 }
	};
	int ret, idx = !!disconnect;

	conn->sstp_state = modes[idx].send_state;
	ret = idx ? sstp_send_msg_call_disconnect(conn) : sstp_send_msg_call_abort(conn);

	conn->timeout_timer.period = modes[idx].timeout * 1000;
	if (conn->timeout_timer.tpd)
		triton_timer_mod(&conn->timeout_timer, 0);
	else
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);

	conn->sstp_state = modes[idx].exit_state;

	return ret;
}

static void sstp_disconnect(struct sstp_conn_t *conn)
{
	struct buffer_t *buf;

	log_ppp_debug("disconnecting\n");

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	if (conn->hnd.tpd) {
		triton_md_unregister_handler(&conn->hnd, 0);
		conn->stream->close(conn->stream);
	}
	if (conn->ppp_hnd.tpd)
		triton_md_unregister_handler(&conn->ppp_hnd, 1);

	switch (conn->ppp_state) {
	case STATE_INIT:
		__sync_sub_and_fetch(&stat_starting, 1);
		break;
	case STATE_STARTING:
	case STATE_AUTHORIZED:
	case STATE_STARTED:
		conn->ppp_state = STATE_FINISHED;
		__sync_sub_and_fetch(&stat_active, 1);
		ap_session_terminate(&conn->ppp.ses, TERM_LOST_CARRIER, 1);
		break;
	case STATE_FINISHED:
		__sync_sub_and_fetch(&stat_active, 1);
		break;
	}
	triton_event_fire(EV_CTRL_FINISHED, &conn->ppp.ses);

	triton_context_unregister(&conn->ctx);

	_free(conn->nonce);
	_free(conn->hlak_key);

	if (conn->stream)
		conn->stream->free(conn->stream);
	free_buf(conn->in);
	free_buf(conn->ppp_in);

	list_splice_init(&conn->ppp_queue, &conn->out_queue);
	list_splice_init(&conn->deferred_queue, &conn->out_queue);
	while (!list_empty(&conn->out_queue)) {
		buf = list_first_entry(&conn->out_queue, typeof(*buf), entry);
		list_del(&buf->entry);
		free_buf(buf);
	}

	_free(conn->ppp.ses.chan_name);
	_free(conn->ctrl.calling_station_id);
	_free(conn->ctrl.called_station_id);

	mempool_free(conn);

	log_info2("sstp: disconnected\n");
}

static void sstp_start(struct sstp_conn_t *conn)
{
	log_debug("sstp: starting\n");

	if (serv.ssl_ctx)
		conn->stream = ssl_stream_init(conn->hnd.fd, serv.ssl_ctx);
	else
		conn->stream = stream_init(conn->hnd.fd);
	if (!conn->stream) {
		log_error("sstp: stream open error: %s\n", strerror(errno));
		goto error;
	}

	triton_md_register_handler(&conn->ctx, &conn->hnd);
	triton_md_enable_handler(&conn->hnd, MD_MODE_READ);

	log_info2("sstp: started\n");

	return;

error:
	sstp_disconnect(conn);
}

static int sstp_connect(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn;
	struct sockaddr_t addr;
	char addr_buf[ADDRSTR_MAXLEN];
	in_addr_t ip;
	int sock, value;

	while (1) {
		addr.len = sizeof(addr.u);
		sock = accept(h->fd, &addr.u.sa, &addr.len);
		if (sock < 0) {
			if (errno == EAGAIN)
				return 0;
			log_error("sstp: accept failed: %s\n", strerror(errno));
			continue;
		}

		if (ap_shutdown) {
			close(sock);
			continue;
		}

		if (conf_max_starting && ap_session_stat.starting >= conf_max_starting) {
			close(sock);
			continue;
		}

		if (conf_max_sessions && ap_session_stat.active + ap_session_stat.starting >= conf_max_sessions) {
			close(sock);
			continue;
		}

		ip = conf_proxyproto ? INADDR_ANY : sockaddr_ipv4(&addr);
		if (ip && triton_module_loaded("connlimit") && connlimit_check(cl_key_from_ipv4(ip))) {
			close(sock);
			continue;
		}

		sockaddr_ntop(&addr, addr_buf, sizeof(addr_buf), 0);
		log_info2("sstp: new connection from %s\n", addr_buf);

		if (ip && iprange_client_check(addr.u.sin.sin_addr.s_addr)) {
			log_warn("sstp: IP is out of client-ip-range, droping connection...\n");
			close(sock);
			continue;
		}

		value = fcntl(sock, F_GETFL);
		if (value < 0 || fcntl(sock, F_SETFL, value | O_NONBLOCK) < 0) {
			log_error("sstp: failed to set nonblocking mode: %s, closing connection...\n", strerror(errno));
			close(sock);
			continue;
		}

		if (addr.u.sa.sa_family != AF_UNIX) {
			if (conf_sndbuf &&
			    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &conf_sndbuf, sizeof(conf_sndbuf)) < 0) {
				log_error("sstp: failed to set send buffer to %d: %s, closing connection...\n",
					  conf_sndbuf, strerror(errno));
				close(sock);
				continue;
			}
			if (conf_rcvbuf &&
			    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &conf_rcvbuf, sizeof(conf_rcvbuf)) < 0) {
				log_error("sstp: failed to set recv buffer to %d: %s, closing connection...\n",
					  conf_rcvbuf, strerror(errno));
				close(sock);
				continue;
			}

			value = 1;
			if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) < 0) {
				log_error("sstp: failed to disable nagle: %s, closing connection...\n", strerror(errno));
				close(sock);
				continue;
			}
		}

		conn = mempool_alloc(conn_pool);
		memset(conn, 0, sizeof(*conn));

		conn->ctx.close = sstp_close;
		conn->ctx.before_switch = sstp_ctx_switch;
		conn->hnd.fd = sock;
		conn->hnd.read = conf_proxyproto ? sstp_recv : sstp_read;
		conn->hnd.write = sstp_write;

		conn->timeout_timer.expire = sstp_timeout;
		conn->timeout_timer.period = conf_timeout * 1000;
		conn->hello_timer.expire = sstp_msg_echo;
		conn->hello_interval = conf_hello_interval;

		conn->sstp_state = STATE_SERVER_CALL_DISCONNECTED;
		conn->ppp_state = STATE_INIT;
		conn->handler = conf_proxyproto ? proxy_handler : http_handler;

		//conn->bypass_auth = conf_bypass_auth;
		//conn->http_cookie = NULL:
		conn->nonce = _malloc(SSTP_NONCE_SIZE);
		conn->hlak_key = _malloc(SSTP_HLAK_SIZE);

		conn->in = alloc_buf(SSTP_MAX_PACKET_SIZE*2);
		INIT_LIST_HEAD(&conn->out_queue);
		INIT_LIST_HEAD(&conn->ppp_queue);
		INIT_LIST_HEAD(&conn->deferred_queue);
		memcpy(&conn->addr, &addr, sizeof(conn->addr));

		conn->ctrl.ctx = &conn->ctx;
		conn->ctrl.started = ppp_started;
		conn->ctrl.finished = ppp_finished;
		conn->ctrl.terminate = ppp_terminate;
		conn->ctrl.max_mtu = conf_ppp_max_mtu;
		conn->ctrl.type = CTRL_TYPE_SSTP;
		conn->ctrl.ppp = 1;
		conn->ctrl.ppp_npmode = NPMODE_DROP;
		conn->ctrl.name = "sstp";
		conn->ctrl.ifname = "";
		conn->ctrl.mppe = MPPE_DENY;

		ppp_init(&conn->ppp);
		conn->ppp.ses.ctrl = &conn->ctrl;
		conn->ppp.ses.chan_name = _strdup(addr_buf);
		if (conf_ip_pool)
			conn->ppp.ses.ipv4_pool_name = _strdup(conf_ip_pool);
		if (conf_ipv6_pool)
			conn->ppp.ses.ipv6_pool_name = _strdup(conf_ipv6_pool);
		if (conf_dpv6_pool)
			conn->ppp.ses.dpv6_pool_name = _strdup(conf_dpv6_pool);
		if (conf_ifname)
			conn->ppp.ses.ifname_rename = _strdup(conf_ifname);
		if (conf_session_timeout)
			conn->ppp.ses.session_timeout = conf_session_timeout;

		sockaddr_ntop(&addr, addr_buf, sizeof(addr_buf), FLAG_NOPORT);
		conn->ctrl.calling_station_id = _strdup(addr_buf);

		addr.len = sizeof(addr.u);
		getsockname(sock, &addr.u.sa, &addr.len);
		sockaddr_ntop(&addr, addr_buf, sizeof(addr_buf), FLAG_NOPORT);
		conn->ctrl.called_station_id = _strdup(addr_buf);

		triton_context_register(&conn->ctx, &conn->ppp.ses);
		triton_context_call(&conn->ctx, (triton_event_func)sstp_start, conn);
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);
		triton_context_wakeup(&conn->ctx);

		triton_event_fire(EV_CTRL_STARTING, &conn->ppp.ses);

		__sync_add_and_fetch(&stat_starting, 1);
	}

	return 0;
}

static void sstp_serv_close(struct triton_context_t *ctx)
{
	struct sstp_serv_t *serv = container_of(ctx, typeof(*serv), ctx);

	triton_md_unregister_handler(&serv->hnd, 1);
	triton_context_unregister(ctx);

	if (serv->ssl_ctx)
		SSL_CTX_free(serv->ssl_ctx);
	serv->ssl_ctx = NULL;

	if (serv->addr.u.sa.sa_family == AF_UNIX && serv->addr.u.sun.sun_path[0])
		unlink(serv->addr.u.sun.sun_path);
}

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static int ssl_servername(SSL *ssl, int *al, void *arg)
{
	const char *servername;

	if (!conf_hostname)
		return SSL_TLSEXT_ERR_OK;

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (conf_verbose) {
		log_ppp_info2("sstp: recv [SSL <%s%s>]\n",
			      servername ? "SNI " : "no SNI", servername ? : "");
	}

	if (strcasecmp(servername ? : "", conf_hostname) != 0)
		return SSL_TLSEXT_ERR_ALERT_FATAL;

	return SSL_TLSEXT_ERR_OK;
}
#endif

#ifndef SSL_OP_NO_RENEGOTIATION
#if OPENSSL_VERSION_NUMBER < 0x10100000L && defined(SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)
static void ssl_info_cb(const SSL *ssl, int where, int ret)
{
	if (where & SSL_CB_HANDSHAKE_DONE) {
		/* disable renegotiation (CVE-2009-3555) */
		ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
	}
}
#endif
#endif

static void ssl_set_cert_hashes(const X509 *cert) {
	if (conf_hash_protocol & CERT_HASH_PROTOCOL_SHA1)
		X509_digest(cert, EVP_sha1(), conf_hash_sha1.hash, &conf_hash_sha1.len);
	if (conf_hash_protocol & CERT_HASH_PROTOCOL_SHA256)
		X509_digest(cert, EVP_sha256(), conf_hash_sha256.hash, &conf_hash_sha256.len);
}

static void ssl_load_config(struct sstp_serv_t *serv, const char *servername)
{
	SSL_CTX *old_ctx, *ssl_ctx = NULL;
	X509 *cert = NULL;
	BIO *in = NULL;
	char *opt;

	opt = conf_get_opt("sstp", "accept");
	if (opt && strhas(opt, "ssl", ',')) {
	legacy_ssl:
		ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (!ssl_ctx) {
			log_error("sstp: %s error: %s\n", "SSL_CTX_new", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL |
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
				SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS |
#endif
#ifdef SSL_OP_NO_RENGOTIATION
				SSL_OP_NO_RENGOTIATION |
#endif
#ifndef OPENSSL_NO_DH
				SSL_OP_SINGLE_DH_USE |
#endif
#ifndef OPENSSL_NO_ECDH
				SSL_OP_SINGLE_ECDH_USE |
#endif
#ifdef OPENSSL_NO_SSL2
				SSL_OP_NO_SSLv2 |
#endif
#ifdef OPENSSL_NO_SSL3
				SSL_OP_NO_SSLv3 |
#endif
				SSL_OP_NO_COMPRESSION);
		SSL_CTX_set_mode(ssl_ctx,
				SSL_MODE_ENABLE_PARTIAL_WRITE);
		SSL_CTX_set_read_ahead(ssl_ctx, 1);

		opt = conf_get_opt("sstp", "ssl-protocol");
		if (opt) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			SSL_CTX_set_min_proto_version(ssl_ctx, 0);
			SSL_CTX_set_max_proto_version(ssl_ctx, 0);
#endif
			if (strhas(opt, "ssl2", ','))
#if defined(OPENSSL_NO_SSL2) || OPENSSL_VERSION_NUMBER >= 0x10100000L
				log_warn("sstp: %s warning: %s is not suported\n", "ssl-protocol", "SSLv2");
#else
				SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_SSLv2);
			else
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
#endif
			if (strhas(opt, "ssl3", ','))
#ifdef OPENSSL_NO_SSL3
				log_warn("sstp: %s warning: %s is not suported\n", "ssl-protocol", "SSLv3");
#else
				SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_SSLv3);
			else
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv3);
#endif
			if (strhas(opt, "tls1", ','))
				SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TLSv1);
			else
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1);
			if (strhas(opt, "tls11", ',') || strhas(opt, "tls1.1", ','))
#ifndef SSL_OP_NO_TLSv1_1
				log_warn("sstp: %s warning: %s is not suported\n", "ssl-protocol", "TLSv1.1");
#else
				SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
			else
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
#endif
			if (strhas(opt, "tls12", ',') || strhas(opt, "tls1.2", ','))
#ifndef SSL_OP_NO_TLSv1_2
				log_warn("sstp: %s warning: %s is not suported\n", "ssl-protocol", "TLSv1.2");
#else
				SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
			else
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
#endif
			if (strhas(opt, "tls13", ',') || strhas(opt, "tls1.3", ','))
#ifndef SSL_OP_NO_TLSv1_3
				log_warn("sstp: %s warning: %s is not suported\n", "ssl-protocol", "TLSv1.3");
#else
				SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TLSv1_3);
			else
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_3);
#endif
		}

		opt = conf_get_opt("sstp", "ssl-dhparam");
		if (opt) {
#ifdef OPENSSL_NO_DH
			log_warn("sstp: %s warning: %s is not suported\n", "ssl-protocol", "DH");
#else
			DH *dh;

			in = BIO_new(BIO_s_file());

			if (BIO_read_filename(in, opt) <= 0) {
				log_error("sstp: %s error: %s\n", "ssl-dhparam", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}

			dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
			if (dh == NULL) {
				log_error("sstp: %s error: %s\n", "ssl-dhparam", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}

			if (!BIO_free(in))
				abort();
			in = NULL;

			SSL_CTX_set_tmp_dh(ssl_ctx, dh);
			DH_free(dh);
#endif
		}

		opt = conf_get_opt("sstp", "ssl-ecdh-curve");
#ifdef OPENSSL_NO_ECDH
		if (opt)
			log_warn("sstp: %s warning: %s is not suported\n", "ssl-protocol", "ECDH");
#else
		{
#if defined(SSL_CTX_set1_curves_list) || defined(SSL_CTRL_SET_CURVES_LIST)
#ifdef SSL_CTRL_SET_ECDH_AUTO
			/* not needed in OpenSSL 1.1.0+ */
			SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#endif
			if (opt && SSL_CTX_set1_curves_list(ssl_ctx, opt) == 0) {
				log_error("sstp: %s error: %s\n", "ssl-ecdh-curve", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}
#else
			EC_KEY *ecdh;
			int nid;

			nid = OBJ_sn2nid(opt ? : "prime256v1");
			if (nid == 0) {
				log_error("sstp: %s error: %s\n", "ssl-ecdh-curve", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}

			ecdh = EC_KEY_new_by_curve_name(nid);
			if (ecdh == NULL) {
				log_error("sstp: %s error: %s\n", "ssl-ecdh-curve", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}

			SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
			EC_KEY_free(ecdh);
#endif
		}
#endif

		opt = conf_get_opt("sstp", "ssl-ciphers");
		if (opt && SSL_CTX_set_cipher_list(ssl_ctx, opt) != 1) {
			log_error("sstp: %s error: %s\n", "ssl-ciphers", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		opt = conf_get_opt("sstp", "ssl-prefer-server-ciphers");
		if (opt && atoi(opt))
			SSL_CTX_set_options(ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

		opt = conf_get_opt("sstp", "ssl-pemfile");
		if (opt) {
			if (SSL_CTX_use_certificate_chain_file(ssl_ctx, opt) != 1) {
				log_error("sstp: %s error: %s\n", "ssl-pemfile", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}
			// cert is a reference. Do not free it.
			X509 *cert_ref = SSL_CTX_get0_certificate(ssl_ctx);
			if (!cert_ref) {
				log_error("sstp: %s error: %s\n", "ssl-pemfile", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}
			ssl_set_cert_hashes(cert_ref);
		}
		opt = conf_get_opt("sstp", "ssl-keyfile") ? : opt;
		if ((opt && SSL_CTX_use_PrivateKey_file(ssl_ctx, opt, SSL_FILETYPE_PEM) != 1) ||
		    SSL_CTX_check_private_key(ssl_ctx) != 1) {
			log_error("sstp: %s error: %s\n", "ssl-keyfile", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		opt = conf_get_opt("sstp", "ssl-ca-file");
		if (opt && SSL_CTX_load_verify_locations(ssl_ctx, opt, NULL) != 1) {
			log_error("sstp: %s error: %s\n", "ssl-ca-file", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
		if (servername && SSL_CTX_set_tlsext_servername_callback(ssl_ctx, ssl_servername) != 1)
			log_warn("sstp: %s error: %s\n", "host-name", ERR_error_string(ERR_get_error(), NULL));
#endif

#ifndef SSL_OP_NO_RENEGOTIATION
#if OPENSSL_VERSION_NUMBER < 0x10100000L && defined(SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)
		SSL_CTX_set_info_callback(ssl_ctx, ssl_info_cb);
#endif
#endif
	} else {
		/* legacy option, to be removed */
		opt = conf_get_opt("sstp", "ssl");
		if (opt && atoi(opt) > 0)
			goto legacy_ssl;

		opt = conf_get_opt("sstp", "ssl-pemfile");
		if (opt) {
			in = BIO_new(BIO_s_file());
			if (!in) {
				log_error("sstp: %s error: %s\n", "ssl-pemfile", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}

			if (BIO_read_filename(in, opt) <= 0) {
				log_error("sstp: %s error: %s\n", "ssl-pemfile", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}

			cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
			if (!cert) {
				log_error("sstp: %s error: %s\n", "ssl-pemfile", ERR_error_string(ERR_get_error(), NULL));
				goto error;
			}
			if (!BIO_free(in))
				abort();
			in = NULL;
			ssl_set_cert_hashes(cert);
		}
	}

	old_ctx = serv->ssl_ctx;
	serv->ssl_ctx = ssl_ctx;
	ssl_ctx = old_ctx;

error:
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	if (cert)
		X509_free(cert);
	if (in && !BIO_free(in))
		abort();
}

static void ev_mppe_keys(struct ev_mppe_keys_t *ev)
{
	struct ppp_t *ppp = ev->ppp;
	struct sstp_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	if (ppp->ses.ctrl->type != CTRL_TYPE_SSTP)
		return;

	if (conn->hlak_key) {
		memcpy(conn->hlak_key, ev->recv_key, 16);
		memcpy(conn->hlak_key + 16, ev->send_key, 16);
	}
}

static void ev_ses_authorized(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct sstp_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	if (ppp->ses.ctrl->type != CTRL_TYPE_SSTP)
		return;

	switch (conn->ppp_state) {
	case STATE_STARTING:
		conn->ppp_state = STATE_AUTHORIZED;
		sstp_read_deferred(conn);
		break;
	}
}

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "sstp:\r\n");
	cli_sendv(client,"  starting: %u\r\n", stat_starting);
	cli_sendv(client,"  active: %u\r\n", stat_active);

	return CLI_CMD_OK;
}

void __export sstp_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static void load_config(void)
{
	int ipmode;
	char *opt;

	opt = conf_get_opt("sstp", "verbose");
	if (opt && atoi(opt) >= 0)
		conf_verbose = atoi(opt) > 0;

	conf_hostname = conf_get_opt("sstp", "host-name");

	opt = conf_get_opt("sstp", "http-error");
	if (opt) {
		if (strcmp(opt, "deny") == 0)
			conf_http_mode = HTTP_ERR_DENY;
		else if (strcmp(opt, "allow") == 0)
			conf_http_mode = HTTP_ERR_ALLOW;
		else if (strstr(opt, "://") != NULL) {
			conf_http_url = opt;
			opt = strstr(opt, "://") + 3;
			while (*opt == '/')
				opt++;
			conf_http_mode = strchr(opt, '/') ? HTTP_ERR_REDIRECT : HTTP_ERR_REDIRECT_APPEND;
		}
	}

	opt = conf_get_opt("sstp", "cert-hash-proto");
	if (opt) {
		conf_hash_protocol = 0;
		if (strhas(opt, "sha1", ','))
			conf_hash_protocol |= CERT_HASH_PROTOCOL_SHA1;
		if (strhas(opt, "sha256", ','))
			conf_hash_protocol |= CERT_HASH_PROTOCOL_SHA256;
	}

	opt = conf_get_opt("sstp", "accept");
	conf_proxyproto = opt && strhas(opt, "proxy", ',');

	ssl_load_config(&serv, conf_hostname);
	opt = serv.ssl_ctx ? "enabled" : "disabled";

	if (conf_verbose) {
		log_info2("sstp: SSL/TLS support %s, PROXY support %s\n",
				opt, conf_proxyproto ? "enabled" : "disabled");
	}

	opt = conf_get_opt("sstp", "cert-hash-sha1");
	if (opt) {
		conf_hash_sha1.len = hex2bin(opt,
				conf_hash_sha1.hash, sizeof(conf_hash_sha1.hash));
	}

	opt = conf_get_opt("sstp", "cert-hash-sha256");
	if (opt) {
		conf_hash_sha256.len = hex2bin(opt,
				conf_hash_sha256.hash, sizeof(conf_hash_sha256.hash));
	}

	opt = conf_get_opt("sstp", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("sstp", "hello-interval");
	if (opt && atoi(opt) >= 0)
		conf_hello_interval = atoi(opt);

	opt = conf_get_opt("sstp", "ppp-max-mtu");
	if (opt && atoi(opt) > 0)
		conf_ppp_max_mtu = atoi(opt);

	conf_ip_pool = conf_get_opt("sstp", "ip-pool");
	conf_ipv6_pool = conf_get_opt("sstp", "ipv6-pool");
	conf_dpv6_pool = conf_get_opt("sstp", "ipv6-pool-delegate");
	conf_ifname = conf_get_opt("sstp", "ifname");

	opt = conf_get_opt("sstp", "sndbuf");
	if (opt && atoi(opt) > 0)
		conf_sndbuf = atoi(opt);

	opt = conf_get_opt("sstp", "rcvbuf");
	if (opt && atoi(opt) > 0)
		conf_rcvbuf = atoi(opt);

	opt = conf_get_opt("sstp", "session-timeout");
	if (opt)
		conf_session_timeout = atoi(opt);
	else
		conf_session_timeout = 0;

	ipmode = (serv.addr.u.sa.sa_family == AF_INET && !conf_proxyproto) ?
			iprange_check_activation() : -1;
	switch (ipmode) {
	case IPRANGE_DISABLED:
		log_warn("sstp: iprange module disabled, improper IP configuration of PPP interfaces may cause kernel soft lockup\n");
		break;
	case IPRANGE_NO_RANGE:
		log_warn("sstp: no IP address range defined in section [%s], incoming sstp connections will be rejected\n",
			 IPRANGE_CONF_SECTION);
		break;
	case -1:
	default:
		/* Makes compiler happy */
		break;
	}
}

static struct sstp_serv_t serv = {
	.hnd.read = sstp_connect,
	.ctx.close = sstp_serv_close,
	.ctx.before_switch = sstp_ctx_switch,
};

static void sstp_init(void)
{
	struct sockaddr_t *addr = &serv.addr;
	struct linger linger;
	struct stat st;
	int port, value;
	char *opt;

	opt = conf_get_opt("sstp", "port");
	if (opt && atoi(opt) > 0)
		port = atoi(opt);
	else
		port = SSTP_PORT;

	opt = conf_get_opt("sstp", "bind");
	if (opt && strncmp(opt, "unix:", sizeof("unix:") - 1) == 0) {
		addr->len = sizeof(addr->u.sun);
		addr->u.sun.sun_family = AF_UNIX;
		snprintf(addr->u.sun.sun_path, sizeof(addr->u.sun.sun_path), "%s", opt + sizeof("unix:") - 1);
		/* abstract socket support */
		if (addr->u.sun.sun_path[0] == '@')
			addr->u.sun.sun_path[0] = '\0';
	} else if (opt && inet_pton(AF_INET6, opt, &addr->u.sin6.sin6_addr) > 0) {
		addr->len = sizeof(addr->u.sin6);
		addr->u.sin6.sin6_family = AF_INET6;
		addr->u.sin6.sin6_port = htons(port);
	} else {
		addr->len = sizeof(addr->u.sin);		
		addr->u.sin.sin_family = AF_INET;
		if (!opt || inet_pton(AF_INET, opt, &addr->u.sin.sin_addr) <= 0)
			addr->u.sin.sin_addr.s_addr = htonl(INADDR_ANY);
		addr->u.sin.sin_port = htons(port);
	}

	serv.hnd.fd = socket(addr->u.sa.sa_family, SOCK_STREAM, 0);
	if (serv.hnd.fd < 0) {
		log_emerg("sstp: failed to create server socket: %s\n", strerror(errno));
		return;
	}

	value = fcntl(serv.hnd.fd, F_GETFD);
	if (value < 0 || fcntl(serv.hnd.fd, F_SETFD, value | FD_CLOEXEC) < 0) {
		log_emerg("sstp: failed to set socket flags: %s\n", strerror(errno));
		goto error_close;
	}

	if (addr->u.sa.sa_family == AF_UNIX) {
		if (addr->u.sun.sun_path[0] &&
		    stat(addr->u.sun.sun_path, &st) == 0 && S_ISSOCK(st.st_mode)) {
			unlink(addr->u.sun.sun_path);
		}
	} else {
		value = 1;
		setsockopt(serv.hnd.fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));

		/* quick timeout */
		linger.l_onoff = 1;
		linger.l_linger = 5;
		setsockopt(serv.hnd.fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
	}

	if (bind(serv.hnd.fd, &addr->u.sa, addr->len) < 0) {
		log_emerg("sstp: failed to bind socket: %s\n", strerror(errno));
		goto error_close;
	}

	if (addr->u.sa.sa_family == AF_UNIX && addr->u.sun.sun_path[0] &&
	    chmod(addr->u.sun.sun_path,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) < 0) {
		log_warn("sstp: failed to set socket permissions: %s\n", strerror(errno));
	}

	if (listen(serv.hnd.fd, 10) < 0) {
		log_emerg("sstp: failed to listen socket: %s\n", strerror(errno));
		goto error_unlink;
	}

	value = fcntl(serv.hnd.fd, F_GETFL);
	if (fcntl(serv.hnd.fd, F_SETFL, value | O_NONBLOCK)) {
		log_emerg("sstp: failed to set nonblocking mode: %s\n", strerror(errno));
		goto error_unlink;
	}

	conn_pool = mempool_create(sizeof(struct sstp_conn_t));

	load_config();

	triton_context_register(&serv.ctx, NULL);
	triton_md_register_handler(&serv.ctx, &serv.hnd);
	triton_md_enable_handler(&serv.hnd, MD_MODE_READ);
	triton_context_wakeup(&serv.ctx);

	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");

	triton_event_register_handler(EV_MPPE_KEYS, (triton_event_func)ev_mppe_keys);
	triton_event_register_handler(EV_SES_AUTHORIZED, (triton_event_func)ev_ses_authorized);
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
	return;

error_unlink:
	if (addr->u.sa.sa_family == AF_UNIX && addr->u.sun.sun_path[0])
		unlink(addr->u.sun.sun_path);
error_close:
	close(serv.hnd.fd);
}

DEFINE_INIT(20, sstp_init);
