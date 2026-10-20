/*
 * LD_PRELOAD shim for the shutdown test: delays an L2TP CDN sent to UDP port
 * CDN_SHIM_PORT by CDN_SHIM_DELAY_MS, so the downstream teardown hop is still
 * in flight when the rest of the daemon believes it has nothing left to do.
 *
 * Other datagrams, and the real sendto() itself, are untouched.
 *
 *   gcc -shared -fPIC -O1 -o cdn_delay_shim.so cdn_delay_shim.c -ldl
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

#define L2TP_HDR_LEN		12	/* T/L/S flags, length, tid, sid, Ns, Nr */
#define MSG_TYPE_AVP_VAL	(L2TP_HDR_LEN + 6)
#define MESSAGE_TYPE_CDN	14

/* the Message-Type AVP is the first one of every control message */
static int is_cdn(const void *buf, size_t len)
{
	const unsigned char *p = buf;

	if (len < MSG_TYPE_AVP_VAL + 2 || !(p[0] & 0x80))
		return 0;
	return ((p[MSG_TYPE_AVP_VAL] << 8) | p[MSG_TYPE_AVP_VAL + 1]) ==
	       MESSAGE_TYPE_CDN;
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
	       const struct sockaddr *addr, socklen_t alen)
{
	static ssize_t (*real_sendto)(int, const void *, size_t, int,
				      const struct sockaddr *, socklen_t);
	const char *port = getenv("CDN_SHIM_PORT");
	const char *delay = getenv("CDN_SHIM_DELAY_MS");

	if (!real_sendto)
		real_sendto = dlsym(RTLD_NEXT, "sendto");

	if (port && delay && addr && addr->sa_family == AF_INET &&
	    ntohs(((const struct sockaddr_in *)addr)->sin_port) == atoi(port) &&
	    is_cdn(buf, len)) {
		long ms = atol(delay);
		struct timespec ts = { .tv_sec = ms / 1000,
				       .tv_nsec = (ms % 1000) * 1000000L };

		nanosleep(&ts, NULL);
	}

	return real_sendto(fd, buf, len, flags, addr, alen);
}
