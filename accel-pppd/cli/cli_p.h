#ifndef __CLI_P_H
#define __CLI_P_H

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "triton.h"

struct cli_client_t
{
	uint8_t *cmdline;
	int (*send)(struct cli_client_t *, const void *buf, int size);
	int (*sendv)(struct cli_client_t *, const char *fmt, va_list ap);
	void (*disconnect)(struct cli_client_t *);
};

int cli_process_cmd(struct cli_client_t *cln);

/* Format peer address (IPv4, IPv6 or IPv4-mapped IPv6) for logging.
 * buf must be at least INET6_ADDRSTRLEN bytes long. */
static inline const char *cli_addr_str(const struct sockaddr_storage *addr,
				       char *buf, size_t size)
{
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
	const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

	buf[0] = '\0';
	if (addr->ss_family == AF_INET6) {
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
			inet_ntop(AF_INET, &sin6->sin6_addr.s6_addr32[3], buf, size);
		else
			inet_ntop(AF_INET6, &sin6->sin6_addr, buf, size);
	} else
		inet_ntop(AF_INET, &sin->sin_addr, buf, size);

	return buf;
}

/* Parse "host:port", "[host]:port" or ":port" listener specification.
 * str is modified in place, *host points into str afterwards (NULL for
 * empty host). For unbracketed hosts the last ':' separates the port,
 * so bare IPv6 addresses like "::1:2001" are accepted too.
 * Returns 0 on success, -1 on invalid format. */
static inline int cli_parse_hostport(char *str, const char **host, int *port)
{
	char *d;

	if (*str == '[') {
		++str;
		d = strchr(str, ']');
		if (!d || d[1] != ':')
			return -1;
		*d++ = '\0';
	} else {
		d = strrchr(str, ':');
		if (!d)
			return -1;
	}

	*d = '\0';
	*port = atoi(d + 1);
	if (*port <= 0)
		return -1;

	*host = *str ? str : NULL;

	return 0;
}

/* Fill sockaddr for binding a CLI listener. host may be an IPv4 or IPv6
 * address; NULL host means any IPv4 address (use "::" for IPv6 wildcard).
 * Returns 0 on success, -1 if host is not a valid address. */
static inline int cli_bind_addr(const char *host, int port,
				struct sockaddr_storage *addr, socklen_t *len)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;

	memset(addr, 0, sizeof(*addr));

	if (host && inet_pton(AF_INET6, host, &sin6->sin6_addr) > 0) {
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		*len = sizeof(*sin6);
	} else {
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		if (!host)
			sin->sin_addr.s_addr = htonl(INADDR_ANY);
		else if (inet_pton(AF_INET, host, &sin->sin_addr) <= 0)
			return -1;
		*len = sizeof(*sin);
	}

	return 0;
}

extern char *conf_cli_passwd;
extern char *conf_cli_prompt;

#endif

