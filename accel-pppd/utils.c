#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "triton.h"
#include "utils.h"

#include "memdebug.h"

extern int urandom_fd;

/* Convenient wrapper around inet_ntop() to print IPv6 addresses.
 * It stores a string representation of addr into buf, which must be at
 * least INET6_ADDRSTRLEN bytes long.
 *
 * Returns buf, which is guaranteed to contain a valid string even if an error
 * occured.
 */
char __export *u_ip6str(const struct in6_addr *addr, char *buf)
{
	if (!inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN))
		snprintf(buf, INET6_ADDRSTRLEN, "< ERROR! >");

	return buf;
}

/* Convenient wrapper around inet_ntop() to print IPv4 addresses.
 * It stores a string representation of addr into buf, which must be at
 * least INET_ADDRSTRLEN bytes long.
 *
 * Returns buf, which is guaranteed to contain a valid string even if an error
 * occured.
 */
char __export *u_ip4str(const struct in_addr *addr, char *buf)
{
	if (!inet_ntop(AF_INET, addr, buf, INET_ADDRSTRLEN))
		snprintf(buf, INET_ADDRSTRLEN, "< ERROR! >");

	return buf;
}

void __export u_inet_ntoa(in_addr_t addr, char *str)
{
	addr = ntohl(addr);
	sprintf(str, "%i.%i.%i.%i", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
}

int __export u_readlong(long int *dst, const char *src,
                        long int min, long int max)
{
        char *src_stop = NULL;
        long int rv;

        if (dst == NULL || src == NULL || src[0] == '\0')
                return -1;

        errno = 0;
        rv = strtol(src, &src_stop, 0);
        if (errno != 0 || *src_stop != '\0' || rv < min || rv > max) {
                return -1;
        } else {
                *dst = rv;
                return 0;
        }
}

/* Parse spaces.
 * Returns the number of leading space characters in str.
 * This is a convenient function around strspn() which preserves the look and
 * feel of other u_parse_*() functions.
 */
size_t __export u_parse_spaces(const char *str)
{
	return strspn(str, " ");
}

/* Parse end of string.
 * Reads a sequence of space characters, followed by the end-of-string
 * mark ('\0').
 * Returns the number of characters parsed on success (that is, the number of
 * space characters plus one for '\0'). Beware that 'str + u_parse_endstr(str)'
 * points to the next byte after the end of the string in this case.
 * Returns 0 if parsing fails (that is, if unexpected characers are found
 * before the end of the string).
 */
size_t __export u_parse_endstr(const char *str)
{
	const char *end;

	end = str + strspn(str, " ");
	if (*end != '\0')
		return 0;

	++end;

	return end - str;
}

/* Parse an 8 bits unsigned integer in base 10.
 * Returns the number of bytes parsed on success.
 * Returns 0 if str doesn't start with a valid number or if this number doesn't
 * fit in 8 bits.
 */
size_t __export u_parse_u8(const char *str, uint8_t *val)
{
	char *endptr;
	unsigned long ul;

	/* strtoul() handles leading signs (+/-) and white spaces. Make sure we
	 * parse raw numbers.
	 */
	if (!isdigit(*str))
		return 0;

	ul = strtoul(str, &endptr, 10);
	if (ul > UINT8_MAX)
		return 0;

	*val = ul;

	return endptr - str;
}

/* Parse a 16 bits unsigned integer in base 10.
 * Returns the number of bytes parsed on success.
 * Returns 0 if str doesn't start with a valid number or if this number doesn't
 * fit in 16 bits.
 */
size_t __export u_parse_u16(const char *str, uint16_t *val)
{
	char *endptr;
	unsigned long ul;

	/* strtoul() handles leading signs (+/-) and white spaces. Make sure we
	 * parse raw numbers.
	 */
	if (!isdigit(*str))
		return 0;

	ul = strtoul(str, &endptr, 10);
	if (ul > UINT16_MAX)
		return 0;

	*val = ul;

	return endptr - str;
}

/* Parse a 32 bits unsigned integer in base 10.
 * Returns the number of bytes parsed on success.
 * Returns 0 if str doesn't start with a valid number or if this number doesn't
 * fit in 32 bits.
 */
size_t __export u_parse_u32(const char *str, uint32_t *val)
{
	char *endptr;
	unsigned long ul;

	/* strtoul() handles leading signs (+/-) and white spaces. Make sure we
	 * parse raw numbers.
	 */
	if (!isdigit(*str))
		return 0;

	errno = 0;
	ul = strtoul(str, &endptr, 10);
	/* On platforms where unsigned longs are 32 bits wide, overflows would
	 * return a valid UINT32_MAX value. So we need to check for ERANGE too.
	 */
	if (errno == ERANGE || ul > UINT32_MAX)
		return 0;

	*val = ul;

	return endptr - str;
}

/* Parse an IPv6 address (for example "2001:db8::1").
 * Returns the number of bytes parsed, or 0 if str doesn't start with an IPv6
 * address.
 */
size_t __export u_parse_ip6addr(const char *str, struct in6_addr *addr)
{
	char buf[INET6_ADDRSTRLEN];
	size_t len;

	len = strspn(str, ":0123456789abcdef");
	if (!len || len >= sizeof(buf))
		return 0;

	memcpy(buf, str, len);
	buf[len] = '\0';

	if (inet_pton(AF_INET6, buf, addr) != 1)
		return 0;

	return len;
}

/* Parse an IPv4 address in dotted-decimal format (for example "198.51.100.1").
 * Other formats (hex "0xc6.0x33.0x64.0x1", octal "0306.063.0144.01", mixed
 * "0xc6.51.0144.1", non dotted-quad "198.51.25601"...) are rejected.
 *
 * Returns the number of bytes parsed, or 0 if str doesn't start with an IPv4
 * address.
 */
size_t __export u_parse_ip4addr(const char *str, struct in_addr *addr)
{
	char buf[INET_ADDRSTRLEN];
	size_t len;

	len = strspn(str, ".0123456789");
	if (!len || len >= sizeof(buf))
		return 0;

	memcpy(buf, str, len);
	buf[len] = '\0';

	if (inet_pton(AF_INET, buf, addr) != 1)
		return 0;

	return len;
}

/* Parse an IPv6 network prefix in CIDR notation (for example "2001:db8::/32").
 * Returns the number of bytes parsed, or 0 if str doesn't start with an IPv6
 * network prefix.
 */
size_t __export u_parse_ip6cidr(const char *str, struct in6_addr *netp, uint8_t *plen)
{
	const char *ptr = str;
	size_t len;

	len = u_parse_ip6addr(ptr, netp);
	if (!len)
		return 0;

	ptr += len;
	if (*ptr != '/')
		return 0;

	len = u_parse_u8(++ptr, plen);
	if (!len)
		return 0;

	if (*plen > 128)
		return 0;

	ptr += len;

	return ptr - str;
}

/* Parse an IPv4 network prefix in CIDR notation (for example "192.0.2.0/24").
 * The IP address must be in dotted-decimal format.
 * Returns the number of bytes parsed, or 0 if str doesn't start with an IPv4
 * network prefix.
 */
size_t __export u_parse_ip4cidr(const char *str, struct in_addr *netp, uint8_t *plen)
{
	const char *ptr = str;
	size_t len;

	len = u_parse_ip4addr(ptr, netp);
	if (!len)
		return 0;

	ptr += len;
	if (*ptr != '/')
		return 0;

	len = u_parse_u8(++ptr, plen);
	if (!len)
		return 0;

	if (*plen > 32)
		return 0;

	ptr += len;

	return ptr - str;
}

/* Parse an IPv4 address range (for example "192.0.2.0-255").
 * The IP address must be in dotted-decimal format. The number following '-'
 * is the upper bound of the address' least significant byte (the lower bound
 * is given by the address itself). The upper bound must be bigger or equal
 * than the lower bound.
 *
 * Returns the number of bytes parsed, or 0 if str doesn't start with an IPv4
 * address range.
 */
size_t __export u_parse_ip4range(const char *str, struct in_addr *base_ip, uint8_t *max)
{
	const char *ptr = str;
	size_t len;

	len = u_parse_ip4addr(ptr, base_ip);
	if (!len)
		return 0;

	ptr += len;
	if (*ptr != '-')
		return 0;

	len = u_parse_u8(++ptr, max);
	if (!len)
		return 0;

	if (*max < (ntohl(base_ip->s_addr) & 0xff))
		return 0;

	ptr += len;

	return ptr - str;
}

int __export u_randbuf(void *buf, size_t buf_len, int *err)
{
	uint8_t *u8buf = buf;
	ssize_t rd_len;

	while (buf_len) {
		rd_len = read(urandom_fd, u8buf, buf_len);
		if (rd_len < 0) {
			if (errno == EINTR)
				rd_len = 0;
			else {
				if (err)
					*err = errno;
				return -1;
			}
		} else if (rd_len == 0) {
			if (err)
				*err = 0;
			return -1;
		}
		u8buf += rd_len;
		buf_len -= rd_len;
	}

	return 0;
}

int __export u_match_regex(const pcre2_code *re, const char *str)
{
	pcre2_match_data *match_data = pcre2_match_data_create(0, NULL);
	int rc;

	if (!match_data)
		return 0;

	rc = pcre2_match(re, (PCRE2_SPTR)str, strlen(str), 0, 0, match_data, NULL);
	pcre2_match_data_free(match_data);

	return rc >= 0;
}
