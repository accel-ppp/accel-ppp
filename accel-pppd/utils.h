#ifndef __UTILS_H
#define __UTILS_H

#include <endian.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

/*
 * Fixed-size memcpy() lets the compiler emit efficient unaligned accesses on
 * architectures that support them without imposing alignment or aliasing
 * requirements on callers.
 */
static inline uint16_t u_read_be16(const void *ptr)
{
	uint16_t value;

	memcpy(&value, ptr, sizeof(value));
	return ntohs(value);
}

static inline uint32_t u_read_be32(const void *ptr)
{
	uint32_t value;

	memcpy(&value, ptr, sizeof(value));
	return ntohl(value);
}

static inline uint64_t u_read_be64(const void *ptr)
{
	uint64_t value;

	memcpy(&value, ptr, sizeof(value));
	return be64toh(value);
}

static inline void u_write_be16(void *ptr, uint16_t value)
{
	value = htons(value);
	memcpy(ptr, &value, sizeof(value));
}

static inline void u_write_be32(void *ptr, uint32_t value)
{
	value = htonl(value);
	memcpy(ptr, &value, sizeof(value));
}

static inline void u_write_be64(void *ptr, uint64_t value)
{
	value = htobe64(value);
	memcpy(ptr, &value, sizeof(value));
}

static inline uint16_t u_read_native16(const void *ptr)
{
	uint16_t value;

	memcpy(&value, ptr, sizeof(value));
	return value;
}

static inline uint32_t u_read_native32(const void *ptr)
{
	uint32_t value;

	memcpy(&value, ptr, sizeof(value));
	return value;
}

static inline uint64_t u_read_native64(const void *ptr)
{
	uint64_t value;

	memcpy(&value, ptr, sizeof(value));
	return value;
}

char *u_ip6str(const struct in6_addr *addr, char *buf);
char *u_ip4str(const struct in_addr *addr, char *buf);

void u_inet_ntoa(in_addr_t, char *str);
int u_readlong(long int *dst, const char *src, long int min, long int max);

size_t u_parse_spaces(const char *str);
size_t u_parse_endstr(const char *str);

size_t u_parse_u8(const char *str, uint8_t *val);
size_t u_parse_u16(const char *str, uint16_t *val);
size_t u_parse_u32(const char *str, uint32_t *val);

size_t u_parse_ip6addr(const char *str, struct in6_addr *addr);
size_t u_parse_ip4addr(const char *str, struct in_addr *addr);

size_t u_parse_ip6cidr(const char *str, struct in6_addr *netp, uint8_t *plen);
size_t u_parse_ip4cidr(const char *str, struct in_addr *netp, uint8_t *plen);
size_t u_parse_ip4range(const char *str, struct in_addr *base_ip, uint8_t *max);

void u_strstrip(char *str, char c);
int u_randbuf(void *buf, size_t buf_len, int *err);

#endif
