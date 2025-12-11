#ifndef __UTILS_H
#define __UTILS_H

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include <netinet/in.h>
#include <stdint.h>

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

int u_randbuf(void *buf, size_t buf_len, int *err);

pcre2_code *u_compile_interface_regex(const char *opt_str, const char *prefix, const char **endptr_out, char *err_buf, size_t err_buf_len);
int u_match_regex(const pcre2_code *re, const char *str);

#endif
