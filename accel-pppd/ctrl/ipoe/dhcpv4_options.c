#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "dhcpv4.h"

struct known_option
{
	int type;
	int min_len;
	int max_len;
	int elem_size;
	const char *name;
	void (*print)(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
};

static void print_int(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
static void print_uint(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
static void print_ip(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
static void print_str(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
static void print_hex(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
static void print_route(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
static void print_classless_route(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
static void print_message_type(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
static void print_request_list(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));
static void print_relay_agent(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...));

static struct known_option options[] = {
	{   1,  4,   4,  4, "Subnet", print_ip },
	{   2,  4,   4,  4, "Time-Offset", print_int },
	{   3,  4, 255,  4, "Router", print_ip },
	{   4,  4, 255,  4, "Time-Server", print_ip },
	{   5,  4, 255,  4, "Name-Server", print_ip },
	{   6,  4, 255,  4, "DNS", print_ip },
	//{   7,  4, 255,  4, "log-server", print_ip },
	//{   8,  4, 255,  4, "cookie-server", print_ip },
	//{   9,  4, 255,  4, "lpr-server", print_ip },
	//{  10,  4, 255,  4, "impress-server", print_ip },
	//{  11,  4, 255,  4, "resourse-location", print_ip },
	{  12,  1, 255,  1, "Host-Name", print_str },
	//{  13,  4, 255,  4, "impress-server", print_ip },
	{  15,  1, 255,  1, "Domain-Name", print_str },
	{  26,  2,   2,  2, "MTU", print_int },
	{  28,  4,   4,  4, "Broadcast", print_ip },
	{  33,  8, 255,  8, "Route", print_route },
	{  42,  4,   4,  4, "NTP", print_ip },
	{  43,  1, 255,  1, "Vendor-Specific", print_hex },
	{  50,  4,   4,  4, "Request-IP", print_ip },
	{  51,  4,   4,  4, "Lease-Time", print_uint },
	{  53,  1,   1,  1, "Message-Type", print_message_type },
	{  54,  4,   4,  4, "Server-ID", print_ip },
	{  55,  1, 255,  1, "Request-List", print_request_list },
	{  56,  1, 255,  1, "Message", print_str },
	{  57,  2,   2,  2, "Max-Message-Size", print_uint },
	{  58,  4,   4,  4, "T1", print_uint },
	{  59,  4,   4,  4, "T2", print_uint },
	{  60,  1, 255,  1, "Vendor-Class", print_hex },
	{  61,  2, 255,  1, "Client-ID", print_hex },
	{  82,  3, 255,  1, "Relay-Agent", print_relay_agent },
	{ 121,  5, 255,  1, "Classless-Route", print_classless_route },
  { 0 },
};

int dhcpv4_check_options(struct dhcpv4_packet *pack)
{
	struct dhcpv4_option *opt;
	struct known_option *kopt;

	list_for_each_entry(opt, &pack->options, entry) {
		for (kopt = options; kopt->type; kopt++) {
			if (kopt->type != opt->type)
				continue;
			if (opt->len < kopt->min_len)
				return -1;
			if (opt->len > kopt->max_len)
				return -1;
			if (opt->len % kopt->elem_size != 0)
				return -1;
			break;
		}
	}

	return 0;
}

void dhcpv4_print_options(struct dhcpv4_packet *pack, void (*print)(const char *fmt, ...))
{
	struct dhcpv4_option *opt;
	struct known_option *kopt;
	int n = 0;

	list_for_each_entry(opt, &pack->options, entry) {
		if (n)
			print(" <");
		else
			print("<");
		n++;
		for (kopt = options; kopt->type && kopt->type != opt->type; kopt++);
		if (kopt->type) {
			print("%s ", kopt->name);
			kopt->print(opt, kopt->elem_size, print);
		} else {
			print("Option-%i ", opt->type);
			print_hex(opt, 1, print);
		}
		print(">");
	}
}


static void print_int(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	if (opt->len == 2)
		print("%i", ntohs(*(int16_t *)(opt->data)));
	else
		print("%i", ntohl(*(int32_t *)(opt->data)));
}

static void print_uint(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	if (opt->len == 2)
		print("%u", ntohs(*(uint16_t *)(opt->data)));
	else
		print("%u", ntohl(*(uint32_t *)(opt->data)));
}

static void print_ip(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	int i, n = opt->len / elem_size;
	uint32_t ip;

	for (i = 0; i < n; i++) {
		ip = ntohl(*(uint32_t *)(opt->data + i*elem_size));

		if (i)
			print(",");

		print("%i.%i.%i.%i",
				(ip >> 24) & 0xff,
				(ip >> 16) & 0xff,
				(ip >> 8) & 0xff,
				ip & 0xff);
	}
}

static void print_str(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	const char *ptr = (const char *)opt->data;
	const char *endptr = ptr + opt->len;

	for(; ptr < endptr; ptr++)
		print("%c", *ptr);
}

static void print_hex(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	const uint8_t *ptr = opt->data;
	const uint8_t *endptr = ptr + opt->len;

	for(; ptr < endptr; ptr++)
		print("%02x", *ptr);
}

static void print_route(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	int i, n = opt->len / 8;
	uint32_t ip, gw;

	for (i = 0; i < n; i++) {
		ip = ntohl(*(uint32_t *)(opt->data + i*8));
		gw = ntohl(*(uint32_t *)(opt->data + i*8 + 4));

		if (i)
			print(",");

		print("%i.%i.%i.%i via %i.%i.%i.%i",
				(ip >> 24) & 0xff,
				(ip >> 16) & 0xff,
				(ip >> 8) & 0xff,
				ip & 0xff,
				(gw >> 24) & 0xff,
				(gw >> 16) & 0xff,
				(gw >> 8) & 0xff,
				gw & 0xff);
	}
}

static void print_message_type(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	const char *msg_name[] = {"", "Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform"};

	print("%s", msg_name[opt->data[0]]);
}

static void print_request_list(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	int i;
	struct known_option *kopt;

	for (i = 0; i < opt->len; i++) {
		if (i)
			print(",");
		for (kopt = options; kopt->type && kopt->type != opt->data[i]; kopt++);
		if (kopt->type)
			print("%s", kopt->name);
		else
			print("%i", opt->data[i]);
	}
}

static void print_relay_agent(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	const uint8_t *ptr = opt->data;
	const uint8_t *endptr = ptr + opt->len;
	const uint8_t *endptr1;
	int type, len;

	while (ptr < endptr) {
		if (ptr != opt->data)
			print(" ");
		type = *ptr++;
		len = *ptr++;
		/*if (ptr + len > endptr) {
			print(" invalid");
			return;
		}*/
		if (type == 1)
			print("{Agent-Circuit-ID ");
		else if (type == 2)
			print("{Agent-Remote-ID ");
		else if (type == 5 && len == 4) {
			print("{Link-Selection ");
			if (len == 4) {
				print("%i.%i.%i.%i}",
					*ptr & 0xff,
					(*(ptr + 1)) & 0xff,
					(*(ptr + 2)) & 0xff,
					(*(ptr + 3)) & 0xff);
				ptr = ptr + len;
				continue;
			}
		} else
			print("{Option-%i ", type);

		endptr1 = ptr + len;
		for (;ptr < endptr1; ptr++) {
			if (!isprint(*ptr)) {
				print("_");
				break;
			}
			print("%c", *ptr);
		}
		for (;ptr < endptr1; ptr++)
			print("%02x", *ptr);
		print("}");
	}
}

static void print_classless_route(const struct dhcpv4_option *opt, int elem_size, void (*print)(const char *fmt, ...))
{
	const uint8_t *ptr = opt->data;
	const uint8_t *endptr = ptr + opt->len;
	int mask, i, mask1 = 0;
	uint32_t ip;
	uint32_t gw;

	while (ptr < endptr) {
		if (ptr != opt->data)
			print(",");

		mask = *ptr++;
		ip = ntohl(*(uint32_t *)ptr);
		for (i = 0; i < mask; i++)
			mask1 |= (1 << (32 - i));
		ip &= mask1;
		if (mask <= 8)
			ptr++;
		else if (mask <= 16)
			ptr += 2;
		else if (mask <= 24)
			ptr += 3;
		else
			ptr += 4;
		gw = ntohl(*(uint32_t *)ptr);
		ptr += 4;

		print("%i.%i.%i.%i/%i via %i.%i.%i.%i",
				(ip >> 24) & 0xff,
				(ip >> 16) & 0xff,
				(ip >> 8) & 0xff,
				ip & 0xff,
				mask,
				(gw >> 24) & 0xff,
				(gw >> 16) & 0xff,
				(gw >> 8) & 0xff,
				gw & 0xff);
	}
}
