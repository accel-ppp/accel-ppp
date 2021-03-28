#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "triton.h"
#include "events.h"
#include "list.h"
#include "log.h"
#include "utils.h"

#include "iprange.h"

#include "memdebug.h"

struct iprange_t
{
	struct list_head entry;
	uint32_t begin;
	uint32_t end;
};

static pthread_mutex_t iprange_lock = PTHREAD_MUTEX_INITIALIZER;
static bool conf_disable = false;
static LIST_HEAD(client_ranges);

static void free_ranges(struct list_head *head)
{
	struct iprange_t *range;

	while (!list_empty(head)) {
		range = list_first_entry(head, typeof(*range), entry);
		list_del(&range->entry);
		_free(range);
	}
}

/* Parse a [client-ip-iprange] configuration entry.
 * Ranges can be defined in CIDR notation ("192.0.2.0/24") or by specifying an
 * upper bound for the last IPv4 byte, after a '-' character ("192.0.2.0-255").
 * For simplicity, only mention the CIDR notation in error messages.
 */
static int parse_iprange(const char *str, struct iprange_t **range)
{
	struct iprange_t *new_range;
	struct in_addr base_addr;
	const char *ptr;
	uint32_t ip_min;
	uint32_t ip_max;
	uint8_t suffix;
	size_t len;

	if (!strcmp(str, "disable"))
		goto disable;

	ptr = str;

	/* Try IPv4 CIDR notation first */
	len = u_parse_ip4cidr(ptr, &base_addr, &suffix);
	if (len) {
		uint32_t addr_hbo;
		uint32_t mask;

		/* Cast to uint64_t to avoid undefined 32 bits shift on 32 bits
		 * integer if 'suffix' is 0.
		 */
		mask = (uint64_t)0xffffffff << (32 - suffix);
		addr_hbo = ntohl(base_addr.s_addr);
		ip_min = addr_hbo & mask;
		ip_max = addr_hbo | ~mask;

		if (ip_min != addr_hbo) {
			struct in_addr min_addr = { .s_addr = htonl(ip_min) };
			char ipbuf[INET_ADDRSTRLEN];

			log_warn("iprange: network %s is equivalent to %s/%hhu\n",
				 str, u_ip4str(&min_addr, ipbuf), suffix);
		}
		goto addrange;
	}

	/* Not an IPv4 CIDR, try the IPv4 range notation */
	len = u_parse_ip4range(ptr, &base_addr, &suffix);
	if (len) {
		ip_min = ntohl(base_addr.s_addr);
		ip_max = (ip_min & 0xffffff00) | suffix;
		goto addrange;
	}

	log_error("iprange: parsing range \"%s\" failed:"
		  " expecting an IPv4 network prefix in CIDR notation\n",
		  str);

	return -1;

addrange:
	ptr += len;

	if (!u_parse_endstr(ptr)) {
		log_error("iprange: parsing range \"%s\" failed:"
			  " unexpected data at \"%s\"\n",
			  str, ptr);
		return -1;
	}

	if (ip_min == INADDR_ANY && ip_max == INADDR_BROADCAST)
		goto disable;

	new_range = _malloc(sizeof(*new_range));
	if (!new_range) {
		log_error("iprange: impossible to load range \"%s\":"
			  " memory allocation failed\n",
			  str);
		return -1;
	}

	new_range->begin = ip_min;
	new_range->end = ip_max;

	*range = new_range;

	return 0;

disable:
	*range = NULL;

	return 0;
}

static bool load_ranges(struct list_head *list, const char *conf_sect)
{
	struct conf_sect_t *s =	conf_get_section(conf_sect);
	struct conf_option_t *opt;
	struct iprange_t *r;

	if (!s)
		return false;

	list_for_each_entry(opt, &s->items, entry) {
		/* Ignore parsing errors, parse_iprange() already logs suitable
		 * error messages.
		 */
		if (parse_iprange(opt->name, &r) < 0)
			continue;

		if (!r) {
			free_ranges(list);

			return true;
		}

		list_add_tail(&r->entry, list);
	}

	return false;
}

static int check_range(struct list_head *list, in_addr_t ipaddr)
{
	struct iprange_t *r;
	uint32_t a = ntohl(ipaddr);

	list_for_each_entry(r, list, entry) {
		if (a >= r->begin && a <= r->end)
			return 0;
	}

	return -1;
}

enum iprange_status __export iprange_check_activation(void)
{
	bool disabled;
	bool empty;

	pthread_mutex_lock(&iprange_lock);
	disabled = conf_disable;
	empty = list_empty(&client_ranges);
	pthread_mutex_unlock(&iprange_lock);

	if (disabled)
		return IPRANGE_DISABLED;

	if (empty)
		return IPRANGE_NO_RANGE;

	return IPRANGE_ACTIVE;
}

int __export iprange_client_check(in_addr_t ipaddr)
{
	int res;

	pthread_mutex_lock(&iprange_lock);
	if (conf_disable)
		res = 0;
	else
		res = check_range(&client_ranges, ipaddr);
	pthread_mutex_unlock(&iprange_lock);

	return res;
}

int __export iprange_tunnel_check(in_addr_t ipaddr)
{
	int res;

	pthread_mutex_lock(&iprange_lock);
	if (conf_disable)
		res = 0;
	else
		res = !check_range(&client_ranges, ipaddr);
	pthread_mutex_unlock(&iprange_lock);

	return res;
}

static void iprange_load_config()
{
	config_lock();
	LIST_HEAD(new_ranges);
	LIST_HEAD(old_ranges);
	bool disable;

	disable = load_ranges(&new_ranges, IPRANGE_CONF_SECTION);

	pthread_mutex_lock(&iprange_lock);
	list_replace(&client_ranges, &old_ranges);
	list_replace(&new_ranges, &client_ranges);
	conf_disable = disable;
	pthread_mutex_unlock(&iprange_lock);

	free_ranges(&old_ranges);
	config_unlock();
}

static void iprange_init(void)
{
	iprange_load_config();
	if (triton_event_register_handler(EV_CONFIG_RELOAD,
					  iprange_load_config) < 0)
		log_error("iprange: registration of CONFIG_RELOAD event failed,"
			  " iprange will not be able to reload its configuration\n");
}

DEFINE_INIT(10, iprange_init);
