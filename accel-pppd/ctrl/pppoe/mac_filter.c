#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "list.h"
#include "cli.h"
#include "triton.h"
#include "log.h"
#include "ppp.h"
#include "memdebug.h"

#include "pppoe.h"

struct mac_t
{
	struct list_head entry;
	uint8_t addr[ETH_ALEN];
};

static LIST_HEAD(mac_list);
static int type; // -1 - disabled, 1 - allow, 0 - denied
static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static const char *conf_mac_filter;

int mac_filter_check(const uint8_t *addr)
{
	struct mac_t *mac;
	int res = type;

	if (type == -1)
		return 0;

	pthread_rwlock_rdlock(&lock);
	list_for_each_entry(mac, &mac_list, entry) {
		if (memcmp(mac->addr, addr, ETH_ALEN))
			continue;
		res = !type;
		break;
	}
	pthread_rwlock_unlock(&lock);

	return res;
}

static int mac_filter_load(const char *opt)
{
	struct mac_t *mac;
	FILE *f;
	char *c;
	char *name = _strdup(opt);
	char *buf = _malloc(1024);
	unsigned int n[ETH_ALEN];
	int i, line = 0;

	c = strstr(name, ",");
	if (!c)
		goto err_inval;

	*c = 0;

	if (!strcmp(c + 1, "allow"))
		type = 1;
	else if (!strcmp(c + 1, "deny"))
		type = 0;
	else
		goto err_inval;

	f = fopen(name, "r");
	if (!f) {
		log_emerg("pppoe: open '%s': %s\n", name, strerror(errno));
		goto err;
	}

	conf_mac_filter = opt;

	pthread_rwlock_wrlock(&lock);
	while (!list_empty(&mac_list)) {
		mac = list_entry(mac_list.next, typeof(*mac), entry);
		list_del(&mac->entry);
		_free(mac);
	}

	while (fgets(buf, 1024, f)) {
		line++;
		if (buf[0] == '#' || buf[0] == ';' || buf[0] == '\n')
			continue;
		if (sscanf(buf, "%x:%x:%x:%x:%x:%x",
			n + 0, n + 1, n + 2, n + 3, n + 4, n + 5) != 6) {
			log_warn("pppoe: mac-filter:%s:%i: address is invalid\n", name, line);
			continue;
		}
		mac = _malloc(sizeof(*mac));
		for (i = 0; i < ETH_ALEN; i++) {
			if (n[i] > 255) {
				log_warn("pppoe: mac-filter:%s:%i: address is invalid\n", name, line);
				_free(mac);
				continue;
			}
			mac->addr[i] = n[i];
		}
		list_add_tail(&mac->entry, &mac_list);
	}
	pthread_rwlock_unlock(&lock);

	fclose(f);

	_free(name);
	_free(buf);

	return 0;

err_inval:
	log_emerg("pppoe: mac-filter format is invalid\n");
err:
	_free(name);
	_free(buf);
	return -1;
}

static void mac_filter_add(const char *addr, void *client)
{
	unsigned int n[ETH_ALEN];
	struct mac_t *mac;
	int i;

	if (sscanf(addr, "%x:%x:%x:%x:%x:%x",
		n + 0, n + 1, n + 2, n + 3, n + 4, n + 5) != 6) {
		cli_send(client, "invalid format\r\n");
		return;
	}

	mac = _malloc(sizeof(*mac));
	for (i = 0; i < ETH_ALEN; i++) {
		if (n[i] > 255) {
			_free(mac);
			cli_send(client, "invalid format\r\n");
			return;
		}
		mac->addr[i] = n[i];
	}

	pthread_rwlock_wrlock(&lock);
	list_add_tail(&mac->entry, &mac_list);
	pthread_rwlock_unlock(&lock);
}

static void mac_filter_del(const char *addr, void *client)
{
	unsigned int n[ETH_ALEN];
	uint8_t a[ETH_ALEN];
	struct mac_t *mac;
	int i;
	int found = 0;

	if (sscanf(addr, "%x:%x:%x:%x:%x:%x",
		n + 0, n + 1, n + 2, n + 3, n + 4, n + 5) != 6) {
		cli_send(client, "invalid format\r\n");
		return;
	}

	for (i = 0; i < ETH_ALEN; i++) {
		if (n[i] > 255) {
			cli_send(client, "invalid format\r\n");
			return;
		}
		a[i] = n[i];
	}

	pthread_rwlock_wrlock(&lock);
	list_for_each_entry(mac, &mac_list, entry) {
		if (memcmp(a, mac->addr, ETH_ALEN))
			continue;
		list_del(&mac->entry);
		_free(mac);
		found = 1;
		break;
	}
	pthread_rwlock_unlock(&lock);

	if (!found)
		cli_send(client, "not found\r\n");
}

static void mac_filter_show(void *client)
{
	struct mac_t *mac;
	const char *filter_type;

	if (type == 0)
		filter_type = "deny";
	else if (type == 1)
		filter_type = "allow";
	else
		filter_type = "disabled";

	cli_sendv(client, "filter type: %s\r\n", filter_type);

	pthread_rwlock_rdlock(&lock);
	list_for_each_entry(mac, &mac_list, entry) {
		cli_sendv(client, "%02x:%02x:%02x:%02x:%02x:%02x\r\n",
			mac->addr[0], mac->addr[1], mac->addr[2],
			mac->addr[3],	mac->addr[4], mac->addr[5]);
	}
	pthread_rwlock_unlock(&lock);
}

static void cmd_help(char * const *fields, int fields_cnt, void *client);
static int cmd_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	if (fields_cnt == 2)
		goto help;

	if (!strcmp(fields[2], "reload")) {
		if (!conf_mac_filter)
			cli_send(client, "error: mac-filter was not specified in the config\r\n");
		else if (mac_filter_load(conf_mac_filter))
			cli_send(client, "error: check logs\r\n");
	} else if (!strcmp(fields[2], "add")) {
		if (fields_cnt != 4)
			goto help;
		mac_filter_add(fields[3], client);
	} else if (!strcmp(fields[2], "del")) {
		if (fields_cnt != 4)
			goto help;
		mac_filter_del(fields[3], client);
	} else if (!strcmp(fields[2], "show")) {
		mac_filter_show(client);
	} else
		goto help;

	return CLI_CMD_OK;
help:
	cmd_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}

static void cmd_help(char * const *fields, int fields_cnt, void *client)
{
	uint8_t show = 15;

	if (fields_cnt >= 3) {
		show &= (strcmp(fields[2], "reload")) ? ~1 : ~0;
		show &= (strcmp(fields[2], "add")) ? ~2 : ~0;
		show &= (strcmp(fields[2], "del")) ? ~4 : ~0;
		show &= (strcmp(fields[2], "show")) ? ~8 : ~0;
		if (show == 0) {
			cli_sendv(client, "Invalid action \"%s\"\r\n",
				  fields[2]);
			show = 15;
		}
	}
	if (show & 1)
		cli_send(client, "pppoe mac-filter reload"
			 " - reload mac-filter file\r\n");
	if (show & 2)
		cli_send(client,
			 "pppoe mac-filter add <address>"
			 " - add address to mac-filter list\r\n");
	if (show & 4)
		cli_send(client,
			 "pppoe mac-filter del <address> -"
			 " delete address from mac-filter list\r\n");
	if (show & 8)
		cli_send(client,
			 "pppoe mac-filter show"
			 " - show current mac-filter list\r\n");
}

static void init(void)
{
	const char *opt = conf_get_opt("pppoe", "mac-filter");
	if (!opt || mac_filter_load(opt))
		type = -1;

	cli_register_simple_cmd2(cmd_exec, cmd_help, 2, "pppoe", "mac-filter");
}

DEFINE_INIT(20, init);
