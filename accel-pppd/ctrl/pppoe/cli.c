#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "triton.h"
#include "cli.h"
#include "ppp.h"
#include "memdebug.h"

#include "pppoe.h"

static void show_interfaces(void *cli)
{
	struct pppoe_serv_t *serv;

	cli_send(cli, "interface:   connections:    state:    vpp-cp:\r\n");
	cli_send(cli, "----------------------------------------------\r\n");

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		cli_sendv(cli, "%9s    %11u    %6s    %7s\r\n", serv->ifname, serv->conn_cnt, serv->stopping ? "stop" : "active",
				serv->is_vpppoe ? "enable" : "disable");
	}
	pthread_rwlock_unlock(&serv_lock);
}

static void intf_help(char * const *fields, int fields_cnt, void *client)
{
	uint8_t show = 15;

	if (fields_cnt >= 3) {
		show &= (strncmp(fields[2], "add", sizeof("add"))) ? ~1 : ~0;
		show &= (strncmp(fields[2], "del", sizeof("del"))) ? ~2 : ~0;
		show &= (strncmp(fields[2], "show", sizeof("show"))) ? ~4 : ~0;
		show &= (strncmp(fields[2], "monitored", sizeof("monitored"))) ? ~8 : ~0;
		if (show == 0) {
			cli_sendv(client, "Invalid action \"%s\"\r\n",
				  fields[2]);
			show = 7;
		}
	}
	if (show & 1)
		cli_send(client,
			 "pppoe interface add <name>"
			 " - start pppoe server on specified interface\r\n");
	if (show & 2)
		cli_send(client,
			 "pppoe interface del <name>"
			 " - stop pppoe server on specified interface and"
			 " drop his connections\r\n");
	if (show & 4)
		cli_send(client,
			 "pppoe interface show"
			 " - show interfaces where PPPoE server is running"
			 " started\r\n");
	if (show & 8)
		cli_send(client,
			 "pppoe interface monitored"
			 " - show the list of monitored interfaces where PPPoE service"
			 " would be launched automatically when the link appears\r\n");
}

static int intf_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	if (fields_cnt == 2)
		goto help;

	if (fields_cnt == 3) {
		if (!strcmp(fields[2], "show"))
			show_interfaces(client);
		else if(!strncmp(fields[2], "monitored", sizeof("monitored"))) {
			struct monitored_link_list_entry_t *e;
			cli_send(client, "interface:   options:\r\n");
			cli_send(client, "---------------------\r\n");
			pthread_rwlock_rdlock(&serv_lock);
			list_for_each_entry(e, &monitored_link_list, entry)
				cli_sendv(client, "%9s    %s\r\n", e->name, e->opt != NULL ? e->opt : "" );
			pthread_rwlock_unlock(&serv_lock);
		}
		else
			goto help;

		return CLI_CMD_OK;
	}

	if (fields_cnt != 4)
		goto help;

	if (!strcmp(fields[2], "add"))
		pppoe_server_start(fields[3], client);
	else if (!strcmp(fields[2], "del"))
		pppoe_server_stop(fields[3]);
	else
		goto help;

	return CLI_CMD_OK;
help:
	intf_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}

//===================================

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "pppoe:\r\n");
	cli_sendv(client, "  starting: %u\r\n", stat_starting);
	cli_sendv(client, "  active: %u\r\n", stat_active);
	cli_sendv(client, "  delayed PADO: %u\r\n", stat_delayed_pado);
	cli_sendv(client, "  recv PADI: %lu\r\n", stat_PADI_recv);
	cli_sendv(client, "  drop PADI: %lu\r\n", stat_PADI_drop);
	cli_sendv(client, "  sent PADO: %lu\r\n", stat_PADO_sent);
	cli_sendv(client, "  recv PADR(dup): %lu(%lu)\r\n", stat_PADR_recv, stat_PADR_dup_recv);
	cli_sendv(client, "  sent PADS: %lu\r\n", stat_PADS_sent);
	cli_sendv(client, "  filtered: %lu\r\n", stat_filtered);

	return CLI_CMD_OK;
}

//===================================

static void set_verbose_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set verbose <n> - set verbosity of pppoe logging\r\n");
}

static void set_pado_delay_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set PADO-delay <delay[,delay1:count1[,delay2:count2[,...]]]> - set PADO delays (ms)\r\n");
}

static void set_service_name_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set Service-Name <name> - set Service-Name to respond\r\n");
	cli_send(cli, "pppoe set Service-Name * - respond with client's Service-Name\r\n");
}

static void set_ac_name_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set AC-Name <name> - set AC-Name tag value\r\n");
}

static void show_verbose_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe show verbose - show current verbose value\r\n");
}

static void show_pado_delay_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe show PADO-delay - show current PADO delay value\r\n");
}

static void show_service_name_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe show Service-Name - show current Service-Name value\r\n");
}

static void show_ac_name_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe show AC-Name - show current AC-Name tag value\r\n");
}

static int show_verbose_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;

	cli_sendv(cli, "%i\r\n", conf_verbose);

	return CLI_CMD_OK;
}

static int show_pado_delay_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;

	cli_sendv(cli, "%s\r\n", conf_pado_delay);

	return CLI_CMD_OK;
}

static int show_service_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;

	if (conf_service_name[0]) {
		int i = 0;
		do {
		    cli_sendv(cli, "%s", conf_service_name[i]);
		    i++;
		    if (conf_service_name[i]) { cli_sendv(cli, ","); }
		} while(conf_service_name[i]);
		cli_sendv(cli, "\r\n");
	} else
		cli_sendv(cli, "*\r\n");

	return CLI_CMD_OK;
}

static int show_ac_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;

	cli_sendv(cli, "%s\r\n", conf_ac_name);

	return CLI_CMD_OK;
}

static int set_verbose_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 4)
		return CLI_CMD_SYNTAX;

	if (!strcmp(f[3], "0"))
		conf_verbose = 0;
	else if (!strcmp(f[3], "1"))
		conf_verbose = 1;
	else
		return CLI_CMD_INVAL;

	return CLI_CMD_OK;
}

static int set_pado_delay_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 4)
		return CLI_CMD_SYNTAX;

	if (dpado_parse(f[3]))
		return CLI_CMD_INVAL;

	return CLI_CMD_OK;
}

static int set_service_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 4)
		return CLI_CMD_SYNTAX;

	if (conf_service_name[0]) {
		int i = 0;
		do {
		    _free(conf_service_name[i]);
		    i++;
		} while(conf_service_name[i]);
		conf_service_name[0] = NULL;
	}
	if (!strcmp(f[3], "*"))
		conf_service_name[0] = NULL;
	else {
	    char *conf_service_name_string = _strdup(f[3]);
	    char *p = strtok (conf_service_name_string, ",");
	    int i = 0;
	    while (p != NULL && i<255) {
		conf_service_name[i++] = _strdup(p);
		p = strtok(NULL, ",");
	    }
	    conf_service_name[i] = NULL;
	    _free(conf_service_name_string);
	}

	return CLI_CMD_OK;
}

static int set_ac_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 4)
		return CLI_CMD_SYNTAX;

	_free(conf_ac_name);
	conf_ac_name = _strdup(f[3]);

	return CLI_CMD_OK;
}
//===================================


static void init(void)
{
	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");
	cli_register_simple_cmd2(intf_exec, intf_help, 2, "pppoe", "interface");
	cli_register_simple_cmd2(set_verbose_exec, set_verbose_help, 3, "pppoe", "set", "verbose");
	cli_register_simple_cmd2(set_pado_delay_exec, set_pado_delay_help,
				 3, "pppoe", "set", "PADO-delay");
	cli_register_simple_cmd2(set_service_name_exec, set_service_name_help,
				 3, "pppoe", "set", "Service-Name");
	cli_register_simple_cmd2(set_ac_name_exec, set_ac_name_help,
				 3, "pppoe", "set", "AC-Name");
	cli_register_simple_cmd2(show_verbose_exec, show_verbose_help,
				 3, "pppoe", "show", "verbose");
	cli_register_simple_cmd2(show_pado_delay_exec, show_pado_delay_help,
				 3, "pppoe", "show", "PADO-delay");
	cli_register_simple_cmd2(show_service_name_exec, show_service_name_help,
				 3, "pppoe", "show", "Service-Name");
	cli_register_simple_cmd2(show_ac_name_exec, show_ac_name_help,
				 3, "pppoe", "show", "AC-Name");
}

DEFINE_INIT(22, init);
