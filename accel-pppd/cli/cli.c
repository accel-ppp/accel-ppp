#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "triton.h"

#include "cli.h"
#include "cli_p.h"
#include "log.h"
#include "events.h"

#include "memdebug.h"

#define MAX_CMD_ITEMS 100
#define MSG_FAILURE_ERROR "command failed\r\n"
#define MSG_SYNTAX_ERROR "syntax error\r\n"
#define MSG_INVAL_ERROR "invalid argument\r\n"
#define MSG_UNKNOWN_CMD "command unknown\r\n"

static const char helpcmd[] = "help";
static const size_t helpcmd_len = sizeof(helpcmd) -1;

char *conf_cli_passwd;
static const char *def_cli_prompt = "accel-ppp";
char *conf_cli_prompt;

static LIST_HEAD(simple_cmd_list);
static LIST_HEAD(regexp_cmd_list);

void __export cli_register_simple_cmd(struct cli_simple_cmd_t *cmd)
{
	list_add_tail(&cmd->entry, &simple_cmd_list);
}

void __export cli_register_simple_cmd2(
	int (*exec)(const char *cmd, char * const *fields, int fields_cnt, void *client),
	void (*help)(char * const *fields, int fields_cnt, void *client),
	int hdr_len,
	...
	)
{
	struct cli_simple_cmd_t *c;
	int i;
	va_list ap;

	va_start(ap, hdr_len);

	c = malloc(sizeof(*c));
	memset(c, 0, sizeof(*c));

	c->exec = exec;
	c->help = help;
	c->hdr_len = hdr_len;
	c->hdr = malloc(hdr_len * sizeof(void*));

	for (i = 0; i < hdr_len; i++)
		c->hdr[i] = va_arg(ap, char *);

	list_add_tail(&c->entry, &simple_cmd_list);

	va_end(ap);
}

int __export cli_send(void *client, const char *data)
{
	struct cli_client_t *cln = (struct cli_client_t *)client;

	return cln->send(cln, data, strlen(data));
}

int __export cli_sendv(void *client, const char *fmt, ...)
{
	struct cli_client_t *cln = (struct cli_client_t *)client;
	int r;

	va_list ap;
	va_start(ap, fmt);
	r = cln->sendv(cln, fmt, ap);
	va_end(ap);

	return r;
}


static char *skip_word(char *ptr)
{
	for(; *ptr; ptr++)
		if (!isgraph(*ptr))
			break;
	return ptr;
}
static char *skip_space(char *ptr)
{
	for(; *ptr; ptr++)
		if (*ptr != ' ' && *ptr != '\t')
			break;
	return ptr;
}
static int split(char *buf, char **ptr)
{
	int i;

	buf = skip_space(buf);
	if (!*buf)
		return 0;

	for (i = 0; i < MAX_CMD_ITEMS; i++) {
		ptr[i] = buf;
		buf = skip_word(buf);
		if (!*buf)
			return i + 1;

		*buf = 0;
		buf = skip_space(buf + 1);
		if (!*buf)
			return i + 1;
	}

	return i;
}

static int cli_process_help_cmd(struct cli_client_t *cln)
{
	struct cli_regexp_cmd_t *recmd = NULL;
	struct cli_simple_cmd_t *sicmd = NULL;
	char *cmd = (char *)cln->cmdline;
	char *items[MAX_CMD_ITEMS] = { 0 };
	int cmd_found = 0;
	int nb_items;

	cmd = skip_space(cmd);
	if (strncmp(helpcmd, cmd, helpcmd_len) != 0)
		return 0;

	if (!isblank(cmd[helpcmd_len]) && cmd[helpcmd_len] != '\0')
		return 0;

	cmd = skip_space(cmd + helpcmd_len);

	if (cmd[0] == '\0')
		/* "help" with no argument always succeeds */
		cmd_found = 1;

	list_for_each_entry(recmd, &regexp_cmd_list, entry) {
		pcre2_match_data *match_data = pcre2_match_data_create(0, NULL);
		if (cmd[0] == '\0'
		    || pcre2_match(recmd->h_re, (PCRE2_SPTR)cmd, strlen(cmd),
				 0, 0, match_data, NULL) >= 0) {
			cmd_found = 1;
			if (recmd->help)
				recmd->help(cmd, cln);
		}
		pcre2_match_data_free(match_data);
	}

	nb_items = split(cmd, items);
	list_for_each_entry(sicmd, &simple_cmd_list, entry) {
		int indx = 0;
		int found = 1;
		while (indx < sicmd->hdr_len && indx < nb_items) {
			if (strcmp(sicmd->hdr[indx], items[indx]) != 0) {
				found = 0;
				break;
			}
			++indx;
		}
		if (found) {
			cmd_found = 1;
			if (sicmd->help)
				sicmd->help(items, nb_items, cln);
		}
	}

	if (!cmd_found)
		cli_send(cln, MSG_INVAL_ERROR);

	return 1;
}

static int cli_process_regexp_cmd(struct cli_client_t *cln, int *err)
{
	struct cli_regexp_cmd_t *recmd = NULL;
	char *cmd = (char *)cln->cmdline;
	int found = 0;
	int res;

	cmd = skip_space(cmd);
	list_for_each_entry(recmd, &regexp_cmd_list, entry) {
		pcre2_match_data *match_data = pcre2_match_data_create(0, NULL);
		if (pcre2_match(recmd->re, (PCRE2_SPTR)cmd, strlen(cmd),
			      0, 0, match_data, NULL) >= 0) {
			found = 1;
			res = recmd->exec(cmd, cln);
			if (res != CLI_CMD_OK) {
				pcre2_match_data_free(match_data);
				break;
			}
		}
		pcre2_match_data_free(match_data);
	}
	if (found)
		*err = res;

	return found;
}

static int cli_process_simple_cmd(struct cli_client_t *cln, int *err)
{
	struct cli_simple_cmd_t *sicmd = NULL;
	char *cmd = (char *)cln->cmdline;
	char *items[MAX_CMD_ITEMS] = { 0 };
	int found = 0;
	int nb_items;
	int indx;
	int res;

	nb_items = split(cmd, items);
	list_for_each_entry(sicmd, &simple_cmd_list, entry) {
		if (sicmd->hdr_len <= 0 || nb_items < sicmd->hdr_len)
			continue;
		for (indx = 0; indx < sicmd->hdr_len; ++indx) {
			if (strcmp(sicmd->hdr[indx], items[indx]) != 0)
				break;
		}
		if (indx == sicmd->hdr_len) {
			found = 1;
			res = sicmd->exec(cmd, items, nb_items, cln);
			if (res != CLI_CMD_OK)
				break;
		}
	}
	if (found)
		*err = res;

	return found;
}

int __export cli_process_cmd(struct cli_client_t *cln)
{
	int found;
	int err;

	if (cli_process_help_cmd(cln))
		return 0;

	found = cli_process_regexp_cmd(cln, &err);
	if (found && err != CLI_CMD_OK)
		goto out_found;

	found |= cli_process_simple_cmd(cln, &err);
	if (found)
		goto out_found;

	if (cli_send(cln, MSG_UNKNOWN_CMD))
		return -1;
	else
		return 0;

out_found:
	switch (err) {
	case CLI_CMD_EXIT:
		cln->disconnect(cln);
		return -1;
	case CLI_CMD_FAILED:
		cli_send(cln, MSG_FAILURE_ERROR);
		return 0;
	case CLI_CMD_SYNTAX:
		cli_send(cln, MSG_SYNTAX_ERROR);
		return 0;
	case CLI_CMD_INVAL:
		cli_send(cln, MSG_INVAL_ERROR);
		return 0;
	case CLI_CMD_OK:
		return 0;
	}
	return -1;
}

static void load_config(void)
{
	const char *opt;

	if (conf_cli_passwd)
		_free(conf_cli_passwd);
	opt = conf_get_opt("cli", "password");
	if (opt)
		conf_cli_passwd = _strdup(opt);
	else
		conf_cli_passwd = NULL;

	if (conf_cli_prompt && conf_cli_prompt != def_cli_prompt)
		_free(conf_cli_prompt);
	opt = conf_get_opt("cli", "prompt");
	if (opt)
		conf_cli_prompt = _strdup(opt);
	else
		conf_cli_prompt = (char *)def_cli_prompt;
}

static void init(void)
{
	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(10, init);
