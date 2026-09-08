#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "log.h"
#include "triton.h"
#include "l2tp.h"
#include "l2tp_switch_conf.h"

#include "memdebug.h"

struct l2tp_switch_line_t {
	struct list_head entry;
	uint8_t *val;
	int len;
	struct l2tp_switch_target_t *target;
};

struct list_head l2tp_switch_targets = { &l2tp_switch_targets, &l2tp_switch_targets };
static LIST_HEAD(l2tp_switch_lines);
static const struct l2tp_dict_attr_t *conf_switch_attr;

const struct l2tp_dict_attr_t *l2tp_switch_conf_attr(void)
{
	return conf_switch_attr;
}

static void free_target(struct l2tp_switch_target_t *t)
{
	if (t->secret)
		_free(t->secret);
	_free(t->name);
	_free(t);
}

static void free_line(struct l2tp_switch_line_t *l)
{
	_free(l->val);
	_free(l);
}

static void switch_conf_clear(void)
{
	struct l2tp_switch_line_t *l;
	struct l2tp_switch_target_t *t;

	/* This project's list.h has no list_for_each_entry_safe (confirmed:
	 * it defines list_for_each_entry and the raw-list_head
	 * list_for_each_safe, but no typed safe-iteration macro) -- the
	 * existing convention for "delete every entry off a list" elsewhere
	 * in l2tp.c (e.g. l2tp_tunnel_clear_sendqueue()) is this
	 * while/list_first_entry idiom instead. */
	while (!list_empty(&l2tp_switch_lines)) {
		l = list_first_entry(&l2tp_switch_lines, typeof(*l), entry);
		list_del(&l->entry);
		free_line(l);
	}
	while (!list_empty(&l2tp_switch_targets)) {
		t = list_first_entry(&l2tp_switch_targets, typeof(*t), entry);
		list_del(&t->entry);
		free_target(t);
	}
}

struct l2tp_switch_target_t *l2tp_switch_target_find(const char *name)
{
	struct l2tp_switch_target_t *t;

	list_for_each_entry(t, &l2tp_switch_targets, entry)
		if (!strcmp(t->name, name))
			return t;

	return NULL;
}

static struct l2tp_switch_line_t *line_find(const uint8_t *val, int len)
{
	struct l2tp_switch_line_t *l;

	list_for_each_entry(l, &l2tp_switch_lines, entry)
		if (l->len == len && !memcmp(l->val, val, len))
			return l;

	return NULL;
}

struct l2tp_switch_target_t *l2tp_switch_lookup(const uint8_t *val, int len)
{
	struct l2tp_switch_line_t *l = line_find(val, len);

	return l ? l->target : NULL;
}

int l2tp_switch_line_add(const uint8_t *val, int len, const char *target_name)
{
	struct l2tp_switch_target_t *target = l2tp_switch_target_find(target_name);
	struct l2tp_switch_line_t *l;

	if (!target) {
		log_error("l2tp-switch: unknown target \"%s\"\n", target_name);
		return -1;
	}

	if (line_find(val, len)) {
		log_error("l2tp-switch: a line entry for this value already exists\n");
		return -1;
	}

	l = _malloc(sizeof(*l));
	if (!l)
		return -1;

	l->val = _malloc(len);
	if (!l->val) {
		_free(l);
		return -1;
	}
	memcpy(l->val, val, len);
	l->len = len;
	l->target = target;

	list_add_tail(&l->entry, &l2tp_switch_lines);

	return 0;
}

int l2tp_switch_line_del(const uint8_t *val, int len)
{
	struct l2tp_switch_line_t *l = line_find(val, len);

	if (!l)
		return -1;

	list_del(&l->entry);
	free_line(l);

	return 0;
}

static int parse_target(const char *val)
{
	/* target=<name>,<peer-addr>,<peer-port>,<secret> */
	struct l2tp_switch_target_t *t;
	char *copy, *name, *addr, *port, *secret, *save = NULL;
	long p;

	copy = _strdup(val);
	if (!copy)
		return -1;

	name = strtok_r(copy, ",", &save);
	addr = strtok_r(NULL, ",", &save);
	port = strtok_r(NULL, ",", &save);
	secret = strtok_r(NULL, ",", &save);

	if (!name || !addr || !port || !secret) {
		log_error("l2tp-switch: malformed target= \"%s\","
			  " expected name,peer-addr,peer-port,secret\n", val);
		goto err;
	}

	if (l2tp_switch_target_find(name)) {
		log_error("l2tp-switch: duplicate target name \"%s\"\n", name);
		goto err;
	}

	p = strtol(port, NULL, 10);
	if (p <= 0 || p > UINT16_MAX) {
		log_error("l2tp-switch: invalid peer-port in target=\"%s\"\n", val);
		goto err;
	}

	t = _malloc(sizeof(*t));
	if (!t)
		goto err;
	memset(t, 0, sizeof(*t));

	t->name = _strdup(name);
	t->secret = _strdup(secret);
	if (!t->name || !t->secret) {
		free_target(t);
		goto err;
	}
	t->secret_len = strlen(t->secret);

	t->peer_addr.sin_family = AF_INET;
	t->peer_addr.sin_port = htons((uint16_t)p);
	if (inet_aton(addr, &t->peer_addr.sin_addr) == 0) {
		log_error("l2tp-switch: invalid peer-addr in target=\"%s\"\n", val);
		free_target(t);
		goto err;
	}

	list_add_tail(&t->entry, &l2tp_switch_targets);
	_free(copy);
	return 0;

err:
	_free(copy);
	return -1;
}

static int parse_line(const char *val)
{
	/* line=<value>,<target-name> */
	char *copy, *value, *target_name, *save = NULL;
	int ret;

	copy = _strdup(val);
	if (!copy)
		return -1;

	value = strtok_r(copy, ",", &save);
	target_name = strtok_r(NULL, ",", &save);

	if (!value || !target_name) {
		log_error("l2tp-switch: malformed line= \"%s\","
			  " expected value,target-name\n", val);
		_free(copy);
		return -1;
	}

	ret = l2tp_switch_line_add((const uint8_t *)value, strlen(value),
				   target_name);
	_free(copy);
	return ret;
}

extern in_addr_t l2tp_conf_get_bind_addr(void); /* added to l2tp.c, Task 1 Step 3 */
extern uint16_t l2tp_conf_get_bind_port(void); /* added to l2tp.c, Task 5 */

static int validate_no_self_loop(void)
{
	in_addr_t bind_addr = l2tp_conf_get_bind_addr();
	uint16_t bind_port = l2tp_conf_get_bind_port();
	struct l2tp_switch_target_t *t;

	if (bind_addr == INADDR_ANY)
		return 0;

	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		/* Both the IP *and* the port must match this host's own
		 * [l2tp] listener for this to actually be a tunnel-to-itself
		 * loop -- an IP-only comparison would reject any target that
		 * merely shares an address with the switch's own bind (e.g.
		 * a downstream instance colocated on the same host at a
		 * different port, which is exactly how this feature's own
		 * test suite runs a switch and downstream side by side on
		 * 127.0.0.1). */
		if (t->peer_addr.sin_addr.s_addr == bind_addr &&
		    ntohs(t->peer_addr.sin_port) == bind_port) {
			log_error("l2tp-switch: target \"%s\" peer-addr:port"
				  " equals this host's own [l2tp]"
				  " bind:port\n", t->name);
			return -1;
		}
	}

	return 0;
}

int l2tp_switch_conf_load(void)
{
	struct conf_sect_t *s = conf_get_section("l2tp-switch");
	struct conf_option_t *opt;
	const char *attr_name;

	switch_conf_clear();
	conf_switch_attr = NULL;

	if (!s)
		return 0;

	attr_name = conf_get_opt("l2tp-switch", "attr");
	if (!attr_name)
		attr_name = "Calling-Number";

	conf_switch_attr = l2tp_dict_find_attr_by_name(attr_name);
	if (!conf_switch_attr || conf_switch_attr->type != ATTR_TYPE_STRING) {
		log_error("l2tp-switch: attr=\"%s\" is not a known"
			  " string-typed AVP\n", attr_name);
		return -1;
	}

	/* targets first: line= entries reference them by name */
	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "target") && opt->val)
			if (parse_target(opt->val) < 0)
				return -1;
	}

	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "line") && opt->val)
			if (parse_line(opt->val) < 0)
				return -1;
	}

	return validate_no_self_loop();
}
