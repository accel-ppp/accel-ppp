#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "log.h"
#include "triton.h"
#include "l2tp.h"
#include "l2tp_switch_conf.h"

#include "memdebug.h"

enum l2tp_switch_match_mode {
	L2TP_SWITCH_MATCH_EXACT,
	L2TP_SWITCH_MATCH_PREFIX,
};

struct l2tp_switch_rule_t {
	struct list_head entry;
	const struct l2tp_dict_attr_t *attr;
	enum l2tp_switch_match_mode mode;
	uint8_t *val;
	int len;
	struct l2tp_switch_target_t *target;
};

struct list_head l2tp_switch_targets = { &l2tp_switch_targets, &l2tp_switch_targets };
static LIST_HEAD(l2tp_switch_rules);

static void free_target(struct l2tp_switch_target_t *t)
{
	if (t->secret)
		_free(t->secret);
	_free(t->name);
	_free(t);
}

static void free_rule(struct l2tp_switch_rule_t *r)
{
	_free(r->val);
	_free(r);
}

static void switch_conf_clear(void)
{
	struct l2tp_switch_rule_t *r;
	struct l2tp_switch_target_t *t;

	/* This project's list.h has no list_for_each_entry_safe (confirmed:
	 * it defines list_for_each_entry and the raw-list_head
	 * list_for_each_safe, but no typed safe-iteration macro) -- the
	 * existing convention for "delete every entry off a list" elsewhere
	 * in l2tp.c (e.g. l2tp_tunnel_clear_sendqueue()) is this
	 * while/list_first_entry idiom instead. */
	while (!list_empty(&l2tp_switch_rules)) {
		r = list_first_entry(&l2tp_switch_rules, typeof(*r), entry);
		list_del(&r->entry);
		free_rule(r);
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

/* True if a rule configured as `r` would fire on a real AVP carrying
 * `val`/`len` -- exact requires an identical value, prefix requires `val`
 * to start with `r`'s own value. Also used, symmetrically, to detect
 * configuration-time overlap between two candidate rules (see
 * rules_overlap() below) -- a single definition of "does this rule fire on
 * this value" is enough for both the runtime lookup and the config-time
 * ambiguity check, rather than keeping two separate notions of "matches"
 * that could drift apart. */
static int rule_matches_value(const struct l2tp_switch_rule_t *r,
			      const uint8_t *val, int len)
{
	switch (r->mode) {
	case L2TP_SWITCH_MATCH_EXACT:
		return len == r->len && !memcmp(val, r->val, len);
	case L2TP_SWITCH_MATCH_PREFIX:
		return len >= r->len && !memcmp(val, r->val, r->len);
	}
	return 0;
}

/* Two rules on the same AVP are ambiguous if either one would fire on the
 * other's own configured value -- this single symmetric check covers every
 * case that matters without enumerating them: an exact duplicate (each
 * matches the other's value trivially), one prefix that is itself a prefix
 * of another (the shorter matches the longer's value), and an exact value
 * that also happens to start with a configured prefix (the prefix rule
 * matches the exact rule's value) -- all come out true here, with no
 * separate exact-vs-exact/prefix-vs-prefix/exact-vs-prefix cases to keep in
 * sync by hand. */
static int rules_overlap(const struct l2tp_switch_rule_t *a,
			 const struct l2tp_switch_rule_t *b)
{
	return rule_matches_value(a, b->val, b->len) ||
	       rule_matches_value(b, a->val, a->len);
}

struct l2tp_switch_target_t *l2tp_switch_match(const struct l2tp_dict_attr_t *attr,
					       const uint8_t *val, int len)
{
	struct l2tp_switch_rule_t *r;

	list_for_each_entry(r, &l2tp_switch_rules, entry)
		if (r->attr == attr && rule_matches_value(r, val, len))
			return r->target;

	return NULL;
}

static int parse_mode(const char *s, enum l2tp_switch_match_mode *mode)
{
	if (!strcmp(s, "exact")) {
		*mode = L2TP_SWITCH_MATCH_EXACT;
		return 0;
	}
	if (!strcmp(s, "prefix")) {
		*mode = L2TP_SWITCH_MATCH_PREFIX;
		return 0;
	}
	return -1;
}

static const struct l2tp_dict_attr_t *resolve_match_attr(const char *attr_name)
{
	const struct l2tp_dict_attr_t *attr = l2tp_dict_find_attr_by_name(attr_name);

	if (!attr || attr->type != ATTR_TYPE_STRING) {
		log_error("l2tp-switch: \"%s\" is not a known string-typed"
			  " AVP\n", attr_name);
		return NULL;
	}

	return attr;
}

static struct l2tp_switch_rule_t *rule_find_exact(const struct l2tp_dict_attr_t *attr,
						   enum l2tp_switch_match_mode mode,
						   const uint8_t *val, int len)
{
	struct l2tp_switch_rule_t *r;

	list_for_each_entry(r, &l2tp_switch_rules, entry)
		if (r->attr == attr && r->mode == mode &&
		    r->len == len && !memcmp(r->val, val, len))
			return r;

	return NULL;
}

int l2tp_switch_rule_add(const char *attr_name, const char *mode_name,
			 const uint8_t *val, int len, const char *target_name)
{
	struct l2tp_switch_target_t *target = l2tp_switch_target_find(target_name);
	const struct l2tp_dict_attr_t *attr;
	enum l2tp_switch_match_mode mode;
	struct l2tp_switch_rule_t *r, candidate;

	if (!target) {
		log_error("l2tp-switch: unknown target \"%s\"\n", target_name);
		return -1;
	}

	attr = resolve_match_attr(attr_name);
	if (!attr)
		return -1;

	if (parse_mode(mode_name, &mode) < 0) {
		log_error("l2tp-switch: unknown match mode \"%s\","
			  " expected \"exact\" or \"prefix\"\n", mode_name);
		return -1;
	}

	candidate.attr = attr;
	candidate.mode = mode;
	candidate.val = (uint8_t *)val;
	candidate.len = len;

	list_for_each_entry(r, &l2tp_switch_rules, entry) {
		if (r->attr != attr)
			continue;
		if (rules_overlap(r, &candidate)) {
			log_error("l2tp-switch: match rule for \"%s\""
				  " overlaps with an existing rule for the"
				  " same attribute (ambiguous)\n", attr_name);
			return -1;
		}
	}

	r = _malloc(sizeof(*r));
	if (!r)
		return -1;

	r->val = _malloc(len);
	if (!r->val) {
		_free(r);
		return -1;
	}
	memcpy(r->val, val, len);
	r->attr = attr;
	r->mode = mode;
	r->len = len;
	r->target = target;

	list_add_tail(&r->entry, &l2tp_switch_rules);

	return 0;
}

int l2tp_switch_rule_del(const char *attr_name, const char *mode_name,
			 const uint8_t *val, int len)
{
	const struct l2tp_dict_attr_t *attr = resolve_match_attr(attr_name);
	enum l2tp_switch_match_mode mode;
	struct l2tp_switch_rule_t *r;

	if (!attr)
		return -1;

	if (parse_mode(mode_name, &mode) < 0) {
		log_error("l2tp-switch: unknown match mode \"%s\","
			  " expected \"exact\" or \"prefix\"\n", mode_name);
		return -1;
	}

	r = rule_find_exact(attr, mode, val, len);
	if (!r)
		return -1;

	list_del(&r->entry);
	free_rule(r);

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

static int parse_match(const char *val)
{
	/* match=<attr-name>,<mode>,<value>,<target-name> */
	char *copy, *attr_name, *mode_name, *value, *target_name, *save = NULL;
	int ret;

	copy = _strdup(val);
	if (!copy)
		return -1;

	attr_name = strtok_r(copy, ",", &save);
	mode_name = strtok_r(NULL, ",", &save);
	value = strtok_r(NULL, ",", &save);
	target_name = strtok_r(NULL, ",", &save);

	if (!attr_name || !mode_name || !value || !target_name) {
		log_error("l2tp-switch: malformed match= \"%s\", expected"
			  " attr-name,mode,value,target-name\n", val);
		_free(copy);
		return -1;
	}

	ret = l2tp_switch_rule_add(attr_name, mode_name,
				   (const uint8_t *)value, strlen(value),
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

	switch_conf_clear();

	if (!s)
		return 0;

	/* targets first: match= entries reference them by name */
	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "target") && opt->val)
			if (parse_target(opt->val) < 0)
				return -1;
	}

	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "match") && opt->val)
			if (parse_match(opt->val) < 0)
				return -1;
	}

	return validate_no_self_loop();
}
