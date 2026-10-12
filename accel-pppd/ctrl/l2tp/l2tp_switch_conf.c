#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
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
/* Protects l2tp_switch_rules. A rule's ->target stays valid after unlock. */
static pthread_rwlock_t l2tp_switch_rules_lock = PTHREAD_RWLOCK_INITIALIZER;

static void free_target(struct l2tp_switch_target_t *t)
{
	pthread_mutex_destroy(&t->lock);
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

static int conf_idle_linger_sec = L2TP_SWITCH_DEFAULT_IDLE_LINGER_SEC;
static int conf_connect_timeout_sec = L2TP_SWITCH_DEFAULT_CONNECT_TIMEOUT_SEC;
static int conf_reconnect_interval_sec = L2TP_SWITCH_DEFAULT_RECONNECT_INTERVAL_SEC;

int l2tp_switch_conf_idle_linger_ms(void)
{
	return conf_idle_linger_sec * 1000;
}

int l2tp_switch_conf_connect_timeout_ms(void)
{
	return conf_connect_timeout_sec * 1000;
}

int l2tp_switch_conf_reconnect_interval_ms(void)
{
	return conf_reconnect_interval_sec * 1000;
}

static int parse_timing_sec(const char *name, const char *val, int *out)
{
	char *endp;
	long n = strtol(val, &endp, 10);

	if (*val == '\0' || *endp || n < 1 || n > L2TP_SWITCH_MAX_TIMING_SEC) {
		log_error("l2tp-switch: invalid %s=\"%s\", expected a whole"
			  " number of seconds between 1 and %d\n", name, val,
			  L2TP_SWITCH_MAX_TIMING_SEC);
		return -1;
	}
	*out = (int)n;
	return 0;
}

static void switch_conf_clear(void)
{
	conf_idle_linger_sec = L2TP_SWITCH_DEFAULT_IDLE_LINGER_SEC;
	conf_connect_timeout_sec = L2TP_SWITCH_DEFAULT_CONNECT_TIMEOUT_SEC;
	conf_reconnect_interval_sec = L2TP_SWITCH_DEFAULT_RECONNECT_INTERVAL_SEC;

	struct l2tp_switch_rule_t *r;
	struct l2tp_switch_target_t *t;

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

/* Two rules are ambiguous if either one matches the other's value */
static int rules_overlap(const struct l2tp_switch_rule_t *a,
			 const struct l2tp_switch_rule_t *b)
{
	return rule_matches_value(a, b->val, b->len) ||
	       rule_matches_value(b, a->val, a->len);
}

struct l2tp_switch_target_t *l2tp_switch_match_locked(const struct l2tp_dict_attr_t *attr,
						      const uint8_t *val, int len)
{
	struct l2tp_switch_rule_t *r;

	list_for_each_entry(r, &l2tp_switch_rules, entry)
		if (r->attr == attr && rule_matches_value(r, val, len))
			return r->target;

	return NULL;
}

void l2tp_switch_match_lock(void)
{
	pthread_rwlock_rdlock(&l2tp_switch_rules_lock);
}

void l2tp_switch_match_unlock(void)
{
	pthread_rwlock_unlock(&l2tp_switch_rules_lock);
}

struct l2tp_switch_target_t *l2tp_switch_match(const struct l2tp_dict_attr_t *attr,
					       const uint8_t *val, int len)
{
	struct l2tp_switch_target_t *target;

	l2tp_switch_match_lock();
	target = l2tp_switch_match_locked(attr, val, len);
	l2tp_switch_match_unlock();

	return target;
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
	struct l2tp_switch_rule_t *r, *existing, candidate;

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

	pthread_rwlock_wrlock(&l2tp_switch_rules_lock);
	list_for_each_entry(existing, &l2tp_switch_rules, entry) {
		if (existing->attr != attr)
			continue;
		if (rules_overlap(existing, &candidate)) {
			pthread_rwlock_unlock(&l2tp_switch_rules_lock);
			log_error("l2tp-switch: match rule for \"%s\""
				  " overlaps with an existing rule for the"
				  " same attribute (ambiguous)\n", attr_name);
			free_rule(r);
			return -1;
		}
	}
	list_add_tail(&r->entry, &l2tp_switch_rules);
	pthread_rwlock_unlock(&l2tp_switch_rules_lock);

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

	pthread_rwlock_wrlock(&l2tp_switch_rules_lock);
	r = rule_find_exact(attr, mode, val, len);
	if (r)
		list_del(&r->entry);
	pthread_rwlock_unlock(&l2tp_switch_rules_lock);
	if (!r)
		return -1;

	free_rule(r);

	return 0;
}

/* Keeps empty fields, which strtok_r() would collapse */
static int split_fields(char *str, char **fields, int max)
{
	int n = 0;

	for (;;) {
		char *comma;

		if (n == max)
			return -1;
		fields[n++] = str;
		comma = strchr(str, ',');
		if (!comma)
			return n;
		*comma = '\0';
		str = comma + 1;
	}
}

static int all_non_empty(char **fields, int n)
{
	int i;

	for (i = 0; i < n; i++)
		if (!fields[i][0])
			return 0;
	return 1;
}

/* Names go verbatim into Prometheus labels and JSON keys */
static int valid_target_name(const char *name)
{
	for (; *name; name++)
		if (!isalnum((unsigned char)*name) && *name != '_' &&
		    *name != '-' && *name != '.')
			return 0;
	return 1;
}

static char *redact_target(const char *name, const char *addr,
			    const char *port, const char *mode_str)
{
	char *out;
	int ret;

	if (mode_str)
		ret = _asprintf(&out, "%s,%s,%s,***,%s", name, addr, port,
				 mode_str);
	else
		ret = _asprintf(&out, "%s,%s,%s,***", name, addr, port);

	return ret < 0 ? NULL : out;
}

static int parse_target(const char *val)
{
	struct l2tp_switch_target_t *t;
	char *copy, *f[5], *name, *addr, *port, *secret, *mode_str, *endp;
	int nf;
	long p;

	copy = _strdup(val);
	if (!copy)
		return -1;

	nf = split_fields(copy, f, 5);
	if (nf < 4 || !all_non_empty(f, nf)) {
		if (nf < 0)
			log_error("l2tp-switch: malformed target= (more than 5"
				  " fields found), expected"
				  " name,peer-addr,peer-port,secret[,mode] with no"
				  " empty fields (secrets and names cannot contain"
				  " ',')\n");
		else
			log_error("l2tp-switch: malformed target= (%d field(s)"
				  " found), expected"
				  " name,peer-addr,peer-port,secret[,mode] with no"
				  " empty fields (secrets and names cannot contain"
				  " ',')\n", nf);
		goto err;
	}
	name = f[0];
	addr = f[1];
	port = f[2];
	secret = f[3];
	mode_str = nf == 5 ? f[4] : NULL;

	if (!valid_target_name(name)) {
		log_error("l2tp-switch: invalid target name \"%s\", only"
			  " letters, digits, '_', '-' and '.' are allowed\n",
			  name);
		goto err;
	}

	if (l2tp_switch_target_find(name)) {
		log_error("l2tp-switch: duplicate target name \"%s\"\n", name);
		goto err;
	}

	p = strtol(port, &endp, 10);
	if (*endp || p <= 0 || p > UINT16_MAX) {
		char *redacted = redact_target(name, addr, port, mode_str);

		log_error("l2tp-switch: invalid peer-port in target=\"%s\"\n",
			  redacted ? redacted : name);
		_free(redacted);
		goto err;
	}

	t = _malloc(sizeof(*t));
	if (!t)
		goto err;
	memset(t, 0, sizeof(*t));
	pthread_mutex_init(&t->lock, NULL);
	INIT_LIST_HEAD(&t->pending_calls);

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
		char *redacted = redact_target(name, addr, port, mode_str);

		log_error("l2tp-switch: invalid peer-addr in target=\"%s\"\n",
			  redacted ? redacted : name);
		_free(redacted);
		free_target(t);
		goto err;
	}

	if (!mode_str || !strcmp(mode_str, "on-demand")) {
		t->mode = L2TP_SWITCH_MODE_ON_DEMAND;
	} else if (!strcmp(mode_str, "persistent")) {
		t->mode = L2TP_SWITCH_MODE_PERSISTENT;
	} else {
		char *redacted = redact_target(name, addr, port, mode_str);

		log_error("l2tp-switch: unknown mode \"%s\" in target=\"%s\","
			  " expected \"persistent\" or \"on-demand\"\n",
			  mode_str, redacted ? redacted : name);
		_free(redacted);
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
	char *copy, *f[4];
	int ret;

	copy = _strdup(val);
	if (!copy)
		return -1;

	if (split_fields(copy, f, 4) != 4 || !all_non_empty(f, 4)) {
		log_error("l2tp-switch: malformed match= \"%s\", expected"
			  " attr-name,mode,value,target-name with no empty"
			  " fields (the value cannot contain ',')\n", val);
		_free(copy);
		return -1;
	}
	ret = l2tp_switch_rule_add(f[0], f[1], (const uint8_t *)f[2],
				   strlen(f[2]), f[3]);
	_free(copy);
	return ret;
}

extern in_addr_t l2tp_conf_get_bind_addr(void);
extern uint16_t l2tp_conf_get_bind_port(void);

/* A wildcard bind listens on every local address, so any local one loops */
static int addr_is_local(in_addr_t addr)
{
	struct ifaddrs *ifa_list, *ifa;
	int local = 0;

	if (addr == htonl(INADDR_ANY) || (ntohl(addr) >> 24) == IN_LOOPBACKNET)
		return 1;

	if (getifaddrs(&ifa_list) < 0) {
		log_error("l2tp-switch: getifaddrs() failed: %s\n",
			  strerror(errno));
		return 0;
	}
	for (ifa = ifa_list; ifa && !local; ifa = ifa->ifa_next) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)ifa->ifa_addr;

		local = sin && sin->sin_family == AF_INET &&
			sin->sin_addr.s_addr == addr;
	}
	freeifaddrs(ifa_list);

	return local;
}

static int validate_no_self_loop(void)
{
	in_addr_t bind_addr = l2tp_conf_get_bind_addr();
	uint16_t bind_port = l2tp_conf_get_bind_port();
	struct l2tp_switch_target_t *t;

	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		in_addr_t peer = t->peer_addr.sin_addr.s_addr;
		int loops = bind_addr == htonl(INADDR_ANY) ?
			    addr_is_local(peer) : peer == bind_addr;

		if (loops && ntohs(t->peer_addr.sin_port) == bind_port) {
			log_error("l2tp-switch: target \"%s\" peer-addr:port"
				  " is this host's own [l2tp]"
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

	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "target") && opt->val)
			if (parse_target(opt->val) < 0)
				return -1;
	}

	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "match") && opt->val)
			if (parse_match(opt->val) < 0)
				return -1;
		if (!strcmp(opt->name, "idle-linger") && opt->val)
			if (parse_timing_sec(opt->name, opt->val,
					     &conf_idle_linger_sec) < 0)
				return -1;
		if (!strcmp(opt->name, "reconnect-interval") && opt->val)
			if (parse_timing_sec(opt->name, opt->val,
					     &conf_reconnect_interval_sec) < 0)
				return -1;
		if (!strcmp(opt->name, "connect-timeout") && opt->val)
			if (parse_timing_sec(opt->name, opt->val,
					     &conf_connect_timeout_sec) < 0)
				return -1;
	}

	return validate_no_self_loop();
}
