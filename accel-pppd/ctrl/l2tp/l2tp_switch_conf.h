#ifndef __L2TP_SWITCH_CONF_H
#define __L2TP_SWITCH_CONF_H

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>

#include "list.h"
#include "triton.h"

struct l2tp_dict_attr_t;
struct l2tp_conn_t;

enum l2tp_switch_conn_mode {
	L2TP_SWITCH_MODE_PERSISTENT,
	L2TP_SWITCH_MODE_ON_DEMAND,
};

/* Freed only by the next config load, so pointers need no refcount. */
struct l2tp_switch_target_t {
	struct list_head entry;
	char *name;
	struct sockaddr_in peer_addr;
	char *secret;
	size_t secret_len;
	enum l2tp_switch_conn_mode mode;

	/* Owned by l2tp.c, set when a connect attempt starts: test state == STATE_ESTB */
	struct l2tp_conn_t *tunnel;
	struct triton_timer_t reconnect_timer;

	/* Protects the fields below, tunnel and reconnect_timer; used from several contexts */
	pthread_mutex_t lock;
	struct list_head pending_calls;
	unsigned int pending_count;
	int connect_budget_open;
	/* Monotonic ms, lets the handler ignore a stale timer dispatch */
	uint64_t connect_deadline;
	struct triton_timer_t connect_timeout_timer;
	/* Monotonic ms, 0 if none; zeroed under lock to cancel instead of deleting the timer */
	uint64_t idle_deadline;
	struct triton_timer_t idle_timer;

	unsigned int active;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
};

extern struct list_head l2tp_switch_targets;

/* Seconds */
#define L2TP_SWITCH_DEFAULT_IDLE_LINGER_SEC 20
#define L2TP_SWITCH_DEFAULT_CONNECT_TIMEOUT_SEC 10
#define L2TP_SWITCH_DEFAULT_RECONNECT_INTERVAL_SEC 5
#define L2TP_SWITCH_MAX_TIMING_SEC 3600

int l2tp_switch_conf_idle_linger_ms(void);
int l2tp_switch_conf_connect_timeout_ms(void);
int l2tp_switch_conf_reconnect_interval_ms(void);

int l2tp_switch_conf_load(void);
struct l2tp_switch_target_t *l2tp_switch_target_find(const char *name);

/* Callers offer every AVP they see until one call returns non-NULL */
struct l2tp_switch_target_t *l2tp_switch_match(const struct l2tp_dict_attr_t *attr,
					       const uint8_t *val, int len);
/* Take the lock once around a loop of l2tp_switch_match_locked() */
void l2tp_switch_match_lock(void);
void l2tp_switch_match_unlock(void);
struct l2tp_switch_target_t *l2tp_switch_match_locked(const struct l2tp_dict_attr_t *attr,
						      const uint8_t *val, int len);
/* Highest-priority (earliest configured) rule matching any AVP in attrs */
struct l2tp_switch_target_t *l2tp_switch_match_attrs_locked(const struct list_head *attrs);
/* Free with _free(); NULL on allocation failure */
char *l2tp_switch_rules_format(void);
int l2tp_switch_rule_add(const char *attr_name, const char *mode_name,
			 const uint8_t *val, int len, const char *target_name);
int l2tp_switch_rule_del(const char *attr_name, const char *mode_name,
			 const uint8_t *val, int len);

#endif
