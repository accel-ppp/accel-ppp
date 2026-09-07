#ifndef __L2TP_SWITCH_CONF_H
#define __L2TP_SWITCH_CONF_H

#include <netinet/in.h>
#include <stdint.h>

#include "list.h"
#include "triton.h"

struct l2tp_dict_attr_t;
struct l2tp_conn_t;

struct l2tp_switch_target_t {
	struct list_head entry;
	char *name;
	struct sockaddr_in peer_addr;
	char *secret;
	size_t secret_len;

	/* Owned by l2tp.c (Task 3): the persistent outbound tunnel for this
	 * target, or NULL while down/reconnecting. */
	struct l2tp_conn_t *tunnel;
	struct triton_timer_t reconnect_timer;

	/* Owned by l2tp.c (Task 7): live/cumulative stats for this target,
	 * from this target's own point of view -- rx is bytes received FROM
	 * this target's downstream LNS, tx is bytes sent TO it. Monotonic:
	 * never reset, never decremented, so they stay valid Prometheus
	 * counters across calls starting and ending. */
	unsigned int active;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
};

extern struct list_head l2tp_switch_targets;

int l2tp_switch_conf_load(void);
const struct l2tp_dict_attr_t *l2tp_switch_conf_attr(void);
struct l2tp_switch_target_t *l2tp_switch_lookup(const uint8_t *val, int len);
struct l2tp_switch_target_t *l2tp_switch_target_find(const char *name);
int l2tp_switch_line_add(const uint8_t *val, int len, const char *target_name);
int l2tp_switch_line_del(const uint8_t *val, int len);

#endif
