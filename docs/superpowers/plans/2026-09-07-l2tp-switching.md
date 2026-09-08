# L2TP Switching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let accel-ppp act as an RFC 2661 §5.1 L2TP switch for a configured subset of incoming calls — relaying Proxy LCP/Auth AVPs and PPP frames to a second, downstream L2TP LNS instead of terminating PPP/RADIUS locally.

**Architecture:** Everything that needs deep access to `l2tp.c`'s static tunnel/session state (AVP capture, matching, the persistent downstream tunnel, pairing, the data-plane splice) lives directly in `accel-pppd/ctrl/l2tp/l2tp.c`, following this module's own established pattern of one large file per protocol (see Global Constraints — this is a deliberate departure from "many small files," justified below). The one piece with no such dependency — the `[l2tp-switch]` config table (targets, line-to-target mapping, validation, lookup) — is split into its own `l2tp_switch_conf.c`/`.h` pair, since it is genuinely self-contained and testable independently. A downstream call is placed by reusing existing internal functions unchanged (`l2tp_tunnel_alloc`, `l2tp_tunnel_start`, `l2tp_tunnel_create_session`/`l2tp_session_place_call`, `l2tp_send_ICRQ`/`l2tp_send_ICCN`) rather than writing a parallel LAC implementation.

**Tech Stack:** C (accel-pppd core), Linux kernel `pppol2tp`/`AF_PPPOX` sockets, `splice(2)`, triton (this project's event loop), pytest + existing `tests/common/` fixtures for integration tests.

**Spec:** `docs/superpowers/specs/2026-09-07-l2tp-switching-design.md` — this plan implements that design; read both. Section references below (`§N`) refer to the spec.

## Global Constraints

- Every other (non-switched) session must be byte-for-byte unaffected — same code path as today. Any change to a shared function (`l2tp_recv_ICRQ`, `l2tp_recv_ICCN`, `l2tp_recv_ICRP`, `l2tp_send_ICRQ`, `l2tp_send_ICCN`, `l2tp_session_free`, `l2tp_tunnel_free`, `l2tp_init`) must be a no-op when the session/tunnel involved has no switch association (`switch_target == NULL` / `switch_peer == NULL` / `conn->switch_target == NULL`).
- Switched sessions must never create a `radius_pd_t`, never call `ppp_init`'s data-channel start (`l2tp_session_start_data_channel`/`apses_start`), and must never fire `EV_SES_*` events (confirmed: RADIUS hooks `EV_SES_STARTING`/`EV_SES_POST_STARTED`/`EV_SES_ACCT_START`/`EV_SES_FINISHING`/`EV_SES_FINISHED` in `radius/radius.c:1440-1444`, all fired from the PPP-engine start path this feature must skip). `EV_CTRL_STARTED`/`EV_CTRL_FINISHED` (a different, lower-level pair — see Task 7) are fine to keep firing unconditionally, since their only in-tree consumer (`logs/log_file.c`) only touches the generically-initialized `ap_session.pd_list`, not `ctrl`.
- Downstream-unreachable/rejected/timed-out always CDNs the upstream call (§7) — never fall back to local PPP termination.
- `attr=` accepts any string-typed AVP already in `dict/dictionary.rfc2661`/`dictionary.rfc3931`, resolved via the existing `l2tp_dict_find_attr_by_name()` (`dict.c:27`) — not a hardcoded enum.
- A `line=` value maps to exactly one target; duplicate values across `line=` entries, a `line=` referencing an undefined `target=`, and a `target=` peer-addr equal to accel-ppp's own `[l2tp] bind` address are all fatal config-load errors (§11).
- Use this file's existing conventions throughout: `_malloc`/`_free`/`_strdup` (not bare `malloc`/`free`/`strdup`), `log_session`/`log_tunnel` for logging, `session_hold`/`session_put`/`tunnel_hold`/`tunnel_put` for reference counting, `container_of` for handler dispatch, `triton_context_call` to cross from one tunnel's context into another's.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `accel-pppd/ctrl/l2tp/l2tp_switch_conf.h` | Create | Public structs (`l2tp_switch_target_t`) and API for the `[l2tp-switch]` table. No dependency on `l2tp.c` internals. |
| `accel-pppd/ctrl/l2tp/l2tp_switch_conf.c` | Create | Parses `[l2tp-switch]` (`attr=`, `target=`, `line=`), validates it, holds the in-memory table, exposes lookup/add/del. |
(No changes to `accel-pppd/ctrl/l2tp/l2tp.h`: `struct l2tp_sess_t`/`struct l2tp_conn_t` are both defined directly in `l2tp.c` — not `l2tp.h`, which only holds the AVP/packet-format declarations shared with `dict.c`/`packet.c` — so every new field (`switch_target`/`switch_peer`/`switch_link`/`switch_avps`) and the new `struct l2tp_switch_avps`/`struct l2tp_switch_link_t` types all live in `l2tp.c` itself; see Task 1's consolidated forward-declaration block.)
| `accel-pppd/ctrl/l2tp/l2tp.c` | Modify | Everything that needs the tunnel/session FSM: persistent tunnel bring-up, ICRQ matching, ICCN AVP capture, downstream call placement, `l2tp_send_ICRQ`/`l2tp_send_ICCN` extensions, kernel-socket-only connect, pairing, splice datapath, teardown, `l2tp switch show/add/del` CLI. |
| `accel-pppd/ctrl/l2tp/CMakeLists.txt` | Modify | Add `l2tp_switch_conf.c` to sources. |
| `accel-pppd/extra/metrics.c` | Modify | Expose `l2tp-switch` counters through accel-ppp's existing native Prometheus/JSON `/metrics` endpoint, via the same lazy-`dlsym` per-protocol mechanism already used for `l2tp_stat_starting`/`l2tp_stat_active`. |
| `accel-pppd/ctrl/l2tp/packet_test.c` | Modify | Extend the stub AVP dictionary and add the Proxy-AVP round-trip regression test. |
| `accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c` | Create | Standalone MK-simulator (same non-cmake, manually-compiled convention as `packet_test.c`). |
| `tests/common/l2tp_peer_process.py` | Create | Subprocess wrapper for the above, structurally identical to `pppd_process.py`. |
| `tests/conftest.py` | Modify | Register the `l2tp_switch` pytest marker. |
| `tests/accel-pppd/l2tp_switch/conftest.py` | Create | Scenario fixtures, mirroring `pppoe/conftest.py`/`ipoe/conftest.py`. |
| `tests/accel-pppd/l2tp_switch/test_*.py` | Create | One test file per task, following `test_pppoe_session_chap_secrets.py`'s style. |
| `docs/l2tp_switching.md` | Create | End-user config reference, matching `docs/pppoe_radius.md`'s style. |

---

### Task 1: `[l2tp-switch]` config table + read-only `l2tp switch show`

**Files:**
- Create: `accel-pppd/ctrl/l2tp/l2tp_switch_conf.h`
- Create: `accel-pppd/ctrl/l2tp/l2tp_switch_conf.c`
- Modify: `accel-pppd/ctrl/l2tp/CMakeLists.txt`
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c` (init hook + CLI registration only, `l2tp_init()` at end of file, `DEFINE_INIT(22, l2tp_init)`)
- Test: `tests/accel-pppd/l2tp_switch/conftest.py`, `tests/accel-pppd/l2tp_switch/test_switch_config.py`

**Interfaces:**
- Produces:
  - `struct l2tp_switch_target_t { struct list_head entry; char *name; struct sockaddr_in peer_addr; char *secret; size_t secret_len; struct l2tp_conn_t *tunnel; struct triton_timer_t reconnect_timer; unsigned int active; uint64_t rx_bytes; uint64_t tx_bytes; }` (`tunnel`/`reconnect_timer` are unused until Task 3, `active`/`rx_bytes`/`tx_bytes` until Task 7 — declared now so the struct doesn't change shape later. `rx_bytes`/`tx_bytes` are from this target's own point of view: `rx` is bytes received *from* this target's downstream LNS, `tx` is bytes sent *to* it. Both are monotonic counters living on the target itself, not on any one call, since a call's own byte counters (Task 7) don't survive the call ending and per-target totals must).
  - `int l2tp_switch_conf_load(void)` — parses `[l2tp-switch]`, returns `0` on success, `-1` on any fatal validation error (already logged via `log_error`).
  - `const struct l2tp_dict_attr_t *l2tp_switch_conf_attr(void)` — the resolved `attr=` AVP (defaults to `Calling-Number`).
  - `struct l2tp_switch_target_t *l2tp_switch_lookup(const uint8_t *val, int len)` — returns the target for a raw AVP value, or `NULL`.
  - `int l2tp_switch_line_count(void)`, and a `list_head l2tp_switch_targets` (extern) for CLI iteration.

- [ ] **Step 1: Write `l2tp_switch_conf.h`**

```c
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
```

- [ ] **Step 2: Write `l2tp_switch_conf.c`**

```c
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

extern in_addr_t l2tp_conf_get_bind_addr(void); /* Task 2 adds this to l2tp.c */
extern uint16_t l2tp_conf_get_bind_port(void); /* Task 5 adds this to l2tp.c */

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
```

`ATTR_TYPE_STRING` comes from `l2tp.h` (already defines `ATTR_TYPE_NONE`/`INT16`/`INT32`/`INT64`/`OCTETS`/`STRING`). `list_add_tail`/`list_del`/`list_first_entry`/`list_empty`/`list_for_each_entry`/`LIST_HEAD` come from the project's own `list.h`, already used identically throughout `l2tp.c` — verified by compiling this file with `gcc -fsyntax-only` against the real headers (see the note in `switch_conf_clear()` above about the one macro this project's `list.h` does *not* have).

- [ ] **Step 3: Add `l2tp_conf_get_bind_addr()` to `l2tp.c`**

There is no existing stored variable to read here: `[l2tp] bind` is parsed **twice** in `l2tp.c` today, independently, and neither call site keeps the result around afterward — `start_udp_server()` (~line 4655) parses it straight into a local `addr.sin_addr.s_addr` used immediately for `bind()`, and `l2tp_create_tunnel_exec()` (~line 4791) parses it again into its own local `host.sin_addr` for the CLI-driven tunnel command. So `l2tp_conf_get_bind_addr()` must parse it fresh too, matching `start_udp_server()`'s exact idiom (`inet_addr()`, defaulting to `INADDR_ANY` when unset):

```c
in_addr_t l2tp_conf_get_bind_addr(void)
{
	const char *opt = conf_get_opt("l2tp", "bind");

	return opt ? inet_addr(opt) : htonl(INADDR_ANY);
}

/* Parsed fresh via conf_get_opt(), like l2tp_conf_get_bind_addr() above --
 * not read from the conf_port global, which start_udp_server() below only
 * populates from "[l2tp] port=" *after* l2tp_switch_conf_load() has already
 * run (l2tp_init() calls them in that order), so conf_port would still be
 * stuck at its L2TP_PORT default at self-loop-validation time otherwise. */
uint16_t l2tp_conf_get_bind_port(void)
{
	const char *opt = conf_get_opt("l2tp", "port");

	return (opt && atoi(opt) > 0) ? atoi(opt) : L2TP_PORT;
}
```

Add these functions next to `start_udp_server()` in `l2tp.c`. `l2tp_conf_get_bind_addr()` returns `INADDR_ANY` when no `bind=` is configured, matching how `l2tp_switch_conf.c`'s `validate_no_self_loop()` already treats `INADDR_ANY` as "skip the check." `l2tp_conf_get_bind_port()` is added by Task 5, not this task — it doesn't exist yet at this point in the plan, but is documented here alongside its sibling since both belong to the same self-loop check and a reader implementing Step 3 needs the full picture. **This function did not exist when this task was originally written** — see Task 5's bug note for why `validate_no_self_loop()` needed it added.

- [ ] **Step 4: Wire into `CMakeLists.txt`**

`accel-pppd/ctrl/l2tp/CMakeLists.txt` in full today is:

```cmake
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

ADD_DEFINITIONS(-DDICTIONARY="${CMAKE_INSTALL_PREFIX}/share/accel-ppp/l2tp/dictionary")

ADD_LIBRARY(l2tp SHARED
	l2tp.c
	dict.c
	packet.c
	#	netlink.c
)
TARGET_LINK_LIBRARIES(l2tp ${crypto_lib})
#TARGET_LINK_LIBRARIES(l2tp nl nl-genl)

INSTALL(TARGETS l2tp LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)

FILE(GLOB dict "${CMAKE_CURRENT_SOURCE_DIR}/dict/*")
INSTALL(FILES ${dict} DESTINATION share/accel-ppp/l2tp)
```

(`netlink.c` is already commented out — leave it that way, it's unrelated to this feature.) Add `l2tp_switch_conf.c` to the `ADD_LIBRARY` source list:

```cmake
ADD_LIBRARY(l2tp SHARED
	l2tp.c
	l2tp_switch_conf.c
	dict.c
	packet.c
	#	netlink.c
)
```

- [ ] **Step 5: Register `l2tp switch show` and load the config, in `l2tp_init()`**

In `l2tp.c`, add near the top of the file (with the other includes):

```c
#include "l2tp_switch_conf.h"
```

In `l2tp_init()` (end of `l2tp.c`), right after the existing `load_config();` call, add:

```c
	if (l2tp_switch_conf_load() < 0) {
		log_emerg("l2tp-switch: configuration is invalid,"
			  " terminating\n");
		_exit(EXIT_FAILURE);
	}
```

(Match `dict.c`'s own `dict_init()` in this exact module verbatim — `log_emerg(...)` followed by `_exit(EXIT_FAILURE)` on its own line, not `exit()`. Confirmed while implementing: the codebase-wide convention for this fatal-config-error pattern uses `_exit`, not `exit` — grepping just `radius/serv.c`'s `log_emerg` calls in isolation doesn't show this, since not all of them are paired with an exit in the same spot; `dict.c`, in this same directory, is the precise match.)

**Deliberately not wired to `EV_CONFIG_RELOAD`.** `l2tp.c`'s own `load_config()` *is* registered against that event (`l2tp_init()`, near the end of the file) — a live `accel-cmd`-triggered or SIGHUP reload re-parses `[l2tp]` settings. `l2tp_switch_conf_load()` must **not** get the same treatment, and this needs to stay a conscious decision, not an oversight someone "completes" later by analogy: `l2tp_switch_conf_load()`'s first action is `switch_conf_clear()` (Task 1 Step 2), which frees every `l2tp_switch_target_t` unconditionally — including ones with a live `tunnel` pointer, and ones referenced right now by `sess->switch_target`/`switch_link->target` on active switched sessions (Tasks 5-7). Reloading while any switched call is active would free memory those sessions still hold pointers to. The static config is loaded once, at startup, by design (§4 of the spec: "changing a target's connection details requires a restart" is exactly this constraint); live changes to the *line-to-target mapping* go through `accel-cmd l2tp switch add/del` (Task 2) instead, which mutate the existing table in place rather than tearing it down and rebuilding it.

Add the CLI registration alongside the existing `cli_register_simple_cmd2` calls in `l2tp_init()`:

```c
	cli_register_simple_cmd2(l2tp_switch_show_exec, NULL, 2,
				 "l2tp", "switch");
```

(`l2tp switch show` with no further arguments — using 2-level dispatch here, unlike `l2tp create tunnel`'s 3-level, since `show` is the only verb this step implements; Task 2 adds `add`/`del` as their own registrations.)

**Add every forward declaration this whole feature needs, right now, in one place.** `l2tp.c` defines `struct l2tp_sess_t`/`struct l2tp_conn_t` very early (~line 127/156) and already forward-declares a handful of functions used before their own definition (`l2tp_conn_read`/`l2tp_session_free`/`l2tp_tunnel_free`/`apses_stop`, together at ~line 208-211) for exactly the same reason later tasks run into repeatedly here: several new switch-related types are referenced as pointer fields inside those two very-early structs, and several new switch-related functions get called from existing functions (`l2tp_session_free` ~1063, `l2tp_recv_ICRP` ~3518, `l2tp_recv_ICCN` ~3597) that sit earlier in the file than where the new code naturally belongs (next to the kernel-socket/pairing code it's part of, all later in the file). Concretely:

- `struct l2tp_switch_avps` and `struct l2tp_switch_link_t` are both referenced only as pointer fields inside `struct l2tp_sess_t` (Tasks 6 and 7) — a pointer to an incomplete type is legal in C, so an opaque forward declaration of the struct *tag* here is sufficient; their full bodies are defined later (Tasks 6 and 7), wherever convenient.
- `l2tp_switch_link_free()` and `l2tp_switch_teardown_peer()` (both Task 7) are called from `l2tp_session_free()`'s teardown hook (Task 8, editing the *existing* function at ~line 1063) but naturally belong next to the rest of the splice/pairing code, anchored near `l2tp_session_connect` (~1951) or later — after 1063, not before it.

Add this block next to the existing forward declarations (`l2tp.c` ~line 208-211), alongside them rather than in a separate spot:

```c
struct l2tp_switch_avps;
struct l2tp_switch_link_t;

static unsigned int l2tp_switch_active_total(void);
static void l2tp_switch_link_free(struct l2tp_switch_link_t *link);
static void l2tp_switch_teardown_peer(void *data);
```

(`l2tp_switch_capture_avp()`, `l2tp_switch_place_downstream_call()` (both Task 6), and `l2tp_switch_finish_upstream()` (Task 7) have the same kind of dependency — each is called from within an existing function's body before its own natural definition point — but each of those existing functions' modifications and the new function's definition are introduced together, in the same task, entirely under that task's own control; those tasks place the new definition directly above the existing function that calls it instead of adding another forward declaration here, which is called out explicitly at each of those points below.)

Write `l2tp_switch_show_exec` above `l2tp_init()`:

```c
static int l2tp_switch_show_exec(const char *cmd, char * const *fields,
				 int fields_cnt, void *client)
{
	struct l2tp_switch_target_t *t;

	cli_send(client, "targets:\r\n");
	list_for_each_entry(t, &l2tp_switch_targets, entry)
		cli_sendv(client, "  %s -> %s:%hu\r\n", t->name,
			 inet_ntoa(t->peer_addr.sin_addr),
			 ntohs(t->peer_addr.sin_port));

	return CLI_CMD_OK;
}
```

- [ ] **Step 6: Write the pytest scaffolding**

Create `tests/accel-pppd/l2tp_switch/conftest.py`:

```python
import pytest


@pytest.fixture()
def l2tp_switch_config():
    # should be redefined by specific tests
    return ""


@pytest.fixture()
def accel_pppd_config(l2tp_switch_config):
    return (
        """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [l2tp]
    verbose=1
    secret=testsecret

    """
        + l2tp_switch_config
    )
```

Create `tests/accel-pppd/l2tp_switch/test_switch_config.py`:

```python
from common import process


def test_l2tp_switch_show_empty(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run([accel_cmd, "l2tp switch"])

    assert exit == 0
    assert "targets:" in out


def test_l2tp_switch_show_target(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run([accel_cmd, "l2tp switch"])

    assert exit == 0
    assert "acme -> 203.0.113.50:1701" in out


test_l2tp_switch_show_target.__test__ = False  # enabled once l2tp_switch_config below is set per-test via fixture override
```

Replace that placeholder-marked last line — pytest fixture overrides are done via re-declaring the fixture in the test module, not a `__test__` flag. Rewrite the file to:

```python
import pytest
from common import process


def test_l2tp_switch_show_empty(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run([accel_cmd, "l2tp switch"])

    assert exit == 0
    assert "targets:" in out


class TestWithTarget:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    attr=Calling-Number
    target=acme,203.0.113.50,1701,targetsecret
    line=472913,acme
    """

    def test_l2tp_switch_show_target(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


class TestDuplicateLine:
    """A line= value must not appear twice, even pointing at different
    targets -- §11's fatal config-load error, not silent last-wins."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    line=472913,acme
    line=472913,other
    """

    def test_duplicate_line_value_rejected(self, accel_pppd_instance):
        # l2tp_switch_conf_load() returning -1 makes l2tp_init() call
        # log_emerg()+exit(EXIT_FAILURE) before the daemon ever becomes
        # ready -- accel_pppd_instance (the shared fixture) should report
        # this as a failed start, not a successful one.
        assert accel_pppd_instance is False


class TestSelfLoopTarget:
    """A target whose peer-addr equals this host's own [l2tp] bind
    address is a tunnel-to-itself misconfiguration -- also a fatal
    config-load error (§11)."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=loopback,127.0.0.1,1701,targetsecret
    line=472913,loopback
    """

    @pytest.fixture()
    def accel_pppd_config(self, l2tp_switch_config):
        # Overrides the module-level fixture (Task 1) to add an explicit
        # [l2tp] bind= -- without one, l2tp_conf_get_bind_addr() returns
        # INADDR_ANY, which validate_no_self_loop() deliberately treats as
        # "skip the check" (Task 1 Step 1), so this test would otherwise
        # never actually exercise the rejection it's testing for.
        return (
            """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [l2tp]
    verbose=1
    secret=testsecret
    bind=127.0.0.1

    """
            + l2tp_switch_config
        )

    def test_self_loop_target_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False
```

- [ ] **Step 7: Build and run**

```bash
cd accel-ppp && mkdir -p build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr -DRADIUS=TRUE ..
make -j"$(nproc)"
sudo make install
cd ../tests
sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_config.py
```

Expected: both tests pass; `l2tp switch` with no `[l2tp-switch]` section prints just `targets:`; with the section, prints the `acme` line.

- [ ] **Step 8: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp_switch_conf.h accel-pppd/ctrl/l2tp/l2tp_switch_conf.c \
        accel-pppd/ctrl/l2tp/l2tp.c accel-pppd/ctrl/l2tp/CMakeLists.txt \
        tests/accel-pppd/l2tp_switch/
git commit -m "feat(l2tp): add [l2tp-switch] config table and read-only CLI"
```

---

### Task 2: `accel-cmd l2tp switch add/del`

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c`
- Test: `tests/accel-pppd/l2tp_switch/test_switch_cli.py`

**Interfaces:**
- Consumes: `l2tp_switch_line_add()`, `l2tp_switch_line_del()`, `l2tp_switch_target_find()` (Task 1).
- Produces: `l2tp switch add <value> <target-name>` / `l2tp switch del <value>` CLI commands.

- [ ] **Step 1: Write the failing test**

`tests/accel-pppd/l2tp_switch/test_switch_cli.py`:

```python
from common import process


def test_l2tp_switch_add_del(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run(
        [accel_cmd, "l2tp switch add 472913 acme"]
    )
    # accel-cmd's own exit code reflects only local/connection errors, never
    # whether the remote CLI command succeeded (confirmed against a real
    # accel-pppd/accel-cmd on a VM while writing this plan -- it is always
    # 0 here, same "# accel-cmd fails" convention already used elsewhere in
    # this test suite, e.g. test_pppoe_session_wo_auth.py). A failed command
    # is signaled by "command failed" appended to the response text instead
    # -- no target named "acme" is configured in this test's base config, so
    # that's what should appear here.
    assert exit == 0
    assert "failed" in out
```

- [ ] **Step 2: Run, verify it fails**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_cli.py`
Expected: FAIL — `l2tp switch add` is not a recognized command yet. `cli_process_simple_cmd()` matches simple commands by header *prefix*, so typing `l2tp switch add ...` still matches Task 1's already-registered 2-word `l2tp switch` (show) handler and runs it, returning `CLI_CMD_OK` with no error text — the assertion looking for `"failed"` in the output fails because that text was never produced, not because the command was rejected outright.

- [ ] **Step 3: Implement `l2tp switch add`/`del`**

In `l2tp.c`, alongside `l2tp_switch_show_exec`:

```c
static int l2tp_switch_add_exec(const char *cmd, char * const *fields,
				int fields_cnt, void *client)
{
	if (fields_cnt != 5) {
		cli_send(client, "usage: l2tp switch add <value> <target>\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (l2tp_switch_line_add((const uint8_t *)fields[3], strlen(fields[3]),
				 fields[4]) < 0) {
		cli_send(client, "failed: unknown target or duplicate value\r\n");
		return CLI_CMD_FAILED;
	}

	return CLI_CMD_OK;
}

static int l2tp_switch_del_exec(const char *cmd, char * const *fields,
				int fields_cnt, void *client)
{
	if (fields_cnt != 4) {
		cli_send(client, "usage: l2tp switch del <value>\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (l2tp_switch_line_del((const uint8_t *)fields[3],
				 strlen(fields[3])) < 0) {
		cli_send(client, "failed: no such value\r\n");
		return CLI_CMD_FAILED;
	}

	return CLI_CMD_OK;
}
```

Register in `l2tp_init()`, next to the `l2tp switch` (show) registration:

```c
	cli_register_simple_cmd2(l2tp_switch_add_exec, NULL, 3,
				 "l2tp", "switch", "add");
	cli_register_simple_cmd2(l2tp_switch_del_exec, NULL, 3,
				 "l2tp", "switch", "del");
```

(`fields_cnt == 5` for `add`: `["l2tp","switch","add",<value>,<target>]`; `fields[3]`/`fields[4]` are the two arguments — the same `fields[]` indexing already used by `l2tp_create_tunnel_exec`.)

- [ ] **Step 4: Run, verify the intended-fail test still fails as designed, then add the success-path test**

Extend `test_switch_cli.py` with a config that defines the `acme` target (mirroring Task 1's `TestWithTarget` pattern) and assert `add` succeeds and `l2tp switch` then lists it under the line, plus `del` removes it:

```python
import pytest
from common import process


def test_l2tp_switch_add_unknown_target(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run([accel_cmd, "l2tp switch add 472913 acme"])
    assert exit == 0
    assert "failed" in out


class TestWithTarget:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_l2tp_switch_add_del(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run(
            [accel_cmd, "l2tp switch add 472913 acme"]
        )
        assert exit == 0
        assert "failed" not in out

        (exit, out, err) = process.run([accel_cmd, "l2tp switch del 472913"])
        assert exit == 0
        assert "failed" not in out

        (exit, out, err) = process.run([accel_cmd, "l2tp switch del 472913"])
        assert exit == 0
        assert "failed" in out  # already removed

    def test_l2tp_switch_add_duplicate_rejected(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch add 472913 acme"])
        assert exit == 0
        assert "failed" not in out

        # same value again, even naming a valid target -- l2tp_switch_line_add()'s
        # own line_find() check (Task 1) must reject this, not silently overwrite it
        (exit, out, err) = process.run([accel_cmd, "l2tp switch add 472913 acme"])
        assert exit == 0
        assert "failed" in out
```

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_cli.py`
Expected: all PASS.

**Bug found verifying this against a real accel-pppd/accel-cmd on a VM:** the original version of this test used `assert exit != 0` for every failure case. `accel-cmd`'s process exit code reflects only local/connection-level errors (bad params, connection failure, timeout) — never whether the remote CLI command itself succeeded (see `accel-cmd/accel_cmd.c`'s `XSTATUS_*` enum, none of which correspond to a remote failure). This is why the existing test suite already carries `# accel-cmd fails` comments next to `assert exit == 0` in several places (e.g. `tests/accel-pppd/pppoe/test_pppoe_session_wo_auth.py`). A remote failure is signaled only by `"command failed"` (`CLI_CMD_FAILED`) or `"syntax error"` (`CLI_CMD_SYNTAX`) appended to the response text (`accel-pppd/cli/cli.c`'s `MSG_FAILURE_ERROR`/`MSG_SYNTAX_ERROR`). Every `assert exit != 0` above fails outright against the real daemon (`accel-cmd`'s exit code is always 0 here) — confirmed by actually running this test against a real accel-pppd/accel-cmd on a VM. Fixed to assert on `"failed" in out`/`"failed" not in out` instead.

- [ ] **Step 5: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c tests/accel-pppd/l2tp_switch/test_switch_cli.py
git commit -m "feat(l2tp): add accel-cmd l2tp switch add/del"
```

---

### Task 3: Persistent downstream tunnel manager

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c`
- Modify: `tests/common/accel_pppd_process.py` (adds an optional `cli_port=` param to `start()`/`end()` — see the bug note after Step 3)
- Test: `tests/accel-pppd/l2tp_switch/test_switch_tunnel.py`

**Interfaces:**
- Consumes: `l2tp_switch_targets` (Task 1), `l2tp_tunnel_alloc()`, `l2tp_tunnel_start()`, `l2tp_send_SCCRQ` (existing, used unchanged — same as the `l2tp create tunnel` CLI path).
- Produces: `target->tunnel` set once up; automatic reconnect on drop; a `status` field in `l2tp switch show`'s target listing.

This is the first task that makes an actual second `accel-pppd` instance necessary in tests — the fixtures already support running two `accel_pppd_instance`s in one test by calling the fixture logic twice with two different config files, since L2TP is plain UDP and needs no veth/netns.

- [ ] **Step 1: Write the failing test**

`tests/accel-pppd/l2tp_switch/test_switch_tunnel.py`:

```python
import time
from common import process, config, accel_pppd_process


def test_switch_tunnel_comes_up(pytestconfig, accel_cmd, accel_pppd):
    # downstream ("customer") LNS instance, plain L2TP LNS on port 12345
    downstream_config = config.make_tmp(
        """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2101
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port=12345
    secret=downstreamsecret
    """
    )
    # cli_port=2101 -- this instance's own [cli] tcp= above, which isn't
    # accel-cmd's default port (2001, used by the switch instance below);
    # without it, the readiness/shutdown checks silently target the wrong
    # port for the whole max_wait_time instead of ever reaching this daemon
    # (see the bug note after Step 3 -- accel_pppd_process.py needs a small
    # change to accept this).
    downstream_started, downstream_thread, downstream_ctrl = (
        accel_pppd_process.start(
            accel_pppd, ["-c" + downstream_config], accel_cmd, 5.0,
            cli_port=2101,
        )
    )
    assert downstream_started

    try:
        # switch instance, pointing a target at the downstream instance
        switch_config = config.make_tmp(
            """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2001
    [l2tp]
    secret=upstreamsecret
    [l2tp-switch]
    target=downstream,127.0.0.1,12345,downstreamsecret
    """
        )
        switch_started, switch_thread, switch_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + switch_config], accel_cmd, 5.0
        )
        assert switch_started

        try:
            up = False
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "l2tp switch"])
                assert exit == 0
                if "downstream -> 127.0.0.1:12345 [up]" in out:
                    up = True
                    break
                time.sleep(0.1)

            assert up
        finally:
            accel_pppd_process.end(switch_thread, switch_ctrl, accel_cmd, 10.0)
    finally:
        accel_pppd_process.end(
            downstream_thread, downstream_ctrl, accel_cmd, 10.0, cli_port=2101
        )
        config.delete_tmp(downstream_config)
```

(Two directly-started `accel_pppd_process` pairs, not the `accel_pppd_instance` fixture, because that fixture is scoped to exactly one instance per test via `conftest.py`'s single `accel_pppd_config_file` fixture — calling `accel_pppd_process.start`/`.end` directly, exactly as `conftest.py`'s own `accel_pppd_instance` fixture does internally, is the natural way to run two. The switch instance doesn't need `cli_port=` since its own `[cli] tcp=127.0.0.1:2001` already matches accel-cmd's default.)

**Bug found running this against real accel-pppd/accel-cmd on a VM: `tests/common/accel_pppd_process.py` needs a small change first.** Both `start()`'s readiness poll (`accel-cmd show version`) and `end()`'s `shutdown hard` hardcode a bare `accel_cmd` invocation, which accel-cmd resolves to its compiled-in default port 2001. Every existing test in this suite only ever runs one instance at a time on that default port, so this was never exposed before — but this task's downstream instance deliberately uses 2101 to avoid colliding with the switch's own 2001, and `start()` has no way to know that. Confirmed by direct reproduction: in isolation, `accel_pppd_process.start()` against the downstream config above returns `started=False` after the full 5-second timeout, every time, because it's polling port 2001 where nothing is listening — not because the daemon failed to come up (its own `[cli]` on 2101 was confirmed listening throughout). Silently running this test unmodified would make the *whole test* impossible to ever pass, not flaky — a 100% reproducible failure.

Fix by adding an optional `cli_port=None` parameter to both `start()` and `end()` in `accel_pppd_process.py`, defaulting to the old bare-`accel_cmd` behavior (so every other existing caller in the test suite is unaffected) and adding `["-p", str(cli_port)]` to the check/shutdown command when given:

```python
def start(accel_pppd, args, accel_cmd, max_wait_time, cli_port=None):
    ...
    check_cmd = [accel_cmd]
    if cli_port is not None:
        check_cmd += ["-p", str(cli_port)]
    check_cmd += ["show version"]
    ...
    (exit, out, err) = process.run(check_cmd)
    ...

def end(accel_pppd_thread, accel_pppd_control, accel_cmd, max_wait_time, cli_port=None):
    ...
    shutdown_cmd = [accel_cmd]
    if cli_port is not None:
        shutdown_cmd += ["-p", str(cli_port)]
    shutdown_cmd += ["shutdown hard"]
    process.run(shutdown_cmd)
    ...
```

Add `tests/common/accel_pppd_process.py` to this task's `git add` in Step 5.

- [ ] **Step 2: Run, verify it fails**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_tunnel.py`
Expected: FAIL — `l2tp switch` doesn't print a `[up]`/`[down]` status yet, and no tunnel is brought up at all.

- [ ] **Step 3: Implement persistent tunnel bring-up**

In `l2tp.c`, add near the other tunnel-lifecycle statics (close to `l2tp_tunnel_alloc`/`l2tp_tunnel_start`):

**Add a forward declaration first**, to Task 1's existing forward-declaration block near the top of the file (next to `l2tp_conn_read`/`l2tp_session_free`/etc.): `l2tp_send_SCCRQ()` is used below but not actually *defined* until much further down in `l2tp.c` (it's what `l2tp_create_tunnel_exec`'s own `l2tp_tunnel_start()` call passes too) — inserting `l2tp_switch_target_connect()` right after `l2tp_tunnel_alloc()`, as this step does, places it well before that definition, so without this the file fails to compile (implicit-declaration error, since it's used as a function-pointer argument of type `triton_event_func`, not merely called):

```c
static void l2tp_send_SCCRQ(void *peer_addr);
```

Every place in this file that accepts or initiates new work checks the global `ap_shutdown` flag first (`l2tp_recv_ICRQ`, `l2tp_recv_OCRQ`, `l2tp_recv_SCCRQ`) — this function must too, since it actively opens a brand-new tunnel and gets re-invoked by the reconnect timer for as long as the daemon runs. Without this guard, a target's tunnel dropping during a graceful shutdown (`ap_shutdown_soft()`, `session.c`) would make the reconnect timer open a new tunnel — new triton context, new network traffic — after the daemon has already started exiting:

```c
static void l2tp_switch_target_connect(struct l2tp_switch_target_t *target)
{
	struct sockaddr_in host = {
		.sin_family = AF_INET,
		.sin_addr = { htonl(INADDR_ANY) },
	};
	struct l2tp_conn_t *conn;

	if (ap_shutdown)
		return;

	conn = l2tp_tunnel_alloc(&target->peer_addr, &host, 3, 0, 0,
				 conf_hide_avps);
	if (conn == NULL) {
		log_error("l2tp-switch: target \"%s\": tunnel allocation"
			  " failed, retrying in 5s\n", target->name);
		goto retry;
	}

	conn->secret = _strdup(target->secret);
	if (conn->secret == NULL) {
		log_error("l2tp-switch: target \"%s\": secret allocation"
			  " failed\n", target->name);
		l2tp_tunnel_free(conn);
		goto retry;
	}
	conn->secret_len = target->secret_len;
	conn->switch_target = target;

	if (l2tp_tunnel_start(conn, l2tp_send_SCCRQ, &target->peer_addr) < 0) {
		log_error("l2tp-switch: target \"%s\": starting tunnel"
			  " failed, retrying in 5s\n", target->name);
		l2tp_tunnel_free(conn);
		goto retry;
	}

	target->tunnel = conn;
	return;

retry:
	target->tunnel = NULL;
	if (triton_timer_add(NULL, &target->reconnect_timer, 0) < 0)
		log_error("l2tp-switch: target \"%s\": failed to schedule"
			  " reconnect\n", target->name);
}

static void l2tp_switch_target_reconnect_timer(struct triton_timer_t *t)
{
	struct l2tp_switch_target_t *target =
		container_of(t, typeof(*target), reconnect_timer);

	triton_timer_del(t);
	l2tp_switch_target_connect(target);
}

static void l2tp_switch_targets_connect(void)
{
	struct l2tp_switch_target_t *target;

	list_for_each_entry(target, &l2tp_switch_targets, entry) {
		target->reconnect_timer.expire =
			l2tp_switch_target_reconnect_timer;
		target->reconnect_timer.period = 5000;
		l2tp_switch_target_connect(target);
	}
}
```

`l2tp_tunnel_alloc(peer, host, framing_cap, lns_mode, port_set, hide_avps)` and the `l2tp_send_SCCRQ`-as-start-func pattern are copied verbatim from `l2tp_create_tunnel_exec` (`l2tp.c`, around line 4871-4890) — `lns_mode=0` because we are the LAC toward this target. `conf_hide_avps` is the existing module-wide default already used elsewhere in `load_config()`.

`triton_timer_add(NULL, ...)`: passing `NULL` for the context runs the timer on the default/global triton context, since a target has no tunnel (and therefore no context) while it's down. Confirmed directly in `accel-pppd/triton/timer.c`'s own `triton_timer_add()` (~line 135): `if (ctx) t->ctx = ...; else t->ctx = (struct _triton_context_t *)default_ctx.tpd;` — `NULL` is an explicitly-handled, intentional case, not an oversight, so no fallback `switch_ctx` is needed.

Add `switch_target` to `struct l2tp_conn_t`. This struct is defined directly in `l2tp.c` (~line 156), not `l2tp.h` — `l2tp.h` only holds the AVP/packet-format declarations shared with `dict.c`/`packet.c`, and neither `l2tp_sess_t` nor `l2tp_conn_t` needs to be visible outside `l2tp.c` itself, so this feature never needs to touch `l2tp.h` at all:

```c
	struct l2tp_switch_target_t *switch_target; /* NULL for ordinary tunnels */
```

(insert next to the existing `unsigned int ref_count;` field in `struct l2tp_conn_t`, matching the codebase's convention of grouping related pointer fields — the `#include "l2tp_switch_conf.h"` already added to `l2tp.c` itself (Task 1 Step 5) supplies the full `struct l2tp_switch_target_t` definition.)

Hook the reconnect-on-drop into `l2tp_tunnel_free()` — right after `conn->state = STATE_CLOSE;`:

```c
	if (conn->switch_target) {
		conn->switch_target->tunnel = NULL;
		if (triton_timer_add(NULL, &conn->switch_target->reconnect_timer, 0) < 0)
			log_error("l2tp-switch: target \"%s\": failed to"
				  " schedule reconnect\n",
				  conn->switch_target->name);
	}
```

Call `l2tp_switch_targets_connect()` from `l2tp_init()`, right after the `l2tp_switch_conf_load()` call added in Task 1.

Extend `l2tp_switch_show_exec` (Task 1) to print status:

```c
	list_for_each_entry(t, &l2tp_switch_targets, entry)
		cli_sendv(client, "  %s -> %s:%hu [%s]\r\n", t->name,
			 inet_ntoa(t->peer_addr.sin_addr),
			 ntohs(t->peer_addr.sin_port),
			 t->tunnel ? "up" : "down");
```

- [ ] **Step 4: Run, verify it passes**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_tunnel.py`
Expected: PASS — the tunnel reaches `STATE_ESTB` against the downstream instance and `l2tp switch` reports `[up]`. Confirmed for real: built and run against a real downstream/switch pair of accel-pppd instances on a Debian 12 VM, `l2tp switch` reported `downstream -> 127.0.0.1:12345 [up]`, pytest PASSED in ~11s.

**Manually verified beyond the automated test, with full log evidence.** First attempt used `[log] log-file=/dev/stdout` redirected to a file over a non-tty shell pipe, which fully buffers rather than line-buffers -- the actual reconnect sequence never got flushed to disk before it could be inspected, leaving the check inconclusive (tunnel came back `[up]`, but no log trail). Re-ran with the `log_file` module correctly loaded in `[modules]` (a real file path under `[log] log-file=` is silently ignored -- and falls through to whatever *other* logging module is loaded, e.g. `log_syslog` -- unless `log_file` itself is also listed in `[modules]`; that's what actually produced usable output this time, via `journalctl`).

Killed the downstream instance while the switch was running. The switch's `l2tp_tunnel_free()` → reconnect-timer hook (Step 3) fired immediately (not after the 60s `conf_hello_interval`, since the peer is now on a closed port and the failing `sendto()`/receive path detects that fast), and from then on retried on the exact configured 5-second cadence -- 15+ consecutive `sending SCCRQ` → `peer is unreachable, disconnecting tunnel` → `deleting tunnel` → `tunnel destroyed` cycles, one every 5s on the dot, for as long as downstream stayed down. The moment downstream was restarted, the very next scheduled retry (within the same 5s window) completed a full SCCRQ → SCCRP → SCCCN exchange and the tunnel reached `established`, with `l2tp switch` immediately reporting `[up]` again. This is a complete, conclusive confirmation of the reconnect path, not just a plausible outcome.

- [ ] **Step 5: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c \
        tests/common/accel_pppd_process.py \
        tests/accel-pppd/l2tp_switch/test_switch_tunnel.py
git commit -m "feat(l2tp): bring up persistent outbound tunnels for switch targets"
```

---

### Task 4: MK-simulator test harness (walking skeleton)

**Files:**
- Create: `accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c`
- Create: `tests/common/l2tp_peer_process.py`
- Test: `tests/accel-pppd/l2tp_switch/test_peer_harness.py`

**Interfaces:**
- Produces: a standalone binary that, given `--peer-addr`, `--peer-port`, `--secret`, `--calling-number`, and (from Task 6 onward) `--proxy-username`/`--proxy-password`, performs one scripted L2TP LAC exchange (SCCRQ→SCCRP→SCCCN, then ICRQ→ICRP→ICCN) and exits 0 on success, non-zero with a diagnostic on stderr otherwise. This task proves the harness works against a **plain, unmodified LNS** (no switch feature involved yet) — later tasks point it at the switch build instead.

This tool is deliberately a fixed, hardcoded script, not a general L2TP client — it exists solely to drive one specific test exchange, reusing the real `packet.c` for wire-format correctness instead of re-implementing L2TP framing.

**Three protocol-correctness bugs found by running this exact code against a real accel-pppd on a disposable Debian 12 VM** (not just the `nc -u -l` static-encoding check) — all fixed in the listing below. Anyone re-deriving this harness from scratch will hit all three, since they only manifest against a real peer, not a static byte-capture:

1. **Peer's tunnel ID read from the wrong place.** RFC 2661 §3.1: the header's Tunnel ID on a received message is the ID *you* assigned to the tunnel (echoed back), not the peer's own ID — that only appears in the `Assigned-Tunnel-ID` AVP of the payload. Using `ntohs(reply->hdr.tid)` as the peer's tunnel ID (an easy mistake — it happens to still be a valid-looking u16) produces a value that is actually just your own `local_tid` reflected back; every subsequent message you send with it as the header tid gets logged and discarded server-side as `discarding message with invalid tid`. Fix: walk `reply->attrs` for `Assigned-Tunnel-ID` exactly as already done for `Assigned-Session-ID` after ICRP.
2. **No Ns/Nr sequence-number tracking.** `l2tp_packet_alloc()` zero-initializes both fields and `packet.c` never touches them again — RFC 2661 §5.8 sequencing is entirely the caller's job. Leaving every message at `Ns=0, Nr=0` makes the SCCCN look like a duplicate retransmission of the SCCRQ to the real daemon (identical Ns/Nr from the tunnel's perspective), which discards it and the exchange stalls until the peer gives up and tears down the tunnel. Fix: track `my_ns` (incremented after every message sent) and `peer_next_nr` (set to `ntohs(reply->hdr.Ns) + 1` after every message received) and stamp both onto `pack->hdr.Ns`/`pack->hdr.Nr` (via `htons()`, matching `l2tp.c`'s own convention at its `pack->hdr.Ns = htons(conn->Ns)` call sites) before every send.
3. **`while (*reply == NULL)` never actually skips a ZLB.** `l2tp_recv()` (`packet.c`) unconditionally sets `*p = pack` at the end of a successful parse (`packet.c:537`) — including for a ZLB, which is just a message with zero AVPs, not a NULL packet. In the two-message-per-side control exchange this harness drives, the daemon's ZLB acking the SCCCN is already sitting in the socket receive buffer *before* the harness sends ICRQ, so the very next `l2tp_recv()` call picks up that empty ZLB instead of waiting for the real ICRP — `send_and_recv()` returns it as if it were the reply, and the caller finds no `Assigned-Session-ID` in an attrs list that is empty by construction. Fix: check `list_empty(&(*reply)->attrs)` instead of a NULL check, freeing and re-looping on an empty (ZLB) packet.

The harness must also implement RFC 2661 §5.1.1 tunnel-authentication Challenge/Challenge-Response: any peer with `[l2tp] secret=` configured (which every test fixture in this plan sets) sends a mandatory `Challenge` AVP in its SCCRP, and rejects a SCCCN that doesn't answer it with a matching MD5 `Challenge-Response`. This mirrors `l2tp_tunnel_genchallresp()`/`comp_chap_md5()` in `l2tp.c` (~line 468/286) exactly: `MD5(msg-ident-octet || secret || challenge)`, where `msg-ident-octet` is the single-byte SCCCN message-type value (`Message_Type_Start_Ctrl_Conn_Connected`, i.e. 3).

- [ ] **Step 1: Write `l2tp_switch_peer_test.c`**

**Do not link the real `dict.c`.** `packet.c`'s `attr_alloc()` (used by every `l2tp_packet_add_*` call) and its AVP-parsing loop in `l2tp_recv()` both call `l2tp_dict_find_attr_by_id()` — without a match, encoding an AVP silently fails (`attr_alloc()` returns `NULL`, and every `add_*` call returns `-1`) and decoding treats it as unknown. The real `dict.c` only becomes usable via `dict_init()`, which needs the `DICTIONARY` path macro (normally supplied by CMake, pointing at an *installed* dictionary file) or `[l2tp] dictionary=` read through `conf_get_opt()` — i.e. the whole triton conf-file subsystem — and is only ever invoked via `DEFINE_INIT`'s init-registration mechanism, none of which a standalone test binary has. `packet_test.c` in this same directory already solves this the right way: it stubs its own minimal dictionary and its own `l2tp_dict_find_attr_by_id()`/`l2tp_dict_find_value()` rather than linking `dict.c` at all. Follow that exact pattern here, with entries for every AVP this harness sends or parses (types and `M` values copied verbatim from `dict/dictionary.rfc2661`, the actual production dictionary file — not guessed):

```c
/*
 * Standalone MK-simulator L2TP LAC peer for integration testing.
 *
 * Not part of the cmake build. Compile and run with:
 *   gcc -O1 -g -Wall -fno-strict-aliasing -D_GNU_SOURCE \
 *       -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -I accel-pppd/include -I accel-pppd/ctrl/l2tp \
 *       -o /tmp/l2tp_switch_peer_test \
 *       accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c \
 *       accel-pppd/ctrl/l2tp/packet.c -lcrypto
 *
 * Performs one scripted LAC exchange: SCCRQ -> SCCRP -> SCCCN, then
 * ICRQ -> ICRP -> ICCN, using real packet.c encode/decode. Exits 0 on
 * success. See packet_test.c in this directory for the sibling harness
 * that exercises packet.c's parser directly rather than over a socket,
 * and whose stub-dictionary approach this file copies (real dict.c is
 * not linked here either -- see the note above this listing).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "l2tp.h"
#include "l2tp_prot.h"
#include "attr_defs.h"
#include <openssl/md5.h>

/* Mirrors l2tp.c's static inline comp_chap_md5() (~line 286) -- tunnel-auth
 * Challenge Response is MD5(msg-ident-octet || secret || challenge), per
 * RFC 2661 section 5.1.1 / 4.3. Needed because every test fixture in this
 * plan sets [l2tp] secret=, which makes the real daemon send a mandatory
 * Challenge AVP in its SCCRP and reject a SCCCN that doesn't answer it. */
static void comp_chap_md5(uint8_t *md5, uint8_t ident,
			  const void *secret, size_t secret_len,
			  const void *chall, size_t chall_len)
{
	MD5_CTX md5_ctx;

	memset(md5, 0, MD5_DIGEST_LENGTH);
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, &ident, sizeof(ident));
	MD5_Update(&md5_ctx, secret, secret_len);
	MD5_Update(&md5_ctx, chall, chall_len);
	MD5_Final(md5, &md5_ctx);
}

/* packet.c needs a working dictionary (attr_alloc() and l2tp_recv()'s AVP
 * loop both call l2tp_dict_find_attr_by_id(), and every l2tp_packet_add_*
 * call fails outright without a match), a mempool implementation, a
 * u_randbuf() (used internally by l2tp_packet_alloc() for the Random-Vector
 * AVP every control message carries), and log_emerg/log_error/log_warn/
 * log_ppp_debug. None of the real implementations are usable standalone --
 * see the note above this listing for why dict.c is out; mempool_*, the
 * log_* functions, and u_randbuf() all live in accel-pppd's core/utils,
 * which pulls in the whole triton runtime. packet_test.c stubs all of
 * these itself for the exact same reason; copy that approach verbatim
 * rather than diverging into a second convention. */
int conf_verbose = 1;
int conf_avp_permissive = 0;

#define DEFINE_LOG_STUB(name)						\
void name(const char *fmt, ...)					\
{									\
	va_list ap;							\
	va_start(ap, fmt);						\
	fprintf(stderr, "l2tp_switch_peer_test: " #name ": ");		\
	vfprintf(stderr, fmt, ap);					\
	va_end(ap);							\
}
DEFINE_LOG_STUB(log_emerg)
DEFINE_LOG_STUB(log_error)
DEFINE_LOG_STUB(log_warn)
DEFINE_LOG_STUB(log_ppp_debug)

mempool_t *mempool_create(int size)
{
	int *pool = malloc(sizeof(int));

	*pool = size;

	return (mempool_t *)pool;
}

void *mempool_alloc(mempool_t *pool)
{
	return malloc(*(int *)pool);
}

void mempool_free(void *ptr)
{
	free(ptr);
}

void triton_register_init(int order, void (*func)(void))
{
	func();
}

int u_randbuf(void *buf, size_t buf_len, int *err)
{
	FILE *f = fopen("/dev/urandom", "rb");

	if (!f) {
		if (err)
			*err = errno;
		return -1;
	}
	if (fread(buf, 1, buf_len, f) != buf_len) {
		if (err)
			*err = errno;
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/* Stub dictionary -- see the note above. Types and M values copied
 * verbatim from dict/dictionary.rfc2661. */
static struct l2tp_dict_attr_t dict[] = {
	{ .name = "Message-Type",           .id = Message_Type,           .type = ATTR_TYPE_INT16,  .M = -1, .H =  0 },
	{ .name = "Result-Code",            .id = Result_Code,            .type = ATTR_TYPE_OCTETS, .M =  1, .H =  0 },
	{ .name = "Protocol-Version",       .id = Protocol_Version,       .type = ATTR_TYPE_INT16,  .M =  1, .H =  0 },
	{ .name = "Framing-Capabilities",   .id = Framing_Capabilities,   .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Bearer-Capabilities",    .id = Bearer_Capabilities,    .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Recv-Window-Size",       .id = Recv_Window_Size,       .type = ATTR_TYPE_INT16,  .M =  1, .H =  0 },
	{ .name = "Challenge",              .id = Challenge,              .type = ATTR_TYPE_OCTETS, .M =  1, .H = -1 },
	{ .name = "Challenge-Response",     .id = Challenge_Response,     .type = ATTR_TYPE_OCTETS, .M =  1, .H = -1 },
	{ .name = "Cause-Code",             .id = Cause_Code,             .type = ATTR_TYPE_OCTETS, .M =  1, .H = -1 },
	{ .name = "Host-Name",              .id = Host_Name,              .type = ATTR_TYPE_STRING, .M =  1, .H =  0 },
	{ .name = "Vendor-Name",            .id = Vendor_Name,            .type = ATTR_TYPE_STRING, .M =  0, .H =  0 },
	{ .name = "Assigned-Tunnel-ID",     .id = Assigned_Tunnel_ID,     .type = ATTR_TYPE_INT16,  .M =  1, .H = -1 },
	{ .name = "Assigned-Session-ID",    .id = Assigned_Session_ID,    .type = ATTR_TYPE_INT16,  .M =  1, .H = -1 },
	{ .name = "Call-Serial-Number",     .id = Call_Serial_Number,     .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Framing-Type",           .id = Framing_Type,           .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Called-Number",          .id = Called_Number,          .type = ATTR_TYPE_STRING, .M =  1, .H = -1 },
	{ .name = "Calling-Number",         .id = Calling_Number,         .type = ATTR_TYPE_STRING, .M =  1, .H = -1 },
	{ .name = "TX-Speed",               .id = TX_Speed,               .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Init-Recv-LCP",          .id = Init_Recv_LCP,          .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Last-Sent-LCP",          .id = Last_Sent_LCP,          .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Last-Recv-LCP",          .id = Last_Recv_LCP,          .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Type",      .id = Proxy_Authen_Type,      .type = ATTR_TYPE_INT16,  .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Name",      .id = Proxy_Authen_Name,      .type = ATTR_TYPE_STRING, .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Challenge", .id = Proxy_Authen_Challenge, .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-ID",        .id = Proxy_Authen_ID,        .type = ATTR_TYPE_INT16,  .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Response",  .id = Proxy_Authen_Response,  .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
};

struct l2tp_dict_attr_t *l2tp_dict_find_attr_by_id(int id)
{
	size_t indx;

	for (indx = 0; indx < sizeof(dict) / sizeof(dict[0]); ++indx)
		if (dict[indx].id == id)
			return &dict[indx];

	return NULL;
}

const struct l2tp_dict_value_t *l2tp_dict_find_value(const struct l2tp_dict_attr_t *attr,
						     l2tp_value_t val)
{
	return NULL;
}

static struct sockaddr_in peer_addr;
static const char *secret = "";
static const char *calling_number = "472913";
static uint16_t local_tid = 0x1234;
static uint16_t local_sid = 0x5678;

static int die(const char *msg)
{
	log_error("%s\n", msg);
	return 1;
}

static int send_and_recv(int fd, struct l2tp_packet_t *pack,
			 struct l2tp_packet_t **reply)
{
	if (l2tp_packet_send(fd, pack) < 0)
		return -1;
	l2tp_packet_free(pack);

	for (;;) {
		if (l2tp_recv(fd, reply, NULL, (const char *)secret,
			     strlen(secret)) != 0)
			return -1;
		/* l2tp_recv() always sets *reply to a valid, non-NULL packet
		 * -- even a ZLB (zero-AVP ack), which just has an empty
		 * attrs list. A NULL check can never catch that; check
		 * attrs emptiness instead (see the bug note above this
		 * listing). */
		if (*reply == NULL)
			continue;
		if (list_empty(&(*reply)->attrs)) {
			l2tp_packet_free(*reply);
			*reply = NULL;
			continue;
		}
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int fd, opt;
	struct l2tp_packet_t *pack, *reply;
	uint16_t peer_tid, peer_sid;
	/* RFC 2661 5.8: every control message carries a monotonically
	 * increasing Ns and acks the peer's last-received Ns via Nr.
	 * l2tp_packet_alloc() zero-initializes both, so this harness must
	 * track and set them itself on every message beyond the first. */
	uint16_t my_ns = 0, peer_next_nr = 0;

	static struct option opts[] = {
		{"peer-addr", required_argument, 0, 'a'},
		{"peer-port", required_argument, 0, 'p'},
		{"secret", required_argument, 0, 's'},
		{"calling-number", required_argument, 0, 'c'},
		{0, 0, 0, 0},
	};

	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = htons(1701);

	while ((opt = getopt_long(argc, argv, "a:p:s:c:", opts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			if (inet_aton(optarg, &peer_addr.sin_addr) == 0)
				return die("invalid --peer-addr");
			break;
		case 'p':
			peer_addr.sin_port = htons(atoi(optarg));
			break;
		case 's':
			secret = optarg;
			break;
		case 'c':
			calling_number = optarg;
			break;
		default:
			return die("usage: --peer-addr A --peer-port P"
				   " --secret S [--calling-number C]");
		}
	}

	/* connect()ed to the peer, exactly like the real daemon's own
	 * l2tp_tunnel_alloc() (l2tp.c ~1776) connect()s its per-tunnel UDP
	 * socket -- an earlier version of this harness left it deliberately
	 * unconnected on the theory that connect() would make l2tp_packet_
	 * send()'s sendto() (which always passes an explicit destination)
	 * fail with EISCONN. That theory was wrong (Linux does not return
	 * EISCONN for a connected SOCK_DGRAM socket used with sendto() --
	 * that restriction is for connection-mode/TCP sockets only; the
	 * real daemon relies on exactly this same connect()+sendto()
	 * combination for every control message it sends) and it hid a real
	 * bug found while building Task 7: the kernel's pppol2tp/l2tp_core
	 * data-plane transmit path routes via the underlying UDP socket's
	 * connected peer (inet_sk(sk)->inet_daddr), so leaving `fd`
	 * unconnected made Task 7's data-channel write()/splice() (Step 5
	 * below) report success while silently emitting nothing to the
	 * wire -- confirmed on a real VM via `tcpdump -i lo udp` (no port
	 * filter) showing zero packets despite a successful write(). */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return die("socket() failed");
	if (connect(fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0)
		return die("connect(fd) failed");

	/* --- SCCRQ --- */
	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Request,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("SCCRQ alloc failed");
	l2tp_packet_add_int16(pack, Protocol_Version, L2TP_V2_PROTOCOL_VERSION, 1);
	l2tp_packet_add_int32(pack, Framing_Capabilities, 3, 1);
	l2tp_packet_add_string(pack, Host_Name, "mk-simulator", 1);
	l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, local_tid, 1);
	pack->hdr.tid = 0;
	pack->hdr.sid = 0;
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (send_and_recv(fd, pack, &reply) < 0)
		return die("SCCRQ/SCCRP exchange failed");
	my_ns++;
	peer_next_nr = ntohs(reply->hdr.Ns) + 1;

	/* RFC 2661 3.1: the header's Tunnel ID just echoes back the tunnel ID
	 * *we* assigned (local_tid) -- the peer's own tunnel ID, which we
	 * must use as the header tid on every subsequent message we send,
	 * comes from the Assigned-Tunnel-ID AVP in the SCCRP payload. */
	peer_tid = 0;

	/* Tunnel-auth Challenge (RFC 2661 5.1.1): present in SCCRP whenever
	 * the peer has a [l2tp] secret= configured, which every fixture in
	 * this plan does. */
	{
		struct l2tp_attr_t *attr;
		uint8_t *chall = NULL;
		int chall_len = 0;
		uint8_t challresp[MD5_DIGEST_LENGTH];

		list_for_each_entry(attr, &reply->attrs, entry) {
			if (attr->attr && attr->attr->id == Assigned_Tunnel_ID)
				peer_tid = (uint16_t)attr->val.int16;
			if (attr->attr && attr->attr->id == Challenge) {
				chall = attr->val.octets;
				chall_len = attr->length;
			}
		}

		if (peer_tid == 0) {
			l2tp_packet_free(reply);
			return die("SCCRP carried no Assigned-Tunnel-ID");
		}

		if (chall && strlen(secret) > 0)
			comp_chap_md5(challresp,
				     Message_Type_Start_Ctrl_Conn_Connected,
				     secret, strlen(secret), chall, chall_len);
		l2tp_packet_free(reply);

		/* --- SCCCN --- */
		pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Connected,
					 &peer_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("SCCCN alloc failed");
		pack->hdr.tid = htons(peer_tid);
		pack->hdr.sid = 0;
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (chall && strlen(secret) > 0) {
			if (l2tp_packet_add_octets(pack, Challenge_Response,
						   challresp,
						   MD5_DIGEST_LENGTH, 1) < 0)
				return die("SCCCN Challenge-Response add failed");
		}
		if (l2tp_packet_send(fd, pack) < 0)
			return die("SCCCN send failed");
		l2tp_packet_free(pack);
		my_ns++;
	}

	/* --- ICRQ --- */
	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Request,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("ICRQ alloc failed");
	l2tp_packet_add_int16(pack, Assigned_Session_ID, local_sid, 1);
	l2tp_packet_add_int32(pack, Call_Serial_Number, 1, 1);
	l2tp_packet_add_string(pack, Calling_Number, calling_number, 1);
	pack->hdr.tid = htons(peer_tid);
	pack->hdr.sid = 0;
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (send_and_recv(fd, pack, &reply) < 0)
		return die("ICRQ/ICRP exchange failed");
	my_ns++;
	peer_next_nr = ntohs(reply->hdr.Ns) + 1;

	{
		struct l2tp_attr_t *a;
		peer_sid = 0;
		list_for_each_entry(a, &reply->attrs, entry)
			if (a->attr && a->attr->id == Assigned_Session_ID)
				peer_sid = a->val.uint16;
	}
	l2tp_packet_free(reply);

	if (!peer_sid)
		return die("ICRP carried no Assigned-Session-ID");

	/* --- ICCN --- */
	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("ICCN alloc failed");
	l2tp_packet_add_int32(pack, TX_Speed, 1000, 1);
	l2tp_packet_add_int32(pack, Framing_Type, 3, 1);
	pack->hdr.tid = htons(peer_tid);
	pack->hdr.sid = htons(peer_sid);
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (l2tp_packet_send(fd, pack) < 0)
		return die("ICCN send failed");
	l2tp_packet_free(pack);
	my_ns++;

	printf("ok tid=%hu sid=%hu\n", peer_tid, peer_sid);
	return 0;
}
```

- [ ] **Step 2: Compile it and run it by hand against a throwaway plain accel-pppd LNS**

```bash
cd accel-ppp
gcc -O1 -g -Wall -fno-strict-aliasing -D_GNU_SOURCE \
    -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I accel-pppd/include -I accel-pppd/ctrl/l2tp \
    -o /tmp/l2tp_switch_peer_test \
    accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c \
    accel-pppd/ctrl/l2tp/packet.c -lcrypto
```

Expected: compiles clean under ASan/UBSan.

This exact code (including all three bugs and their fixes above) was compiled and linked against the real `packet.c`, then actually run end-to-end against a real, unmodified `accel-pppd` LNS on a disposable Debian 12 VM while writing this plan — not just a static `nc -u -l` byte-capture (which only confirms the SCCRQ encoding, since it can't produce a real SCCRP/ICRP to receive). The full exchange completed: SCCRQ → SCCRP (tunnel established, including answering the tunnel-auth Challenge) → SCCCN → ICRQ → ICRP → ICCN (carrying real Proxy-Authen AVPs, confirming they survive the real dict/packet encode-decode round trip), the daemon started a real PPP session over it (`lcp_layer_init` etc., since Task 5's diversion doesn't exist yet to intercept it), and a trailing StopCCN cleanly tore the tunnel down — output `ok tid=<n> sid=<n>`, exit 0.

**Test-fixture note:** the real LNS this harness talks to must have `[client-ip-range]` configured (e.g. `127.0.0.0/8` for a loopback test) — without it, accel-ppp's L2TP module silently discards every incoming control packet as `IP address is out of client-ip-range` before this harness's SCCRQ is even parsed. This is a pre-existing accel-ppp requirement, unrelated to the switch feature; every test fixture's `accel_pppd_config` in this plan that actually exchanges L2TP packets over a socket (as opposed to Task 1's CLI-only tests) needs this section added if it isn't already implied by a shared fixture.

**Unrelated pre-existing cosmetic bug noticed, not fixed here:** `l2tp.c`'s own debug logging prints `Assigned-Tunnel-ID`/`Assigned-Session-ID` values above 32767 as negative numbers (e.g. `<Assigned-Tunnel-ID -1569>` for the unsigned value 63967) — `packet.c:55`'s `log_ppp_debug`/print helper formats the `int16` union member with `%i` instead of casting to `unsigned`. Purely a log-readability issue (the actual wire encoding and this harness's own parsing are unaffected, since both correctly treat the value as `uint16`); flag to the user before touching, since it's pre-existing code with no connection to this feature.

- [ ] **Step 3: Write `tests/common/l2tp_peer_process.py`**

```python
from subprocess import Popen, PIPE
from threading import Thread


def peer_thread_func(peer_control):
    process = peer_control["process"]
    (out, err) = process.communicate()
    peer_control["out"] = out
    peer_control["err"] = err
    process.wait()


def start(peer_bin, args):
    peer_process = Popen([peer_bin] + args, stdout=PIPE, stderr=PIPE, text=True)
    peer_control = {"process": peer_process, "out": "", "err": ""}
    peer_thread = Thread(target=peer_thread_func, args=[peer_control])
    peer_thread.start()

    return (peer_thread, peer_control)


def wait(peer_thread, peer_control, timeout):
    peer_thread.join(timeout)
    return peer_control["process"].returncode, peer_control["out"], peer_control["err"]
```

(Same `Popen` + reader-thread shape as `pppd_process.py`; simpler because this tool runs to completion and exits rather than persisting like `pppd`, so there's no `end()`/kill step, just `wait()`.)

- [ ] **Step 4: Write the walking-skeleton test**

`tests/accel-pppd/l2tp_switch/test_peer_harness.py`:

```python
from common import process, config, accel_pppd_process, l2tp_peer_process


def test_peer_harness_against_plain_lns(pytestconfig, accel_cmd, accel_pppd):
    lns_config = config.make_tmp(
        """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2001
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port=17010
    secret=testsecret
    """
    )
    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + lns_config], accel_cmd, 5.0
    )
    assert started

    try:
        peer_thread, peer_ctrl = l2tp_peer_process.start(
            "/tmp/l2tp_switch_peer_test",
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", "17010",
                "--secret", "testsecret",
                "--calling-number", "472913",
            ],
        )
        rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
        assert rc == 0, err
        assert out.startswith("ok ")
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0)
        config.delete_tmp(lns_config)
```

- [ ] **Step 5: Run**

```bash
sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_peer_harness.py
```

Expected: PASS. This confirms the harness correctly completes a full SCCRQ..ICCN exchange against a real, unmodified accel-ppp LNS before it's used to test the switch feature itself in Task 6.

- [ ] **Step 6: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c \
        tests/common/l2tp_peer_process.py \
        tests/accel-pppd/l2tp_switch/test_peer_harness.py
git commit -m "test(l2tp): add standalone MK-simulator peer harness"
```

---

### Task 5: ICRQ-time matching and tagging

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c` (struct field addition; `l2tp_recv_ICRQ`, around line 3358 — `l2tp.h` itself is untouched, see Task 1)
- Test: `tests/accel-pppd/l2tp_switch/test_switch_match.py`

**Interfaces:**
- Consumes: `l2tp_switch_conf_attr()`, `l2tp_switch_lookup()` (Task 1).
- Produces: `sess->switch_target` set on match; a "pending" count surfaced via `l2tp switch show` for observability during this intermediate step.

- [ ] **Step 1: Add the field**

Add to `struct l2tp_sess_t` (next to `lns_mode:1` and friends) — this struct is defined directly in `l2tp.c` (~line 127), not `l2tp.h`:

```c
	struct l2tp_switch_target_t *switch_target; /* NULL: normal session */
```

`l2tp.c` already includes `l2tp_switch_conf.h` (added in Task 1 Step 5), which is where `struct l2tp_switch_target_t` comes from — nothing further to add for this field to compile.

- [ ] **Step 2: Write the failing test**

`tests/accel-pppd/l2tp_switch/test_switch_match.py` (extends the Task 4 walking-skeleton pattern — switch instance in the middle, downstream plain-LNS instance, MK-simulator peer):

```python
import time
from common import process, config, accel_pppd_process, l2tp_peer_process


def start_instance(accel_pppd, accel_cmd, cli_port, l2tp_bind, l2tp_port, secret, extra=""):
    cfg = config.make_tmp(
        f"""
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind={l2tp_bind}
    port={l2tp_port}
    secret={secret}
    {extra}
    """
    )
    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port
    )
    return started, thread, ctrl, cfg


def test_switch_tags_matching_call(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17020, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17021,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17020,downstreamsecret
    line=472913,downstream
    """,
        )
        assert s_started

        try:
            # wait for the persistent downstream tunnel (Task 3)
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17021",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            # the switch instance's own accel-cmd should show one pending/switched call
            (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
            assert "matched: 1" in out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
```

**Bug found running this exact code against real accel-pppd instances on a VM: same `accel_pppd_process.start()`/`end()` port-mismatch as Task 3's bug note (`cli_port=` didn't exist yet when this task's test was first drafted).** `start_instance()` is shared across both the downstream (2101) and switch (2001) instances here, so it must always pass `cli_port=cli_port` through, and every direct `process.run([accel_cmd, ...])` call against the switch instance needs `-p 2001` explicitly rather than relying on it happening to be accel-cmd's default (fragile, and inconsistent with how the downstream instance has to be addressed) -- fixed throughout the listing above.

**Also add a `--called-number` option to the harness now** (`l2tp_switch_peer_test.c`, Task 4), following the exact same incremental-extension pattern Tasks 6/7/8 already use for `--proxy-username`/`--data-pattern`/`--send-stopccn` — every test so far only exercises the *default* `attr=Calling-Number`, and `attr=` being configurable to name any string-typed AVP (§4 of the spec, the whole reason it isn't a hardcoded enum) has no test proving it actually works with a different AVP:

```c
/* add to the option globals, next to calling_number */
static const char *called_number;

/* add to the getopt_long array */
{"called-number", required_argument, 0, 'n'},

/* add "n:" to the existing getopt_long() short-option string
 * ("a:p:s:c:" -> "a:p:s:c:n:") -- without it, --called-number's long
 * form still works (glibc's getopt_long() doesn't require a long
 * option's short equivalent to appear in the optstring to return its
 * val), but -n as a short flag would not parse correctly */

/* add to the switch statement */
case 'n':
	called_number = optarg;
	break;

/* in the ICRQ-building block, right after the existing
 * l2tp_packet_add_string(pack, Calling_Number, calling_number, 1) call: */
if (called_number)
	l2tp_packet_add_string(pack, Called_Number, called_number, 1);
```

Add `tests/accel-pppd/l2tp_switch/test_switch_match_called_number.py`, identical to `test_switch_tags_matching_call` above except `attr=Called-Number` in the switch instance's config and `--called-number` (not `--calling-number`) on the harness invocation — proving the configurable `attr=` mechanism itself works, not just its default value:

```python
import time
from common import process, l2tp_peer_process
from test_switch_match import start_instance  # see the Task 5 helpers.py note below


def test_switch_matches_on_called_number(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17022, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17023,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    attr=Called-Number
    target=downstream,127.0.0.1,17022,downstreamsecret
    line=5551234,downstream
    """,
        )
        assert s_started

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17023",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",  # deliberately not the match key
                    "--called-number", "5551234",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
            assert "matched: 1" in out
        finally:
            from common import accel_pppd_process, config
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        from common import accel_pppd_process, config
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
```

(`--calling-number` deliberately set to a value that is *not* in the switch table — if matching were accidentally still keying off Calling-Number instead of the configured `attr=Called-Number`, this test would fail to match, catching exactly that regression. Note the `from test_switch_match import start_instance` line — not `from helpers import start_instance` as an earlier draft had it — see the plan-ordering bug note after Step 4 below for why, and Task 6's helpers.py refactor for when this import changes again.)

- [ ] **Step 3: Run, verify it fails**

Expected: FAIL — nothing tags sessions yet, `"matched: 1"` never appears (for either test above).

- [ ] **Step 4: Implement matching in `l2tp_recv_ICRQ`**

In `l2tp.c`, `l2tp_recv_ICRQ` (around line 3358) already parses `Calling_Number` into a local `calling[]`/`n` pair before allocating the session (see the existing `case Calling_Number:` branch around line 3411). After `sess = l2tp_tunnel_alloc_session(conn);` succeeds and `sess->peer_sid = peer_sid;` is set (around line 3456), add:

```c
	{
		const struct l2tp_dict_attr_t *match_attr = l2tp_switch_conf_attr();

		if (match_attr) {
			list_for_each_entry(attr, &pack->attrs, entry) {
				if (attr->attr->id != match_attr->id)
					continue;
				sess->switch_target = l2tp_switch_lookup(
					attr->val.octets, attr->length);
				if (sess->switch_target)
					log_tunnel(log_info1, conn,
						   "call matches l2tp-switch"
						   " target \"%s\"\n",
						   sess->switch_target->name);
				break;
			}
		}
	}
```

(Placed after session allocation so `log_tunnel`/`log_session` both remain valid to use; `attr`/`pack` are already in scope from the existing AVP-parsing loop above in this function. `match_attr->id` compares against the *dictionary* id, which is what `l2tp_dict_find_attr_by_id`-style lookups use elsewhere in this file — matches `Calling_Number`'s own numeric id (`attr_defs.h: Calling_Number = 22`) when `attr=Calling-Number` is configured, or whatever AVP `attr=` names otherwise.)

**Extend `struct l2tp_stat_t` once, now, for the whole feature.** `l2tp_stat_t` (`l2tp.c` ~line 103) is a plain struct of `unsigned int` counters; the *only* place its fields are ever read is `l2tp_stat_get()` (~line 229), which does a manual per-field `__atomic_load_n()` copy into a caller-supplied snapshot struct — `show_stat_exec` (the existing `accel-cmd show stat` handler, ~line 4743) only ever sees that snapshot, never the live `l2tp_stat` global directly. A field added to the struct but not to `l2tp_stat_get()` would make `show_stat_exec` read uninitialized stack memory for it. To avoid touching this in four different tasks (this one, Task 6, Task 7, Task 9) and risking exactly that mistake, add every field this whole feature needs in this one place:

```c
struct l2tp_stat_t
{
	unsigned int conn_starting;
	unsigned int conn_active;
	unsigned int conn_finishing;

	unsigned int sess_starting;
	unsigned int sess_active;
	unsigned int sess_finishing;

	unsigned int data_starting;
	unsigned int data_active;
	unsigned int data_finishing;

	/* l2tp-switch (Tasks 5-9) */
	unsigned int switch_matched;             /* ICRQ matched a target (Task 5) */
	unsigned int switch_placed;              /* downstream call placed (Task 6) */
	unsigned int switch_downstream_connected; /* downstream ICRP handled (Task 6/7) */

	/* No switch_active field here, deliberately: "currently bridged
	 * pairs" already has exactly one correct source of truth --
	 * l2tp_switch_target_t.active (Task 1), kept accurate by symmetric
	 * increment/decrement in l2tp_switch_link_create()/_free() (Task 7),
	 * including every partial-failure path. A second, independently
	 * incremented/decremented copy here would be redundant at best and
	 * silently wrong at worst if the two ever drift -- which is exactly
	 * what an earlier draft of this plan did (incremented in one place,
	 * never decremented anywhere). Task 9 derives the aggregate by
	 * summing every target's `active` on read instead. */

	/* LNS-side aggregate byte counters (Task 7) -- named after
	 * lns_mode/the existing `mode <lac|lns>` CLI terminology already in
	 * this file, not "upstream": in ISP/BNG contexts "upstream" usually
	 * means upload-vs-download traffic direction, which would collide
	 * with the rx/tx direction these very counters carry. This is the
	 * side facing MK, from that side's own point of view: rx is bytes
	 * received FROM MK (which then get spliced out to whichever target
	 * each call belongs to), tx is bytes sent back TO MK. Deliberately
	 * aggregated across every target rather than split by MK's own
	 * tunnel ID: those IDs are ephemeral (renegotiated on every
	 * reconnect), so they make poor identity for a long-lived counter.
	 * Per-target rx/tx (from that target's own point of view) live on
	 * l2tp_switch_target_t itself (Task 1), not here -- there can be
	 * several targets, and this struct is a single global snapshot.
	 * Both are monotonic: never decremented, so Prometheus scraping
	 * (Task 9) behaves correctly. */
	uint64_t switch_lns_rx_bytes;
	uint64_t switch_lns_tx_bytes;
};
```

and in `l2tp_stat_get()`, right after the existing `stat->data_finishing = ...` line:

```c
	stat->switch_matched = __atomic_load_n(&l2tp_stat.switch_matched, __ATOMIC_RELAXED);
	stat->switch_placed = __atomic_load_n(&l2tp_stat.switch_placed, __ATOMIC_RELAXED);
	stat->switch_downstream_connected = __atomic_load_n(&l2tp_stat.switch_downstream_connected, __ATOMIC_RELAXED);
	stat->switch_lns_rx_bytes = __atomic_load_n(&l2tp_stat.switch_lns_rx_bytes, __ATOMIC_RELAXED);
	stat->switch_lns_tx_bytes = __atomic_load_n(&l2tp_stat.switch_lns_tx_bytes, __ATOMIC_RELAXED);
```

Tasks 6, 7, and 9 below reference these fields as already existing — they add no further struct or `l2tp_stat_get()` changes. (Task 9 separately adds `l2tp_switch_active_total()`, a plain function that sums `l2tp_switch_target_t.active` across `l2tp_switch_targets` — not a field on this struct, and not part of `l2tp_stat_get()`'s snapshot, since it isn't itself an atomic counter.)

Increment `switch_matched` via the existing `l2tp_stat_inc()` helper (`l2tp_stat_inc(&l2tp_stat.switch_matched);`, `~line 118` area) right after the successful match in the code above, and extend `l2tp_switch_show_exec` (Task 1) to print it — following `show_stat_exec`'s own existing *nested* output style (`l2tp:\r\n  tunnels:\r\n    starting: %u\r\n...`) rather than flat `key: value` lines, so `l2tp switch show`'s output reads consistently with `show stat`'s:

```c
	cli_send(client, "calls:\r\n");
	cli_sendv(client, "  matched: %u\r\n", l2tp_stat.switch_matched);
```

(Reading `l2tp_stat.switch_matched` directly here, not through `l2tp_stat_get()`'s snapshot — `l2tp_switch_show_exec` is a new command with no existing snapshot convention to match, so a direct atomic load is simplest; `show_stat_exec` keeps using its own established snapshot pattern in Task 9.)

**Real, pre-existing bug found running this task's test against a real accel-pppd on a VM — in Task 1's already-committed `validate_no_self_loop()`, not anything new here.** That check compared only `t->peer_addr.sin_addr.s_addr == bind_addr`, ignoring port entirely. This task's own test needs the switch instance on a non-default `[l2tp] bind=127.0.0.1 port=17021` (to avoid colliding with the downstream instance's own listener) while pointing a target at `127.0.0.1:17020` — same IP, different port, not actually a loop. With the IP-only check, the daemon rejected this as a false self-loop and `_exit(EXIT_FAILURE)`ed at startup, 100% reproducibly (confirmed by manually stripping the test config down option-by-option until isolating `bind=`+`port=` together as the trigger). Any deployment running a switch and one of its own targets on the same host at different ports — exactly this test suite's own pattern — would have hit this.

Fixed by adding `l2tp_conf_get_bind_port()` to `l2tp.c` (documented in Task 1 Step 3 above, since that's where its sibling `l2tp_conf_get_bind_addr()` lives) and updating `validate_no_self_loop()` in `l2tp_switch_conf.c` to require *both* the IP and the port to match before rejecting a target as a loop. Re-verified: the true self-loop case (Task 1's own `TestSelfLoopTarget`, where the target's port genuinely matches the switch's own default `L2TP_PORT`) still correctly rejects; the false-positive case (this task's test) now starts and matches correctly. Full suite re-run: 11/11 passing.

**Also found: a plan-ordering issue in this task's own test files.** The originally-written `test_switch_match_called_number.py` (below) imported `from helpers import start_instance` — but `helpers.py` isn't created until Task 6's Step 2. Fixed for this task by importing directly from the sibling test module instead (`from test_switch_match import start_instance`); Task 6's refactor into `helpers.py` should update *both* test files' imports, not just `test_switch_match.py`'s, when it runs.

- [ ] **Step 5: Run, verify it passes**

Expected: PASS. Confirmed for real on a VM: `test_switch_match.py` and `test_switch_match_called_number.py` (see the `--called-number` addendum above) both pass, and the full `l2tp_switch` suite (11 tests as of this task) passes together with no regressions.

- [ ] **Step 6: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c \
        accel-pppd/ctrl/l2tp/l2tp_switch_conf.c \
        accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c \
        tests/accel-pppd/l2tp_switch/test_switch_match.py \
        tests/accel-pppd/l2tp_switch/test_switch_match_called_number.py
git commit -m "feat(l2tp): tag ICRQ-matched calls with their switch target"
```

---

### Task 6: ICCN Proxy AVP capture + downstream call placement

This is the core control-plane task. It makes the switch actually place a call downstream and forward Proxy LCP/Auth AVPs — but does **not** yet bridge data (Task 7); a switched call reaches "downstream ICCN sent" and stops there, verified via `l2tp switch show` and log output, with the pairing/splice added in Task 7 as the very next task (these two are split only because Step-count would otherwise exceed this skill's bite-sized guidance many times over for one task — they are not independently reviewable as "done" on their own, and the combined feature is only actually usable after Task 7).

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c` (struct field additions; `l2tp_recv_ICCN` ~3597, `l2tp_send_ICRQ` ~2483, `l2tp_send_ICCN` ~2556, `l2tp_recv_ICRP` ~3518 — `l2tp.h` itself is untouched, see Task 1)
- Test: `tests/accel-pppd/l2tp_switch/test_switch_avp_forward.py`

**Interfaces:**
- Produces: `struct l2tp_switch_avps` (captured raw AVP octets); `sess->switch_avps`; downstream leg placed via existing `l2tp_tunnel_create_session`/`l2tp_session_place_call`.

- [ ] **Step 1: Add the AVP-capture struct**

In `l2tp.c` (not `l2tp.h` — `struct l2tp_sess_t` lives in `l2tp.c` itself, ~line 127; `l2tp.h` only holds the AVP/packet-format declarations shared with `dict.c`/`packet.c`). Task 1 already forward-declared the `struct l2tp_switch_avps` tag, so the full body can go anywhere convenient in `l2tp.c` — right above `l2tp_recv_ICCN` (Step 4 below) is a natural spot, next to the code that actually fills it in:

```c
struct l2tp_switch_avp_t {
	int id;
	int M;
	uint8_t *val;
	int len;
};

struct l2tp_switch_avps {
	struct l2tp_switch_avp_t avp[8]; /* Init/Last-Sent/Last-Recv LCP,
					   * 5x Proxy-Authen-* */
	int count;
};
```

Add to `struct l2tp_sess_t` (`l2tp.c` ~line 127):

```c
	struct l2tp_switch_avps *switch_avps; /* captured from upstream ICCN */
	struct l2tp_sess_t *switch_downstream; /* the outbound leg, once placed */
	struct l2tp_sess_t *switch_upstream;   /* back-pointer from the outbound leg */
```

(Two separate pointers rather than one symmetric `switch_peer`, because the two legs are asymmetric until Task 7 pairs their data planes — the upstream leg tracks "my downstream leg, if any", the downstream leg tracks "the upstream leg I exist for." Task 7 adds the actual splice wiring on top of these.)

- [ ] **Step 2: Write the failing test**

`tests/accel-pppd/l2tp_switch/test_switch_avp_forward.py` extends Task 5's `start_instance` helper (move it to `conftest.py` as a fixture-free helper function importable by every test file that needs it — create `tests/accel-pppd/l2tp_switch/helpers.py` with `start_instance` moved there verbatim, and update `test_switch_match.py`'s import accordingly in this same step. Also update `test_switch_match_called_number.py`'s `from test_switch_match import start_instance` to `from helpers import start_instance` here too — it was pointed at the sibling test module as an interim fix in Task 5, since `helpers.py` didn't exist yet at that point):

```python
# tests/accel-pppd/l2tp_switch/helpers.py
from common import config, accel_pppd_process


def start_instance(accel_pppd, accel_cmd, cli_port, l2tp_bind, l2tp_port, secret, extra=""):
    cfg = config.make_tmp(
        f"""
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind={l2tp_bind}
    port={l2tp_port}
    secret={secret}
    {extra}
    """
    )
    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + cfg], accel_cmd, 5.0
    )
    return started, thread, ctrl, cfg
```

Update `test_switch_match.py`'s top to `from helpers import start_instance` and delete its now-duplicated local definition. Also update `test_switch_match_called_number.py`'s import from `from test_switch_match import start_instance` to `from helpers import start_instance`.

Add `--proxy-username`/`--proxy-password` options to `l2tp_switch_peer_test.c` (Task 4) that add `Proxy_Authen_Type`/`Proxy_Authen_Name`/`Proxy_Authen_Response` AVPs to the ICCN it sends:

```c
/* add near the other option globals */
static const char *proxy_username;
static const char *proxy_password;

/* add to the getopt_long array */
{"proxy-username", required_argument, 0, 'u'},
{"proxy-password", required_argument, 0, 'w'},

/* add to the switch statement */
case 'u':
	proxy_username = optarg;
	break;
case 'w':
	proxy_password = optarg;
	break;

/* in the ICCN-building block, before l2tp_packet_send(fd, pack): */
if (proxy_username) {
	/* Proxy-Authen-Type is int16 per dict/dictionary.rfc2661 (id 29),
	 * not an octet string -- 2 = PPP_PAP is sufficient here since this
	 * harness only needs to prove the AVP survives the switch intact,
	 * not exercise real PAP semantics. */
	l2tp_packet_add_int16(pack, Proxy_Authen_Type, 2, 1);
	l2tp_packet_add_string(pack, Proxy_Authen_Name, proxy_username, 1);
	if (proxy_password)
		l2tp_packet_add_string(pack, Proxy_Authen_Response,
				       proxy_password, 1);
}
```

Test:

```python
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance


def test_switch_forwards_proxy_avps(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17030, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17031,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17030,downstreamsecret
    line=472913,downstream
    """,
        )
        assert s_started

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "l2tp switch"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17031",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "simon",
                    "--proxy-password", "secretpw",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            # the assertion lives on the switch instance itself: it placed
            # exactly one downstream call carrying the proxy AVPs
            (exit, out, err) = process.run([accel_cmd, "l2tp switch"])
            assert exit == 0
            assert "placed: 1" in out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0)
        config.delete_tmp(d_cfg)
```

- [ ] **Step 3: Run, verify it fails**

Expected: FAIL — `"placed: 1"` doesn't exist yet, and ICCN handling still calls `l2tp_session_connect` unconditionally for every session including switch-tagged ones.

- [ ] **Step 4: Capture Proxy AVPs and skip local PPP in `l2tp_recv_ICCN`**

In `l2tp.c`, `l2tp_recv_ICCN` (~3597), the AVP-parsing loop currently has (see the code already read during design) -- **the full case group, not just the AVPs relevant to this task**, since that distinction is the entire point of the fix below:

```c
		case Message_Type:
		case Random_Vector:
		case TX_Speed:
		case Framing_Type:
		case Init_Recv_LCP:
		case Last_Sent_LCP:
		case Last_Recv_LCP:
		case Proxy_Authen_Type:
		case Proxy_Authen_Name:
		case Proxy_Authen_Challenge:
		case Proxy_Authen_ID:
		case Proxy_Authen_Response:
		case Private_Group_ID:
		case RX_Speed:
			break;
```

(Note: `attr_defs.h` names this AVP `Init_Recv_LCP`, spec §5 calls it `Initial LCP CONFREQ` per RFC wording — same AVP, this plan uses the codebase's own identifier throughout.)

**Do not add the capture call to this whole shared group — split it.** Only `Init_Recv_LCP`/`Last_Sent_LCP`/`Last_Recv_LCP`/`Proxy_Authen_Type`/`Proxy_Authen_Name`/`Proxy_Authen_Challenge`/`Proxy_Authen_ID`/`Proxy_Authen_Response` are AVPs this feature ever needs to re-inject downstream; `Message_Type`/`Random_Vector`/`TX_Speed`/`Framing_Type` must keep falling through to a bare `break` exactly as before. An earlier draft of this task added the capture call to the *entire* combined group as it actually exists in the real file (the snippet above, not the 8-case-only fragment a stale earlier read of this function had suggested) and crashed reproducibly on a real VM the moment a real ICCN arrived: `l2tp_switch_capture_avp()` (below) reads `attr->val.octets` unconditionally, but `Message_Type`/`TX_Speed`/`Framing_Type` are `int16`/`int32`-typed in the dictionary, not `octets` — their union member holds a small integer *value*, not a pointer, so reading `.octets` reinterprets that value as a garbage pointer and segfaults on the subsequent `memcpy`. Split the case labels as shown next:

```c
		case Message_Type:
		case Random_Vector:
		case TX_Speed:
		case Framing_Type:
			break;
		case Init_Recv_LCP:
		case Last_Sent_LCP:
		case Last_Recv_LCP:
		case Proxy_Authen_Type:
		case Proxy_Authen_Name:
		case Proxy_Authen_Challenge:
		case Proxy_Authen_ID:
		case Proxy_Authen_Response:
			if (sess->switch_target &&
			    l2tp_switch_capture_avp(sess, attr) < 0) {
				log_session(log_error, sess,
					    "impossible to handle ICCN:"
					    " capturing proxy AVP failed\n");
				l2tp_session_disconnect(sess, 2, 6);
				return -1;
			}
			break;
```

Add the helper **directly above** `l2tp_recv_ICCN` in the file (not just "nearby" — it's called from inside that function's body, and this file has no forward declaration for it, so it must be defined earlier in the source than its first use):

```c
static int l2tp_switch_capture_avp(struct l2tp_sess_t *sess,
				   const struct l2tp_attr_t *attr)
{
	struct l2tp_switch_avp_t *slot;

	if (!sess->switch_avps) {
		sess->switch_avps = _malloc(sizeof(*sess->switch_avps));
		if (!sess->switch_avps)
			return -1;
		memset(sess->switch_avps, 0, sizeof(*sess->switch_avps));
	}

	if (sess->switch_avps->count >=
	    (int)(sizeof(sess->switch_avps->avp) /
		  sizeof(sess->switch_avps->avp[0])))
		return -1; /* more of these AVPs than RFC 2661 defines */

	slot = &sess->switch_avps->avp[sess->switch_avps->count];
	slot->id = attr->attr->id;
	slot->M = attr->M;

	/* attr->val is a union: which member is actually populated depends
	 * on attr->attr->type (set by packet.c's parser from the dictionary
	 * entry for this AVP id). Every AVP this function is ever invoked
	 * for (after the case-split above) is octets, string, or int16
	 * (Init/Last-*-LCP and Proxy-Authen-Challenge/Response are octets;
	 * Proxy-Authen-Name is string; Proxy-Authen-Type/ID are int16) --
	 * reading attr->val.octets unconditionally works for the first two
	 * (both are just a pointer into real byte data, string vs uint8_t*
	 * makes no difference for memcpy purposes) but for int16 it
	 * reinterprets a small integer VALUE stored directly in the union as
	 * if it were a pointer and crashes dereferencing it -- confirmed by
	 * reproducing this exact segfault against a real accel-pppd on a VM
	 * (Proxy-Authen-Type, sent whenever --proxy-username is used, i.e.
	 * Task 6's own test below). Serialize to the same on-the-wire byte
	 * representation l2tp_packet_add_int16() itself would produce, so
	 * re-injecting via l2tp_packet_add_octets() later (Step 6) round-
	 * trips correctly -- the wire format for an int16 AVP is just its 2
	 * network-order bytes, indistinguishable from an octets AVP of
	 * length 2 to whichever end decodes it. */
	switch (attr->attr->type) {
	case ATTR_TYPE_INT16: {
		uint16_t val = htons(attr->val.uint16);

		slot->len = sizeof(val);
		slot->val = _malloc(slot->len);
		if (!slot->val)
			return -1;
		memcpy(slot->val, &val, slot->len);
		break;
	}
	case ATTR_TYPE_OCTETS:
	case ATTR_TYPE_STRING:
	default:
		slot->len = attr->length;
		slot->val = _malloc(slot->len ? slot->len : 1);
		if (!slot->val)
			return -1;
		memcpy(slot->val, attr->val.octets, slot->len);
		break;
	}

	sess->switch_avps->count++;
	return 0;
}
```

At the end of `l2tp_recv_ICCN`, the existing tail is:

```c
	if (l2tp_session_connect(sess)) {
		...
	}

	return 0;
}
```

Change it to branch on `sess->switch_target`:

```c
	if (sess->switch_target) {
		if (l2tp_switch_place_downstream_call(sess) < 0) {
			log_session(log_error, sess,
				    "impossible to switch call:"
				    " placing downstream call failed,"
				    " disconnecting session\n");
			l2tp_session_disconnect(sess, 2, 6);

			return -1;
		}

		return 0;
	}

	if (l2tp_session_connect(sess)) {
		log_session(log_error, sess, "impossible to handle ICCN:"
			    " connecting session failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	return 0;
}
```

- [ ] **Step 5: Implement `l2tp_switch_place_downstream_call`**

Add the three functions below directly above `l2tp_recv_ICCN`, right after Step 4's `l2tp_switch_capture_avp` — same reason: `l2tp_recv_ICCN`'s tail (Step 4) calls `l2tp_switch_place_downstream_call()`, which is not forward-declared, so it must be defined earlier in the source. `l2tp_switch_disconnect_upstream` and `l2tp_switch_place_call` only need to precede `l2tp_switch_place_downstream_call` itself (which calls both), so keep all three together in the order shown below.

Spec §11 raised a "downstream tunnel not yet up when ICCN arrives" edge case and suggested queuing the call with a bounded deadline. This implementation makes a deliberate, simpler choice instead: if the target's persistent tunnel (Task 3) isn't `STATE_ESTB` at the exact moment ICCN arrives, CDN the upstream call immediately rather than queuing and waiting. Rationale: the persistent tunnel is normally already up (that is the entire point of bringing it up at startup, Task 3); the only time it would not be is a brief window right after daemon startup or right after a drop-and-reconnect, both rare and both already handled correctly by MK's own call-retry behavior (a rejected call gets retried, and by the time it is, Task 3's tunnel is very likely re-established). Building an actual queue-with-timeout adds a second state machine (pending calls per target, its own timer, its own CDN-on-expiry path) for a race window measured in seconds, at most a few times per target's lifetime. If this proves too aggressive in practice (MK's retry policy turns out not to tolerate it), revisit by adding a short queue here — but do not build it speculatively.

**A bounded deadline already exists for the case where the target tunnel *is* up but the downstream ICRQ/ICRP/ICCN round trip is slow** — worth being explicit about, since it isn't a new timer this plan adds, and it would be easy for a future change to break without anyone noticing why. `l2tp_session_incall_reply` (the existing function that accepts the *upstream* ICRQ, well before any of this switch logic runs) already arms `sess->timeout_timer` — the generic 60-second (`conf_timeout`, default) session-establishment timeout every non-switched session also gets. The only place that ever disarms it is `l2tp_session_connect_socket`'s own `if (sess->timeout_timer.tpd) triton_timer_del(...)` at its top. For a switch's upstream leg, that call is deferred all the way to `l2tp_switch_finish_upstream` (Task 7 Step 4) — meaning the timer set at ICRQ-acceptance time stays armed through ICCN receipt, the entire downstream ICRQ/ICRP/ICCN exchange, and `l2tp_switch_finish_upstream` itself. If that whole sequence doesn't complete within `conf_timeout` seconds, `l2tp_session_timeout` fires and calls `l2tp_session_disconnect_push(sess, 10, 0)` on the upstream leg — which is exactly what should happen (bound the whole pairing attempt, then give up), and it interacts correctly with Task 8's teardown hook without any special-casing: by the time this could fire, `upstream->switch_downstream` is already set (from `l2tp_switch_place_call`, Task 6 Step 5, one of the very first things it does), so the hook finds it and correctly tears down the downstream leg too, in whatever state *it* happens to be in. The downstream leg has the same protection independently — `l2tp_session_place_call` (the existing function used to send its ICRQ) arms the identical timer for it, so a downstream LNS that never responds also self-heals via the same generic mechanism, cascading back to the upstream leg the same way. Net effect: both directions of a stuck pairing are already bounded by existing, generic machinery — no new timer needed, but this only holds as long as neither leg's socket-connect call moves earlier than `l2tp_switch_finish_upstream`/`l2tp_recv_ICRP`'s existing placement; if a future change disarms this timer earlier for either leg (e.g. "helpfully" clearing it right after ICCN is received), this safety net disappears silently.

```c
static void l2tp_switch_disconnect_upstream(void *data)
{
	struct l2tp_sess_t *upstream = data;

	if (upstream->state1 != STATE_CLOSE)
		l2tp_session_disconnect(upstream, 2, 6);

	session_put(upstream); /* the temporary hold taken in
				 * l2tp_switch_place_downstream_call() below */
}

static void l2tp_switch_place_call(void *data)
{
	struct l2tp_sess_t *upstream = data;
	struct l2tp_conn_t *conn = upstream->switch_target->tunnel;
	struct l2tp_sess_t *downstream;

	/* This function runs in conn's context (the downstream target's
	 * tunnel), scheduled via l2tp_switch_place_downstream_call() below --
	 * NOT in upstream->paren_conn->ctx. Touching upstream's own state
	 * (timers, send queue -- exactly what l2tp_session_disconnect()
	 * does) from here would violate this codebase's per-tunnel-context
	 * threading model, so every path that needs to disconnect upstream
	 * crosses into its own context first via triton_context_call()
	 * rather than calling l2tp_session_disconnect(upstream, ...) here
	 * directly. */

	if (!conn || conn->state != STATE_ESTB) {
		log_session(log_error, upstream,
			    "l2tp-switch: target tunnel not available,"
			    " disconnecting upstream call\n");
		goto err_no_pairing;
	}

	downstream = l2tp_tunnel_alloc_session(conn);
	if (!downstream) {
		log_session(log_error, upstream,
			    "l2tp-switch: downstream session allocation"
			    " failed\n");
		goto err_no_pairing;
	}

	if (upstream->calling_num) {
		downstream->calling_num = _malloc(upstream->calling_num_len + 1);
		if (downstream->calling_num) {
			memcpy(downstream->calling_num, upstream->calling_num,
			      upstream->calling_num_len + 1);
			downstream->calling_num_len = upstream->calling_num_len;
		}
	}
	if (upstream->called_num) {
		downstream->called_num = _malloc(upstream->called_num_len + 1);
		if (downstream->called_num) {
			memcpy(downstream->called_num, upstream->called_num,
			      upstream->called_num_len + 1);
			downstream->called_num_len = upstream->called_num_len;
		}
	}

	/* Mirror the upstream leg's sequencing request onto the downstream
	 * leg (spec §11: sequencing must match across legs, not fall back to
	 * independent per-tunnel defaults). l2tp_send_ICCN already sends a
	 * Sequencing_Required AVP whenever sess->send_seq is set -- no other
	 * change is needed for the downstream leg to advertise the same
	 * requirement MK made of the upstream leg. */
	downstream->send_seq = upstream->send_seq;
	downstream->recv_seq = upstream->recv_seq;

	downstream->switch_upstream = upstream;
	downstream->switch_avps = upstream->switch_avps;
	upstream->switch_avps = NULL; /* ownership moves to the downstream leg */
	upstream->switch_downstream = downstream;
	session_hold(downstream);
	session_hold(upstream);

	if (l2tp_session_place_call(downstream) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: placing downstream call failed\n");
		/* downstream->switch_upstream == upstream was just set above,
		 * so l2tp_session_free()'s Task 8 hook finds it and, via
		 * l2tp_switch_teardown_peer(), correctly crosses into
		 * upstream's own context to tear it down too -- nothing more
		 * to do for upstream on this path. */
		l2tp_session_free(downstream);
		goto err_pairing_done;
	}

	/* l2tp_session_place_call() only enqueues the ICRQ -- l2tp_tunnel_send()/
	 * l2tp_session_send() append to conn->send_queue and return; nothing
	 * about them transmits. Every other existing path that ends up
	 * calling l2tp_session_place_call() runs from within l2tp_conn_read()'s
	 * own receive loop, which unconditionally flushes the send queue
	 * afterward -- this function instead runs via triton_context_call()
	 * from a *different* tunnel's context (see
	 * l2tp_switch_place_downstream_call() below), which never passes
	 * through that loop. l2tp_tunnel_create_session() -- the existing
	 * CLI-triggered path this whole cross-context pattern is modeled on
	 * -- already calls l2tp_tunnel_push_sendqueue() explicitly for
	 * exactly this reason; missing it here was a bug found while
	 * building Task 7 against a real VM: the ICRQ sat in the queue,
	 * silently undelivered, until some *unrelated* event on the
	 * downstream tunnel (e.g. the next HELLO) happened to flush it --
	 * observed as a ~40+ second stall between "sending ICRQ" in the log
	 * and the packet actually reaching the wire, misleadingly looking
	 * like a matching/pairing failure (`matched: 0`/`placed: 0` for
	 * tens of seconds) rather than a late packet. Flush explicitly: */
	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: transmitting downstream ICRQ"
			    " failed\n");
		l2tp_session_free(downstream);
		goto err_pairing_done;
	}

	l2tp_stat_inc(&l2tp_stat.switch_placed);
	session_put(upstream); /* the temporary hold taken in
				 * l2tp_switch_place_downstream_call() below --
				 * the two pairing holds taken just above stay
				 * intact for the life of the active pairing */
	return;

err_no_pairing:
	/* No downstream leg exists yet -- upstream has no peer, so there is
	 * nothing for a Task 8 hook to cascade to. Cross into upstream's own
	 * context to disconnect it directly. */
	if (triton_context_call(&upstream->paren_conn->ctx,
				l2tp_switch_disconnect_upstream, upstream) < 0)
		session_put(upstream); /* couldn't even schedule it; still
					 * release our own hold */
	return;

err_pairing_done:
	/* The Task 8 hook triggered by l2tp_session_free(downstream) above
	 * already scheduled upstream's teardown in its own context; just
	 * release the call-site's own temporary hold on upstream. */
	session_put(upstream);
}

static int l2tp_switch_place_downstream_call(struct l2tp_sess_t *upstream)
{
	struct l2tp_conn_t *conn = upstream->switch_target->tunnel;

	if (!conn)
		return -1;

	/* Placing the downstream call touches conn's own tunnel context,
	 * which is not upstream's context -- cross via triton_context_call,
	 * same as l2tp_create_session_exec() already does for the CLI path. */
	session_hold(upstream);
	if (triton_context_call(&conn->ctx, l2tp_switch_place_call, upstream) < 0) {
		session_put(upstream);
		return -1;
	}

	return 0;
}
```

`switch_placed` already exists on `l2tp_stat_t` (added in Task 5's consolidated struct update). Print it from `l2tp_switch_show_exec`'s `calls:` block (Task 5):

```c
	cli_sendv(client, "  placed: %u\r\n", l2tp_stat.switch_placed);
```

- [ ] **Step 6: Forward Calling-Number/Called-Number and the captured Proxy AVPs**

Extend `l2tp_send_ICRQ` (~2483) to forward the two AVPs `l2tp_recv_ICRQ` already captures for inbound sessions but this function has never sent for outbound ones, right before the existing `l2tp_session_try_send` call. Both AVPs are `M=1` in `dict/dictionary.rfc2661`, so pass `1` for the mandatory flag (the dictionary's own `M` would silently override a mismatched caller value here anyway — `attr_alloc()` in `packet.c` always prefers the dictionary's `M` when it specifies one — but pass the correct value regardless, for clarity):

```c
	if (sess->calling_num &&
	    l2tp_packet_add_string(pack, Calling_Number, sess->calling_num,
				   1) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (sess->called_num &&
	    l2tp_packet_add_string(pack, Called_Number, sess->called_num,
				   1) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
```

Extend `l2tp_send_ICCN` (~2556) to inject captured Proxy AVPs when present, right before the existing `l2tp_session_send(sess, pack);` call:

```c
	if (sess->switch_avps) {
		int i;

		for (i = 0; i < sess->switch_avps->count; i++) {
			struct l2tp_switch_avp_t *a = &sess->switch_avps->avp[i];

			if (l2tp_packet_add_octets(pack, a->id, a->val, a->len,
						   a->M) < 0) {
				log_session(log_error, sess,
					    "impossible to send ICCN:"
					    " re-injecting proxy AVP %d"
					    " failed\n", a->id);
				goto out_err;
			}
		}
	}
```

- [ ] **Step 7: Wire up `l2tp_recv_ICRP` for the downstream leg**

`l2tp_recv_ICRP` (~3518) already calls `l2tp_send_ICCN(sess)` then `l2tp_session_connect(sess)` unconditionally for every outbound-call session (used today only by the manual `l2tp create session` CLI path). For a switch downstream leg, `l2tp_session_connect` must not run yet (that starts local PPP — Task 7 replaces it with the kernel-socket-only variant). Change the tail of `l2tp_recv_ICRP` from:

```c
	if (l2tp_send_ICCN(sess) < 0) {
		...
	}

	if (l2tp_session_connect(sess) < 0) {
		...
	}

	return 0;
}
```

to:

```c
	if (l2tp_send_ICCN(sess) < 0) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " sending ICCN failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	if (sess->switch_upstream) {
		l2tp_stat_inc(&l2tp_stat.switch_downstream_connected);
		/* Task 7 replaces this with the kernel-socket-only connect
		 * and pairing; for now the downstream leg is left in
		 * STATE_ESTB without a running PPP engine or splice, which
		 * is intentional for this task's scope. */
		sess->state1 = STATE_ESTB;
		return 0;
	}

	if (l2tp_session_connect(sess) < 0) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " connecting session failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	return 0;
}
```

`switch_downstream_connected` already exists on `l2tp_stat_t` (Task 5). Print it from `l2tp_switch_show_exec`'s `calls:` block alongside `placed`:

```c
	cli_sendv(client, "  connected: %u\r\n", l2tp_stat.switch_downstream_connected);
```

- [ ] **Step 8: Run, verify it passes**

Rebuild, rerun `test_switch_avp_forward.py`. Expected: PASS — `"placed: 1"` appears once the MK-simulator's ICCN reaches the switch instance. Confirmed for real on a VM after the two bug fixes above (the case-split and the type-aware capture serialization): `test_switch_avp_forward.py` passes on its own, and the full `l2tp_switch` suite (12 tests as of this task) passes together with no regressions. Before those fixes, every test that sent a real ICCN through a switch-tagged session (including the pre-existing `test_switch_match.py`, once it reached ICCN) crashed the daemon; `accel-cmd` would then report `matched: 0`/`placed: 0` against a *freshly re-executed* daemon process (accel-ppp's own `sigsegv` handler `execv()`s itself back to a clean start on crash, same PID, all state lost) rather than surfacing as an obvious test failure -- worth knowing if a similar "counters silently reset to 0" symptom ever reappears.

- [ ] **Step 9: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c \
        accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c \
        tests/accel-pppd/l2tp_switch/
git commit -m "feat(l2tp): capture and forward Proxy LCP/Auth AVPs to downstream leg"
```

---

### Task 7: Kernel-socket-only connect, pairing, and the splice datapath

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c` (struct field additions; `l2tp_session_connect` ~1951, `l2tp_recv_ICCN` ~3597, `l2tp_recv_ICRP` ~3518 — `l2tp.h` itself is untouched, see Task 1)
- Test: `tests/accel-pppd/l2tp_switch/test_switch_splice.py`

**Interfaces:**
- Produces: PPP frames flow end-to-end between the two legs' kernel `pppol2tp` sockets. This is the task that makes the feature actually usable end-to-end.

- [x] **Step 0: Validate that `splice(2)` actually works on `pppol2tp` sockets — DONE, CONFIRMED WORKING**

**Verified on real hardware during planning** (Debian 12 bookworm, kernel 6.1.0-52-amd64, `l2tp_ppp`/`l2tp_netlink`/`l2tp_core`/`pppox` modules loaded) — this whole task's data plane rested on one previously-unverified assumption: that the kernel's `pppol2tp` socket implementation (`net/l2tp/l2tp_ppp.c`) provides a working `splice_read` path. A standalone test program (two `AF_PPPOX`/`PX_PROTO_OL2TP` sockets connected to each other over loopback UDP, exactly replicating `l2tp_session_connect_socket`'s connect sequence) confirmed:

- `splice()` **out of** a `pppol2tp` socket into a pipe: works.
- `splice()` **into** a `pppol2tp` socket from a pipe: works.
- A full loop (write → splice out → splice in → kernel re-encapsulates → read on the peer) delivered the exact bytes written, unmodified.

No fallback to `read()`/`write()` is needed — proceed with the `splice(2)`-based design in Step 3 below exactly as specified.

**One real, previously-unknown prerequisite this testing surfaced**: a session-level `pppol2tp` `connect()` (real `s_tunnel`/`d_tunnel`/`s_session`/`d_session`, matching what `l2tp_session_connect_socket` does) fails with `ENOENT` unless the *tunnel* has first been registered with the kernel's L2TP subsystem — a separate, throwaway `pppol2tp` socket connected with `s_session`/`d_session` left at `0`, then immediately closed. This is exactly what the existing `l2tp_tunnel_connect()` (`l2tp.c` ~2071) already does, called once a tunnel's SCCRQ/SCCRP/SCCCN handshake completes (~lines 3123, 3190) — **already correct for both legs without any change**, precisely because this design reuses the existing tunnel-establishment machinery wholesale (Task 3's persistent downstream tunnel goes through the exact same `l2tp_tunnel_start`/SCCRQ/SCCRP/SCCCN path the upstream MK tunnel already does) rather than reimplementing tunnel setup. Worth knowing this exists, in case any future change ever tries to open a session-level `pppol2tp` socket without having gone through normal tunnel establishment first — that would reproduce this exact `ENOENT` on real hardware, and this note is the reason why.

- [ ] **Step 1: Split `l2tp_session_connect`**

`l2tp_session_connect` (~1951) currently does kernel-socket setup, then unconditionally calls `l2tp_session_start_data_channel(sess)`. Rename the existing function to `l2tp_session_connect_socket` and change its `return 0;`/error paths so it no longer calls `l2tp_session_start_data_channel` itself; instead, give it a `start_ppp` parameter:

```c
static int l2tp_session_connect_socket(struct l2tp_sess_t *sess, int start_ppp)
{
	/* ... unchanged body up through the existing connect() call ... */

	if (connect(sess->ppp.fd,
		    (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " connect() failed: %s\n", strerror(errno));
		goto out_err;
	}

	/* start_ppp==0 sessions (l2tp-switch) read/write this socket
	 * directly via splice() in l2tp_switch_link_read() (Step 3 below) --
	 * unlike the normal (start_ppp==1) path, where this fd is handed
	 * off to the kernel's generic PPP channel via PPPIOCATTCHAN and
	 * userspace never touches it again, so it has never needed
	 * O_NONBLOCK. Found missing while testing on a real VM: without
	 * this, splice()'s read side blocks forever once the currently
	 * pending datagram(s) are drained (SPLICE_F_NONBLOCK only avoids
	 * blocking on the *pipe* end of the pair -- per splice(2), it does
	 * nothing for a blocking-mode fd on the other end), permanently
	 * consuming one of triton's worker threads per active switched
	 * session. Once `thread-count` (default 2, or nproc) many sessions
	 * are up, this starves every other triton context in the process,
	 * including the CLI -- observed as `accel-cmd` hanging indefinitely
	 * against an otherwise-healthy daemon, confirmed via `gdb -p <pid>
	 * -batch -x <(echo 'thread apply all bt')` showing both worker
	 * threads stuck inside splice(). */
	if (!start_ppp) {
		int flg = fcntl(sess->ppp.fd, F_GETFL);

		if (flg < 0) {
			log_session(log_error, sess,
				    "impossible to connect session:"
				    " fcntl(F_GETFL) failed: %s\n",
				    strerror(errno));
			goto out_err;
		}
		if (fcntl(sess->ppp.fd, F_SETFL, flg | O_NONBLOCK) < 0) {
			log_session(log_error, sess,
				    "impossible to connect session:"
				    " fcntl(F_SETFL) failed: %s\n",
				    strerror(errno));
			goto out_err;
		}
	}

	/* ... unchanged body up through: ... */

	triton_event_fire(EV_CTRL_STARTED, &sess->ppp.ses);
	l2tp_stat_move(&l2tp_stat.sess_starting, &l2tp_stat.sess_active);
	sess->state1 = STATE_ESTB;

	if (start_ppp && l2tp_session_start_data_channel(sess) < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " starting data channel failed\n");
		goto out_err;
	}

	return 0;

out_err:
	/* ... unchanged ... */
}

static int l2tp_session_connect(struct l2tp_sess_t *sess)
{
	return l2tp_session_connect_socket(sess, 1);
}
```

Every existing call site (`l2tp_recv_ICRP`'s non-switch path, `l2tp_recv_ICCN`'s non-switch path, `l2tp_session_outcall_reply`) keeps calling `l2tp_session_connect(sess)` unchanged — always `start_ppp=1`, so the new `fcntl` block above never runs for them and normal sessions see zero behavior change, satisfying the Global Constraints entry on this. Note this also means `link->dst->ppp.fd` (the *write* side of a splice link in Step 3) is `O_NONBLOCK` too, since both legs of a switched pair go through this same `start_ppp=0` path — Step 3's write-side splice call must handle `EAGAIN` accordingly (see below), not just the read side.

- [ ] **Step 2: Add the pairing/link data structures**

Add to `struct l2tp_sess_t` (`l2tp.c` ~line 127 — not `l2tp.h`, see the note in Task 6 Step 1):

```c
	struct l2tp_switch_link_t *switch_link; /* this session's own
						  * read-and-forward link,
						  * once paired (Task 7) */
```

Task 1 already forward-declared the `struct l2tp_switch_link_t` tag, so the field above compiles regardless of where the full body ends up. Add that body in `l2tp.c`, anywhere convenient — right above `l2tp_switch_link_read` below is the natural spot:

```c
struct l2tp_switch_link_t {
	struct triton_md_handler_t hnd;
	struct l2tp_sess_t *src; /* read from src->ppp.fd */
	struct l2tp_sess_t *dst; /* write to dst->ppp.fd */
	int pipe_rd, pipe_wr;
	uint64_t bytes; /* this link's own lifetime, dies with the call --
			  * see target->rx_bytes/tx_bytes (Task 1) for the
			  * persistent, per-target totals this feeds into */

	/* Set once at creation (Step 4 below), read-only for this link's
	 * whole lifetime -- which of the two directions this link carries,
	 * and which target's traffic it counts against. */
	struct l2tp_switch_target_t *target;
	int from_upstream; /* 1: src is the upstream (MK-facing) leg, this
			     * link's bytes are "upstream rx" / "target tx";
			     * 0: src is the downstream (target-facing) leg,
			     * this link's bytes are "target rx" / "upstream tx" */
};
```

- [ ] **Step 3: Implement the splice read callback and link setup/teardown**

`l2tp_switch_link_free()` and `l2tp_switch_teardown_peer()` below are already forward-declared (Task 1), since `l2tp_session_free()`'s teardown hook (Task 8) needs to call both and sits much earlier in the file (~line 1063) than this code. Their real definitions can go anywhere in `l2tp.c` — here, next to the rest of the splice/pairing code, is where they naturally belong:

```c
#define L2TP_SWITCH_SPLICE_LEN (1 << 16)

static int l2tp_switch_link_read(struct triton_md_handler_t *h)
{
	struct l2tp_switch_link_t *link = container_of(h, typeof(*link), hnd);
	ssize_t n;

	while (1) {
		n = splice(link->src->ppp.fd, NULL, link->pipe_wr, NULL,
			  L2TP_SWITCH_SPLICE_LEN,
			  SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		if (n < 0) {
			if (errno == EAGAIN)
				return 0;
			if (errno == EINTR)
				continue;
			log_session(log_error, link->src,
				    "l2tp-switch: splice(in) failed: %s\n",
				    strerror(errno));
			l2tp_switch_link_fail(link);
			return 0;
		}
		if (n == 0)
			return 0;

		link->bytes += n;
		if (link->from_upstream) {
			__atomic_add_fetch(&l2tp_stat.switch_lns_rx_bytes,
					   (uint64_t)n, __ATOMIC_RELAXED);
			__atomic_add_fetch(&link->target->tx_bytes,
					   (uint64_t)n, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&link->target->rx_bytes,
					   (uint64_t)n, __ATOMIC_RELAXED);
			__atomic_add_fetch(&l2tp_stat.switch_lns_tx_bytes,
					   (uint64_t)n, __ATOMIC_RELAXED);
		}

		while (n > 0) {
			ssize_t w = splice(link->pipe_rd, NULL,
					   link->dst->ppp.fd, NULL, n,
					   SPLICE_F_MOVE);
			if (w < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN) {
					/* link->dst->ppp.fd is O_NONBLOCK (see
					 * Step 1's l2tp_session_connect_socket
					 * fix) -- wait for it to become
					 * writable rather than treating a
					 * momentarily full send path as a
					 * hard failure. Without this, the
					 * O_NONBLOCK fix in Step 1 turns every
					 * transient EAGAIN here into an
					 * incorrectly torn-down session. */
					struct pollfd pfd = {
						.fd = link->dst->ppp.fd,
						.events = POLLOUT,
					};

					if (poll(&pfd, 1, -1) < 0 &&
					    errno != EINTR) {
						log_session(log_error, link->src,
							    "l2tp-switch: poll(out)"
							    " failed: %s\n",
							    strerror(errno));
						l2tp_switch_link_fail(link);
						return 0;
					}
					continue;
				}
				log_session(log_error, link->src,
					    "l2tp-switch: splice(out)"
					    " failed: %s\n", strerror(errno));
				l2tp_switch_link_fail(link);
				return 0;
			}
			n -= w;
		}
	}
}
```

(`poll()`/`struct pollfd`/`POLLOUT` need `#include <poll.h>` — add it near the top of `l2tp.c`, alongside the existing `<pthread.h>` include.)

```c

static void l2tp_switch_link_free(struct l2tp_switch_link_t *link)
{
	/* Every pair has exactly one from_upstream link and one that isn't,
	 * and -- across every teardown path (the l2tp_session_free() hook,
	 * l2tp_switch_teardown_peer(), l2tp_switch_link_fail()) -- both
	 * always get freed exactly once each, in whichever order that
	 * teardown happens to take. Decrementing target->active here,
	 * gated on from_upstream, therefore fires exactly once per pair
	 * regardless of which of the two links is freed first or through
	 * which path -- unlike gating on "is this the first link freed",
	 * which the splice-failure path (l2tp_switch_link_fail frees its
	 * own link *before* disconnecting, so the l2tp_session_free hook
	 * never sees it non-NULL) would get wrong. */
	if (link->from_upstream)
		__atomic_sub_fetch(&link->target->active, 1, __ATOMIC_RELAXED);

	if (link->hnd.tpd) {
		triton_md_unregister_handler(&link->hnd, 1 /* close fd */);
		/* triton_md_unregister_handler() closes and resets
		 * link->hnd.fd -- but that is a separate int from
		 * link->src->ppp.fd (same value, different storage; hnd.fd
		 * was only ever set *from* it in l2tp_switch_link_create()
		 * below). Left alone, this is a real double-close bug found
		 * during Task 7 testing: __session_destroy() (~line 1063)
		 * unconditionally does `if (sess->ppp.fd >= 0) close(sess->
		 * ppp.fd);` once the session's ref count reaches zero, finds
		 * the now-stale fd number still >= 0, and closes it a second
		 * time -- by then potentially reassigned by the kernel to an
		 * unrelated fd opened by any other thread in the meantime
		 * (this daemon is multi-threaded and constantly opening
		 * sockets/pipes), silently closing something it doesn't own. */
		link->src->ppp.fd = -1;
	}
	close(link->pipe_rd);
	close(link->pipe_wr);
	link->src->switch_link = NULL;
	_free(link);
}
```

**Reference-counting design (read this before writing the next function):** a link object does *not* hold its own references on `src`/`dst` — it borrows the two references `l2tp_switch_place_call()` (Task 6 Step 5) already took once, at pairing time: `session_hold(upstream)` (justified for as long as `downstream->switch_upstream == upstream`) and `session_hold(downstream)` (justified for as long as `upstream->switch_downstream == downstream`). A link's lifetime is always a subset of the pairing's lifetime, so it doesn't need independent refcounting. This means exactly two holds exist per pair, one per session, and each must be released exactly once, at the moment the *other* session's pointer to it is cleared (not before). Whoever clears `X->switch_downstream`/`X->switch_upstream` (pointing at `Y`) is the one who must call `session_put(Y)` in that same step — never the reverse, and never both sides for the same pointer.

```c
/* Runs in whichever session's own context is passed as `data`. This is
 * the "forced" half of teardown: sess's own l2tp_session_free() hook
 * (Task 8) calls this, via triton_context_call(), only when it finds its
 * peer is *not* already closing on its own. It mirrors exactly what the
 * peer's *own* l2tp_session_free() hook would have done had the peer
 * been the one to go through l2tp_session_free() first -- clearing the
 * peer's own outgoing pointer and releasing the hold that pointer
 * justified -- which is what stops this from ping-ponging back and
 * forth: by the time l2tp_session_disconnect() below reaches the peer's
 * own l2tp_session_free() hook, that hook finds no pointer left to chase.
 */
static void l2tp_switch_teardown_peer(void *data)
{
	struct l2tp_sess_t *peer = data;
	struct l2tp_sess_t *sess = peer->switch_downstream ?
		peer->switch_downstream : peer->switch_upstream;

	if (peer->switch_link)
		l2tp_switch_link_free(peer->switch_link);
	peer->switch_downstream = NULL;
	peer->switch_upstream = NULL;
	if (sess)
		session_put(sess); /* the hold justified by the pointer just cleared */

	if (peer->state1 != STATE_CLOSE)
		l2tp_session_disconnect(peer, 2, 6);

	session_put(peer); /* the temporary hold taken to survive the
			     * context switch into here -- see the caller */
}

static void l2tp_switch_link_fail(struct l2tp_switch_link_t *link)
{
	struct l2tp_sess_t *src = link->src;

	log_session(log_error, src, "l2tp-switch: splice failed,"
		    " disconnecting session\n");
	l2tp_switch_link_free(link); /* src->switch_link = NULL happens inside */
	if (src->state1 != STATE_CLOSE)
		l2tp_session_disconnect(src, 2, 6); /* runs in src's own
			context, which is exactly where this callback already
			executes -- reaches l2tp_session_free(src)'s Task 8
			hook synchronously, which is what actually tears down
			the peer (see that hook for the other half of this). */
}

static int l2tp_switch_link_create(struct l2tp_sess_t *src,
				   struct l2tp_sess_t *dst,
				   struct l2tp_switch_target_t *target,
				   int from_upstream)
{
	struct l2tp_switch_link_t *link;
	int pfd[2];

	if (pipe(pfd) < 0)
		return -1;
	fcntl(pfd[0], F_SETFL, O_NONBLOCK);
	fcntl(pfd[1], F_SETFL, O_NONBLOCK);

	link = _malloc(sizeof(*link));
	if (!link) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}
	memset(link, 0, sizeof(*link));
	link->pipe_rd = pfd[0];
	link->pipe_wr = pfd[1];
	link->src = src;
	link->dst = dst;
	link->target = target;
	link->from_upstream = from_upstream;
	/* No session_hold() here: src and dst are already kept alive for the
	 * whole pairing's lifetime by the two holds l2tp_switch_place_call()
	 * (Task 6) took once -- see the note above this function. */

	/* Symmetric with l2tp_switch_link_free()'s decrement, gated the same
	 * way -- see the comment there for why this must live in
	 * create/free themselves rather than being incremented once after
	 * both links succeed: if the *second* link's creation fails, the
	 * first is torn down via this same l2tp_switch_link_free(), which
	 * must find a matching increment to undo or target->active
	 * underflows (it's unsigned). Incrementing here means every
	 * l2tp_switch_link_free() call has exactly one create() call to
	 * balance against, on every path, including partial failure. */
	if (from_upstream)
		__atomic_add_fetch(&target->active, 1, __ATOMIC_RELAXED);

	link->hnd.fd = src->ppp.fd;
	link->hnd.read = l2tp_switch_link_read;

	triton_md_register_handler(&src->paren_conn->ctx, &link->hnd);
	if (triton_md_enable_handler(&link->hnd, MD_MODE_READ) < 0) {
		if (from_upstream)
			__atomic_sub_fetch(&target->active, 1, __ATOMIC_RELAXED);
		triton_md_unregister_handler(&link->hnd, 0);
		close(pfd[0]);
		close(pfd[1]);
		_free(link);
		return -1;
	}

	src->switch_link = link;
	return 0;
}
```

(`fcntl` and `pipe`/`splice`/`SPLICE_F_MOVE`/`SPLICE_F_NONBLOCK` need `#include <fcntl.h>` — already included in `l2tp.c` — and `#define _GNU_SOURCE` before any system header for `splice(2)`'s prototype; check the top of `l2tp.c` for an existing `_GNU_SOURCE` define or add one as the very first line of the file if missing.)

- [ ] **Step 4: Pair both legs once the downstream socket connects**

In `l2tp_recv_ICRP`'s `sess->switch_upstream` branch (added in Task 6 Step 7), replace the placeholder body:

```c
	if (sess->switch_upstream) {
		struct l2tp_sess_t *upstream = sess->switch_upstream;

		if (l2tp_session_connect_socket(sess, 0) < 0) {
			log_session(log_error, sess,
				    "l2tp-switch: connecting downstream"
				    " kernel socket failed\n");
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}

		l2tp_stat_inc(&l2tp_stat.switch_downstream_connected);

		/* Both sessions must survive until l2tp_switch_finish_upstream()
		 * actually runs, since triton_context_call() only schedules it
		 * -- upstream is dereferenced there via the data pointer's own
		 * ->switch_upstream, and downstream (sess) is the data pointer
		 * itself, so both need a temporary hold, released inside that
		 * function on every path. */
		session_hold(upstream);
		session_hold(sess);
		if (triton_context_call(&upstream->paren_conn->ctx,
					l2tp_switch_finish_upstream, sess) < 0) {
			session_put(sess);
			session_put(upstream);
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}

		return 0;
	}
```

Add `l2tp_switch_finish_upstream` directly above `l2tp_recv_ICRP` in the file — it's called from that function's tail above, isn't forward-declared, and so must be defined earlier in the source. It runs in the *upstream* leg's own context (crossed into via `triton_context_call`, matching how `l2tp_switch_place_call` already crosses the other way):

```c
static void l2tp_switch_finish_upstream(void *data)
{
	struct l2tp_sess_t *downstream = data;
	struct l2tp_sess_t *upstream = downstream->switch_upstream;

	if (l2tp_session_connect_socket(upstream, 0) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: connecting upstream kernel socket"
			    " failed\n");
		goto err;
	}

	if (l2tp_switch_link_create(upstream, downstream,
				    upstream->switch_target, 1) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: creating upstream->downstream"
			    " splice link failed\n");
		goto err;
	}
	if (l2tp_switch_link_create(downstream, upstream,
				    upstream->switch_target, 0) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: creating downstream->upstream"
			    " splice link failed\n");
		l2tp_switch_link_free(upstream->switch_link);
		goto err;
	}

	/* target->active was already incremented inside the first
	 * l2tp_switch_link_create() call above (gated on from_upstream) --
	 * nothing further to do for it here. See that function and
	 * l2tp_switch_link_free() for why the increment/decrement live
	 * there symmetrically rather than being tracked separately at the
	 * point where "the pair is now fully up" is known. */
	session_put(downstream); /* temporary hold taken at the call site */
	session_put(upstream);   /* temporary hold taken at the call site */
	return;

err:
	/* upstream->switch_downstream is still set to downstream (it was
	 * set once, back in Task 6 Step 5, and nothing before this point
	 * clears it) -- disconnecting upstream reaches l2tp_session_free()'s
	 * Task 8 hook synchronously, which finds that pointer, releases the
	 * hold it justifies, and tears down downstream too via
	 * l2tp_switch_teardown_peer(). */
	l2tp_session_disconnect(upstream, 2, 6);
	session_put(downstream); /* temporary hold taken at the call site */
	session_put(upstream);   /* temporary hold taken at the call site */
}
```

`switch_downstream_connected` is already printed (previous step in this task). "Currently active pairs" is *not* tracked as its own counter on `l2tp_stat_t` (see the note in Task 5's struct) — it's derived by summing every target's own `active` field, which `l2tp_switch_link_create()`/`_free()` above already keep correct through every teardown and partial-failure path. Task 1 already added a forward declaration for this (alongside `l2tp.c`'s existing ones for `l2tp_conn_read`/etc., since `l2tp_switch_show_exec` needed to reference it before it existed) — add the matching definition now, anywhere convenient in the file:

```c
static unsigned int l2tp_switch_active_total(void)
{
	struct l2tp_switch_target_t *t;
	unsigned int total = 0;

	list_for_each_entry(t, &l2tp_switch_targets, entry)
		total += __atomic_load_n(&t->active, __ATOMIC_RELAXED);

	return total;
}
```

and print it from `l2tp_switch_show_exec`'s `calls:` block:

```c
	cli_sendv(client, "  active: %u\r\n", l2tp_switch_active_total());
```

- [ ] **Step 5: Extend the MK-simulator harness to write into its own data-channel socket**

Add to `l2tp_switch_peer_test.c` (Task 4), after the existing ICCN-sending block in `main()`, right before `printf("ok tid=%hu sid=%hu\n", peer_tid, peer_sid);`:

```c
#include <linux/if_pppox.h>
```

(add this include near the top of the file, alongside the existing `<arpa/inet.h>`/`<sys/socket.h>` includes — it supplies `AF_PPPOX`, `PX_PROTO_OL2TP`, `struct sockaddr_pppol2tp`, `SOL_PPPOL2TP`, `PPPOL2TP_SO_LNSMODE`, the same header `l2tp.c` itself relies on for these).

Add a `--data-pattern <text>` option (following the exact same `getopt_long` shape as the existing options):

```c
/* add to the option globals */
static const char *data_pattern;

/* add to the getopt_long array */
{"data-pattern", required_argument, 0, 'd'},

/* add to the switch statement */
case 'd':
	data_pattern = optarg;
	break;
```

Then, once `peer_tid`/`peer_sid` are known (right before the final `printf`):

The plan as originally written jumped straight to a session-level `pppol2tp` connect. In practice that fails with `ENOENT`: Step 0 above already established that a *tunnel* must be registered with the kernel's L2TP subsystem (a throwaway `pppol2tp` connect with `s_session`/`d_session` left at `0`, then closed) before any session-level connect on it will succeed — `l2tp_tunnel_connect()` (`l2tp.c` ~2248) already does this for the real daemon's own tunnels, but nothing on this harness's side (playing the MK/LAC role for the *upstream* tunnel) ever did it for that tunnel until this task. Register it explicitly first, then open the real session-level data socket:

```c
	if (data_pattern) {
		struct sockaddr_pppol2tp pppox_addr;
		int reg_fd, data_fd, lns_mode = 0;

		/* Tunnel registration (Step 0's ENOENT prerequisite) --
		 * s_session/d_session left at 0, closed immediately after. */
		reg_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
		if (reg_fd < 0)
			return die("tunnel registration socket() failed");

		memset(&pppox_addr, 0, sizeof(pppox_addr));
		pppox_addr.sa_family = AF_PPPOX;
		pppox_addr.sa_protocol = PX_PROTO_OL2TP;
		pppox_addr.pppol2tp.fd = fd;
		pppox_addr.pppol2tp.addr = peer_addr;
		pppox_addr.pppol2tp.s_tunnel = local_tid;
		pppox_addr.pppol2tp.d_tunnel = peer_tid;

		if (connect(reg_fd, (struct sockaddr *)&pppox_addr,
			   sizeof(pppox_addr)) < 0)
			return die("tunnel registration connect() failed");
		close(reg_fd);

		data_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
		if (data_fd < 0)
			return die("data socket() failed");

		memset(&pppox_addr, 0, sizeof(pppox_addr));
		pppox_addr.sa_family = AF_PPPOX;
		pppox_addr.sa_protocol = PX_PROTO_OL2TP;
		pppox_addr.pppol2tp.fd = fd; /* share the control-channel UDP socket */
		pppox_addr.pppol2tp.addr = peer_addr;
		pppox_addr.pppol2tp.s_tunnel = local_tid;
		pppox_addr.pppol2tp.d_tunnel = peer_tid;
		pppox_addr.pppol2tp.s_session = local_sid;
		pppox_addr.pppol2tp.d_session = peer_sid;

		if (connect(data_fd, (struct sockaddr *)&pppox_addr,
			   sizeof(pppox_addr)) < 0)
			return die("data socket connect() failed");

		if (setsockopt(data_fd, SOL_PPPOL2TP, PPPOL2TP_SO_LNSMODE,
			      &lns_mode, sizeof(lns_mode)) < 0)
			return die("data socket setsockopt(LNSMODE) failed");

		if (write(data_fd, data_pattern, strlen(data_pattern)) < 0)
			return die("data socket write() failed");

		close(data_fd);

		/* Give the kernel a moment to finish encapsulating and
		 * emitting the queued datagram before the process (and so
		 * `fd`, the UDP socket the tunnel/session are keyed to)
		 * exits and tears down the underlying socket. */
		usleep(200000);
	}
```

(`pppox_addr.pppol2tp.fd = fd` reuses this harness's own control-channel UDP socket, exactly as `l2tp_session_connect_socket`'s existing `pppox_addr.pppol2tp.fd = conn->hnd.fd;` reuses the tunnel's own UDP socket — `s_tunnel`/`s_session` are this harness's own IDs (`local_tid`/`local_sid`, already used when building the SCCRQ/ICRQ earlier in `main()`), `d_tunnel`/`d_session` are the switch's IDs captured from SCCRP/ICRP (`peer_tid`/`peer_sid`, already captured by the existing code).)

- [ ] **Step 6: Write the failing test**

`tests/accel-pppd/l2tp_switch/test_switch_splice.py`, extending Task 6's `test_switch_forwards_proxy_avps` setup with a wire capture. This needs `tcpdump` on the test machine — add it to `tests/README.md`'s existing "Install additional tools required for tests" `apt install` line (currently `iproute2 ppp pppoe isc-dhcp-client`) alongside this task's other changes:

```python
import subprocess
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance

DATA_PATTERN = "SWITCHOK"


def test_switch_splices_data_plane(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17040, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17041,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17040,downstreamsecret
    line=472913,downstream
    """,
        )
        assert s_started

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            capture = subprocess.Popen(
                ["tcpdump", "-l", "-A", "-i", "lo", "udp", "port", "17040"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            time.sleep(0.5)  # let tcpdump attach before traffic starts

            try:
                peer_thread, peer_ctrl = l2tp_peer_process.start(
                    "/tmp/l2tp_switch_peer_test",
                    [
                        "--peer-addr", "127.0.0.1",
                        "--peer-port", "17041",
                        "--secret", "upstreamsecret",
                        "--calling-number", "472913",
                        "--data-pattern", DATA_PATTERN,
                    ],
                )
                rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
                assert rc == 0, err

                time.sleep(0.5)  # let the capture see the data packet
            finally:
                capture.terminate()
                capture_out, _ = capture.communicate(timeout=5.0)

            assert DATA_PATTERN in capture_out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
```

(`-p 2001`/`cli_port=2001`/`cli_port=2101`, matching the convention already established in Tasks 5-6's tests — `process.run([accel_cmd, "l2tp switch"])` and `accel_pppd_process.end(..., 10.0)` without an explicit port, as originally written above, target `accel-cmd`'s default CLI port rather than either of this test's two instances.)

The assertion is on the wire between the switch and the downstream instance, not on the downstream instance's own behavior — the downstream instance in this test is a **plain, unmodified accel-pppd LNS**, so it will try to interpret the arriving bytes as a real PPP frame and will not echo or acknowledge them meaningfully; `SWITCHOK` is not a valid PPP frame, so it is simply discarded by the downstream LNS's LCP layer without side effects. What this test actually proves is narrower and sufficient: the switch's `splice(2)` datapath (Task 7) correctly moved the exact bytes written into the MK-simulator's own kernel socket into a real L2TP data-message UDP packet addressed to the downstream target — which is the switch's entire responsibility; what the downstream LNS does with those bytes is outside this feature's scope.

- [ ] **Step 7: Run, verify it fails, then implement and verify it passes**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_splice.py`
Expected before this task's implementation: FAIL (`DATA_PATTERN not in capture_out`) — no data-plane bridging exists yet, so the write into the MK-simulator's kernel socket goes nowhere. After implementing Steps 1-4 above: PASS.

Confirmed for real on a VM, after fixing the four bugs documented inline above (Task 6's missing `l2tp_tunnel_push_sendqueue()` call, the harness's missing tunnel registration and missing `connect()` on its control-channel socket, the missing `O_NONBLOCK` on switch-mode session sockets, and the resulting need for `EAGAIN` handling on the write-side splice plus the `l2tp_switch_link_free()` double-close): `test_switch_splice.py` passes on its own in ~12s, and the full `l2tp_switch` suite (13 tests as of this task) passes together with no regressions. Before the `O_NONBLOCK` fix specifically, the *daemon itself* would hang shortly after the first successful splice — `accel-cmd` timing out against an otherwise-alive process — which is a considerably worse failure mode than a failing test and would not have been obvious from the test suite alone (the test's own 10-second `l2tp_peer_process.wait` timeout masks it as an ordinary assertion failure rather than the underlying thread-pool starvation); worth knowing if a similar "daemon looks alive but the CLI hangs" symptom ever reappears elsewhere in this codebase.

- [ ] **Step 8: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c \
        accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c \
        tests/accel-pppd/l2tp_switch/test_switch_splice.py
git commit -m "feat(l2tp): pair switched sessions and splice PPP frames via splice(2)"
```

---

### Task 8: Error handling & teardown

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c` (`l2tp_session_free` ~1063; also `l2tp_switch_place_call` (Task 6) and `l2tp_switch_finish_upstream`/`l2tp_recv_ICRP` (Task 7) — two pre-existing functions that turn out to need their own fixes, found while testing this task's own teardown hook, see Step 3's addendum below)
- Modify: `accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c` (adds `--wait-cdn`, for confirming the surviving leg is actually notified, and `--send-stopccn`, for the symmetric upstream-teardown test)
- Test: `tests/accel-pppd/l2tp_switch/test_switch_teardown.py`, `tests/accel-pppd/l2tp_switch/test_switch_teardown_upstream.py`

**Interfaces:**
- Consumes: `sess->switch_link`, `sess->switch_downstream`/`switch_upstream` (Tasks 6-7), `l2tp_switch_teardown_peer()` (Task 7 — already fully defined there; this task adds no new definition, only a new call site).
- Produces: a CDN or StopCCN (whichever `l2tp_tunnel_disconnect()` actually sends — see `--wait-cdn`'s own comment below) propagates to whichever leg is still up when the other is torn down for any reason (peer CDN/StopCCN, splice error, target tunnel drop).

- [ ] **Step 1: Write the failing test**

`tests/accel-pppd/l2tp_switch/test_switch_teardown.py`: reuse Task 7's setup (switch instance + downstream instance + MK-simulator harness establishing one switched call), then kill the **downstream** `accel_pppd_process` mid-call (`accel_pppd_process.end(...)` on it while the switch instance is still up) and assert, via `l2tp switch`, that the switch instance's `active` count drops back to 0 and (via the MK-simulator harness, extended to optionally listen for teardown after ICCN instead of exiting immediately) that the upstream leg is actually notified.

Add a `--wait-cdn` flag to `l2tp_switch_peer_test.c` that, after ICCN, blocks on `l2tp_recv()` with a wall-clock deadline (not a single `SO_RCVTIMEO`-bounded call, since that bounds each individual `recv()` rather than the cumulative wait — an intervening Hello/ZLB would otherwise reset the budget) for up to 5 seconds, and exits 0 only once it sees a message that unambiguously means "this call is over":

```c
/* add to the option globals */
static int wait_cdn;

/* add to the getopt_long array */
{"wait-cdn", no_argument, 0, 'W'},

/* add to the switch statement */
case 'W':
	wait_cdn = 1;
	break;

/* after the ICCN-sending block (and after Step 5's --send-stopccn
 * block below, if both happen to be given), before the final printf: */
if (wait_cdn) {
	/* RFC 2661 5.1: a control message's header sid/tid is the ID
	 * *assigned by the recipient* -- a session-level CDN sent to us
	 * for our own call carries our own fixed local_sid (not
	 * peer_sid); a tunnel-level StopCCN carries sid 0 and our own
	 * local_tid. Accept either: l2tp_tunnel_disconnect() (l2tp.c
	 * ~1039) deliberately discards any already-queued CDN and sends
	 * only StopCCN when the tunnel itself is going down (the common
	 * case when the call being torn down is the tunnel's last
	 * session) -- "to minimise delay in case of congestion", per
	 * that function's own comment. Both signals unambiguously mean
	 * the same thing to a peer: this call is over. Requiring a CDN
	 * specifically would fail exactly the scenario this flag exists
	 * to test -- confirmed on a real VM: an earlier version of this
	 * flag that only accepted Message_Type_Call_Disconnect_Notify
	 * timed out every time against test_switch_teardown.py's own
	 * scenario, because the switch's upstream leg is the *only*
	 * session on its tunnel, so tearing it down always takes the
	 * StopCCN-only path. */
	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	time_t deadline = time(NULL) + 5;
	int got_cdn = 0;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		return die("setsockopt(SO_RCVTIMEO) failed");

	while (time(NULL) < deadline) {
		struct l2tp_packet_t *cdn = NULL;
		struct l2tp_attr_t *msg_type;
		int is_ours;

		if (l2tp_recv(fd, &cdn, NULL, secret, strlen(secret)) != 0) {
			if (errno == EAGAIN)
				break;
			continue;
		}
		if (!cdn)
			continue;
		is_ours = ntohs(cdn->hdr.sid) == local_sid ||
			  (ntohs(cdn->hdr.sid) == 0 &&
			   ntohs(cdn->hdr.tid) == local_tid);
		if (list_empty(&cdn->attrs) || !is_ours) {
			l2tp_packet_free(cdn);
			continue;
		}
		msg_type = list_first_entry(&cdn->attrs, typeof(*msg_type), entry);
		if (msg_type->attr && msg_type->attr->id == Message_Type &&
		    (msg_type->val.uint16 == Message_Type_Call_Disconnect_Notify ||
		     msg_type->val.uint16 == Message_Type_Stop_Ctrl_Conn_Notify))
			got_cdn = 1;
		l2tp_packet_free(cdn);
		if (got_cdn)
			break;
	}

	if (!got_cdn)
		return die("timed out waiting for CDN");
}
```

(`#include <time.h>` for `time_t`/`time()`, needed alongside the existing includes.)

`tests/accel-pppd/l2tp_switch/test_switch_teardown.py`:

```python
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance


def test_downstream_drop_tears_down_upstream(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17060, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17061,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17060,downstreamsecret
    line=472913,downstream
    """,
        )
        assert s_started

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            # establish one switched call, then block waiting for the CDN
            # (or StopCCN -- see --wait-cdn's own comment above) the
            # switch's upstream leg must send once the paired downstream
            # leg goes away -- proves the actual RFC-level teardown, not
            # just an internal counter.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17061",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--wait-cdn",
                ],
            )

            active = None
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
                if "active: 1" in out:
                    active = 1
                    break
                time.sleep(0.1)
            assert active == 1, out

            # kill the downstream instance mid-call -- the switch's
            # l2tp_session_free() teardown hook must notice and tear down
            # the paired upstream leg too, rather than crashing or leaking.
            accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)

            rc, out2, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            active = None
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
                assert exit == 0
                if "active: 0" in out:
                    active = 0
                    break
                time.sleep(0.1)
            assert active == 0, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        # already ended mid-test above in the success path; end() is a
        # no-op on an already-terminated process, so this still cleans up
        # correctly if an earlier assertion failed first.
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
```

(`-p 2001`/`cli_port=2001`/`cli_port=2101`, matching the convention already established in Tasks 5-7's tests.)

- [ ] **Step 2: Run, verify it fails**

Expected: FAIL — nothing currently notices the downstream tunnel dying and tears down the paired upstream leg; `active` stays at 1 and no CDN arrives within the harness's timeout.

- [ ] **Step 3: Implement the teardown hook in `l2tp_session_free`**

`l2tp_session_free` (~1063) is the single choke point for both "one session CDN'd/freed individually" and "whole tunnel torn down, all its sessions freed via `l2tp_tunnel_free_sessions`" (confirmed: both paths call this function). Add the switch-teardown hook right after `sess->state1 = STATE_CLOSE;` is set (before the send-queue cleanup):

```c
	if (sess->switch_downstream || sess->switch_upstream) {
		struct l2tp_sess_t *peer = sess->switch_downstream ?
			sess->switch_downstream : sess->switch_upstream;

		if (sess->switch_link)
			l2tp_switch_link_free(sess->switch_link);

		sess->switch_downstream = NULL;
		sess->switch_upstream = NULL;
		session_put(peer); /* the hold justified by the pointer just
				     * cleared above -- see the reference-
				     * counting note in Task 7 before
				     * l2tp_switch_link_free() */

		if (peer->state1 != STATE_CLOSE) {
			session_hold(peer); /* survive the context switch */
			if (triton_context_call(&peer->paren_conn->ctx,
						l2tp_switch_teardown_peer,
						peer) < 0)
				session_put(peer);
		}
	}

	if (sess->switch_avps) {
		int i;

		for (i = 0; i < sess->switch_avps->count; i++)
			_free(sess->switch_avps->avp[i].val);
		_free(sess->switch_avps);
		sess->switch_avps = NULL;
	}
```

No new function is needed here: `l2tp_switch_teardown_peer()` (Task 7) already does exactly what the peer side of this teardown requires — clear the peer's own pointer, release the hold that pointer justified, and disconnect the peer if it isn't already closing. Result code `2`/error code `6`, used both there and in the hook above, are re-used verbatim from the existing "impossible to handle ICCN"/"impossible to handle ICRP" disconnect calls already in this file — matches Global Constraints' "follow existing conventions" and avoids inventing a new error-code scheme.

**Two more race conditions surfaced while testing this hook against real VMs, both in Task 6/7 functions that this hook now makes reachable from a genuinely concurrent angle they weren't written against.** Both are fixed in `l2tp.c` alongside the hook above, not deferred to a later task, since the hook above is useless without them (the very scenario it exists for — a leg dying mid-pairing — is exactly what triggers both races).

**Race 1: `l2tp_switch_place_call()` (Task 6) never checks whether `upstream` is still alive.** `l2tp_switch_place_downstream_call()` schedules `l2tp_switch_place_call(upstream)` via `triton_context_call()` from inside ICCN handling — a genuine deferral, not a synchronous call. If the MK peer sends ICCN and then *immediately* StopCCN (no delay — confirmed with `l2tp_switch_peer_test.c`'s own `--send-stopccn`, sent right after ICCN with zero pause), the StopCCN can be processed on upstream's own tunnel context — tearing upstream down completely via the now-hooked `l2tp_session_free()` — *before* the already-scheduled `l2tp_switch_place_call()` gets its turn to run. `l2tp_session_free()` is a no-op on an already-`STATE_CLOSE` session (its own `switch` statement returns immediately), so if `l2tp_switch_place_call()` proceeds anyway — pairing `upstream->switch_downstream = downstream` and placing the downstream call — nothing will *ever* call `l2tp_session_free(upstream)` again to trigger Step 3's hook. `downstream`'s hold on `upstream`, and the pairing itself, leak forever: confirmed on a real VM as `active` stuck at `1` indefinitely, with the log showing the downstream call being placed *after* "deleting session" for the upstream leg that supposedly placed it. Fix — bail out before doing anything if `upstream` is already gone, in `l2tp_switch_place_call()` (`l2tp.c`, Task 6), right after its parameter/local declarations:

```c
	/* upstream can already be STATE_CLOSE by the time this scheduled
	 * cross-context call actually runs -- e.g. the MK peer sends ICCN
	 * then immediately StopCCN, and the StopCCN is processed on
	 * upstream's own tunnel context (tearing upstream down completely,
	 * via l2tp_session_free()'s normal STATE_CLOSE-guarded path) before
	 * this call is scheduled to run. l2tp_session_free() is a no-op on
	 * an already-STATE_CLOSE session (its own switch statement returns
	 * immediately), so pairing downstream to a dead upstream here would
	 * mean nothing ever calls l2tp_session_free(upstream) again --
	 * Task 8's teardown hook would never fire, downstream's own
	 * session_hold(upstream) would never be released, and the pairing
	 * would leak forever (confirmed on a real VM: active stuck at 1
	 * indefinitely). session_put() directly (no context cross needed --
	 * l2tp_switch_finish_upstream() already does the same for its own
	 * trailing releases) releases the hold taken by the caller without
	 * pairing or placing any downstream call for a call that no longer
	 * exists. */
	if (upstream->state1 == STATE_CLOSE) {
		session_put(upstream);
		return;
	}
```

**Race 2: `l2tp_switch_finish_upstream()` (Task 7) re-derives `upstream` from a pointer this same hook can concurrently clear.** It read `upstream` as `downstream->switch_upstream` at call time rather than being handed a stable reference. If *either* leg dies and Step 3's hook runs while this scheduled call is still in flight, the hook clears `switch_upstream`/`switch_downstream` on the surviving leg — so `l2tp_switch_finish_upstream()` can find `downstream->switch_upstream == NULL` and crash dereferencing it, or (if it finds a stale but non-NULL leftover in some other interleaving) proceed to call `l2tp_session_connect_socket()`/`l2tp_switch_link_create()` against an already-`STATE_CLOSE` session — leaking a stray kernel socket that nothing will ever clean up, since that session's own `l2tp_session_free()` already ran and is a no-op on any later call. Fix — carry both pointers explicitly instead of re-deriving one from the other, and guard against either already being closed. Change the struct and function signature (`l2tp.c`, Task 7, directly above `l2tp_recv_ICRP`):

```c
struct l2tp_switch_finish_ctx {
	struct l2tp_sess_t *upstream;
	struct l2tp_sess_t *downstream;
};

static void l2tp_switch_finish_upstream(void *data)
{
	struct l2tp_switch_finish_ctx *ctx = data;
	struct l2tp_sess_t *upstream = ctx->upstream;
	struct l2tp_sess_t *downstream = ctx->downstream;

	_free(ctx);

	if (upstream->state1 == STATE_CLOSE || downstream->state1 == STATE_CLOSE) {
		session_put(downstream);
		session_put(upstream);
		return;
	}

	if (l2tp_session_connect_socket(upstream, 0) < 0) {
		/* ... unchanged from here on ... */
```

And its call site in `l2tp_recv_ICRP`'s `switch_upstream` branch (Task 7 Step 4) — allocate and pass the ctx instead of passing `sess` alone:

```c
		struct l2tp_switch_finish_ctx *ctx = _malloc(sizeof(*ctx));

		if (!ctx) {
			log_session(log_error, sess,
				    "l2tp-switch: allocating finish-upstream"
				    " context failed\n");
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}
		ctx->upstream = upstream;
		ctx->downstream = sess;

		session_hold(upstream);
		session_hold(sess);
		if (triton_context_call(&upstream->paren_conn->ctx,
					l2tp_switch_finish_upstream, ctx) < 0) {
			_free(ctx);
			session_put(sess);
			session_put(upstream);
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}
```

Both races were found the same way: running `test_switch_teardown_upstream.py` (Step 5 below) repeatedly rather than once. Race 1 reproduced on the very first real-VM attempt (the harness's `--send-stopccn` has zero delay after ICCN by design); Race 2 never reproduced under either race's own test as written (both send StopCCN either immediately after ICCN or wait for full pairing first, never split the difference), but was found by code inspection while fixing Race 1 and is real regardless — a MK peer that waits for pairing to fully complete and *then* immediately drops the tunnel would hit it. Fixed proactively rather than left for a future task to rediscover the hard way.

- [ ] **Step 4: Handle the "downstream tunnel itself dropped, before any per-session CDN" case**

Task 3's `l2tp_tunnel_free()` hook already clears `target->tunnel` and arms a reconnect. Confirm (by reading `l2tp_tunnel_free`'s body again) that it calls `l2tp_tunnel_free_sessions(conn)` for every session still in that tunnel — since that function iterates the tunnel's sessions and calls `l2tp_session_free()` on each, and Step 3 above already hooks `l2tp_session_free()`, every switched session on a dying downstream tunnel gets its paired upstream leg torn down automatically with no additional code needed here. Confirm this experimentally in Step 6 rather than adding redundant logic.

- [ ] **Step 5: Cover the symmetric direction — the *upstream* (MK-facing) tunnel torn down while downstream stays connected**

Step 4's reasoning applies identically in reverse: `l2tp_tunnel_free()` → `l2tp_tunnel_free_sessions()` → `l2tp_session_free()` is the same choke point regardless of *which* tunnel goes down or *why* (admin-initiated disconnect, StopCCN received, protocol error, timeout — confirmed by grepping every `l2tp_tunnel_free`/`l2tp_tunnel_disconnect`/`l2tp_tunnel_disconnect_push` call site in `l2tp.c`: all of them funnel through `l2tp_tunnel_free`, with no bypass). So removing the upstream tunnel while a downstream pairing is still active is already handled by the exact same Step 3 hook — but only the downstream-dies direction has an actual test so far (Step 1). Add the missing direction now rather than relying on the symmetry argument alone.

The MK-simulator harness normally just exits right after sending ICCN, leaving its tunnel lingering (neither side sent StopCCN) — fine for the tests so far, but it means there is no existing, deterministic way to make the *upstream* tunnel go down on command. Add a `--send-stopccn` flag to `l2tp_switch_peer_test.c` that, after ICCN, sends a StopCCN for the tunnel it opened and exits:

```c
/* add to the option globals */
static int send_stopccn;

/* add to the getopt_long array */
{"send-stopccn", no_argument, 0, 'x'},

/* add to the switch statement */
case 'x':
	send_stopccn = 1;
	break;

/* after the existing ICCN-sending block, before the final printf: */
if (send_stopccn) {
	pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("StopCCN alloc failed");
	l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, local_tid, 1);
	pack->hdr.tid = htons(peer_tid);
	pack->hdr.sid = 0;
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (l2tp_packet_send(fd, pack) < 0)
		return die("StopCCN send failed");
	l2tp_packet_free(pack);
	my_ns++;
}
```

(Like every other message this harness sends from Task 4 onward, StopCCN must carry the current `my_ns`/`peer_next_nr` — see Task 4's Ns/Nr bug note. Confirmed end-to-end against a real accel-pppd: sending StopCCN with stale `Ns=0` after several prior exchanges would otherwise look like a duplicate/out-of-order message and be discarded rather than tearing the tunnel down.)

(`l2tp_recv_StopCCN` in `l2tp.c` (~3236) only requires `Assigned_Tunnel_ID` to identify which tunnel is closing — `Result_Code` is read if present but not required; the harness already knows its own `local_tid`, sent identically in the SCCRQ earlier in `main()`.) Add `Message_Type_Stop_Ctrl_Conn_Notify` to the harness's includes if not already visible via `attr_defs.h` (it already defines it, per that header's `Message_Type_Stop_Ctrl_Conn_Notify = 4`).

Add `tests/accel-pppd/l2tp_switch/test_switch_teardown_upstream.py`, mirroring `test_switch_teardown.py`'s shape but tearing down the *upstream* side instead:

```python
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance


def test_upstream_tunnel_drop_tears_down_downstream(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17070, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17071,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17070,downstreamsecret
    line=472913,downstream
    """,
        )
        assert s_started

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            # establish one switched call, then have the "MK" side itself
            # send StopCCN -- tearing down the upstream tunnel while the
            # downstream pairing is still up
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17071",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--send-stopccn",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            active = None
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch"])
                assert exit == 0
                if "active: 0" in out:
                    active = 0
                    break
                time.sleep(0.1)
            assert active == 0, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
```

(`-p 2001`/`cli_port=2001`/`cli_port=2101`, matching Task 7's fixed convention — different ports (17070/17071) from `test_switch_teardown.py` above, since pytest may run both in the same session and reused ports across tests have caused cross-test interference before. Imports collected at the top of the file rather than split inline, matching every other test file in this plan.)

- [ ] **Step 6: Run, verify both directions pass**

Expected: PASS for both `test_switch_teardown.py` (downstream dies) and `test_switch_teardown_upstream.py` (upstream dies) — in both cases the switch instance's `active` count returns to `0` and the surviving leg is cleanly disconnected, confirming the single `l2tp_session_free()` choke point handles either direction without direction-specific code.

Confirmed for real on a VM, after fixing the two race conditions documented above (in addition to the teardown hook itself): both tests pass individually, and the full `l2tp_switch` suite (15 tests as of this task) passes together with no regressions. Because Race 1 is timing-dependent, a single passing run does not prove it is fixed — `test_switch_teardown_upstream.py` was run 15 times back-to-back in a loop (bypassing pytest's own per-test overhead so each iteration exercises the same tight ICCN-then-StopCCN timing) with zero failures, versus reproducing on the very next attempt (1-in-3 to 1-in-5, inconsistently) before the fix. `test_switch_teardown.py` additionally confirms Step 4's claim experimentally: killing the downstream instance mid-call (no code path specific to "downstream" vs "upstream" dying) correctly cascades through the exact same `l2tp_session_free()` hook.

- [ ] **Step 7: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c \
        tests/accel-pppd/l2tp_switch/test_switch_teardown.py \
        tests/accel-pppd/l2tp_switch/test_switch_teardown_upstream.py
git commit -m "fix(l2tp): tear down the paired leg when either side of a switch fails"
```

---

### Task 9: Observability polish

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c` (`l2tp_switch_show_exec`, `show_stat_exec`, new `l2tp_switch_stat_active()`/`l2tp_switch_stat_bytes()` exports)
- Modify: `accel-pppd/extra/metrics.c` (native Prometheus/JSON metrics — `render_prometheus()`, `render_json()`, a new `l2tp_switch_stat_resolve()`)
- Test: `tests/accel-pppd/l2tp_switch/test_switch_show.py`

**Interfaces:**
- Produces: `l2tp switch show` (renamed from bare `l2tp switch` used in earlier tasks' scaffolding — this task finalizes the exact CLI surface documented in the spec) listing, per target, tunnel status/active-call-count/`bytes_in`/`bytes_out`, plus one line per active call with the same byte split; an aggregate `l2tp-switch:` block (`active:`/`lns_rx_bytes:`/`lns_tx_bytes:`) in `accel-cmd show stat`, matching that command's existing nested-block format; the same numbers (aggregate *and* per-target, via a new callback-based `l2tp_switch_stat_targets_foreach()` export) in accel-ppp's native `/metrics` endpoint (Prometheus and JSON), resolved lazily by `metrics.c` through `dlsym`, matching the existing `l2tp_stat_starting`/`l2tp_stat_active` mechanism.

- [ ] **Step 1: Rename the CLI path to match the spec's documented `l2tp switch show`**

The earlier tasks registered `l2tp switch` (2-level) for brevity. Change the registration in `l2tp_init()` to 3-level, matching `l2tp switch add`/`l2tp switch del`'s existing 3-level shape:

```c
	cli_register_simple_cmd2(l2tp_switch_show_exec, NULL, 3,
				 "l2tp", "switch", "show");
```

Update every test file from Tasks 1-8 that calls `accel_cmd, "l2tp switch"` to `accel_cmd, "l2tp switch show"` (grep `"l2tp switch\"` and `'l2tp switch'` across `tests/accel-pppd/l2tp_switch/*.py` and fix each call site).

- [ ] **Step 2: Write the failing test**

`tests/accel-pppd/l2tp_switch/test_switch_show.py`: reuse Task 7's `test_switch_splices_data_plane` setup (one active switched call, `helpers.start_instance` for both instances, the `--data-pattern` flag on the MK-simulator harness — see that test for the full setup this one mirrors), assert `l2tp switch show` includes a per-session line with the calling-number value (`472913`), both tunnel/session ID pairs, and a non-zero `bytes=` count once the harness's `DATA_PATTERN` write has gone through (`len("SWITCHOK") == 8`, so `bytes=8` once the switch has spliced that write through — allow >=8 in the assertion in case a stray retransmit or control-channel byte inflates the count slightly, i.e. assert the reported byte count is at least 8, not exactly 8).

- [ ] **Step 3: Run, verify it fails**

Expected: FAIL — no per-session listing exists yet, only target/counter lines.

- [ ] **Step 4: Implement per-session listing**

Since sessions aren't tracked in a flat global list (`l2tp_conn_t.sessions` is a per-tunnel tree via `tsearch`/`tdestroy`), iterate the switch targets' tunnels' `sessions` trees using `twalk` (already used for this purpose in `l2tp_tunnel_free_sessions` — check that function's existing `twalk`/`tdestroy` call for the exact idiom and mirror it):

```c
static void switch_show_walk(const void *nodep, VISIT which, void *closure)
{
	struct l2tp_sess_t *sess = *(struct l2tp_sess_t **)nodep;
	void *client = closure;

	if (which != postorder && which != leaf)
		return;
	if (!sess->switch_upstream)
		return; /* only list downstream legs -- one line per call */

	/* sess->switch_link is this (downstream) leg's own link: it reads
	 * from the downstream socket and writes to upstream, i.e. it's the
	 * "target rx / upstream tx" direction (from_upstream == 0). The
	 * other direction is the upstream leg's own link, reachable via
	 * sess->switch_upstream->switch_link. Both are read here purely for
	 * display -- see Task 1's l2tp_switch_target_t for the persistent,
	 * per-target totals these feed into once the call ends. */
	cli_sendv(client, "  call: %s tunnel %hu-%hu / %hu-%hu"
			   " bytes_in=%llu bytes_out=%llu\r\n",
		 sess->switch_upstream->calling_num ?
			 sess->switch_upstream->calling_num : "?",
		 sess->switch_upstream->paren_conn->tid,
		 sess->switch_upstream->paren_conn->peer_tid,
		 sess->paren_conn->tid, sess->paren_conn->peer_tid,
		 (unsigned long long)(sess->switch_link ?
			 sess->switch_link->bytes : 0),
		 (unsigned long long)(sess->switch_upstream->switch_link ?
			 sess->switch_upstream->switch_link->bytes : 0));
}
```

(`bytes_in`/`bytes_out` from the *target's* point of view, matching the per-target totals below: `bytes_in` = bytes received from this target's downstream LNS, `bytes_out` = bytes sent to it.)

Call it from `l2tp_switch_show_exec`, once per target with a live tunnel, and extend the existing per-target line (added in Task 3) with the target's own persistent counters:

```c
	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		cli_sendv(client, "  %s -> %s:%hu [%s] active=%u"
				   " bytes_in=%llu bytes_out=%llu\r\n",
			 t->name, inet_ntoa(t->peer_addr.sin_addr),
			 ntohs(t->peer_addr.sin_port),
			 t->tunnel ? "up" : "down",
			 __atomic_load_n(&t->active, __ATOMIC_RELAXED),
			 (unsigned long long)__atomic_load_n(&t->rx_bytes, __ATOMIC_RELAXED),
			 (unsigned long long)__atomic_load_n(&t->tx_bytes, __ATOMIC_RELAXED));
		if (t->tunnel)
			twalk(t->tunnel->sessions, switch_show_walk); /* closure param needs
									 * threading through --
									 * see note below */
	}
```

(This replaces Task 3's simpler `[up]`/`[down]`-only line with the same line plus the three new fields — Task 3's own version is superseded here, not left in place alongside it.)

`twalk()`'s callback signature (`void (*)(const void *, VISIT, int)`, no user-data parameter in POSIX `twalk`) does not support passing `client` through directly. Use `twalk_r()` instead (GNU extension, already linked since this is a Linux-only codebase per `l2tp_kernel.h`'s netlink usage) which does take a closure argument — confirm `twalk_r` is declared under `_GNU_SOURCE` in `<search.h>` (already needed for `splice(2)` in Task 7, so the feature-test macro is already in place) and use:

```c
	twalk_r(t->tunnel->sessions, switch_show_walk, client);
```

with `switch_show_walk`'s signature adjusted to `(const void *nodep, VISIT which, void *closure)` matching `twalk_r`'s callback type exactly (GNU's `twalk_r` closure parameter is the third callback argument, not cast through `int` as some older POSIX `twalk` prototypes do — verify against `<search.h>` on the build machine, since this detail has changed across glibc versions).

- [ ] **Step 5: Add `show stat` counters**

`show_stat_exec` (`l2tp.c` ~line 4743, registered as `cli_register_simple_cmd2(&show_stat_exec, NULL, 2, "show", "stat")`) prints a **nested** block structure, not flat `key: value` lines — `l2tp:\r\n  tunnels:\r\n    starting: %u\r\n    active: %u\r\n    finishing: %u\r\n`, then a `sessions (control channels):` block, then `sessions (data channels):`. Match that exactly by adding a fourth block, right after the existing `sessions (data channels):` block and before `return CLI_CMD_OK;`:

```c
	cli_send(client, "  l2tp-switch:\r\n");
	cli_sendv(client, "    active: %u\r\n", l2tp_switch_active_total());
	cli_sendv(client, "    lns_rx_bytes: %llu\r\n",
		 (unsigned long long)stat.switch_lns_rx_bytes);
	cli_sendv(client, "    lns_tx_bytes: %llu\r\n",
		 (unsigned long long)stat.switch_lns_tx_bytes);
```

(`active` calls the same `l2tp_switch_active_total()` helper added in Task 7 Step 4 — summed fresh here rather than read from the snapshot, since it isn't one of `l2tp_stat_get()`'s atomic fields; see the note on `struct l2tp_stat_t` in Task 5 for why. The two byte fields *are* read from the local `stat` snapshot `l2tp_stat_get()` already filled at the top of this function — Task 5's consolidated `l2tp_stat_get()` update already copies both into it. The per-direction increments themselves already live in Task 7's splice loop, right after `link->bytes += n;` — nothing left to add there either.)

This block is deliberately global/LNS-side-aggregate only, not per-target — `show stat` is accel-ppp's existing compact fixed-shape summary command, not something that already iterates arbitrary lists; per-target `active`/`rx_bytes`/`tx_bytes` belong on `l2tp switch show`'s own per-target lines (Step 4 above), which already iterates `l2tp_switch_targets`.

- [ ] **Step 6: Export the same counters as native accel-ppp metrics, per target and in aggregate**

accel-ppp already ships a native Prometheus/JSON metrics endpoint — `accel-pppd/extra/metrics.c`, activated by listing `metrics` in `[modules]` and adding a `[metrics]` section (`accel-ppp.conf.5`, `.SH [metrics]`). It exposes `/metrics` over HTTP in `prometheus` (default) or `json` format, and per its own man page text, "the same numbers shown by `accel-cmd show stat`" — so this is a second, native consumer of exactly the counters this task just added, not an unrelated system.

Per-protocol numbers reach `metrics.c` without it depending on `l2tp.c` at link time: `l2tp.c` already exports `l2tp_stat_starting()`/`l2tp_stat_active()` (`__export`, i.e. visible to `dlsym`), and `metrics.c`'s `proto_stats[]` table (`metrics.c` ~line 48) resolves them lazily via `dlsym(RTLD_DEFAULT, ...)` — deliberately not a direct symbol reference, so that module load order never matters (see the comment directly above `proto_stats[]`). `proto_stats[]`'s fixed one-`starting`/one-`active`-per-protocol shape doesn't fit here at all — this needs a global aggregate (two byte counters) *and* a per-target breakdown (four numbers per target, over an unbounded, runtime-configured list `metrics.c` has no static knowledge of) — so this adds two small, purpose-built resolvers next to `proto_stats[]`/`proto_resolve()`, following the same lazy-`dlsym` idiom rather than reshaping the existing table.

In `l2tp.c`, add the LNS-side aggregate accessors next to the existing `l2tp_stat_starting()`/`l2tp_stat_active()` (~line 241):

```c
unsigned int __export l2tp_switch_stat_active(void)
{
	return l2tp_switch_active_total(); /* Task 7 Step 4 -- summed across
					     * targets, not a stored counter;
					     * see the note on struct
					     * l2tp_stat_t in Task 5 */
}

uint64_t __export l2tp_switch_stat_lns_rx_bytes(void)
{
	return __atomic_load_n(&l2tp_stat.switch_lns_rx_bytes, __ATOMIC_RELAXED);
}

uint64_t __export l2tp_switch_stat_lns_tx_bytes(void)
{
	return __atomic_load_n(&l2tp_stat.switch_lns_tx_bytes, __ATOMIC_RELAXED);
}
```

For the per-target breakdown, `metrics.c` cannot iterate `l2tp_switch_targets` itself (that list, and `struct l2tp_switch_target_t`'s layout, are internal to `l2tp.c` — sharing the struct definition across the module boundary would tie the two modules' binary layouts together, exactly what the existing `dlsym`-based design avoids everywhere else). Instead, export an iteration function that takes a callback, so `metrics.c` supplies only a function pointer plus plain scalar arguments — no shared struct, matching the existing loose-coupling approach one step further:

```c
typedef void (*l2tp_switch_target_stat_cb)(const char *name, int up,
					   unsigned int active,
					   uint64_t rx_bytes, uint64_t tx_bytes,
					   void *arg);

void __export l2tp_switch_stat_targets_foreach(l2tp_switch_target_stat_cb cb, void *arg)
{
	struct l2tp_switch_target_t *t;

	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		cb(t->name, t->tunnel != NULL,
		   __atomic_load_n(&t->active, __ATOMIC_RELAXED),
		   __atomic_load_n(&t->rx_bytes, __ATOMIC_RELAXED),
		   __atomic_load_n(&t->tx_bytes, __ATOMIC_RELAXED),
		   arg);
	}
}
```

In `extra/metrics.c`, add both resolvers next to `proto_stats[]`/`proto_resolve()` (~line 54):

```c
typedef uint64_t (*l2tp_switch_bytes_fn)(void);
typedef void (*l2tp_switch_target_stat_cb)(const char *name, int up,
					   unsigned int active,
					   uint64_t rx_bytes, uint64_t tx_bytes,
					   void *arg);
typedef void (*l2tp_switch_targets_foreach_fn)(l2tp_switch_target_stat_cb, void *);

static struct {
	proto_stat_fn active;
	l2tp_switch_bytes_fn lns_rx_bytes;
	l2tp_switch_bytes_fn lns_tx_bytes;
} l2tp_switch_stat;

static l2tp_switch_targets_foreach_fn l2tp_switch_targets_foreach;

static int l2tp_switch_stat_resolve(void)
{
	if (!triton_module_loaded("l2tp"))
		return 0;
	if (!l2tp_switch_stat.active)
		l2tp_switch_stat.active = (proto_stat_fn)(uintptr_t)
			dlsym(RTLD_DEFAULT, "l2tp_switch_stat_active");
	if (!l2tp_switch_stat.lns_rx_bytes)
		l2tp_switch_stat.lns_rx_bytes = (l2tp_switch_bytes_fn)(uintptr_t)
			dlsym(RTLD_DEFAULT, "l2tp_switch_stat_lns_rx_bytes");
	if (!l2tp_switch_stat.lns_tx_bytes)
		l2tp_switch_stat.lns_tx_bytes = (l2tp_switch_bytes_fn)(uintptr_t)
			dlsym(RTLD_DEFAULT, "l2tp_switch_stat_lns_tx_bytes");
	return l2tp_switch_stat.active && l2tp_switch_stat.lns_rx_bytes
	    && l2tp_switch_stat.lns_tx_bytes;
}

static int l2tp_switch_targets_resolve(void)
{
	if (!triton_module_loaded("l2tp"))
		return 0;
	if (!l2tp_switch_targets_foreach)
		l2tp_switch_targets_foreach = (l2tp_switch_targets_foreach_fn)(uintptr_t)
			dlsym(RTLD_DEFAULT, "l2tp_switch_stat_targets_foreach");
	return l2tp_switch_targets_foreach != NULL;
}
```

(`proto_stat_fn` is already `typedef unsigned int (*proto_stat_fn)(void);`, declared just above `proto_stats[]` — reused verbatim for the `active` counter, since its shape matches exactly.)

In `render_prometheus()`, right after the closing brace of the existing `proto_stats[]` loop (the one emitting `accel_ppp_protocol_sessions`, ~line 659):

```c
	if (l2tp_switch_stat_resolve()) {
		emit_prom_gauge(sb, "accel_ppp_l2tp_switch_active",
				"Currently bridged L2TP switch calls",
				l2tp_switch_stat.active());
		strbuf_appendf(sb, "# HELP accel_ppp_l2tp_switch_lns_bytes_total"
				   " Bytes spliced to/from MK, aggregated across all targets\n");
		strbuf_appendf(sb, "# TYPE accel_ppp_l2tp_switch_lns_bytes_total counter\n");
		strbuf_appendf(sb, "accel_ppp_l2tp_switch_lns_bytes_total{direction=\"rx\"} %" PRIu64 "\n",
			       l2tp_switch_stat.lns_rx_bytes());
		strbuf_appendf(sb, "accel_ppp_l2tp_switch_lns_bytes_total{direction=\"tx\"} %" PRIu64 "\n",
			       l2tp_switch_stat.lns_tx_bytes());
	}
	if (l2tp_switch_targets_resolve()) {
		strbuf_appendf(sb, "# HELP accel_ppp_l2tp_switch_target_up"
				   " Whether a switch target's downstream tunnel is up\n");
		strbuf_appendf(sb, "# TYPE accel_ppp_l2tp_switch_target_up gauge\n");
		strbuf_appendf(sb, "# HELP accel_ppp_l2tp_switch_target_active"
				   " Currently bridged calls for a switch target\n");
		strbuf_appendf(sb, "# TYPE accel_ppp_l2tp_switch_target_active gauge\n");
		strbuf_appendf(sb, "# HELP accel_ppp_l2tp_switch_target_bytes_total"
				   " Bytes spliced to/from a switch target's downstream LNS\n");
		strbuf_appendf(sb, "# TYPE accel_ppp_l2tp_switch_target_bytes_total counter\n");
		l2tp_switch_targets_foreach(emit_prom_target_stat, sb);
	}
```

with the callback (`emit_prom_target_stat`) defined near `emit_prom_gauge`:

```c
static void emit_prom_target_stat(const char *name, int up, unsigned int active,
				  uint64_t rx_bytes, uint64_t tx_bytes, void *arg)
{
	struct strbuf *sb = arg;

	strbuf_appendf(sb, "accel_ppp_l2tp_switch_target_up{target=\"%s\"} %d\n", name, up);
	strbuf_appendf(sb, "accel_ppp_l2tp_switch_target_active{target=\"%s\"} %u\n", name, active);
	strbuf_appendf(sb, "accel_ppp_l2tp_switch_target_bytes_total{target=\"%s\",direction=\"rx\"} %" PRIu64 "\n",
		       name, rx_bytes);
	strbuf_appendf(sb, "accel_ppp_l2tp_switch_target_bytes_total{target=\"%s\",direction=\"tx\"} %" PRIu64 "\n",
		       name, tx_bytes);
}
```

(`_bytes_total` rather than `_bytes`: Prometheus's own naming convention requires a `_total` suffix on counters, distinguishing them from gauges like `accel_ppp_l2tp_switch_active`/`_target_up`/`_target_active` — `emit_prom_gauge()` only knows how to emit `TYPE ... gauge`, so the counter HELP/TYPE/value lines are written out directly, matching that helper's own line shape. `direction="rx"|"tx"` is always from the labeled entity's own point of view — the target's for `_target_bytes_total`, the LNS side's (the MK-facing leg — named after `lns_mode`/the existing `mode <lac|lns>` CLI terminology this file already uses, not "upstream", which in ISP/BNG contexts usually means upload-vs-download traffic direction and would collide with the `direction=` label right next to it) for `_lns_bytes_total` — matching the CLI's `bytes_in`/`bytes_out` framing in Step 4 above.)

In `render_json()`, right before its final `strbuf_appendf(sb, "}\n");` (~line 886, immediately after the `if (conf_sessions) render_json_sessions(sb);` line):

```c
	if (l2tp_switch_stat_resolve()) {
		strbuf_appendf(sb, ",\"l2tp_switch\":{\"active\":%u,"
				   "\"lns_rx_bytes\":%" PRIu64 ","
				   "\"lns_tx_bytes\":%" PRIu64,
			      l2tp_switch_stat.active(),
			      l2tp_switch_stat.lns_rx_bytes(),
			      l2tp_switch_stat.lns_tx_bytes());
		if (l2tp_switch_targets_resolve()) {
			struct json_target_ctx ctx = { .sb = sb, .first = 1 };

			strbuf_appendf(sb, ",\"targets\":{");
			l2tp_switch_targets_foreach(emit_json_target_stat, &ctx);
			strbuf_appendf(sb, "}");
		}
		strbuf_appendf(sb, "}");
	}
```

The per-target `foreach` callback signature (fixed above, shared with the Prometheus renderer) only carries one `void *arg`, but this callback needs both the output buffer and a running "have I emitted one yet" flag for the leading-comma convention `emit_json_proto` already uses elsewhere in this file — bundle both into one small struct passed as `arg`, rather than trying to smuggle two things through a bare pointer:

```c
struct json_target_ctx {
	struct strbuf *sb;
	int first;
};

static void emit_json_target_stat(const char *name, int up, unsigned int active,
				  uint64_t rx_bytes, uint64_t tx_bytes, void *arg)
{
	struct json_target_ctx *ctx = arg;

	if (!ctx->first)
		strbuf_appendf(ctx->sb, ",");
	ctx->first = 0;

	strbuf_appendf(ctx->sb, "\"%s\":{\"up\":%s,\"active\":%u,"
			       "\"rx_bytes\":%" PRIu64 ",\"tx_bytes\":%" PRIu64 "}",
		       name, up ? "true" : "false", active, rx_bytes, tx_bytes);
}
```

Add `#include <stdint.h>` to `extra/metrics.c` if not already present, for `uint64_t`/`PRIu64` (the latter needs `<inttypes.h>`, already included per the existing `strbuf_appendf(sb, "\"mempool_allocated_bytes\":%" PRIu64 ",", ...)` call seen in `render_json()`).

**External `accel_exporter` compatibility.** The ansible-deployed `accel_exporter` (a separate, vendored Go binary — `roles/accel_exporter` in the ansible repo, not part of this codebase) works by parsing `accel-cmd show stat`'s text output, not by talking to accel-ppp's native `/metrics` endpoint. This task's Step 5 only *adds* a new `l2tp-switch:` block to that text output — every line `accel_exporter` already parses is untouched, so it keeps working exactly as it does today; it simply won't surface the new l2tp-switch numbers (global or per-target) unless it is itself updated to recognize them, which is a change in that separate project, out of scope here. The native `[metrics]` module extended in this step is a real, lower-risk alternative for anyone who wants Prometheus scraping of these numbers without waiting on that: point Prometheus directly at accel-ppp's own `/metrics` (`format=prometheus`, the default) instead of `accel_exporter`. Document both facts in Task 10's end-user doc.

- [ ] **Step 7: Run, verify it passes**

Build with the `metrics` module enabled (it already is — `extra/CMakeLists.txt` builds it unconditionally as `ADD_LIBRARY(metrics SHARED metrics.c)`, no special CMake flag needed), add `metrics`/`[metrics]` to a test instance's config, and `curl` its `/metrics` endpoint to confirm `accel_ppp_l2tp_switch_active`, `accel_ppp_l2tp_switch_lns_bytes_total{direction=...}`, `accel_ppp_l2tp_switch_target_up{target=...}`, `accel_ppp_l2tp_switch_target_active{target=...}`, and `accel_ppp_l2tp_switch_target_bytes_total{target=...,direction=...}` all appear with the expected values alongside the existing `accel_ppp_protocol_sessions{protocol="l2tp",...}` lines. Extend `test_switch_show.py` (or add a sibling `test_switch_metrics.py`) with this assertion, reusing Task 7's active-switched-call setup.

Expected: PASS — all the metric lines listed above appear, with `accel_ppp_l2tp_switch_target_active{target="downstream"}` matching `l2tp switch show`'s own per-target `active=` count and `accel_ppp_l2tp_switch_target_bytes_total{target="downstream",direction="tx"}` (the direction the harness's upstream-originated write travels) at least as large as the harness's `DATA_PATTERN` length, same as the CLI assertion in Step 2.

- [ ] **Step 8: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c accel-pppd/extra/metrics.c tests/accel-pppd/l2tp_switch/
git commit -m "feat(l2tp): finalize l2tp switch show CLI, show-stat counters, and native Prometheus/JSON metrics"
```

---

### Task 10: Unit test, marker registration, and end-user docs

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/packet_test.c`
- Modify: `tests/conftest.py`
- Modify: `tests/accel-pppd/l2tp_switch/*.py` (mark with `@pytest.mark.l2tp_switch`)
- Create: `docs/l2tp_switching.md`

**Interfaces:** None new — this task closes out testing/documentation coverage for the whole feature.

- [ ] **Step 1: Register the `l2tp_switch` marker**

In `tests/conftest.py`'s `pytest_configure`, alongside the existing three `config.addinivalue_line("markers", ...)` calls:

```python
    config.addinivalue_line(
        "markers",
        "l2tp_switch: marks tests as related to L2TP switching (deselect with '-m \"not l2tp_switch\"')",
    )
```

Add `@pytest.mark.l2tp_switch` above every `def test_*` in `tests/accel-pppd/l2tp_switch/*.py` from Tasks 1-9.

- [ ] **Step 2: Extend `packet_test.c`'s stub dictionary**

In `accel-pppd/ctrl/l2tp/packet_test.c`, extend the stub `dict[]` array (currently 6 entries, listed in the file's header comment) with the AVPs this feature captures/re-injects:

```c
	{ .name = "Init-Recv-LCP",       .id = Init_Recv_LCP,       .type = ATTR_TYPE_OCTETS, .M = 0, .H = -1 },
	{ .name = "Last-Sent-LCP",       .id = Last_Sent_LCP,       .type = ATTR_TYPE_OCTETS, .M = 0, .H = -1 },
	{ .name = "Last-Recv-LCP",       .id = Last_Recv_LCP,       .type = ATTR_TYPE_OCTETS, .M = 0, .H = -1 },
	{ .name = "Proxy-Authen-Type",   .id = Proxy_Authen_Type,   .type = ATTR_TYPE_INT16,  .M = 0, .H = -1 },
	{ .name = "Proxy-Authen-Name",   .id = Proxy_Authen_Name,   .type = ATTR_TYPE_STRING, .M = 0, .H = -1 },
	{ .name = "Proxy-Authen-Challenge", .id = Proxy_Authen_Challenge, .type = ATTR_TYPE_OCTETS, .M = 0, .H = -1 },
	{ .name = "Proxy-Authen-ID",     .id = Proxy_Authen_ID,     .type = ATTR_TYPE_INT16,  .M = 0, .H = -1 },
	{ .name = "Proxy-Authen-Response", .id = Proxy_Authen_Response, .type = ATTR_TYPE_OCTETS, .M = 0, .H = -1 },
```

(Types per RFC 2661 §4.4.7-4.4.8: the LCP AVPs and Proxy-Authen-Challenge/Response are raw octet strings — the actual CONFREQ/challenge/response bytes — while Proxy-Authen-Type and Proxy-Authen-ID are 16-bit integers and Proxy-Authen-Name is a string, matching how `attr_defs.h`'s other AVPs of each shape are already typed elsewhere in this same stub array.)

This file already has exactly the right shape of test to copy: `test_roundtrip(int hide_avps)` sends a hand-built packet through the shared loopback UDP socket (`sock`/`sock_addr`, set up once by `loopback_socket()` in `main()`) using the module-level `secret[]`, reads it back with `l2tp_recv()`, and checks specific AVPs via the existing `find_attr(pack, id)` helper — there is no `socketpair()` or per-test socket setup anywhere in this file; reuse the same shared `sock`/`sock_addr`/`secret` exactly as `test_roundtrip` does, following its structure line for line:

```c
static void test_proxy_avp_round_trip(void)
{
	static const uint8_t lcp[] = { 0x01, 0x02, 0x03, 0x04 };
	struct l2tp_packet_t *pack;
	const struct l2tp_attr_t *attr;

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
				 &sock_addr, 0, secret, sizeof(secret) - 1);
	CHECK(pack != NULL);
	if (!pack)
		return;

	CHECK(l2tp_packet_add_octets(pack, Last_Sent_LCP, lcp, sizeof(lcp), 0) == 0);

	CHECK(l2tp_packet_send(sock, pack) == 0);
	l2tp_packet_free(pack);

	pack = NULL;
	CHECK(l2tp_recv(sock, &pack, NULL, secret, sizeof(secret) - 1) == 0);
	CHECK(pack != NULL);
	if (!pack)
		return;

	attr = find_attr(pack, Last_Sent_LCP);
	CHECK(attr && attr->length == (int)sizeof(lcp));
	CHECK(attr && memcmp(attr->val.octets, lcp, sizeof(lcp)) == 0);

	l2tp_packet_free(pack);
}
```

Add `test_proxy_avp_round_trip();` to `main()`'s existing sequence of test calls (`loopback_socket(); test_hidden_avp_length_prefix(); ...`), right alongside `test_roundtrip(0)`/`test_roundtrip(1)`.

- [ ] **Step 3: Compile and run under ASan/UBSan**

```bash
cd accel-ppp
gcc -O1 -g -Wall -fno-strict-aliasing -D_GNU_SOURCE \
    -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I accel-pppd/include -I accel-pppd/ctrl/l2tp \
    -o /tmp/l2tp_packet_test \
    accel-pppd/ctrl/l2tp/packet_test.c accel-pppd/ctrl/l2tp/packet.c \
    -lcrypto && /tmp/l2tp_packet_test
```

Expected: no `FAIL` lines, clean ASan/UBSan exit.

- [ ] **Step 4: Write `docs/l2tp_switching.md`**

```markdown
# L2TP Switching

accel-ppp can act as an RFC 2661 §5.1 L2TP switch for a configured subset
of incoming calls: instead of terminating PPP locally, it relays the
Proxy LCP/Auth AVPs from the incoming call's ICCN into a second, outbound
call toward a downstream L2TP LNS, and bridges the resulting PPP frames
between the two tunnels. Neither PPP negotiation nor RADIUS is ever
touched for a switched call.

## Configuration

```
[l2tp-switch]
attr=Calling-Number
target=<name>,<peer-addr>,<peer-port>,<secret>
line=<value>,<target-name>
```

- `attr=<name>` — which L2TP AVP identifies a line, by its name in this
  build's AVP dictionary (`Calling-Number`, `Called-Number`, `Sub-Address`,
  ...). Must be a string-typed AVP. Defaults to `Calling-Number`.
- `target=<name>,<peer-addr>,<peer-port>,<secret>` — a downstream LNS.
  Repeatable. accel-ppp brings up one persistent outbound tunnel per
  target at startup and reconnects automatically if it drops.
- `line=<value>,<target-name>` — routes one `attr=`-identified line to one
  target. Repeatable; several lines may point at the same target. A value
  must not appear in more than one `line=` entry.

## Runtime management

```
l2tp switch show                    # list targets, tunnel status, active calls
l2tp switch add <value> <target>    # route a line to a target without a restart
l2tp switch del <value>             # stop routing a line
```

`target=` definitions are base-config only; changing a target's
peer-addr/secret requires a restart, same as other `[l2tp]` settings.

## Observability

`l2tp switch show` lists, per target: whether its tunnel is up, its
currently-bridged call count, and `bytes_in`/`bytes_out` (from that
target's own point of view — `in` is bytes received from that
target's downstream LNS, `out` is bytes sent to it), plus one line per
active call with the same `bytes_in`/`bytes_out` split. All the byte
counters are running totals: they only increase, even as individual
calls end, so a target's numbers reflect everything ever spliced to it,
not just its currently-active calls.

`accel-cmd show stat` includes an `l2tp-switch:` block alongside the
existing `l2tp:` one, with the aggregate (not per-target) `active:`,
`lns_rx_bytes:`, and `lns_tx_bytes:` — the totals to/from MK
across every target combined. In a healthy setup, `lns_rx_bytes`
should track the sum of every target's `bytes_out`, and
`lns_tx_bytes` the sum of every target's `bytes_in`; a persistent
mismatch points at a data-plane problem on one specific target's leg.

If accel-ppp's own `metrics` module is loaded (`[modules]` `metrics` +
a `[metrics]` section — see `accel-ppp.conf.5`), the same numbers are
also served natively over HTTP at `/metrics`, in both the default
Prometheus format and `format=json`:

- `accel_ppp_l2tp_switch_active` (gauge) — aggregate active calls.
- `accel_ppp_l2tp_switch_lns_bytes_total{direction="rx"|"tx"}` (counter) — aggregate, to/from MK.
- `accel_ppp_l2tp_switch_target_up{target="..."}` (gauge) — per-target tunnel status.
- `accel_ppp_l2tp_switch_target_active{target="..."}` (gauge) — per-target active calls.
- `accel_ppp_l2tp_switch_target_bytes_total{target="...",direction="rx"|"tx"}` (counter) — per-target, to/from that target's own LNS.

Deliberately not labeled by tunnel ID: MK's and each target's tunnel
IDs are renegotiated on every reconnect, which would make for
ever-churning, useless label series — `target` (an operator-assigned,
stable name) is the right dimension for per-flow visibility instead.

Point Prometheus at `/metrics` directly for these numbers rather than
the separately-deployed `accel_exporter` tool: `accel_exporter` parses
`accel-cmd show stat`'s text output and does not automatically pick up
the new `l2tp-switch:` block — that would require a change in
`accel_exporter`'s own (separate) codebase, which is out of scope here.
`accel_exporter` itself is unaffected either way: every line it already
parses is untouched.

Switched calls do not appear in `accel-cmd show sessions` and generate no
RADIUS accounting records — they never create a PPP session object at
all. If a switched line needs to be billed or usage-tracked, use these
counters or accounting on the downstream LNS itself.

## Operational constraints

- **MTU is not renegotiated.** The Proxy LCP AVPs forwarded to the
  downstream LNS carry whatever MRU was already negotiated upstream; the
  switch has no PPP engine of its own able to adapt it. Make sure the path
  between this host and each downstream LNS has at least as much usable
  MTU as the upstream path, or supports PMTUD end to end — a smaller
  downstream-path MTU will silently drop or fragment traffic with no
  diagnostic from this feature.
- **Sequencing is mirrored, not chosen per leg.** If MK requires L2TP data
  sequencing on a switched call, the same requirement is placed on the
  downstream call automatically; there is no way to configure the two legs
  independently.
```

- [ ] **Step 5: Run the complete l2tp_switch suite once more, end to end**

```bash
cd tests
sudo python3 -m pytest -v -m l2tp_switch accel-pppd/l2tp_switch/
```

Expected: all tests from Tasks 1-9 PASS together in one run (not just individually) — this catches any state leakage between tests (stray `/tmp` config files, leftover processes) that per-task runs might have missed.

- [ ] **Step 6: Commit**

```bash
git add accel-pppd/ctrl/l2tp/packet_test.c tests/conftest.py \
        tests/accel-pppd/l2tp_switch/ docs/l2tp_switching.md
git commit -m "test(l2tp): add proxy-AVP unit test, l2tp_switch marker, end-user docs"
```
