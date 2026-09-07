# L2TP Switching (Multi-Hop L2TP) — Design

## 1. Problem

accel-ppp currently acts purely as an L2TP LNS: it terminates the tunnel from
MK (the upstream wholesale carrier), then terminates PPP locally (LCP, PAP/CHAP
via FreeRADIUS, IPCP/IPv6CP) for every session. All migrated IP-BSA lines
(xDSL and FTTH) go through this path today.

A subset of lines need a different outcome: the downstream customer runs
their own LNS (a VM, router, or another BRAS) and wants full, unmediated
control over PPP negotiation and IP assignment for their own subscribers.
accel-ppp must sit between MK (tunnel source) and the customer's LNS (tunnel
destination) without ever becoming the real PPP peer for these sessions —
i.e. it must act as an **L2TP switch**, not an LNS, for this subset.

This is the RFC 2661 §5.1 "multihop" scenario: the AVP groups carried in
ICCN — Proxy LCP (AVP 26–28: Initial/Last-Sent/Last-Received LCP CONFREQ) and
Proxy Authentication (AVP 29–33: Auth Type, Name, Challenge, ID, Response) —
exist precisely so a middle box can read what a LAC already collected and
re-inject it into a second, outbound tunnel toward the real LNS, without
redoing PPP negotiation itself. Classic Cisco IOS `vpdn multihop` and some
Juniper BRAS platforms implement this; it is not a common feature in
general-purpose open-source LNS daemons, and accel-ppp does not have it
today (the AVPs in question are already parsed in `l2tp_recv_ICCN` but
immediately discarded).

## 2. Scope

- A small, explicit set of lines (identified by a configurable L2TP AVP,
  e.g. Calling-Number) get switched to a named downstream target instead of
  terminated locally.
- Every other session is unaffected — same code path as today, including
  RADIUS auth/accounting.
- Multiple downstream targets are supported from day one (multiple
  customers, each running their own LNS), not just a single dedicated LNS.
- Out of scope for v1: RADIUS-driven dynamic target selection (see §10),
  hot-reload of the switch table from the base config file (accel-cmd
  covers the "add a line without a restart" need instead — see §4),
  IPv6-only or dual-stack—specific handling (the switch never looks past
  the PPP frame boundary, so this is a non-issue by construction).

## 3. Architecture overview

This lives inside the existing `l2tp` module (`accel-pppd/ctrl/l2tp/l2tp.c`),
not a separate module — it reuses the tunnel/session state machine, AVP
dictionary, and kernel `pppol2tp` socket plumbing already there.

```
MK (LAC)                    accel-ppp (switch)                 Customer LNS (VM/router)
   |                              |                                     |
   |--- SCCRQ/SCCRP/SCCCN ------->|  (tunnel A, accel-ppp = LNS)        |
   |--- ICRQ (Calling-Number) --->|                                     |
   |<-- ICRP ---------------------|                                     |
   |--- ICCN (Proxy LCP/Auth) --->|                                     |
   |                              |--- SCCRQ/SCCRP/SCCCN -------------->|  (tunnel B, accel-ppp = LAC,
   |                              |                                     |   persistent, brought up at
   |                              |--- ICRQ (same Calling-Number) ----->|   startup — see §4)
   |                              |<-- ICRP ----------------------------|
   |                              |--- ICCN (same Proxy LCP/Auth) ----->|
   |                              |                                     |
   |<==== PPP frames spliced between tunnel A's and tunnel B's ========>|
   |      kernel pppol2tp sockets — accel-ppp's PPP/LCP/RADIUS          |
   |      engine never runs for this session (§6)                      |
```

Two `l2tp_sess_t` objects exist for a switched call — one per tunnel — linked
via a `switch_peer` pointer once both legs are up. Neither ever calls
`l2tp_session_start_data_channel()` (the function that hands a session to
`ppp_init`/the PPP engine); that call site is exactly where switched sessions
diverge from normal ones.

## 4. Configuration

New `[l2tp-switch]` section, sibling to `[l2tp]`:

```
[l2tp-switch]
attr=Calling-Number
target=simon-vm,203.0.113.50,1701,<secret>
line=472913,simon-vm
target=acme-router,198.51.100.9,1701,<secret2>
line=550021,acme-router
line=550022,acme-router
```

- `attr=<name>` — the L2TP AVP used to identify a line, by its exact
  name in accel-ppp's own AVP dictionary (`dict/dictionary.rfc2661`, resolved
  via the existing `l2tp_dict_find_attr_by_name()`). Any string-typed AVP
  already known to the dictionary is valid — `Calling-Number`,
  `Called-Number`, `Sub-Address`, etc. — not a hardcoded enum. An unknown
  name or a non-string-typed AVP is a config-load error (fatal, logged).
  Default: `Calling-Number`. Which AVP MK actually populates stably and
  uniquely per line needs an empirical check (see §9) before onboarding the
  first real customer — the config shape does not change based on the
  answer, only the value of `attr`.
- `target=<name>,<peer-addr>,<peer-port>,<secret>` — one downstream LNS.
  One persistent outbound tunnel per target (see below).
- `line=<value>,<target-name>` — maps one raw AVP value to exactly one
  target; a value must not appear in more than one `line=` entry (fatal
  config-load error if it does — see §11). This is a many-to-one mapping
  across the whole table, not one-to-many per line: several different
  `line=` entries (several different values) can each point at the same
  target (one customer, several lines, all going to that customer's one
  LNS), and other entries point at other targets (other customers) — but a
  single value/line is only ever switched to one target, because a single
  subscriber's PPP session is placed into exactly one outbound call toward
  exactly one downstream LNS; there's no notion of one session terminating
  at two LNS's at once. Repeatable key, following the same style as
  `[ip-pool]`/`[ipv6-pool]` ranges elsewhere in accel-ppp.conf.

This mirrors two existing precedents in accel-ppp rather than inventing new
conventions: `ipoe`'s `calling-sid=mac|ip` (a config knob that selects which
field identifies a session), generalized here to "any named AVP" since the
L2TP dictionary already gives every AVP a resolvable name; and `shaper`'s
`attr=Filter-Id` (naming an attribute in config rather than hardcoding it).

**Runtime updates without a restart**: `accel-cmd` gets three new commands —
`l2tp switch add <value> <target-name>`, `l2tp switch del <value>`, and
`l2tp switch show` — reusing the existing CLI-command registration pattern
already in `l2tp.c` for `l2tp create tunnel` / `l2tp create session`. Adding
one customer's line is an `accel-cmd` call, not a config edit + restart. The
`target=` definitions themselves (peer address/secret) are base-config-only
in v1 — changing a target's connection details is expected to be rare enough
to accept the existing "config change requires a restart" convention this
daemon already operates under (see the ansible role's
`accel_ppp_apply_restart` gate). This asymmetry is deliberate: the frequent
operation (onboard a new line to an existing target) is restart-free; the
rare one (add/change a downstream LNS's connection details) is not.

## 5. Control-plane call flow

1. **ICRQ from MK** — `l2tp_recv_ICRQ` runs unchanged through AVP parsing
   (Calling-Number/Called-Number are already captured here today). New: look
   up the configured `attr`'s value against the switch table. On a
   match, set `sess->switch_target` on the newly allocated session. ICRP is
   sent as normal — MK sees no difference at this stage.
2. **ICCN from MK** — `l2tp_recv_ICCN`'s AVP walk currently has explicit
   `case` labels for `Init_Recv_LCP`, `Last_Sent_LCP`, `Last_Recv_LCP`,
   `Proxy_Authen_Type`, `Proxy_Authen_Name`, `Proxy_Authen_Challenge`,
   `Proxy_Authen_ID`, `Proxy_Authen_Response` that just `break` (discard).
   For a session with `switch_target` set, these get `memdup`'d instead into
   a new `struct l2tp_switch_avps` hung off `sess`. Then, instead of the
   normal `l2tp_session_connect(sess)` call (which starts local PPP), control
   passes to the switch manager.
3. **Downstream leg** — the target's tunnel is normally already up (brought
   up persistently at startup, see §6). The switch manager places a call
   into it via the existing `l2tp_tunnel_create_session` →
   `l2tp_session_place_call` → `l2tp_send_ICRQ` path (already used today by
   the `l2tp create session` CLI command for manually-initiated LAC-mode
   calls), carrying forward the original `calling_num`/`called_num`. On
   ICRP from the customer's LNS, `l2tp_send_ICCN` is called as usual but
   extended to attach the captured `l2tp_switch_avps` verbatim instead of
   the locally-negotiated values it would normally send.
4. **Pairing** — `l2tp_session_connect()` is split into (a) kernel-socket
   setup (`socket(AF_PPPOX, ...)`, the `PPPOL2TP_SO_*` setsockopts, `connect()`
   — unchanged, reused by both normal and switched sessions) and (b) PPP
   engine start (`l2tp_session_start_data_channel`, which calls `ppp_init`
   and hands off to the generic PPP/RADIUS engine). Switched sessions run
   (a) on both legs and skip (b) entirely. Once both legs' kernel sockets are
   connected, `sess->switch_peer` is set on each, and the data-plane splice
   (§6) is wired up.

## 6. Data plane

Each `pppol2tp` kernel socket already presents a clean "deframed PPP frame
in, deframed PPP frame out" datagram interface — the kernel's L2TP module
handles per-tunnel sequencing/reassembly regardless of LNS or LAC role. A
switched session's two legs are bridged by `splice(2)` through a small pipe
pair (not `read()`/`write()` through userspace buffers): zero-copy at the
page level, two syscalls per direction. Registered as `triton_md_handler_t`
callbacks on each tunnel's own triton context (each `l2tp_conn_t` already
runs on an independent context today), so one switched session's traffic
cannot stall another session's or MK's control-channel processing. No
`ppp_t`, no LCP/CHAP/IPCP state machine, no RADIUS client ever touches these
bytes.

## 7. Error handling & teardown

- Downstream ICRQ rejected, ICRP times out, or the target's tunnel is
  unreachable → CDN the upstream (MK-facing) call. Never fall back to local
  PPP termination — that would silently violate the contractual boundary
  that motivates this feature in the first place.
- Either leg receives CDN/StopCCN, or a `splice()` call errors → tear down
  both legs: CDN on whichever side is still up, unregister the pipe/handlers,
  clear `switch_peer` on both sessions before freeing either.
- A target's persistent tunnel drops → CDN every switched session currently
  paired through it (MK's tunnel is a separate object and is unaffected);
  the tunnel manager attempts reconnection per the persistent-tunnel policy
  in §4/§6.

## 8. Observability

Switched sessions never create a `ppp_t`/`ap_session`, so they are invisible
to `accel-cmd show sessions` and to RADIUS-based accounting — a real blind
spot given this deployment's reliance on `accel_exporter` scraping
`accel-cmd show stat`. Mitigations:

- New CLI: `l2tp switch show` — lists active switched sessions (match value,
  target, both tunnel/session ID pairs, up-since, bytes spliced).
- A `l2tp_switch_active` / `l2tp_switch_bytes` line added to the existing
  `show stat` output, so `accel_exporter` picks it up without a new scrape
  target or exporter change.

## 9. Open question: which AVP is actually stable

`attr` defaults to `Calling-Number`, the AVP conventionally used for
this exact purpose (line/circuit identity) in wholesale DSL/FTTH L2TP
handoffs. This needs verifying against what MK actually sends for one of the
lines being switched — accel-ppp already logs every incoming call's
Calling-Number at `log_info1` (`l2tp_recv_ICRQ`, "new session ... with
calling num %s..."), so this is a log-grep on the LNS host, not new
instrumentation. If Called-Number (or another dictionary AVP) turns out to
be the stable per-line identifier instead, only the `attr` config
value changes — no code or schema change required. This check should happen
before or during early implementation, not block writing the code.

## 10. Why not RADIUS-driven target selection

Considered and rejected for v1: accel-ppp's RADIUS client
(`accel-pppd/radius/req.c`, `rad_req_alloc`) is hard-wired to an active
`ap_session`/`radius_pd_t`, which only exists once a PPP session object has
been created. The switch/no-switch decision has to happen at ICRQ time,
before any PPP negotiation and therefore before any `ap_session` exists.
Making this RADIUS-driven would mean either faking a session object solely
to obtain a RADIUS answer, or building a second, parallel minimal RADIUS
client path independent of `ap_session` — real new-subsystem effort, not
proportionate to "a few sessions." The `accel-cmd`-driven live table (§4)
gets the actual operational need (add a customer without a restart) via a
pattern the codebase already has, at a fraction of the risk.

## 11. Additional edge cases

- **MTU/PMTU mismatch across the two tunnels.** The captured Proxy LCP AVPs
  (including the already-negotiated MRU) are forwarded to the downstream LNS
  verbatim, never renegotiated — the switch has no PPP entity able to adapt
  them. If the accel-ppp↔downstream-LNS path has a smaller effective MTU
  than the accel-ppp↔MK path, there is no mechanism in this design to
  compensate; the path must be sized correctly (or support PMTUD end to
  end) as an operational precondition, not something the switch fixes.
- **Sequencing/reorder settings must mirror across legs.** MK's
  `Sequencing_Required` AVP sets `send_seq`/`recv_seq` on the upstream
  kernel socket independently of whatever the downstream leg negotiates.
  The downstream ICRQ must propagate the same sequencing request MK made,
  rather than falling back to independent per-tunnel defaults — a mismatch
  wouldn't break the splice mechanically, but could reorder frames on one
  leg in a way that leg's real PPP peer never expects.
- **`switch_peer` lifetime.** Two `l2tp_sess_t`s holding pointers to each
  other is a use-after-free risk if one leg is freed while the other still
  references it. Requires the same `session_hold`/`session_put` discipline
  already used for `paren_conn`, with the pointer cleared under lock before
  either side is freed. Correctness-critical, called out explicitly for the
  implementation plan.
- **Downstream tunnel not yet up when ICCN arrives.** If the target's
  persistent tunnel is mid-reconnect, queuing the call (§5) needs a bounded
  deadline — otherwise MK's own completion timers on the upstream leg could
  fire and CDN out from under us while we wait indefinitely. On timeout,
  actively CDN upstream per the §7 policy rather than hang.
- **Accounting/billing blind spot**, distinct from the monitoring blind spot
  in §8: switched sessions never touch RADIUS, so there is no Acct-Start/Stop
  at all for them, not merely a missing `show sessions` entry. If these
  lines need to be billed or usage-tracked internally, that has to come from
  somewhere else (e.g. `l2tp switch show`'s byte counters scraped
  periodically, or accounting on the customer's own downstream LNS) — a
  decision to make before onboarding a billed customer this way, not after.
- **Config validation.** A `line=` referencing an undefined `target=`, a
  duplicate `line=` value pointing at two different targets, or a `target=`
  peer-addr equal to accel-ppp's own `[l2tp] bind` address (a self-loop)
  must all be fatal config-load errors, not silently last-wins or silently
  accepted.

## 12. Testing

No existing test exercises an actual L2TP tunnel/session end-to-end today —
the only `l2tp` reference under `tests/` is `accel-pppd/general/test_basic.py`
loading the module in a smoke test that just checks `show stat`. Reusable
scaffolding does exist, though, and both layers below build on it rather than
starting from scratch:

- **Unit**: AVP capture/re-injection round-trip, extending
  `accel-pppd/ctrl/l2tp/packet_test.c` (the existing standalone ASan/UBSan
  regression harness for `packet.c`, run manually outside cmake). Its stub
  AVP dictionary (`packet_test.c:52-58`) gets entries for `Init_Recv_LCP`,
  `Last_Sent_LCP`, `Last_Recv_LCP`, and the five `Proxy_Authen_*` AVPs; a new
  test case sends a hand-crafted ICCN-shaped packet containing them through
  the real `l2tp_packet_send()`/`l2tp_recv()` and asserts the raw octets
  captured into `l2tp_switch_avps` are byte-identical, and that the extended
  `l2tp_send_ICCN` reproduces them exactly in the outbound packet.
- **Integration**: a pytest test under `tests/accel-pppd/`, built on the same
  fixtures `tests/accel-pppd/general/test_basic.py` and the PPPoE tests
  already use — `tests/common/netns.py` + `veth.py` for network namespaces,
  `accel_pppd_process.py` to launch real `accel-pppd` instances,
  `pppd_process.py` for a real PPP client. Three `accel-pppd` instances
  linked by veth pairs: one in LAC mode (simulating MK) running real local
  PPP against a real `pppd` client — genuine LCP/PAP negotiation, so the
  ICCN it sends carries genuine Proxy AVPs, not hand-crafted ones; the switch
  build in the middle, configured with a `[l2tp-switch]` rule matching the
  LAC instance's calling-number; a third instance in plain LNS mode
  (simulating the customer's downstream LNS) with its own `chap-secrets`/IP
  pool. Assertions: the `pppd` client's negotiated username and IP address
  come from the *downstream* (third) instance's config, not the switch's;
  `l2tp switch show` on the middle instance lists the session; the switch
  instance's own RADIUS/PPP accounting shows no activity for it.
- **`accel-cmd` tests**: `l2tp switch show/add/del` get coverage alongside
  the existing command tests in `tests/accel-cmd/test_cmd_basic.py` and
  `test_real_commands.py`, following those files' existing assertion style
  against real `accel-cmd` output.
- **Manual**: the Calling-Number empirical check (§9) is a prerequisite, not
  part of the automated suite.
