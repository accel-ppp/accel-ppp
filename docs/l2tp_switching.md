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
- **A call ending always tears down its pair.** Whichever leg goes away
  first — a CDN, a StopCCN for its whole tunnel, a splice failure, or the
  downstream target's tunnel dropping — the other leg is torn down too.
  There is no partial/orphaned-leg state to clean up manually.
- **Throughput on a single switched call is bounded by one synchronous
  relay path, not by the network.** Unlike an ordinary PPP session (whose
  data plane runs entirely in-kernel, attached to the generic PPP channel),
  a switched call's bytes are relayed via a userspace `splice(2)` loop on
  one of triton's worker threads. Under a sustained, very high packet rate
  on a single call, the kernel's UDP receive buffer for that session can
  fill faster than this loop drains it, and excess packets are dropped
  silently at the kernel level (visible as `Udp: receive buffer errors` in
  `netstat -su`, not as anything this feature reports itself). Ordinary
  call volumes and realistically network-paced traffic do not approach
  this ceiling; a single session sustaining an artificial, unpaced burst
  of many thousands of packets per second is the scenario this affects.
