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
  relay path, and by the path's own UDP capacity — and a large enough
  instantaneous burst can end the call, not just lose data.** Unlike an
  ordinary PPP session (whose data plane runs entirely in-kernel, attached
  to the generic PPP channel), a switched call's bytes are relayed via a
  userspace `splice(2)` loop on one of triton's worker threads. Two
  distinct failure modes were measured (real two-VM setup, one switched
  call, one MK-side sender writing as fast as possible with no pacing):
  - Below roughly 100 packets (1400 bytes each) written back-to-back with
    no delay, everything is relayed with zero loss.
  - Above that, the kernel's UDP receive buffer for the session can fill
    faster than the relay loop drains it (excess packets dropped silently
    at the kernel level, visible as `Udp: receive buffer errors` in
    `netstat -su`, not as anything this feature reports itself); on a real
    (non-loopback) network path, the relay's own outbound `splice(2)` call
    can also fail outright under the same burst (`ENOMEM`, occasionally
    `EBADF` on the paired leg as a direct side effect of the first leg's
    teardown) — in that case the switch disconnects the call cleanly
    (CDN sent, both legs torn down, matching the "a call ending always
    tears down its pair" behavior above) rather than continuing degraded.
    This is the intended, safe failure mode — not a crash or a leak — but
    it means a large enough burst ends the call rather than merely
    throttling it.

  Ordinary call volumes and realistically network-paced traffic do not
  approach either threshold; a single session sustaining an artificial,
  unpaced burst of many thousands of packets per second is the scenario
  this affects.

  **Before assuming this is the switch's own limit, measure the path's
  actual UDP capacity** — it is very often lower than what the same path
  does over TCP, and that gap is easy to mistake for a software problem.
  On the pair of cloud VMs used to measure the numbers above, a plain
  `iperf3` TCP test reached 9.15 Gbit/s, but UDP on the *same* path
  topped out around 1.2-1.4 Gbit/s aggregate — and adding parallel UDP
  streams did not raise that ceiling, which points at the underlying
  virtualized network path itself (packet-per-second handling for many
  small UDP datagrams, not this feature's own single relay thread nor
  either host's CPU). A switched call is carried over UDP end to end, so
  it can never exceed whatever a plain UDP test between the same two
  hosts already shows — no amount of tuning on this feature's own side
  changes that ceiling if it's set by the path itself:

  ```bash
  # on the downstream LNS
  iperf3 -s -p 5201

  # on the switch host, from a shell -- NOT through the switch itself
  iperf3 -c <downstream-lns-ip> -p 5201 -t 10                     # TCP baseline
  iperf3 -c <downstream-lns-ip> -p 5201 -u -b 0 -t 10 -l 1400      # UDP, uncapped
  iperf3 -c <downstream-lns-ip> -p 5201 -u -b 0 -P 4 -t 10 -l 1400 # UDP, 4 parallel streams
  ```

  Compare the three: if UDP is dramatically lower than TCP on the same
  path, and adding parallel streams doesn't close the gap, the path
  itself — not this feature — is the ceiling, and no amount of buffer
  tuning here will raise it. If UDP scales up cleanly with more parallel
  streams instead, the earlier single-stream number was CPU/generation
  bound rather than a path limit, which is a different (and more
  fixable, e.g. by giving the switch host more CPU) situation. Either
  way, treat whatever this shows as the hard ceiling for any one
  switched call's sustained throughput on that path, well before
  looking at this feature's own relay design as the cause of a
  throughput problem.
