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
target=<name>,<peer-addr>,<peer-port>,<secret>
match=<attr-name>,<mode>,<value>,<target-name>
```

- `target=<name>,<peer-addr>,<peer-port>,<secret>` — a downstream LNS.
  Repeatable. accel-ppp brings up one persistent outbound tunnel per
  target at startup and reconnects automatically if it drops.
- `match=<attr-name>,<mode>,<value>,<target-name>` — routes calls to one
  target based on the value of one L2TP AVP. Repeatable; several rules
  may point at the same target.
  - `<attr-name>` — the AVP to match against, by its name in this
    build's AVP dictionary (`Calling-Number`, `Called-Number`,
    `Sub-Address`, `Proxy-Authen-Name`, ...). Must be a string-typed
    AVP.
  - `<mode>` — `exact` (the AVP's value must equal `<value>` exactly)
    or `prefix` (the AVP's value must start with `<value>`; useful for
    routing on a realm/prefix baked into a proxied username, e.g.
    `Proxy-Authen-Name,prefix,downstream-,downstream` matches any
    username starting with `downstream-`). Matching is case-sensitive.
  - Rules are checked whenever the named AVP is available: Calling-Number
    and Called-Number arrive in the incoming call's ICRQ, so those rules
    are evaluated at ICRQ time; Proxy-Authen-Name only arrives in ICCN,
    so rules on it are evaluated then instead — after any ICRQ-time
    match has already had a chance to apply. A call already assigned a
    target by an ICRQ-time rule is not re-evaluated at ICCN time.
  - Two rules on the same AVP must not overlap: the same `<value>` must
    not appear twice, and no rule's value may be a prefix of (or
    prefixed by) another rule's value — either would make the outcome
    ambiguous for at least one possible call. Config load fails fast on
    any such overlap.

## Runtime management

```
l2tp switch show                                    # list targets, tunnel status, active calls
l2tp switch add <attr-name> <mode> <value> <target>  # add a match rule without a restart
l2tp switch del <attr-name> <mode> <value>           # remove a match rule
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
  relay path, and by the path's own UDP capacity.** Unlike an ordinary PPP
  session (whose data plane runs entirely in-kernel, attached to the
  generic PPP channel), a switched call's bytes are relayed via a
  userspace `splice(2)` loop on one of triton's worker threads, through
  sockets sized at 4 MiB (`SO_RCVBUF`/`SO_SNDBUF`, forced past the usual
  `net.core.rmem_max`/`wmem_max` default of ~208 KiB via
  `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`) specifically to absorb bursts well
  beyond ordinary call traffic. Measured on a real two-VM setup, one
  switched call, one MK-side sender writing as fast as possible with no
  pacing:
  - Bursts up to at least 2,000 back-to-back 1400-byte writes (2.8 MB) are
    relayed with **zero loss**, and the call stays up.
  - Far larger bursts (tested up to 100,000 writes, 140 MB, requested at
    ~410 MB/s of local write() calls) no longer end the call at all — the
    kernel's UDP receive buffer can still fill faster than the relay
    drains it under a burst this extreme, and the relay's own outbound
    `splice(2)` call can still hit transient `ENOMEM`/`ENOBUFS` under
    real (non-loopback) network pressure, but both are now handled as
    recoverable: excess *received* bytes are simply not there to relay
    (ordinary, silent UDP loss, visible only in `netstat -su`'s
    `Udp: receive buffer errors`), and a transient outbound `ENOMEM`/
    `ENOBUFS` is retried with a short backoff (up to ~1s total) rather
    than immediately disconnecting the call. In the 100 MB/140 MB test
    above, roughly 40% of the burst was actually delivered — the rest
    lost to the receive-side buffer filling faster than the relay could
    drain it — but the call itself survived the entire burst with no
    disconnect and no daemon impact.
  - A large enough *sustained* burst can still eventually exhaust the
    bounded outbound retry budget and disconnect the call (the original,
    intentional safe failure mode — CDN sent, both legs torn down,
    matching "a call ending always tears down its pair" above) — this now
    takes meaningfully more sustained overload to reach than before, not
    a single short spike.

  Ordinary call volumes and realistically network-paced traffic do not
  approach either threshold; a single session sustaining an artificial,
  unpaced burst of many thousands of packets per second is the scenario
  this affects.

  **Before assuming this is the switch's own limit, measure the path's
  actual UDP capacity** — it is very often lower than what the same path
  does over TCP, and that gap is easy to mistake for a software problem.
  On the pair of cloud VMs used to measure the numbers above, a plain
  `iperf3` TCP test reached 9.15 Gbit/s, but UDP on the *same* path
  topped out around 1.2-1.4 Gbit/s — and neither adding parallel UDP
  streams nor the sending host's own CPU explained the ceiling (both
  cores sat mostly idle throughout). A switched call is carried over UDP
  end to end, so it can never exceed whatever a plain UDP test between
  the same two hosts already shows — no amount of tuning on this
  feature's own side changes that ceiling if it's set by the path
  itself. Run all four of these (`mpstat` needs `sysstat` installed):

  ```bash
  # on the downstream LNS
  iperf3 -s -p 5201

  # on the switch host, in one shell -- NOT through the switch itself
  iperf3 -c <downstream-lns-ip> -p 5201 -t 10                        # TCP baseline
  iperf3 -c <downstream-lns-ip> -p 5201 -u -b 0 -t 10 -l 1400         # UDP, uncapped
  iperf3 -c <downstream-lns-ip> -p 5201 -u -b 0 -P 4 -t 10 -l 1400    # UDP, 4 parallel streams
  iperf3 -c <downstream-lns-ip> -p 5201 -u -b 0 -t 10 -l <path-MTU-safe-max>  # UDP, larger payload

  # in a second shell on the switch host, while the *uncapped single-stream*
  # UDP test above is running:
  mpstat -P ALL 1 8
  ```

  (For the last `iperf3` line, pick a payload as large as the path allows
  without IP fragmentation — `<MTU> - 28` for a plain, non-jumbo path, e.g.
  `1472` for a standard 1500-byte-MTU path; check `ip link show` for the
  outbound interface's actual MTU first. A fragmented payload still gives
  a usable data point, just a noisier one — fragmentation itself adds
  overhead and a small amount of loss, since losing any one fragment
  drops the whole datagram.)

  Read the four results together, in this order:
  1. **UDP far below TCP on the same path** is the first sign of a
     UDP-specific ceiling — expected, not itself conclusive of *why*.
  2. **`mpstat` during the single-stream UDP run** is the most decisive
     signal. If a core is pegged near 100%, the ceiling is CPU/syscall
     overhead on whichever host is generating or receiving the traffic —
     a real, fixable constraint (more CPU, or a more efficient relay). If
     every core stays mostly idle while throughput is already capped,
     CPU is *not* the bottleneck, no matter what the other tests show.
  3. **Parallel streams (`-P 4`) not raising the aggregate** is
     ambiguous on its own — it's also what you'd see on a CPU-bound path
     with only 1-2 cores available, since oversubscribing a small core
     count doesn't multiply throughput either. Only meaningful once read
     together with the `mpstat` result from step 2.
  4. **Throughput scaling up with a larger payload while wire-level
     packets-per-second stays roughly the same** (compute pps from the
     reported datagram count and interval, accounting for fragmentation
     if the payload didn't fit in one IP packet) is the signature of a
     packets-per-second rate limit somewhere in the path, independent of
     both hosts. This is exactly what was measured on the cloud VM pair
     above: ~101,000 pps at a 1400-byte payload and ~1.13 Gbit/s vs.
     ~127,000 wire-level pps (after accounting for fragmentation) at a
     larger payload and ~1.30 Gbit/s — the packet *rate* stayed in the
     same band while the bitrate moved with packet size, and CPU stayed
     idle throughout. That combination points at a PPS-based
     policer/rate-limiter in the network path — a common anti-UDP-flood
     protection at cloud and hosting providers — rather than either
     host's own processing capacity or a raw bandwidth cap. No change to
     this feature, and no amount of additional CPU on either host, moves
     a ceiling enforced outside both of them; the only lever is the
     network path itself (a different route, or asking the provider
     about UDP policing on the account/interface).

  Whichever combination of results you get, treat it as the hard ceiling
  for any one switched call's sustained throughput on that specific path
  — and only reach for a switch-side fix (more `SO_RCVBUF`/`SO_SNDBUF`, a
  less single-threaded relay) once `mpstat` actually shows a host's CPU,
  not the network, as the constraint.
