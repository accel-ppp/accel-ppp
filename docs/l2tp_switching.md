# L2TP switching

accel-ppp can act as an L2TP switch (RFC 2661 section 5.1) for a configured
subset of incoming calls. Instead of terminating PPP locally, it forwards the
Proxy LCP/Auth AVPs from the incoming call's ICCN to a second, outbound call
toward a downstream LNS and relays the PPP frames between the two tunnels.
PPP negotiation and RADIUS are not used for a switched call.

## Configuration

```
[l2tp-switch]
target=<name>,<peer-addr>,<peer-port>,<secret>[,<mode>]
match=<attr-name>,<mode>,<value>,<target-name>
idle-linger=<seconds>
connect-timeout=<seconds>
reconnect-interval=<seconds>
```

`target=` defines a downstream LNS and may be repeated. Fields are separated
by commas with no escaping, so none may be empty and `name` and `secret`
cannot contain a comma. `name` may contain only letters, digits, `_`, `-`
and `.`, because it is used as a metrics label. A malformed `target=` or
`match=` line is a fatal configuration error. The optional last field is the
mode:

- `on-demand` (default): the tunnel to the target is opened when a call needs
  it and closed after the target has had no active calls for `idle-linger`
  seconds. A call that arrives while the tunnel is connecting is queued, and
  is refused with a CDN if the connect does not finish within
  `connect-timeout` seconds. At most 64 calls are queued per target.
- `persistent`: the tunnel is opened at startup and kept up, with automatic
  reconnect, whether or not any call is using it. Use it only if the
  downstream LNS accepts a tunnel with no sessions.

`idle-linger` is the time in seconds an on-demand tunnel stays open after
its last call ends (default 20). `connect-timeout` is the time in seconds a
call waits for an on-demand tunnel to connect (default 10). `reconnect-interval`
is the delay in seconds between connection attempts to a target whose tunnel
is down (default 5). All three accept 1-3600.

`target=` and `match=` lines are read at startup and are not re-read on
configuration reload. Changing a target's address or secret requires a
restart.

## Match rules

`match=` selects the target for a call from the value of one AVP. It may be
repeated, and several rules may name the same target.

- `attr-name` is the AVP name from the build's AVP dictionary
  (`Calling-Number`, `Called-Number`, `Sub-Address`, `Proxy-Authen-Name`,
  and so on). The AVP must be string-typed.
- `mode` is `exact` or `prefix`. With `prefix` the AVP value must start with
  `value`, which is useful for a realm or prefix in a proxied username:
  `Proxy-Authen-Name,prefix,downstream-,downstream` matches every username
  that begins with `downstream-`. Matching is case-sensitive.

Calling-Number and Called-Number arrive in the ICRQ and are matched then.
Proxy-Authen-Name arrives in the ICCN and is matched then. A call that an
ICRQ rule has already assigned to a target is not matched again at ICCN.

Two rules on the same AVP must not overlap. The same value may not appear
twice, and no value may be a prefix of another. Configuration loading fails
if they do.

## CLI

```
l2tp switch show
l2tp switch add <attr-name> <mode> <value> <target>
l2tp switch del <attr-name> <mode> <value>
```

`show` lists each target with its tunnel status, number of bridged calls and
byte counters, followed by one indented line per active call. `add` and `del`
change match rules at runtime. These changes are not written to the
configuration file.

The status shown in brackets depends on the mode. A persistent target is
`[up]` when its tunnel is established and `[down]` otherwise. An on-demand
target is `[up]` when at least one call is bridged through it, `[connecting]`
while a call waits for the tunnel, and `[idle]` otherwise. `[idle]` covers
both a target that has not been used and one that is waiting out
`idle-linger`.

`bytes_in` and `bytes_out` are from the target's point of view: `in` is
received from the downstream LNS, `out` is sent to it. They are running
totals and do not drop when a call ends.

## Metrics

`accel-cmd show stat` has an `l2tp-switch:` block with `active`,
`lns_rx_bytes` and `lns_tx_bytes`, which are totals to and from the upstream
LAC over all targets. When the `metrics` module is loaded the same values are
available at `/metrics`, in Prometheus or JSON format, together with
per-target values:

- `accel_ppp_l2tp_switch_active` (gauge): active calls.
- `accel_ppp_l2tp_switch_lns_bytes_total{direction="rx"|"tx"}` (counter):
  bytes to and from the upstream LAC.
- `accel_ppp_l2tp_switch_target_up{target="..."}` (gauge): 1 if the target's
  tunnel is established, for both modes. An on-demand target stays at 1
  during `idle-linger`, so `target_up=1` with `target_active=0` means the
  tunnel is open but unused.
- `accel_ppp_l2tp_switch_target_active{target="..."}` (gauge): active calls
  on the target.
- `accel_ppp_l2tp_switch_target_bytes_total{target="...",direction="rx"|"tx"}`
  (counter): bytes to and from the target's LNS.

The metrics have no tunnel ID label, since tunnel IDs change on every
reconnect. The `accel_exporter` tool parses the text output of
`accel-cmd show stat` and does not read the new block.

Switched calls do not appear in `accel-cmd show sessions` and produce no
RADIUS accounting, because no PPP session is created. Use these counters, or
accounting on the downstream LNS, if the traffic has to be billed.

## Authentication

accel-ppp does not authenticate a switched call. The calling client and the
downstream LNS negotiate LCP, authentication and NCP with each other through
the relay.

accel-ppp has a different L2TP role on each leg. Toward the upstream LAC it
is the LNS. Toward the target it is the LAC, which is the side that sends
`Proxy-Authen-*` AVPs when it already holds the client's credentials.

One of the following must be true for the call to authenticate:

1. The upstream LAC relays the client's PAP or CHAP frames through the
   tunnel, without `Proxy-Authen-*` AVPs. The downstream LNS then
   authenticates the client with its normal PAP/CHAP configuration.
2. The upstream LAC sends `Proxy-Authen-Type`, `Proxy-Authen-Name` and
   `Proxy-Authen-Response` (and, for CHAP, `Proxy-Authen-Challenge` and
   `Proxy-Authen-ID`) in the ICCN and never sends a PAP/CHAP exchange.
   accel-ppp copies these AVPs unchanged into the ICCN it sends to the
   target, and the target's LNS must accept them as proof of
   authentication.

If the upstream proxies the credentials and the target expects a live
exchange, the call stays in the authentication phase until the target gives
up on it.

To find out which case applies, check the log. At info level the switch
logs what the target's first LCP Configure-Request asks for: `downstream LCP
Configure-Request asks for PAP`, `asks for CHAP (algorithm 0x..)`, `asks for
authentication protocol 0x....` or `has no authentication-protocol option`.
It logs warnings for `downstream rejected PPP protocol 0x....` and
`downstream sent an LCP Terminate-Request`. If a target's calls show "asks
for PAP" or CHAP and then a Terminate-Request some seconds later, the target
LNS is waiting for a live exchange and needs to be configured to accept
`Proxy-Authen-*` AVPs.

## Operational constraints

- The MRU negotiated upstream is passed to the downstream LNS in the Proxy
  LCP AVPs and is not renegotiated. The path to each downstream LNS needs at
  least as much MTU as the upstream path.
- If the upstream LAC requires data sequencing, the downstream call is
  created with sequencing as well.
- When one leg ends, the other leg is torn down too.
- Data is relayed in userspace with `splice(2)`, so a single switched call
  has a throughput limit. The sockets use 4 MiB buffers, and a call is
  ended with a CDN if the outbound `splice(2)` keeps failing with `ENOMEM`
  or `ENOBUFS` for about a second.
