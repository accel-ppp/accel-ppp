# Changelog

## 1.15.0 - 2026-10-29

### Deprecations
- `log_pgsql` is deprecated and scheduled for removal. The `LOG_PGSQL` build
  flag now fails the build; build with `LOG_PGSQL_DEPRECATED=TRUE` to keep it
  for now, and the module logs a warning on startup. If you depend on it,
  please object at https://github.com/accel-ppp/accel-ppp/issues, otherwise it
  will be deleted.

### Compatibility
- PPTP: removed the obsolete out-of-tree kernel driver and the
  `BUILD_PPTP_DRIVER` option. The userspace PPTP module remains available;
  use the Linux kernel's PPTP PPPoX support (`CONFIG_PPTP`).
- IP pools: IPv4 and IPv6 pools now use bitmap allocators. Each range is
  limited to 2^24 allocation units (IPv4 addresses or net30 blocks, or IPv6
  prefixes); larger ranges are skipped with an error. The legacy IPv4
  `gw=` range option is deprecated and ignored; use `gw-ip-address` for
  the local PPP address.
- Module API: statistics are exposed through snapshot/getter functions
  instead of writable exported counters, and the Triton reload callback
  signature has changed. External modules using those interfaces need
  adaptation and rebuilding.

### Features
- Metrics: new HTTP `/metrics` endpoint with Prometheus and JSON output,
  an IPv4 CIDR allow-list, read timeouts, and a client limit. Optional
  `sessions=1` adds per-session details to JSON output and is disabled by
  default. Enable `metrics` in `[modules]` and configure `[metrics]` to use it.
- IP pools: reload IPv4 and IPv6 pools without restarting the daemon.
  `reload-orphan=keep|disconnect` controls sessions whose address or prefix
  leaves the configured pools; the default is `keep`.
- SSTP: optional PPPoSEQ kernel transport avoids userspace HDLC framing.
  Build and install it with `BUILD_PPPOSEQ_DRIVER=TRUE`. At startup,
  `[sstp] ppp-mode=auto` selects it when available and otherwise uses async
  PPP; `seqpacket` and `async` select the transport explicitly.
- IPv6: per-session DNS servers from RADIUS `DNS-Server-IPv6-Address`
  attributes (RFC 6911), used by Router Advertisements and DHCPv6.
  Assigned servers replace `[ipv6-dns]` defaults for that session.
  Removed the three-server configuration limit; advertised lists remain
  bounded by packet capacity.
- CLI: IPv6 support for TCP and Telnet listeners.
- RADIUS: optional `framed-route-strict=1` rejects IPv4 routes with host
  bits set in the destination prefix. The default remains permissive.
- IPoE: bulk cleanup of stale session interfaces after daemon restarts,
  with a fallback for older kernel modules, and support for removing
  session interfaces with `ip link del`.

### Fixes
- CLI: fix millisecond timeout conversion in accel-cmd so `1500ms` means
  1.5 seconds, as documented, instead of 1.0005 seconds.
- RADIUS: verify response authenticators against the request and secret
  actually sent before delivering replies or updating server health.
  Fix outbound Message-Authenticator calculation on retransmission and
  accounting request signing, including Accounting-On/Off.
- RADIUS: fix request/socket leaks, accounting-stop cleanup, secret reloads,
  route parsing, attribute bounds, and VRF name validation for Access-Accept
  and CoA. Only the literal CoA value `0` removes a VRF; names beginning
  with `0` are treated as interface names.
- PPP: validate control-packet lengths and option boundaries, avoid
  unaligned accesses, and clear reused packet buffers. Fix unit descriptor
  cleanup races and unit-cache locking.
- PPP: keep optional IPv6 termination from ending the whole session;
  defer IPCP/IPV6CP acknowledgements while CCP negotiates instead of
  sending premature TermAck responses. Correct default IPv6 interface-ID
  byte order on little-endian hosts.
- PPPoE: validate discovery tag lengths, duplicate Service-Name tags,
  and missing Service-Name handling. Fix tag-copy bounds, discovery
  buffer allocation and movement, and MAC-filter reload use-after-free.
- DHCPv6 / IPv6: validate option sizes, Rapid-Commit and AFTR-Name semantics,
  relay nesting, and reply capacity. Fix configuration parsing, IPv6
  host-bit masks, and Router Advertisement prefix buffer bounds.
- IPoE: fix DHCPv4 option and classless-route decoding, prefix/netmask
  validation, relay/username leaks, stale-session enumeration, driver
  locking, and operation with IPv6 disabled.
- SSTP: fix async PPP escape/FCS buffer bounds, drain queued PPP writes,
  flush output on disconnect, validate packet header sizes, and send
  standard HTTP error responses without a body.
- PPTP: fix partial control writes, short-message handling, peer call-ID
  byte order, socket error cleanup, and bind validation. Make
  `echo-failure=0` explicitly disable failure-based termination.
- L2TP: validate decrypted hidden AVP lengths and use alignment-safe
  attribute access.
- Logging / core: bound log lines and PostgreSQL log headers, avoid an
  unwanted general file target, preserve the CHAP challenge name on reload,
  and reject concurrent configuration reloads. Fix unaligned accesses in
  memory debugging and session backup restoration.
- Net-SNMP: fix ASN_INTEGER scalar sizes. Fix VRF netlink handle leaks and
  VLAN monitoring packet-handler registration on Linux 6.6 and newer.
- Build / install: install kernel modules from their actual build
  directories, honor `DESTDIR`, and propagate installation failures.
- Packaging: include the optional PPPoSEQ kernel module in Debian and RPM
  installation rules, including standalone driver packages.

### Docs
- Refreshed the README and synchronized the sample configuration and man
  page, including metrics, pool reloads, SSTP transport, and IPv6 DNS.
- Added contribution guidelines and a safeguard integration review.
- Corrected RADIUS option examples, shaper units and directions, kernel
  module requirements, metrics freshness guidance, and the accel-cmd
  timeout synopsis. Updated test setup instructions.

### Tests / CI
- Added focused suites for DHCPv6, RADIUS, VRF, LCP, memory pools, logging,
  L2TP, IPv6 DNS, and bitmap allocation. Updated the DHCPv6 safeguard fixture
  for shared DNS storage and bounded replies, and run all six standalone
  safeguard suites in sanitizer CI.
- Added metrics, IPoE stale-interface cleanup and link deletion, PPPoE
  negotiation, and kernel-module installation regression coverage.
- Added Ubuntu 26.04 coverage and removed Debian 11 jobs. Continue testing
  32-bit and big-endian platforms and ASan/UBSan builds. Fix test-interface
  MAC races, big-endian VM setup flakes, and coverage counter handling.
- L2TP switching (RFC 2661 section 5.1): selected incoming calls are relayed to a downstream LNS instead of being terminated locally. Targets and match rules (Calling-Number, Called-Number or proxied username) are set in the new `[l2tp-switch]` section and managed with `l2tp switch show|add|del`. See docs/l2tp_switching.md.

## 1.14.0 - 2026-01-24

### Breaking / Compatibility
- Crypto: removed bundled tomcrypt; OpenSSL-only builds.
- Regex: migrated from libpcre to libpcre2.
- Build: raised minimum CMake version (3.10+).
- Build: MUSL detection and conditional linking; additional Entware/Gentoo compatibility fixes.

### Features
- CLI: new `show ippool` command.
- RADIUS: Message-Authenticator blast attack protection.
- RADIUS: Framed-Interface-Id support in `radattr`.
- SSTP: load certificate chain (not just single cert).
- PPPoE/IPoE/L2TP/SSTP: multiple protocol improvements (see fixes).

### Fixes
- PPPoE: RFC2516 tag parsing compliance; ignore vendor-specific tags in PADR; missing break fix.
- PPPoE: additional RFC2516 PADI tag parsing fixes.
- PPP LCP: truncate echo reply when larger than client MRU.
- L2TP: fix buffer overflow and Calling/Called Number handling; include calling number in Calling-Station-ID.
- IPoE: DHCP noauth username fix; DHCP option 42 fix; kernel 6.12 driver fixes.
- IPoE: build fixes for newer kernels (NETIF_F_NETNS_LOCAL, del_timer/timer_delete, flowi4_tos).
- IPv6: DHCPv6 Confirm support; RFC6334 AFTR-Name support.
- Accounting: preserve last counters on disconnect.
- RADIUS: refresh session stats in req_set_stat; restrict DM/CoA sources.
- Logging: fix log_tcp memory leak.
- Shaper: TBF leaf-qdisc support and clsact policer support; tbf leaf-qdisc fix.
- Misc: GCC14/musl/big-endian build fixes; net-snmp 5.9.4+ compatibility; connlimit/pptp fix; post_msg bug fix; SSTP HTTP replay handling fix.

### Docs
- Expanded documentation for PPPoE/IPoE/SSTP/L2TP/PPP/RADIUS/IPPools, certs, proxy protocol.

### Tests / CI
- Added asan/ubsan runs, 32-bit and big-endian test jobs, and broader distro coverage; expanded pytest coverage.
- New or updated CI targets: Ubuntu 24.04 default runner, Fedora rawhide, Debian 13, Ubuntu devel, Gentoo, Alpine (including s390x), plus KVM speedups.
- Removed/disabled outdated or flaky jobs and tests (Ubuntu 20, Debian 10, Alpine chap-secrets); added more pcre/pppoe/ipoe test coverage.
