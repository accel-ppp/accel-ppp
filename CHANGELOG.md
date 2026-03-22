# Changelog

## 1.14.1 - 2026-03-23

### Fixes
- RADIUS: fix use-after-free in request handling.
- RADIUS: fix vendor attribute parsing over-reads.
- RADIUS: fix MS-CHAP2-Success unchecked memcpy (40 bytes).
- RADIUS: fix invalid check after mempool allocation.
- RADIUS: fix mismatched allocator/deallocator types.
- RADIUS: fix invalid integer and date attribute parsing.
- RADIUS: fix buggy Framed-Route parsing and improve error messages.
- RADIUS: fix stop accounting timeout flow and request cleanup.
- PPP: fix uninitialized struct fields.
- PPP: fix TOCTOU race on uc_size (not guarded by mutex).
- PPP: guard LCP logging field reads.
- PPP: defend against possible ppp init failure.
- CLI: clear show sessions cell buffer to avoid stale output.

### Build / Portability
- Replace `linux/if.h` with `net/if.h` includes for broader portability.
- Refactor ARP header includes in arp.c.
- Refactor session free function pointer in l2tp.c (remove `__free_fn_t` ifdef).
- Remove unused `printf.h` include and CMake checks.
- Clean up CMakeLists.txt by removing unused checks.

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
