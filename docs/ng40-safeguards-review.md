# Additional safeguards from accel-ppp-ng PR #40

Compared against freshly fetched accel-ppp `upstream/master` at
`c414f0a7` (2026-09-07). Reference:
[accel-ppp-ng PR #40](https://github.com/accel-ppp/accel-ppp-ng/pull/40/commits),
base `c7b67eb010a99ceefe13d2f74fc672cb91ce0af9`, head
`3843773f15af477c39a326720ac5f3e713b373fb`.

The reference contains 20 commits. Several reported vulnerabilities already
have independent upstream fixes by Denys Fedoryshchenko. This branch adds the
remaining safeguards while retaining upstream's existing parsing and policy.

## What was missing

- PPPoE rejected missing Service-Name tags but accepted duplicates. A matching
  earlier tag could validate a different final selection. Require exactly one
  tag. Preserve silent rejection before cookie validation; no error response
  is sent for an unauthenticated request.
- DHCPv6 accepted duplicate/nonempty Rapid-Commit options and emitted one
  response option per occurrence. Reject malformed requests and emit at most
  one Rapid-Commit. AFTR printing was already bounded, but parsing did not
  validate the uncompressed, terminated DNS name or reject duplicate AFTR
  options. Add those checks and an eight-layer relay nesting limit.
- DHCPv6 reply bounds were measured from a moving inner-message pointer.
  Bound relay headers and both option allocators by the actual 4096-byte
  allocation, including the inner header. Propagate allocation failures
  through both reply builders, status insertion, and ORO expansion; discard
  an incomplete reply. Encode Relay-Message length in network byte order,
  excluding its option header, so valid relayed replies remain usable.
- RADIUS accepted replies based only on the identifier. Verify the Response
  Authenticator using the request's wire authenticator and secret snapshot
  before updating server health, releasing the request slot, or invoking its
  callback. Use constant-time comparison. This is independent of the existing
  outbound Message-Authenticator/`blast-protection` setting.
- Accounting signing did not preserve its computed Request Authenticator.
  Centralize signing after server selection and delay updates, zero the
  authenticator before each hash, and retain the result and signing secret.
  This covers Start/Interim/Stop and Accounting-On/Off, including retransmits
  with `acct-delay-time` disabled. Snapshot Access-Request secrets too; use
  that snapshot for PAP encryption and MPPE decryption, refresh it on server
  changes, and zero Message-Authenticator before each retransmit calculation.
- Accel-VRF-Name could reach an unbounded interface-name copy. Reject oversized
  and embedded-NUL Access-Accept values and handle allocation failure. Enforce
  the same boundary at interface lookup and the length-delimited session API.
  Preserve the CoA attribute length instead of silently accepting a prefix
  before NUL. Only the literal CoA value `0` removes the VRF; names such as
  `0blue` are now treated as interface names. Empty names and `(NULL, 0)` still
  select the default VRF.
- LCP already bounded received packets and mandatory fields, but an Echo-Request
  larger than the peer's MTU produced a truncated response with the old length
  field. Discard it before modifying the packet or echo state.
- Normal pooled allocations retained their former contents after free. Clear
  the payload before returning it to the pool as defense in depth. This adds a
  write proportional to object size; it does not replace protocol bounds checks.
  The separate MEMDEBUG allocator is unchanged.

## Reference commit coverage

Reference hashes link to the original authors' commits. “Present” identifies
upstream code already providing the relevant safeguard, not necessarily an
identical patch.

| Reference commit | Topic | Upstream baseline and this branch |
| --- | --- | --- |
| [ef7323fd](https://github.com/accel-ppp/accel-ppp-ng/commit/ef7323fd6dfe5655a46581733c86f4abcbfee548) | T8464 Service-Name | Missing-name rejection present (`f8dfbeca`, `4deb615d`); add duplicate rejection. |
| [371e7f0a](https://github.com/accel-ppp/accel-ppp-ng/commit/371e7f0a3e21d3040941330858274e104f1dfdcd) | T8473 Rapid-Commit | Add parser checks and single response option. |
| [10a3e72d](https://github.com/accel-ppp/accel-ppp-ng/commit/10a3e72d523c7fe910a23febe979a3de9cd55d8f) | T8474 AFTR | Printer bounds present (`3004db8b`); add parser semantics and duplicate checks. |
| [bd1806e7](https://github.com/accel-ppp/accel-ppp-ng/commit/bd1806e74baff0ef9b6a24a1a73741f8b7ca5125) | T8475 relay layers | Inner bounds/progress present (`b0e7444c`, `a9bfcdb8`, `94993558`); add depth and physical reply bounds, including caller failure handling. |
| [248e7caa](https://github.com/accel-ppp/accel-ppp-ng/commit/248e7caa2cf5c2e1fcaad60abedd7ccfc6365d3b) | T8526 response authentication | Add verification with upstream's OpenSSL API and reload-safe secret ownership. |
| [7ce6244f](https://github.com/accel-ppp/accel-ppp-ng/commit/7ce6244f044f10650adadfcb34e8b6f095a8967b) | T8543 Framed-Route | Present (`a4c79494`, `027bff94`); retain configurable strictness. |
| [be2f54db](https://github.com/accel-ppp/accel-ppp-ng/commit/be2f54dbf8272d6bdd3da1c98c7d9838b95dc27b) | T8545 accounting RA | Add shared zero/hash/save signing. |
| [24afb859](https://github.com/accel-ppp/accel-ppp-ng/commit/24afb859e0a28a509d930a6cf9bea1d8f5baf732) | T8549 status printing | Present (`6019e1d1`, `52a01730`). |
| [2fa64759](https://github.com/accel-ppp/accel-ppp-ng/commit/2fa647594e9d2c64e2f75e3e1537a748e5568d73) | T8550 SSTP lengths | Present (`1719b4ab`). |
| [55a804af](https://github.com/accel-ppp/accel-ppp-ng/commit/55a804afaaddd671fbb58290977a59c03369ab5e) | T8611 VRF | Add Access-Accept, CoA, session API, and shared lookup safeguards. |
| [c93b3675](https://github.com/accel-ppp/accel-ppp-ng/commit/c93b36755c285ef05400fa7be34f7560f02fe2e3) | T8825 tag copy | Present (`c32518d7`); no duplicate port. |
| [1a42ab40](https://github.com/accel-ppp/accel-ppp-ng/commit/1a42ab408da86acde9292120835bd76eb82e8809) | T8830 PPP lengths/pool clear | Packet bounds present (`028b942d`, `d22666a8`); add pool payload clearing. |
| [1957e7d1](https://github.com/accel-ppp/accel-ppp-ng/commit/1957e7d1c131b65768f9fc4b3881e5fdb544f159) | T8830 LCP fields/Echo | Mandatory-field access checks present (`028b942d`); add Echo MTU rejection. |
| [64311652](https://github.com/accel-ppp/accel-ppp-ng/commit/64311652003f719a16cecbb1d5be71af02f57370) | T8545 Accounting-On/Off | Use shared signing; callback UAF already fixed by `7bd6843c`. |
| [01baa010](https://github.com/accel-ppp/accel-ppp-ng/commit/01baa010a45b01ff067405646da89411fd2cc02a) | T8464 cookie ordering | Upstream silently rejects malformed Service-Name; preserve that safe behavior. |
| [8305387d](https://github.com/accel-ppp/accel-ppp-ng/commit/8305387d80c7a5009988106702b23c6eeca8f57a) | T8825 tag fixup | Existing capacity check protects the write; no duplicate port. |
| [f52607d4](https://github.com/accel-ppp/accel-ppp-ng/commit/f52607d4ae216e7d84d7bdacd8581a136248b3e2) | T8545 EVP cleanup | Upstream uses stack MD5 contexts; no EVP allocation to free here. |
| [177238b1](https://github.com/accel-ppp/accel-ppp-ng/commit/177238b1799456510d56637eaa210d62eedef353) | T8611 allocation failure | Include VRF allocation failure handling. |
| [2f18c76d](https://github.com/accel-ppp/accel-ppp-ng/commit/2f18c76d92eef9d09805146847ee690234371963) | T8550 cast fixup | SSTP safeguard already present. |
| [3843773f](https://github.com/accel-ppp/accel-ppp-ng/commit/3843773f15af477c39a326720ac5f3e713b373fb) | T8474 log indentation | New parser log follows upstream style; no standalone cosmetic port. |

## Credits

Original safeguard patches: **Ritika Chopra** `<r.chopra@vyos.io>`.
The tag fixup `8305387d` is authored as **RC** `<ritika0313@gmail.com>` and
carries the original trailer
`Co-authored-by: Copilot Autofix powered by AI <175728472+Copilot@users.noreply.github.com>`.
That fixup is already covered upstream and was not copied into this branch.
Adaptations retain Ritika's credit in their commit messages. Existing upstream
fixes and this integration are by **Denys Fedoryshchenko**.

## Validation

Run from the repository root:

```sh
cmake -S . -B /tmp/accel-ppp-ng40-build -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE
cmake --build /tmp/accel-ppp-ng40-build -j 8
sh tests/unit/run_safeguards.sh /tmp/accel-ppp-ng40-build
git diff --check
```

Build, the existing IPv6 DNS selection test, and five standalone suites passed. Tests compile production code with
small external-service stubs. DHCPv6, RADIUS, VRF, and pool tests use ASan,
UBSan, and LeakSanitizer; the LCP test uses UBSan (ASan's global registration
otherwise retains the entire daemon's layer table). No sanitizer failures.
The VRF harness emits an unused-path compiler warning about the uninitialized
namespace configuration in `alloc_net`; that path is not executed.

Covered: duplicate/nonempty Rapid-Commit, valid single Rapid-Commit replies,
malformed/duplicate AFTR, direct and eight-layer replies, excessive nesting,
exact buffer fill and overflow rejection, negative allocation lengths, ORO
expansion exhaustion in both reply builders, response digests for Accept/
Reject/Challenge/Accounting, forged reply rejection before callbacks/health,
valid reply delivery, Message-Authenticator retransmission, accounting digest
recomputation and secret changes,
VRF boundaries/embedded NUL/CoA/default removal, Echo MTU boundaries, and pool
payload clearing on reuse.

Baseline reproductions against `c414f0a7` failed as expected: the duplicate
Rapid-Commit rejection assertion and the forged Access-Accept rejection
assertion. The corresponding patched checks pass.

Limits: these are focused in-process tests, not a complete deployed NAS or
network-namespace session suite. PPPoE duplicate rejection was reviewed against
its real parser and callers but was not exercised over an Ethernet interface.
Live RADIUS server failover, full PAP/MPPE interoperability, and pool-clearing
throughput were not measured. In particular, upstream already sends PAP's
original encrypted password when changing to a server with a different secret;
this branch does not redesign that pre-existing failover behavior.
