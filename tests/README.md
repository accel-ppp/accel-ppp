# Requirements

These tests are done for Ubuntu and Debian distros. Please use latest stable Debian or Ubuntu to run the tests.

The commands in this guide require CMake/CTest 3.20 or newer, including
`ctest --test-dir`. The standalone kernel-module installation script requires
CMake 3.15 or newer for `cmake --install`. These command requirements are
separate from the project's minimum CMake version of 3.10.

## Focused unit tests

The standalone unit tests compile production callbacks with small test fixtures
and run them with AddressSanitizer and UndefinedBehaviorSanitizer. Pass a configured
CMake build directory and optional test names:

```bash
sh tests/unit/run_safeguards.sh build log_line
```

These tests do not require installed kernel modules or root privileges. The
sanitizer runtime needs an environment that permits its process inspection.

The runner has six suites: `dhcpv6`, `radius`, `vrf`, `lcp`, `mempool`, and
`log_line`. With no names it runs all six:

```bash
sh tests/unit/run_safeguards.sh build
```

The DHCPv6 suite checks bounded DNS replies and failure propagation when
non-truncatable options exhaust reply space. The
[integration validation record](../docs/ng40-safeguards-review.md#validation)
describes results from the revision at which those safeguards were introduced.

## Kernel module installation test

The kernel module installation regression test is rootless and does not need
kernel headers. It uses a fake kernel build tree to verify that `ipoe`,
`vlan_mon`, and `ppposeq` are installed from their actual build directories,
honor `DESTDIR`, and make installation fail when `modules_install` fails.
It also verifies that Debian and CentOS packaging configurations include
`ppposeq.ko` with the standalone driver package name, and omit it when the
build flag is disabled.

Run it through CTest after configuring the project:

```bash
ctest --test-dir build --output-on-failure -R '^kernel-module-install$'
```

It can also be run directly from the repository root:

```bash
sh tests/kernel-module-install/test.sh cmake
```

## Preparations

Install pytest and its plugins from the distribution packages:

```bash
sudo apt install python3-pytest python3-pytest-dependency python3-pytest-order
```

pytest-dependency version must be >= 0.5 (with 'scope' support)

The network/session tests run under sudo, so the plugins must be available to
the system Python interpreter used by `sudo python3`.

Install additional tools required for tests:
```bash
sudo apt install iproute2 ppp pppoe isc-dhcp-client
```

Install the build dependencies described in the project README, including
kernel headers and Lua 5.1 development files (`liblua5.1-0-dev` on Debian and
Ubuntu) for `LUA=TRUE` below. Run these
commands from the repository root.

Install accel-pppd (make install or use distro package). Do not run accel-pppd using systemd or other supervisors
```bash
cmake -S . -B build \
  -DBUILD_IPOE_DRIVER=TRUE -DBUILD_VLAN_MON_DRIVER=TRUE \
  -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc \
  -DCMAKE_INSTALL_LOCALSTATEDIR=/var \
  -DKDIR="/usr/src/linux-headers-$(uname -r)" \
  -DLUA=TRUE -DSHAPER=TRUE -DRADIUS=TRUE
cmake --build build
sudo cmake --install build
```

For a package-based installation on Ubuntu 24.04, configure the matching
package dependencies before building the DEB:

```bash
cmake -S . -B build -DCPACK_TYPE=Ubuntu24
cpack --config build/CPackConfig.cmake -G DEB -B build
sudo dpkg -i build/accel-ppp.deb
```

Use `Ubuntu22`, `Debian12`, or `Debian13` when building for those releases.
Do not use `Ubuntu20` for a newer distribution: it declares dependencies on
older libraries, including `libssl1.1`.

Load the kernel modules from the repository root after either installation method:

```bash
sudo insmod build/drivers/vlan_mon/driver/vlan_mon.ko
sudo insmod build/drivers/ipoe/driver/ipoe.ko
```


## Run tests (without coverage)

```bash
# from this dir (tests)
sudo python3 -m pytest -Wall --order-dependencies -v
```

To skip tests related to ipoe and vlan_mon kernel modules:
```bash
# from this dir (tests)
sudo python3 -m pytest -Wall --order-dependencies -v -m "not ipoe_driver and not vlan_mon_driver"
```

## Preparations (for coverage report)

Perform preparation steps for running tests  without coverage

Install gcovr

Using apt:
```bash
sudo apt install gcovr
```

```bash
# from root dir
cmake -S . -B build \
  -DBUILD_IPOE_DRIVER=TRUE -DBUILD_VLAN_MON_DRIVER=TRUE \
  -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc \
  -DCMAKE_INSTALL_LOCALSTATEDIR=/var \
  -DKDIR="/usr/src/linux-headers-$(uname -r)" \
  -DLUA=TRUE -DSHAPER=TRUE -DRADIUS=TRUE \
  -DCMAKE_C_FLAGS="--coverage -O0"
cmake --build build
sudo cmake --install build
```

Then insert kernel modules (ipoe.ko and vlan-mon.ko)

## Run tests and generate coverage report

```bash
# from root dir (parent for this dir)
sudo python3 -m pytest -Wall --order-dependencies tests -v # execute tests to collect coverage data
mkdir tests/report
gcovr --config=tests/gcovr.conf # default report
gcovr --config=tests/gcovr.conf --csv # csv report
gcovr --config=tests/gcovr.conf --html --html-details --output=tests/report/accel-ppp.html # html reports (most useful)
```

(If `gcovr` command does not exist, use `python3 -m gcovr` instead)

## Remove coverage data

If you want to re-run tests 'from scratch', you may want to remove coverage data. To do this:

```bash
# from root dir (parent for this dir)
sudo gcovr -d # build report and delete
sudo gcovr -d # check that data is deleted (any coverage = 0%)
```
