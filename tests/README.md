# Requirements

These tests are done for Ubuntu and Debian distros. Please use latest stable Debian or Ubuntu to run the tests.

## Preparations

Install pytest

Using apt: `sudo apt install python3-pytest python3-pytest-dependency` or using pip: `sudo pip3 install pytest pytest-dependency`. 

pytest-dependency version must be >= 0.5 (with 'scope' support)

---
Note: tests will be run under sudo. If you prefer install python modules using pip, then do it under sudo as described above.

---

Install additional tools required for tests:
```bash
sudo apt install iproute2 ppp pppoe isc-dhcp-client
```

Then build accel-ppp in 'build' directory (as usual)

Install accel-pppd (make install or use distro package). Do not run accel-pppd using systemd or other supervisors
```bash
mkdir build && cd build
cmake -DBUILD_IPOE_DRIVER=TRUE -DBUILD_VLAN_MON_DRIVER=TRUE -DCMAKE_INSTALL_PREFIX=/usr  -DKDIR=/usr/src/linux-headers-`uname -r`  -DLUA=TRUE -DSHAPER=TRUE -DRADIUS=TRUE -DCPACK_TYPE=Ubuntu20 ..
make
sudo make install # or 
# cpack -G DEB && dpkg -i accel-ppp.deb
```

If you prefer make install, then it is required to insert kernel modules:
```bash
# form root dir
sudo insmod build/drivers/vlan_mon/driver/vlan_mon.ko
sudo insmod build/drivers/ipoe/driver/ipoe.ko
```


## Run tests (without coverage)

```bash
# from this dir (tests)
sudo python3 -m pytest -Wall -v
```

To skip tests related to ipoe and vlan_mon kernel modules:
```bash
# from this dir (tests)
sudo python3 -m pytest -Wall -v -m "not ipoe_driver and not vlan_mon_driver"
```

## Preparations (for coverage report)

Perform preparation steps for running tests  without coverage

Install gcovr

Using apt:
```bash
sudo apt install gcovr
```

Using pip
```bash
sudo pip3 install gcovr
```

```bash
# from root dir
rm -rf build && mkdir build && cd build
cmake -DBUILD_IPOE_DRIVER=TRUE -DBUILD_VLAN_MON_DRIVER=TRUE -DCMAKE_INSTALL_PREFIX=/usr  -DKDIR=/usr/src/linux-headers-`uname -r`  -DLUA=TRUE -DSHAPER=TRUE -DRADIUS=TRUE -DCPACK_TYPE=Ubuntu20 -DCMAKE_C_FLAGS="--coverage -O0" ..
make
sudo make install # or 
# cpack -G DEB && dpkg -i accel-ppp.deb
```

Then insert kernel modules (ipoe.ko and vlan-mon.ko)

## Run tests and generate coverage report

```bash
# from root dir (parent for this dir)
sudo python3 -m pytest -Wall tests -v # execute tests to collect coverage data
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