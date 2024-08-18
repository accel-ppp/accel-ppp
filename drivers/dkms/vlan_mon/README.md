## Building Debian DKMS pacakge

Install deb packages: dkms, debhelper and devscripts. For Debian >= 12 and Ubuntu >=24.04 it is also required to install dh-dkms package.

Build accel-ppp without drivers, then from this level directory, execute:

```
cp ../../../build/version.h src/
debuild -us -uc -tc -b
```
