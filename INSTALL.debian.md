To build deb package


```
git clone https://github.com/accel-ppp/accel-ppp.git
mkdir accel-ppp-build
cd accel-ppp-build
cmake -DBUILD_DRIVER=TRUE -DCMAKE_INSTALL_PREFIX=/usr ../accel-ppp
cmake --build .
cpack -G DEB
```
