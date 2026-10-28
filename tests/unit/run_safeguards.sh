#!/bin/sh
# Run from any directory, passing a configured CMake build directory.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build=${1:?usage: run_safeguards.sh /path/to/cmake-build [test-name ...]}
shift
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT HUP INT TERM
cd "$root"
names=${*:-"dhcpv6 radius vrf lcp mempool log_line"}
for name in $names; do
	extra=
	# LCP's global layer table retains the whole daemon under ASan; its test
	# checks wire lengths with UBSan. The packet/VRF tests also use ASan.
	if [ "$name" = lcp ]; then extra=-fno-sanitize=address; fi
	set -- "tests/unit/${name}_safeguards_test.c"
	if [ "$name" = dhcpv6 ]; then
		set -- "$@" accel-pppd/ipv6_dns.c
	fi
	${CC:-cc} -O1 -g -Wall -Wno-unused-function -Wno-unused-result -D_GNU_SOURCE -DAP_SESSIONID_LEN=16 \
		-DOPENSSL_API_COMPAT=0x10100000L -fno-strict-aliasing \
		-ffunction-sections -fdata-sections -Wl,--gc-sections \
		-fsanitize=address,undefined -fno-sanitize-recover=all $extra \
		-I "$build" -I accel-pppd -I accel-pppd/include -I accel-pppd/triton \
		-o "$out/$name" "$@" -lcrypto -lpthread
	"$out/$name"
done
