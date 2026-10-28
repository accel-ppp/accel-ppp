#!/bin/sh

set -eu

cmake_command=${1:-cmake}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "${script_dir}/../.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "${work_dir}"' EXIT HUP INT TERM

"${cmake_command}" \
	-S "${source_dir}" \
	-B "${work_dir}/build" \
	-DBUILD_TESTING=OFF \
	-DBUILD_DRIVER_ONLY=TRUE \
	-DBUILD_IPOE_DRIVER=TRUE \
	-DBUILD_VLAN_MON_DRIVER=TRUE \
	-DBUILD_PPPOSEQ_DRIVER=TRUE \
	-DIGNORE_GIT=TRUE \
	-DKDIR="${script_dir}"

"${cmake_command}" --build "${work_dir}/build" --parallel 2

DESTDIR="${work_dir}/stage" \
	"${cmake_command}" --install "${work_dir}/build"

test -f "${work_dir}/stage/lib/modules/test-kernel/extra/ipoe.ko"
test -f "${work_dir}/stage/lib/modules/test-kernel/extra/vlan_mon.ko"
test -f "${work_dir}/stage/lib/modules/test-kernel/extra/ppposeq.ko"

if FAIL_MODULES_INSTALL=1 DESTDIR="${work_dir}/failed-stage" \
	"${cmake_command}" --install "${work_dir}/build" \
	>"${work_dir}/failed-install.log" 2>&1; then
	printf '%s\n' 'kernel module installation unexpectedly succeeded' >&2
	exit 1
fi

grep -q 'Failed to install kernel module' "${work_dir}/failed-install.log"

# Packaging configurations bypass modules_install and must install the .ko
# explicitly, including when PPPoSEQ is built as a standalone driver package.
for package_type in Debian12 Centos9; do
	package_build="${work_dir}/package-${package_type}"
	package_stage="${work_dir}/stage-${package_type}"
	"${cmake_command}" \
		-S "${source_dir}" \
		-B "${package_build}" \
		-DBUILD_TESTING=OFF \
		-DBUILD_DRIVER_ONLY=TRUE \
		-DBUILD_PPPOSEQ_DRIVER=TRUE \
		-DIGNORE_GIT=TRUE \
		-DCPACK_TYPE="${package_type}" \
		-DMODULES_KDIR=test-kernel \
		-DCENTOS_KDIR=test-kernel \
		-DKDIR="${script_dir}"
	"${cmake_command}" --build "${package_build}"
	DESTDIR="${package_stage}" \
		"${cmake_command}" --install "${package_build}"
	test -f "${package_stage}/lib/modules/test-kernel/extra/ppposeq.ko"
	grep -q 'set(CPACK_PACKAGE_NAME "accel-ppp-ppposeq-kmod")' \
		"${package_build}/CPackConfig.cmake"

	# A stale build artifact must not be installed after the flag is disabled.
	"${cmake_command}" -S "${source_dir}" -B "${package_build}" \
		-DBUILD_PPPOSEQ_DRIVER=FALSE
	DESTDIR="${package_stage}-disabled" \
		"${cmake_command}" --install "${package_build}"
	test ! -e "${package_stage}-disabled/lib/modules/test-kernel/extra/ppposeq.ko"
done
