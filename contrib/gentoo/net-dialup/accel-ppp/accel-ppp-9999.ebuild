# Copyright 1999-2006 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=2

inherit eutils git linux-mod cmake-utils

EGIT_REPO_URI="git://accel-ppp.git.sourceforge.net/gitroot/accel-ppp/accel-ppp"

DESCRIPTION="PPtP/L2TP/PPPoE Server for Linux"
SRC_URI=""
HOMEPAGE="http://accel-ppp.sourceforge.net/"

SLOT="0"
LICENSE="GPL"
KEYWORDS="~amd64 ~x86"
IUSE="postgres debug shaper pptp_driver radius"

DEPEND=">=sys-libs/glibc-2.8
	dev-libs/openssl
	dev-libs/libaio
	shaper? ( =dev-libs/libnl-2* )
	postgres? ( dev-db/postgresql-base )"

RDEPEND="$DEPEND
         pptp_driver? ( virtual/modutils )"

BUILD_TARGETS="default"
BUILD_PARAMS="KDIR=${KERNEL_DIR}"
CONFIG_CHECK="PPP PPPOE"
MODULESD_PPTP_ALIASES=("net-pf-24 pptp")
PREFIX="/"
MODULE_NAMES="pptp(extra:${S}/driver/)"

src_unpack () {
	git_src_unpack
}

src_prepare() {
	sed -i -e "/mkdir/d" "${S}/accel-pppd/CMakeLists.txt"
	sed -i -e "/echo/d" "${S}/accel-pppd/CMakeLists.txt"
	sed -i -e "/INSTALL/d" "${S}/driver/CMakeLists.txt"
}

src_configure() {
	if use debug; then
		mycmakeargs+=( "-DCMAKE_BUILD_TYPE=Debug" )
	fi

	if  use postgres; then
		mycmakeargs+=( "-DLOG_PGSQL_DEPRECATED=TRUE" )
	fi
	
	if use shaper; then
		mycmakeargs+=( "-DSHAPER=TRUE" )
	fi

	if ! use radius; then
		mycmakeargs+=( "-DRADIUS=FALSE" )
	fi

	mycmakeargs+=( "-DCMAKE_INSTALL_PREFIX=/usr" )

	cmake-utils_src_configure
}

src_compile() {
	cmake-utils_src_compile
	
	if use pptp_driver; then
		cd ${S}/driver
		#convert_to_m Makefile
		linux-mod_src_compile || die "failed to build driver"
	fi
}

src_install() {
	cmake-utils_src_install

	if use pptp_driver; then
		cd ${S}/driver
		linux-mod_src_install
	fi

	exeinto /etc/init.d
	newexe "${S}/contrib/gentoo/net-dialup/accel-ppp/files/accel-pppd-init" accel-pppd

	insinto /etc/conf.d
	newins "${S}/contrib/gentoo/net-dialup/accel-ppp/files/accel-pppd-confd" accel-pppd

	dodir /var/log/accel-ppp
	dodir /var/run/accel-ppp
	dodir /var/run/radattr
}
