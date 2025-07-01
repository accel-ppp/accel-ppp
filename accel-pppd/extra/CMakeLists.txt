ADD_LIBRARY(sigchld SHARED sigchld.c)
ADD_LIBRARY(pppd_compat SHARED pppd_compat.c)
TARGET_LINK_LIBRARIES(pppd_compat sigchld)
set_property(TARGET pppd_compat PROPERTY INSTALL_RPATH "$ORIGIN")
ADD_LIBRARY(ippool SHARED ippool.c)
ADD_LIBRARY(ipv6pool SHARED ipv6pool.c)
ADD_LIBRARY(chap-secrets SHARED chap-secrets.c)
ADD_LIBRARY(logwtmp SHARED logwtmp.c)
TARGET_LINK_LIBRARIES(logwtmp util)
ADD_LIBRARY(connlimit SHARED connlimit.c)

INSTALL(TARGETS pppd_compat ippool ipv6pool sigchld chap-secrets logwtmp connlimit
	LIBRARY DESTINATION ${ACCELPPP_INSTALL_LIBDIR}
)

IF (NETSNMP)
	ADD_SUBDIRECTORY(net-snmp)
ENDIF (NETSNMP)
