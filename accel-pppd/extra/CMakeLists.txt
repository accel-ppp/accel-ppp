ADD_LIBRARY(sigchld SHARED sigchld.c)
ADD_LIBRARY(pppd_compat SHARED pppd_compat.c)
TARGET_LINK_LIBRARIES(pppd_compat sigchld)
set_property(TARGET pppd_compat PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)
ADD_LIBRARY(ippool SHARED ippool.c)
ADD_LIBRARY(ipv6pool SHARED ipv6pool.c)
ADD_LIBRARY(chap-secrets SHARED chap-secrets.c)
ADD_LIBRARY(logwtmp SHARED logwtmp.c)
TARGET_LINK_LIBRARIES(logwtmp util)
ADD_LIBRARY(connlimit SHARED connlimit.c)
ADD_LIBRARY(metrics SHARED metrics.c)

INSTALL(TARGETS pppd_compat ippool ipv6pool sigchld chap-secrets logwtmp connlimit metrics
	LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
)

IF (NETSNMP)
	ADD_SUBDIRECTORY(net-snmp)
ENDIF (NETSNMP)
