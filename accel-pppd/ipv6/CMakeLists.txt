ADD_LIBRARY(ipv6_dhcp SHARED dhcpv6.c dhcpv6_packet.c)
ADD_LIBRARY(ipv6_nd SHARED nd.c)

IF (HAVE_SESSION_HOOKS)
	TARGET_SOURCES(ipv6_dhcp PRIVATE ppp_ipv6layer.c)
	TARGET_SOURCES(ipv6_nd PRIVATE ppp_ipv6layer.c)
ENDIF (HAVE_SESSION_HOOKS)

INSTALL(TARGETS ipv6_dhcp ipv6_nd
	LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
)

