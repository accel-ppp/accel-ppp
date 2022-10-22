INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-address-of-packed-member")

SET(sources
	ipoe.c
	dhcpv4.c
	dhcpv4_options.c
	ipoe_netlink.c
#	backup.c
	arp.c
)

IF (LUA)
	INCLUDE_DIRECTORIES(${LUA_INCLUDE_DIR})
	ADD_DEFINITIONS(-DUSE_LUA)
	SET(sources ${sources} lua.c)
ENDIF (LUA)

ADD_LIBRARY(ipoe SHARED ${sources})

IF (LUA)
	TARGET_LINK_LIBRARIES(ipoe luasupp)
ENDIF(LUA)

TARGET_LINK_LIBRARIES(ipoe vlan-mon)

set_property(TARGET ipoe PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET ipoe PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)

INSTALL(TARGETS ipoe LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)
