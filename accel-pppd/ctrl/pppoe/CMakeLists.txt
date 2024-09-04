INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

SET(sources
	pppoe.c
	mac_filter.c
	dpado.c
	cli.c
	disc.c
)

IF (RADIUS)
SET(sources ${sources} tr101.c)
ENDIF(RADIUS)

ADD_LIBRARY(pppoe SHARED ${sources})

IF (RADIUS)
	TARGET_LINK_LIBRARIES(pppoe vlan-mon connlimit radius)
ELSE (RADIUS)
	TARGET_LINK_LIBRARIES(pppoe vlan-mon connlimit)
ENDIF (RADIUS)

set_property(TARGET pppoe PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET pppoe PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)

INSTALL(TARGETS pppoe LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)
