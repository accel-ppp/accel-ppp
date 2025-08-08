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
# if MUSL is set then we need to link with the connlimit library
IF (MUSL)
	TARGET_LINK_LIBRARIES(pppoe vlan-mon connlimit)
ELSE (MUSL)
	TARGET_LINK_LIBRARIES(pppoe vlan-mon)
ENDIF (MUSL)
set_property(TARGET pppoe PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET pppoe PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)

INSTALL(TARGETS pppoe LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)
