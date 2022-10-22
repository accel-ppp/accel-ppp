INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-address-of-packed-member")

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
TARGET_LINK_LIBRARIES(pppoe vlan-mon)
set_property(TARGET pppoe PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET pppoe PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)

INSTALL(TARGETS pppoe LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)
