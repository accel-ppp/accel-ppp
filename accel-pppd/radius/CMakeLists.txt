SET(sources
	stat_accm.c
	dict.c
	req.c
	packet.c
	auth.c
	acct.c
	serv.c
	dm_coa.c
	radius.c
)

IF (BACKUP)
	SET(sources ${sources} backup.c)
ENDIF (BACKUP)

IF (LUA)
	INCLUDE_DIRECTORIES(${LUA_INCLUDE_DIR})
	SET(sources ${sources} lua.c)
ENDIF ()

ADD_DEFINITIONS(-DDICTIONARY="${CMAKE_INSTALL_PREFIX}/share/accel-ppp/radius/dictionary")

ADD_LIBRARY(radius SHARED ${sources})
set_property(TARGET radius PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET radius PROPERTY INSTALL_RPATH "$ORIGIN")

IF (LUA)
	TARGET_LINK_LIBRARIES(radius luasupp)
ENDIF ()

INSTALL(TARGETS radius
	LIBRARY DESTINATION ${ACCELPPP_INSTALL_LIBDIR}
)
FILE(GLOB dict "${CMAKE_CURRENT_SOURCE_DIR}/dict/*")
INSTALL(FILES ${dict} DESTINATION ${ACCELPPP_INSTALL_DATADIR}/radius)
