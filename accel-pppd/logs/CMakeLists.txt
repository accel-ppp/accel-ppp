IF(NOT DEFINED LOG_FILE)
	SET(LOG_FILE TRUE)
ENDIF(NOT DEFINED LOG_FILE)

IF(NOT DEFINED LOG_TCP)
	SET(LOG_TCP TRUE)
ENDIF(NOT DEFINED LOG_TCP)

IF(NOT DEFINED LOG_SYSLOG)
	SET(LOG_SYSLOG TRUE)
ENDIF(NOT DEFINED LOG_SYSLOG)


IF(LOG_FILE)
	ADD_LIBRARY(log_file SHARED log_file.c)
	TARGET_LINK_LIBRARIES(log_file rt)
	INSTALL(TARGETS log_file
		LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
	)
ENDIF(LOG_FILE)

IF(LOG_TCP)
	ADD_LIBRARY(log_tcp SHARED log_tcp.c)
	INSTALL(TARGETS log_tcp
		LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
	)
ENDIF(LOG_TCP)

IF(LOG_SYSLOG)
	ADD_LIBRARY(log_syslog SHARED log_syslog.c)
	INSTALL(TARGETS log_syslog
		LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
	)
ENDIF(LOG_SYSLOG)

# log_pgsql is deprecated and scheduled for removal, the build flag was
# renamed so that nobody keeps building it without noticing
IF(LOG_PGSQL)
	message(FATAL_ERROR "${Esc}[31mLOG_PGSQL is deprecated.\n The log_pgsql module is scheduled for removal in a future release.\n Build with -DLOG_PGSQL_DEPRECATED=TRUE if you still need it, and please say so at https://github.com/accel-ppp/accel-ppp/issues so that it is kept${Esc}[m")
ENDIF(LOG_PGSQL)

IF(LOG_PGSQL_DEPRECATED)
	message(WARNING "${Esc}[33mBuilding deprecated module log_pgsql, it is scheduled for removal in a future release.\n Please say so at https://github.com/accel-ppp/accel-ppp/issues if you need it kept${Esc}[m")

	find_library(PGSQL_LIBRARY pq
					HINTS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
					PATHS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
	)
	IF(NOT PGSQL_LIBRARY)
					message(FATAL_ERROR "${Esc}[31mRequired libpq not found.\n Install libpq-dev and run cmake again${Esc}[m")
	ENDIF(NOT PGSQL_LIBRARY)

	ADD_LIBRARY(log_pgsql SHARED log_pgsql.c)
	TARGET_LINK_LIBRARIES(log_pgsql ${PGSQL_LIBRARY})
	INSTALL(TARGETS log_pgsql
		LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
	)
ENDIF(LOG_PGSQL_DEPRECATED)

