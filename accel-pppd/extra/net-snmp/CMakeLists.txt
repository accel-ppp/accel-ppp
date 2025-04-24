SET(sources
	agent.c
	sessionTable.c
	sessionTable_data_access.c
	sessionTable_data_get.c
	sessionTable_data_set.c
	sessionTable_interface.c
	statCore.c
	statL2TP.c
	statPPP.c
	statPPPOE.c
	statPPTP.c
	statIPOE.c
	statSSTP.c
	terminate.c
	shutdown.c
	exec_cli.c
)

find_library(SNMP_LIBRARY netsnmp
			 HINTS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
			 PATHS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
)

find_library(SNMPAGENT_LIBRARY netsnmpagent
			 HINTS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
			 PATHS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
)

find_library(SNMPHELPERS_LIBRARY netsnmphelpers
			 HINTS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
			 PATHS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
)

find_library(SNMPMIBS_LIBRARY netsnmpmibs
			 HINTS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
			 PATHS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
)

IF(NOT SNMP_LIBRARY)
	message(FATAL_ERROR "${Esc}[31mRequired snmp libraries not found.\n Install libsnmp-dev and run cmake again${Esc}[m")
ENDIF(NOT SNMP_LIBRARY)
	

ADD_LIBRARY(net-snmp SHARED ${sources})
TARGET_LINK_LIBRARIES(net-snmp ${SNMP_LIBRARY} ${SNMPAGENT_LIBRARY} ${SNMPHELPERS_LIBRARY} ${SNMPMIBS_LIBRARY})

INSTALL(TARGETS net-snmp
	LIBRARY DESTINATION ${ACCELPPP_INSTALL_LIBDIR}
)
