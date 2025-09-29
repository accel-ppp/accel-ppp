cmake_minimum_required(VERSION 3.5)

if (CMAKE_BINARY_DIR STREQUAL CMAKE_HOME_DIRECTORY)
    message(FATAL_ERROR "Building in source directory is forbidden. Please make separated build directory.")
endif ()

project(accel-ppp C)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fno-strict-aliasing -D_GNU_SOURCE -fPIC -rdynamic -Wno-unused-result")

IF (NOT DEFINED LIB_SUFFIX)
	EXECUTE_PROCESS(
		COMMAND uname -m
		COMMAND tr -d '\n'
		OUTPUT_VARIABLE ARCH
	)
	message(STATUS "'"  ${ARCH}  "'")
	IF (ARCH STREQUAL x86_64)
		SET(LIB_SUFFIX 64)
	ENDIF (ARCH STREQUAL x86_64)
ENDIF (NOT DEFINED LIB_SUFFIX)

# Set flag if we are building with MUSL
IF (CMAKE_SYSTEM_NAME STREQUAL Linux AND CMAKE_C_COMPILER_ID STREQUAL GNU)
    execute_process(
        COMMAND sh -c "ldd --version 2>&1 || true"
        OUTPUT_VARIABLE LDD_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
	if (LDD_VERSION MATCHES "[Mm]usl")
		set(MUSL ON)
	else ()
		set(MUSL OFF)
	endif ()
	message(STATUS "Building with MUSL: ${MUSL}")
ENDIF (CMAKE_SYSTEM_NAME STREQUAL Linux AND CMAKE_C_COMPILER_ID STREQUAL GNU)

#color console example  message(FATAL_ERROR "${Esc}[31m Red Text ${Esc}[m Restore Normal Text")
string(ASCII 27 Esc)

#Check libpcre2
find_library(PCRE2_LIBRARY pcre2-8
	HINTS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
	PATHS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
)

IF(NOT PCRE2_LIBRARY)
	message(FATAL_ERROR "${Esc}[31mRequired libpcre not found.\n Install libpcre2-dev and run cmake again${Esc}[m")
ENDIF(NOT PCRE2_LIBRARY)


IF (EXISTS ${CMAKE_HOME_DIRECTORY}/.git AND NOT IGNORE_GIT)
	EXECUTE_PROCESS(
		COMMAND git describe --tags --always
		WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}
		OUTPUT_VARIABLE ACCEL_PPP_VERSION
	)
	STRING(STRIP "${ACCEL_PPP_VERSION}" ACCEL_PPP_VERSION)
ELSE (EXISTS ${CMAKE_HOME_DIRECTORY}/.git AND NOT IGNORE_GIT)
	SET (ACCEL_PPP_VERSION 1.13.0)
ENDIF (EXISTS ${CMAKE_HOME_DIRECTORY}/.git AND NOT IGNORE_GIT)

# we must include cpack.cmake after generating the ACCEL_PPP_VERSION variable
include(cmake/cpack.cmake)

ADD_DEFINITIONS(-DACCEL_PPP_VERSION="${ACCEL_PPP_VERSION}")
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/version.h)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

if (NOT BUILD_DRIVER_ONLY)
	if (MEMDEBUG)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector -fstack-protector-all")
	endif (MEMDEBUG)

	find_library(CRYPTO_LIBRARY ssl
		HINTS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
		PATHS ${CMAKE_SOURCE_DIR}/lib/linux/gcc/${BIT}/lib
	)
	IF(NOT CRYPTO_LIBRARY)
		message(FATAL_ERROR "${Esc}[31mRequired libcrypto-0.9.8 or probably later (openssl-0.9.8)  not found.\n Install libssl-dev and run cmake again${Esc}[m")
	ENDIF(NOT CRYPTO_LIBRARY)
	add_definitions(-DCRYPTO_OPENSSL)
	set(crypto_lib crypto ssl)

	add_subdirectory(accel-pppd)
	add_subdirectory(accel-cmd)

	install(DIRECTORY DESTINATION /var/log/accel-ppp)
endif (NOT BUILD_DRIVER_ONLY)

if (BUILD_PPTP_DRIVER)
	add_subdirectory(drivers/pptp)
endif (BUILD_PPTP_DRIVER)

if (BUILD_IPOE_DRIVER)
	add_subdirectory(drivers/ipoe)
endif (BUILD_IPOE_DRIVER)

if (BUILD_VLAN_MON_DRIVER)
	add_subdirectory(drivers/vlan_mon)
endif ()

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
