SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
ADD_DEFINITIONS(-DPTHREAD_SPINLOCK)

include(GNUInstallDirs)

INCLUDE_DIRECTORIES(include)

IF (MEMDEBUG)
	ADD_DEFINITIONS(-DMEMDEBUG)
	IF (VALGRIND)
		ADD_DEFINITIONS(-DVALGRIND)
	ENDIF (VALGRIND)
ENDIF (MEMDEBUG)

IF (SESSIONID_LEN)
	ADD_DEFINITIONS(-DAP_SESSIONID_LEN=${SESSIONID_LEN})
ELSE (SESSIONID_LEN)
	ADD_DEFINITIONS(-DAP_SESSIONID_LEN=16)
ENDIF (SESSIONID_LEN)

#IF (BACKUP)
#	ADD_DEFINITIONS(-DUSE_BACKUP)
#	ADD_SUBDIRECTORY(backup)
#ENDIF (BACKUP)

IF (NOT DEFINED RADIUS)
	SET(RADIUS TRUE)
ENDIF (NOT DEFINED RADIUS)

IF (LUA)
	IF (LUA STREQUAL "TRUE")
		include(FindLua51)
	ELSE ()
		find_package("Lua" ${LUA})
	ENDIF ()
	IF (NOT DEFINED LUA_VERSION_STRING)
		MESSAGE(FATAL_ERROR "lua not found")
	ENDIF ()
	ADD_SUBDIRECTORY(lua)
ENDIF (LUA)

IF (RADIUS)
	ADD_DEFINITIONS(-DRADIUS)
	ADD_SUBDIRECTORY(radius)
ENDIF (RADIUS)

# define __free_fn_t in musl
INCLUDE (CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <stdlib.h>
#include <search.h>
int main(void)
{
	__free_fn_t *f;
	return 0;
}" HAVE_FREE_FN_T)
IF (HAVE_FREE_FN_T)
	ADD_DEFINITIONS(-DHAVE_FREE_FN_T)
ENDIF (HAVE_FREE_FN_T)

INCLUDE (CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <linux/if_arp.h>
#include <net/ethernet.h>
int main(void)
{
	return 0;
}" HAVE_GOOD_IFARP)

IF (HAVE_GOOD_IFARP)
	ADD_DEFINITIONS(-DHAVE_GOOD_IFARP)
ENDIF (HAVE_GOOD_IFARP)

INCLUDE (CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <utmp.h>
int main(void)
{
	logwtmp(\"\", \"\", \"\");
	return 0;
}" HAVE_LOGWTMP)

IF (HAVE_LOGWTMP)
	ADD_DEFINITIONS(-DHAVE_LOGWTMP)
ENDIF (HAVE_LOGWTMP)


ADD_SUBDIRECTORY(triton)
ADD_SUBDIRECTORY(vlan-mon)
ADD_SUBDIRECTORY(ctrl)
ADD_SUBDIRECTORY(auth)
ADD_SUBDIRECTORY(logs)
ADD_SUBDIRECTORY(extra)
ADD_SUBDIRECTORY(ipv6)

IF (NOT DEFINED SHAPER)
	SET(SHAPER TRUE)
ENDIF (NOT DEFINED SHAPER)

IF (SHAPER)
	ADD_SUBDIRECTORY(shaper)
ENDIF (SHAPER)

INCLUDE(CheckIncludeFile)
CHECK_INCLUDE_FILE("linux/netfilter/ipset/ip_set.h" HAVE_IPSET)
# MUSL does not have printf.h
CHECK_INCLUDE_FILE("printf.h" HAVE_PRINTF_H)
IF (HAVE_PRINTF_H)
	ADD_DEFINITIONS(-DHAVE_PRINTF_H)
ENDIF (HAVE_PRINTF_H)


INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(setns HAVE_SETNS)

INCLUDE (CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <linux/if_link.h>
int main(void)
{
	return IFLA_VRF_UNSPEC+IFLA_VRF_TABLE;
}" HAVE_VRF)

ADD_EXECUTABLE(accel-pppd
	memdebug.c
	session.c
	session_backup.c
	ifcfg.c
	net.c

	backup/backup.c

	ppp/ppp.c
	ppp/ppp_fsm.c
	ppp/ppp_lcp.c
	ppp/lcp_opt_mru.c
	ppp/lcp_opt_magic.c
	ppp/lcp_opt_pcomp.c
	ppp/lcp_opt_accomp.c
	ppp/ppp_auth.c
	ppp/ppp_ipcp.c
	ppp/ipcp_opt_ipaddr.c
	ppp/ipcp_opt_dns.c
	ppp/ipcp_opt_wins.c
	ppp/ipv6cp_opt_intfid.c
	ppp/ppp_ipv6cp.c
	ppp/ppp_ccp.c	
	ppp/ccp_mppe.c

	cli/std_cmd.c
	cli/show_sessions.c
	cli/telnet.c
	cli/tcp.c
	cli/cli.c
	
	libnetlink/libnetlink.c
	libnetlink/iputils.c
	libnetlink/genl.c
	libnetlink/ipset.c

	pwdb.c
	ipdb.c

	iprange.c

	utils.c
	rbtree.c

	log.c
	main.c
)

# check if we have getcontext/setcontext
INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(getcontext HAVE_GETCONTEXT)
CHECK_FUNCTION_EXISTS(setcontext HAVE_SETCONTEXT)

IF (HAVE_GETCONTEXT AND HAVE_SETCONTEXT)
	TARGET_LINK_LIBRARIES(accel-pppd triton rt pthread ${crypto_lib} pcre2-8)
ELSE (HAVE_GETCONTEXT AND HAVE_SETCONTEXT)
	TARGET_LINK_LIBRARIES(accel-pppd triton rt pthread ${crypto_lib} pcre2-8 ucontext)
ENDIF (HAVE_GETCONTEXT AND HAVE_SETCONTEXT)

set_property(TARGET accel-pppd PROPERTY CMAKE_SKIP_BUILD_RPATH FALSE)
set_property(TARGET accel-pppd PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET accel-pppd PROPERTY INSTALL_RPATH_USE_LINK_PATH FALSE)
set_property(TARGET accel-pppd PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)

INSTALL(TARGETS accel-pppd
	RUNTIME DESTINATION sbin
)

INSTALL(FILES accel-ppp.conf.5 DESTINATION share/man/man5)

IF (NOT DEFINED CPACK_TYPE)
	INSTALL(FILES accel-ppp.conf DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}" RENAME accel-ppp.conf.dist)

	INSTALL(DIRECTORY DESTINATION "${CMAKE_INSTALL_LOCALSTATEDIR}/log/accel-ppp")
	INSTALL(DIRECTORY DESTINATION "${CMAKE_INSTALL_LOCALSTATEDIR}/lib/accel-ppp")
ENDIF (NOT DEFINED CPACK_TYPE)

