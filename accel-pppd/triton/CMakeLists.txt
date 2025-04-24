SET(sources_c 
	md.c
	timer.c
	triton.c
	conf_file.c
	loader.c
	log.c
	mempool.c
	event.c
)

INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(timerfd_create HAVE_TIMERFD)

IF (HAVE_TIMERFD)
	ADD_DEFINITIONS(-DHAVE_TIMERFD)
ELSE (HAVE_TIMERFD)
	INCLUDE (CheckCSourceCompiles)
	CHECK_C_SOURCE_COMPILES("
	#include <sys/syscall.h>
	int main()
	{
		syscall(SYS_timerfd_create);
	}" HAVE_SYSCALL)
	IF (NOT HAVE_SYSCALL)
		MESSAGE(FATAL_ERROR "Your system is too old and is not supported by accel-ppp, sorry...")
	ENDIF (NOT HAVE_SYSCALL)
	SET(sources_c ${sources_c} timerfd.c)
ENDIF (HAVE_TIMERFD)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

# Note: Use of absolute path in MODULE_PATH makes it non-relocatable
# There are ways to get the path dynamically like https://github.com/gpakosz/whereami
if("${CMAKE_VERSION}" VERSION_LESS "3.7")
	# Before CMake 3.7 GNUInstallDirs_get_absolute_install_dir is not available
	# Try to use best guess
	set(MODULE_PATH "${CMAKE_INSTALL_PREFIX}/${ACCELPPP_INSTALL_LIBDIR}")
else()
	if("${CMAKE_VERSION}" VERSION_LESS "3.20")
		# Before CMake 3.20 GNUInstallDirs_get_absolute_install_dir needed variable dir
		set(dir LIBDIR)
	endif()
	GNUInstallDirs_get_absolute_install_dir(MODULE_PATH ACCELPPP_INSTALL_LIBDIR ${dir})
endif()
ADD_DEFINITIONS(-DMODULE_PATH="${MODULE_PATH}")
# Because this is non-relocatable add a check that the CMAKE_INSTALL_PREFIX was not overwritten
install(CODE [===[
if (DEFINED CACHE{CMAKE_INSTALL_PREFIX})
    message(FATAL_ERROR
        "accel-ppp is not relocatable.\n"
        "Overwriting the install location with `cmake --install --prefix` is not supported.\n"
        "Please re-run the configure/build/install with the CMAKE_INSTALL_PREFIX set to desired location."
        )
endif ()
]===]
)

ADD_LIBRARY(triton SHARED ${sources_c})
TARGET_LINK_LIBRARIES(triton dl)

INSTALL(TARGETS triton
	LIBRARY DESTINATION ${ACCELPPP_INSTALL_LIBDIR}
)
