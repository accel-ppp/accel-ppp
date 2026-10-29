SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -D_GNU_SOURCE")

ADD_DEFINITIONS(-DACCEL_PPP_VERSION="${ACCEL_PPP_VERSION}")

ADD_EXECUTABLE(accel-cmd
	accel_cmd.c
)

if (BUILD_TESTING)
	add_executable(accel-cmd-timeout-test accel_cmd_test.c)
	add_test(NAME accel-cmd-timeout COMMAND accel-cmd-timeout-test)
endif ()

INSTALL(TARGETS accel-cmd
	RUNTIME DESTINATION bin
)
INSTALL(FILES accel-cmd.1
	DESTINATION share/man/man1
)
