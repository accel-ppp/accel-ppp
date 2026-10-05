if (NOT DEFINED KERNEL_BUILD_DIR OR KERNEL_BUILD_DIR STREQUAL "")
	message(FATAL_ERROR "Kernel build directory is not set")
endif ()

if (NOT DEFINED KERNEL_MODULE_BUILD_DIR OR
    KERNEL_MODULE_BUILD_DIR STREQUAL "")
	message(FATAL_ERROR "Kernel module build directory is not set")
endif ()

set(_install_command
	make -C "${KERNEL_BUILD_DIR}"
	"M=${KERNEL_MODULE_BUILD_DIR}"
	modules_install
)

# DESTDIR is the conventional CMake staging root.  The kernel build system
# uses INSTALL_MOD_PATH for the same purpose, so propagate it explicitly.
if (NOT "$ENV{DESTDIR}" STREQUAL "")
	list(APPEND _install_command "INSTALL_MOD_PATH=$ENV{DESTDIR}")
endif ()

execute_process(
	COMMAND ${_install_command}
	RESULT_VARIABLE _install_result
)

if (NOT "${_install_result}" STREQUAL "0")
	message(FATAL_ERROR
		"Failed to install kernel module from "
		"${KERNEL_MODULE_BUILD_DIR} (exit status: ${_install_result})"
	)
endif ()

unset(_install_command)
unset(_install_result)
