if (NOT DEFINED KDIR)
	set(KDIR "/usr/src/linux")
endif (NOT DEFINED KDIR)

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/driver/ppposeq.ko
	COMMAND rm -rf ${CMAKE_CURRENT_BINARY_DIR}/driver
	COMMAND mkdir ${CMAKE_CURRENT_BINARY_DIR}/driver
	COMMAND ln -sf ${CMAKE_CURRENT_SOURCE_DIR}/* ${CMAKE_CURRENT_BINARY_DIR}/driver
	COMMAND make -C ${KDIR} M=${CMAKE_CURRENT_BINARY_DIR}/driver modules
	DEPENDS ppposeq.c ppposeq.h
)

ADD_CUSTOM_TARGET(ppposeq_drv ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/driver/ppposeq.ko
)

IF (NOT DEFINED CPACK_TYPE)
	INSTALL(CODE "
		set(KERNEL_BUILD_DIR [==[${KDIR}]==])
		set(KERNEL_MODULE_BUILD_DIR [==[${CMAKE_CURRENT_BINARY_DIR}/driver]==])
		include([==[${CMAKE_SOURCE_DIR}/cmake/install-kernel-module.cmake]==])
	")
ENDIF()
