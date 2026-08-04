IF (CRYPTO STREQUAL INTERNAL OR CRYPTO STREQUAL TOMCRYPT)

SET(sources crypto.c)

IF (CRYPTO STREQUAL INTERNAL)
	FILE(GLOB ltc_sources ${CMAKE_CURRENT_SOURCE_DIR}/libtomcrypt/src/*.c)
	SET(sources ${sources} ${ltc_sources})
ENDIF (CRYPTO STREQUAL INTERNAL)

#
# Built shared on purpose.  register_hash() maintains a process-global
# registry, and find_hash() (used by HMAC) only sees what was registered in
# the same copy of the library.  A static archive would give accel-pppd and
# every dlopen'd module its own registry, so HMAC would fail inside modules.
#
ADD_LIBRARY(internal-crypto SHARED ${sources})

IF (CRYPTO STREQUAL INTERNAL)
	TARGET_INCLUDE_DIRECTORIES(internal-crypto PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}/libtomcrypt/headers
	)
	#
	# The vendored tree is kept byte-identical to upstream, so its
	# configuration cannot live in tomcrypt_custom.h.  Force-include our
	# config header instead: every TU that sees tomcrypt.h must see the
	# same LTC_* defines or hash_state changes size underneath callers.
	#
	# Only the vendored .c files need this; everything else reaches
	# tomcrypt.h through crypto.h, which includes the config header itself.
	TARGET_COMPILE_OPTIONS(internal-crypto PRIVATE
		-include ${CMAKE_CURRENT_SOURCE_DIR}/accel_ltc_config.h
	)
ELSE (CRYPTO STREQUAL INTERNAL)
	TARGET_INCLUDE_DIRECTORIES(internal-crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
	TARGET_LINK_LIBRARIES(internal-crypto tomcrypt)
ENDIF (CRYPTO STREQUAL INTERNAL)

TARGET_LINK_LIBRARIES(internal-crypto pthread)

INSTALL(TARGETS internal-crypto LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)

ENDIF (CRYPTO STREQUAL INTERNAL OR CRYPTO STREQUAL TOMCRYPT)

