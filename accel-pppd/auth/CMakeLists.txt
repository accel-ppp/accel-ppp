ADD_LIBRARY(auth_pap SHARED auth_pap.c)
ADD_LIBRARY(auth_chap_md5 SHARED auth_chap_md5.c)
ADD_LIBRARY(auth_mschap_v1 SHARED auth_mschap_v1.c)
ADD_LIBRARY(auth_mschap_v2 SHARED auth_mschap_v2.c)

TARGET_LINK_LIBRARIES(auth_chap_md5 ${crypto_lib})
TARGET_LINK_LIBRARIES(auth_mschap_v1 ${crypto_lib})
TARGET_LINK_LIBRARIES(auth_mschap_v2 ${crypto_lib})

INSTALL(TARGETS auth_pap auth_chap_md5 auth_mschap_v1 auth_mschap_v2
	LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
)
