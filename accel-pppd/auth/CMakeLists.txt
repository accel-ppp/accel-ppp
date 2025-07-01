ADD_LIBRARY(auth_pap SHARED auth_pap.c)
ADD_LIBRARY(auth_chap_md5 SHARED auth_chap_md5.c)
ADD_LIBRARY(auth_mschap_v1 SHARED auth_mschap_v1.c)
ADD_LIBRARY(auth_mschap_v2 SHARED auth_mschap_v2.c)

INSTALL(TARGETS auth_pap auth_chap_md5 auth_mschap_v1 auth_mschap_v2
	LIBRARY DESTINATION ${ACCELPPP_INSTALL_LIBDIR}
)

