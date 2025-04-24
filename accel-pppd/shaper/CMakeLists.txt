ADD_LIBRARY(shaper SHARED shaper.c limiter.c leaf_qdisc.c tc_core.c)

INSTALL(TARGETS shaper
	LIBRARY DESTINATION ${ACCELPPP_INSTALL_LIBDIR}
)

