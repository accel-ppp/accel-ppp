ADD_LIBRARY(shaper SHARED shaper.c adv_shaper.c limiter.c leaf_qdisc.c tc_core.c)

INSTALL(TARGETS shaper
	LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
)

