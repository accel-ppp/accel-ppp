#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utmp.h>

#include "ppp.h"
#include "events.h"
#include "triton.h"
#include "log.h"

#include "memdebug.h"


#ifdef HAVE_LOGWTMP
static void ev_ses_started(struct ap_session *ses)
{
	logwtmp(ses->ifname, ses->username ?: "", ses->ctrl->calling_station_id);
}

static void ev_ses_finished(struct ap_session *ses)
{
	logwtmp(ses->ifname, "", "");
}

static void init(void)
{
	triton_event_register_handler(EV_SES_STARTED, (triton_event_func)ev_ses_started);
	triton_event_register_handler(EV_SES_FINISHED, (triton_event_func)ev_ses_finished);
}
#else
static void init(void)
{
    log_warn("logwtmp is not supported on your platfrom, check libc doc\n");
}
#endif

DEFINE_INIT(200, init);
