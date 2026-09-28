/* Exercise the shared interface lookup and length-delimited VRF API. */
#include <assert.h>
#include <pthread.h>
#include "triton.h"
#undef DEFINE_INIT
#undef __init
#define __init
#define DEFINE_INIT(o, f)
#include "../../accel-pppd/net.c"
#include "../../accel-pppd/ifcfg.c"
#define init coa_init
#include "../../accel-pppd/radius/dm_coa.c"
#undef init

static int lookups, changes, last_master;
static char last_name[IFNAMSIZ];
void log_ppp_error(const char *fmt, ...) {}
void log_ppp_info2(const char *fmt, ...) {}

static int lookup(const char *name)
{
	lookups++;
	assert(strlen(name) < IFNAMSIZ);
	strcpy(last_name, name);
	return 7;
}
static int set_vrf(int index, int master)
{
	changes++;
	last_master = master;
	return 0;
}

int main(void)
{
	struct kern_net kn = {0};
	struct ap_net backend = {.get_ifindex = lookup, .set_vrf = set_vrf};
	struct ap_session ses = {.net = &backend};
	struct radius_pd_t rpd = {.ses = &ses};
	char name[IFNAMSIZ + 1];

	net = &kn.net;
	kn.sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(kn.sock >= 0);
	assert(def_get_ifindex("lo") > 0);
	assert(def_get_ifindex(NULL) == -1);
	memset(name, 'x', sizeof(name));
	name[IFNAMSIZ] = 0;
	assert(def_get_ifindex(name) == -1);
	assert(ap_session_vrf(&ses, name, -1) == -1);
	assert(ap_session_vrf(&ses, name, IFNAMSIZ) == -1);
	assert(ap_session_vrf(&ses, NULL, 1) == -1);
	assert(ap_session_vrf(&ses, name, -2) == -1);
	assert(ap_session_vrf(&ses, "a\0b", 3) == -1);
	assert(!lookups && !changes);
	/* Explicit length need not be followed by a NUL in caller memory. */
	assert(!ap_session_vrf(&ses, name, IFNAMSIZ - 1));
	assert(strlen(last_name) == IFNAMSIZ - 1 && last_master == 7);
	assert(!ap_session_vrf(&ses, NULL, 0));
	assert(last_master == 0 && !ses.vrf_name);
	assert(!ap_session_vrf(&ses, NULL, -1));
	assert(lookups == 1 && changes == 3);
	assert(!rad_update_vrf(&rpd, "blue\0junk", 9));
	assert(!rad_update_vrf(&rpd, name, IFNAMSIZ));
	assert(rad_update_vrf(&rpd, "0", 1));
	assert(last_master == 0);
	assert(rad_update_vrf(&rpd, "0blue", 5));
	assert(last_master == 7 && !strcmp(last_name, "0blue"));
	close(kn.sock);
	puts("VRF safeguards: PASS");
	return 0;
}
