#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <pthread.h>

#include "triton.h"
#include "events.h"
#include "log.h"
#include "ppp.h"
#include "cli.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "memdebug.h"

#include "shaper.h"
#include "tc_core.h"

#ifndef __BITS_PER_LONG
#define __BITS_PER_LONG (sizeof(long) * 8)
#endif

#define ATTR_UP 1
#define ATTR_DOWN 2

static int conf_verbose = 0;
#ifdef RADIUS
static int conf_attr_down = 11; //Filter-Id
static int conf_attr_up = 11; //Filter-Id
static int conf_vendor = 0;
#endif
double conf_down_burst_factor = 0.1;
double conf_up_burst_factor = 1;
double conf_latency = 0.05;
int conf_mpu = 0;
int conf_mtu = 0;
int conf_quantum = 1500;
int conf_moderate_quantum;
int conf_r2q = 10;
int conf_cburst = 1534;
int conf_ifb_ifindex;
static double conf_multiplier = 1;
int conf_fwmark;

int conf_up_limiter = LIM_POLICE;
int conf_down_limiter = LIM_TBF;

int conf_leaf_qdisc;
int conf_lq_arg1;
int conf_lq_arg2;
int conf_lq_arg3;
int conf_lq_arg4;
int conf_lq_arg5;
int conf_lq_arg6;

static int temp_down_speed;
static int temp_up_speed;

static int dflt_down_speed;
static int dflt_up_speed;

static pthread_rwlock_t shaper_lock = PTHREAD_RWLOCK_INITIALIZER;
static LIST_HEAD(shaper_list);

struct time_range_pd_t;
struct shaper_pd_t {
	struct list_head entry;
	struct ap_session *ses;
	struct ap_private pd;
	int temp_down_speed;
	int temp_up_speed;
	int down_speed;
	int up_speed;
	struct list_head tr_list;
	struct time_range_pd_t *cur_tr;
	int refs;
	int idx;
};

struct time_range_pd_t {
	struct list_head entry;
	int id;
	int down_speed;
	int down_burst;
	int up_speed;
	int up_burst;
	int act;
};

struct time_range_t {
	struct list_head entry;
	int id;
	struct triton_timer_t begin;
	struct triton_timer_t end;
};

static void *pd_key;

static LIST_HEAD(time_range_list);
static int time_range_id = 0;

#define MAX_IDX 65536
static long *idx_map;

static void shaper_ctx_close(struct triton_context_t *);
static struct triton_context_t shaper_ctx = {
	.close = shaper_ctx_close,
	.before_switch = log_switch,
};

static int alloc_idx(int init)
{
	int i, p = 0;

	init %= MAX_IDX;

	pthread_rwlock_wrlock(&shaper_lock);
	if (idx_map[init / __BITS_PER_LONG] & (1 << (init % __BITS_PER_LONG))) {
		i = init / __BITS_PER_LONG;
		p = (init % __BITS_PER_LONG) + 1;
	} else {
		for (i = init / __BITS_PER_LONG; i < MAX_IDX / __BITS_PER_LONG; i++) {
			p = ffs(idx_map[i]);
			if (p)
				break;
		}

		if (!p) {
			for (i = 0; i < init / __BITS_PER_LONG; i++) {
				p = ffs(idx_map[i]);
				if (p)
					break;
			}
		}
	}

	if (p)
		idx_map[i] &= ~(1 << (p - 1));

	pthread_rwlock_unlock(&shaper_lock);

	if (!p)
		return 0;

	return i * __BITS_PER_LONG + p - 1;
}

static void free_idx(int idx)
{
	idx_map[idx / __BITS_PER_LONG] |= 1 << (idx % __BITS_PER_LONG);
}

static struct shaper_pd_t *find_pd(struct ap_session *ses, int create)
{
	struct ap_private *pd;
	struct shaper_pd_t *spd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key) {
			spd = container_of(pd, typeof(*spd), pd);
			return spd;
		}
	}

	if (create) {
		spd = _malloc(sizeof(*spd));
		if (!spd) {
			log_emerg("shaper: out of memory\n");
			return NULL;
		}

		memset(spd, 0, sizeof(*spd));
		spd->ses = ses;
		list_add_tail(&spd->pd.entry, &ses->pd_list);
		spd->pd.key = &pd_key;
		INIT_LIST_HEAD(&spd->tr_list);
		spd->refs = 1;

		pthread_rwlock_wrlock(&shaper_lock);
		list_add_tail(&spd->entry, &shaper_list);
		pthread_rwlock_unlock(&shaper_lock);
		return spd;
	}

	return NULL;
}

static long int parse_integer(const char *str, char **endptr, double *multiplier)
{
	const static struct {
		char suffix;
		double multiplier;
	} table[] = {
		{ 'B', 0.001 },
		{ 'K', 1.0 },
		{ 'M', 1000.0 },
		{ 'G', 10000000.0 }
	};
	long int val;
	int i;

	val = strtol(str, endptr, 10);
	if (multiplier) {
		*multiplier = 1;
		if (endptr && **endptr) {
			char suffix = toupper(**endptr);
			for (i = 0; i < sizeof(table)/sizeof(table[0]); i++) {
				if (table[i].suffix == suffix) {
					*multiplier = table[i].multiplier;
					(*endptr)++;
					break;
				}
			}
		}
	}

	return val;
}

static int parse_string_simple(const char *str, int dir, int *speed, int *burst, int *tr_id)
{
	char *endptr;
	long int val;
	double mult = 1;

	val = parse_integer(str, &endptr, &mult);
	if (*endptr == ',') {
		*tr_id = val;
		val = parse_integer(endptr + 1, &endptr, &mult);
	}

	if (*endptr == '\0' || isblank(*endptr)) {
		*speed = conf_multiplier * mult * val;
		return 0;
	} else if (*endptr == '/' || *endptr == '\\' || *endptr == ':') {
		if (dir == ATTR_DOWN) {
			*speed = conf_multiplier * mult * val;
			return 0;
		} else {
			val = parse_integer(endptr + 1, &endptr, &mult);
			if (*endptr == '\0' || isblank(*endptr)) {
				*speed = conf_multiplier * mult * val;
				return 0;
			}
		}
	}

	return -1;
}

static int parse_string_cisco(const char *str, int dir, int *speed, int *burst, int *tr_id)
{
	long int val;
	unsigned int n1, n2, n3;
	char *str1;

	if (dir == ATTR_DOWN) {
		str1 = strstr(str, "rate-limit output access-group");
		if (str1) {
			val = sscanf(str1, "rate-limit output access-group %i %u %u %u", tr_id, &n1, &n2, &n3);
			if (val == 4) {
				*speed = n1/1000;
				*burst = n2;
			}
			return 0;
		}

		str1 = strstr(str, "rate-limit output");
		if (str1) {
			val = sscanf(str1, "rate-limit output %u %u %u", &n1, &n2, &n3);
			if (val == 3) {
				*speed = n1/1000;
				*burst = n2;
			}
			return 0;
		}
	} else {
		str1 = strstr(str, "rate-limit input access-group");
		if (str1) {
			val = sscanf(str1, "rate-limit input access-group %i %u %u %u", tr_id, &n1, &n2, &n3);
			if (val == 4) {
				*speed = n1/1000;
				*burst = n2;
			}
			return 0;
		}

		str1 = strstr(str, "rate-limit input");
		if (str1) {
			val = sscanf(str1, "rate-limit input %u %u %u", &n1, &n2, &n3);
			if (val == 3) {
				*speed = n1/1000;
				*burst = n2;
			}
			return 0;
		}
	}

	return -1;
}

static int parse_string(const char *str, int dir, int *speed, int *burst, int *tr_id)
{
	int ret;

	ret = parse_string_cisco(str, dir, speed, burst, tr_id);
	if (ret < 0)
		ret = parse_string_simple(str, dir, speed, burst, tr_id);

	return ret;
}

static struct time_range_pd_t *get_tr_pd(struct shaper_pd_t *pd, int id)
{
	struct time_range_pd_t *tr_pd;

	list_for_each_entry(tr_pd, &pd->tr_list, entry) {
		if (tr_pd->id == id) {
			tr_pd->act = 1;
			if (id == time_range_id)
				pd->cur_tr = tr_pd;
			return tr_pd;
		}
	}

	tr_pd = _malloc(sizeof(*tr_pd));
	memset(tr_pd, 0, sizeof(*tr_pd));
	tr_pd->id = id;
	tr_pd->act = 1;

	if (id == time_range_id)
		pd->cur_tr = tr_pd;

	list_add_tail(&tr_pd->entry, &pd->tr_list);

	return tr_pd;
}

static void clear_tr_pd(struct shaper_pd_t *pd)
{
	struct time_range_pd_t *tr_pd;

	while (!list_empty(&pd->tr_list)) {
		tr_pd = list_entry(pd->tr_list.next, typeof(*tr_pd), entry);
		list_del(&tr_pd->entry);
		_free(tr_pd);
	}
}

#ifdef RADIUS
static void clear_old_tr_pd(struct shaper_pd_t *pd)
{
	struct time_range_pd_t *tr_pd;
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, &pd->tr_list) {
		tr_pd = list_entry(pos, typeof(*tr_pd), entry);
		if (!tr_pd->act) {
			list_del(&tr_pd->entry);
			_free(tr_pd);
		}
	}
}

static void parse_attr(struct rad_attr_t *attr, int dir, int *speed, int *burst, int *tr_id)
{
	if (attr->attr->type == ATTR_TYPE_STRING) {
		int vendor = attr->vendor ? attr->vendor->id : 0;
		if (vendor == 9) {
			/* VENDOR_Cisco */
			parse_string_cisco(attr->val.string, dir, speed, burst, tr_id);
		} else if (vendor == 14988 && attr->attr->id == 8) {
			/* VENDOR_Mikrotik && Mikrotik-Rate-Limit */
			dir = (dir == ATTR_DOWN) ? ATTR_UP : ATTR_DOWN;
			parse_string_simple(attr->val.string, dir, speed, burst, tr_id);
		} else
			parse_string(attr->val.string, dir, speed, burst, tr_id);
	} else if (attr->attr->type == ATTR_TYPE_INTEGER)
		*speed = conf_multiplier * attr->val.integer;
}

static int check_radius_attrs(struct shaper_pd_t *pd, struct rad_packet_t *pack)
{
	struct rad_attr_t *attr;
	int down_speed, down_burst;
	int up_speed, up_burst;
	int tr_id;
	struct time_range_pd_t *tr_pd;
	int r = 0;

	list_for_each_entry(tr_pd, &pd->tr_list, entry)
		tr_pd->act = 0;

	pd->cur_tr = NULL;

	list_for_each_entry(attr, &pack->attrs, entry) {
		if (attr->vendor && attr->vendor->id != conf_vendor)
			continue;
		if (!attr->vendor && conf_vendor)
			continue;
		if (attr->attr->id != conf_attr_down && attr->attr->id != conf_attr_up)
			continue;
		r = 1;
		tr_id = 0;
		down_speed = 0;
		down_burst = 0;
		up_speed = 0;
		up_burst = 0;
		if (attr->attr->id == conf_attr_down)
			parse_attr(attr, ATTR_DOWN, &down_speed, &down_burst, &tr_id);
		if (attr->attr->id == conf_attr_up)
			parse_attr(attr, ATTR_UP, &up_speed, &up_burst, &tr_id);
		tr_pd = get_tr_pd(pd, tr_id);
		if (down_speed)
			tr_pd->down_speed = down_speed;
		if (down_burst)
			tr_pd->down_burst = down_burst;
		if (up_speed)
			tr_pd->up_speed = up_speed;
		if (up_burst)
			tr_pd->up_burst = up_burst;
	}

	if (!r)
		return 0;

	if (!pd->cur_tr)
		pd->cur_tr = get_tr_pd(pd, 0);

	clear_old_tr_pd(pd);

	return 1;
}

static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct shaper_pd_t *pd = find_pd(ev->ses, 1);

	if (!pd)
		return;

	check_radius_attrs(pd, ev->reply);
}

static void ev_radius_coa(struct ev_radius_t *ev)
{
	struct shaper_pd_t *pd = find_pd(ev->ses, 0);

	if (!pd) {
		ev->res = -1;
		return;
	}

	if (!check_radius_attrs(pd, ev->request))
		return;

	if (pd->temp_down_speed || pd->temp_up_speed)
		return;

	if (!pd->cur_tr) {
		if (pd->down_speed || pd->up_speed) {
			pd->down_speed = 0;
			pd->up_speed = 0;
			if (conf_verbose)
				log_ppp_info2("shaper: removed shaper\n");
			remove_limiter(ev->ses, pd->idx);
		}
		return;
	}

	if (pd->down_speed != pd->cur_tr->down_speed || pd->up_speed != pd->cur_tr->up_speed) {
		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;

		if (pd->idx && remove_limiter(ev->ses, pd->idx)) {
			ev->res = -1;
			return;
		}

		if (pd->down_speed > 0 || pd->up_speed > 0) {
			if (!pd->idx)
				pd->idx = alloc_idx(pd->ses->ifindex);

			if (install_limiter(ev->ses, pd->cur_tr->down_speed, pd->cur_tr->down_burst, pd->cur_tr->up_speed, pd->cur_tr->up_burst, pd->idx)) {
				ev->res= -1;
				return;
			} else {
				if (conf_verbose)
					log_ppp_info2("shaper: changed shaper %i/%i (Kbit)\n", pd->down_speed, pd->up_speed);
			}
		} else {
			if (conf_verbose)
				log_ppp_info2("shaper: removed shaper\n");
		}
	}
}
#endif

static void ev_shaper(struct ev_shaper_t *ev)
{
	struct shaper_pd_t *pd = find_pd(ev->ses, 1);
	int down_speed = 0, down_burst = 0;
	int up_speed = 0, up_burst = 0;
	int tr_id = 0;
	struct time_range_pd_t *tr_pd;

	if (!pd)
		return;

	parse_string(ev->val, ATTR_DOWN, &down_speed, &down_burst, &tr_id);
	parse_string(ev->val, ATTR_UP, &up_speed, &up_burst, &tr_id);

	tr_pd = get_tr_pd(pd, tr_id);
	tr_pd->down_speed = down_speed;
	tr_pd->down_burst = down_burst;
	tr_pd->up_speed = up_speed;
	tr_pd->up_burst = up_burst;

	if (temp_down_speed || temp_up_speed) {
		pd->temp_down_speed = temp_down_speed;
		pd->temp_up_speed = temp_up_speed;
		pd->down_speed = temp_down_speed;
		pd->up_speed = temp_up_speed;
		down_speed = temp_down_speed;
		up_speed = temp_up_speed;
		down_burst = 0;
		up_burst = 0;
	} else {
		if (!pd->cur_tr)
			return;
		pd->down_speed = down_speed;
		pd->up_speed = up_speed;
	}

	if (!pd->idx)
		pd->idx = alloc_idx(pd->ses->ifindex);

	if (pd->down_speed > 0 || pd->up_speed > 0) {
		if (!install_limiter(ev->ses, down_speed, down_burst, up_speed, up_burst, pd->idx)) {
			if (conf_verbose)
				log_ppp_info2("shaper: installed shaper %i/%i (Kbit)\n", down_speed, up_speed);
		}
	}
}

static void ev_ppp_pre_up(struct ap_session *ses)
{
	int down_speed, down_burst;
	int up_speed, up_burst;
	struct shaper_pd_t *pd = find_pd(ses, 1);

	if (!pd)
		return;

	if (temp_down_speed || temp_up_speed) {
		pd->temp_down_speed = temp_down_speed;
		pd->temp_up_speed = temp_up_speed;
		pd->down_speed = temp_down_speed;
		pd->up_speed = temp_up_speed;
		down_speed = temp_down_speed;
		up_speed = temp_up_speed;
		down_burst = 0;
		up_burst = 0;
	} else if (pd->cur_tr){
		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;
		down_speed = pd->cur_tr->down_speed;
		up_speed = pd->cur_tr->up_speed;
		down_burst = pd->cur_tr->down_burst;
		up_burst = pd->cur_tr->up_burst;
	}
	else if (dflt_down_speed || dflt_up_speed){
		pd->down_speed = dflt_down_speed;
		pd->up_speed = dflt_up_speed;
		down_speed = dflt_down_speed;
		up_speed =  dflt_up_speed;
		down_burst = 0;
		up_burst = 0;
	}
	else return;

	if (!pd->idx)
		pd->idx = alloc_idx(ses->ifindex);

	if (down_speed > 0 || up_speed > 0) {
		if (!install_limiter(ses, down_speed, down_burst, up_speed, up_burst, pd->idx)) {
			if (conf_verbose)
				log_ppp_info2("shaper: installed shaper %i/%i (Kbit)\n", down_speed, up_speed);
		}
	}
}

static void ev_ppp_finishing(struct ap_session *ses)
{
	struct shaper_pd_t *pd = find_pd(ses, 0);

	if (pd) {
		pthread_rwlock_wrlock(&shaper_lock);
		if (pd->idx)
			free_idx(pd->idx);
		list_del(&pd->entry);
		pthread_rwlock_unlock(&shaper_lock);

		list_del(&pd->pd.entry);

		if (pd->down_speed || pd->up_speed)
			remove_limiter(ses, pd->idx);

		if (__sync_sub_and_fetch(&pd->refs, 1) == 0) {
			clear_tr_pd(pd);
			_free(pd);
		} else
			pd->ses = NULL;
	}
}

static void shaper_change_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "shaper change <interface> <value> [temp] - change shaper on specified interface, if temp is set then previous settings may be restored later by 'shaper restore'\r\n");
	cli_send(cli, "shaper change all <value> [temp] - change shaper on all interfaces, if temp is set also new interfaces will have specified shaper value\r\n");
}

static void shaper_change(struct shaper_pd_t *pd)
{
	if (!pd->ses || pd->ses->terminating)
		goto out;

	if (pd->down_speed || pd->up_speed)
		remove_limiter(pd->ses, pd->idx);
	else if (!pd->idx)
		pd->idx = alloc_idx(pd->ses->ifindex);

	if (pd->temp_down_speed || pd->temp_up_speed) {
		pd->down_speed = pd->temp_down_speed;
		pd->up_speed = pd->temp_up_speed;
		install_limiter(pd->ses, pd->temp_down_speed, 0, pd->temp_up_speed, 0, pd->idx);
	} else if (pd->cur_tr->down_speed || pd->cur_tr->up_speed) {
		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;
		install_limiter(pd->ses, pd->cur_tr->down_speed, pd->cur_tr->down_burst, pd->cur_tr->up_speed, pd->cur_tr->up_burst, pd->idx);
	} else {
		pd->down_speed = 0;
		pd->up_speed = 0;
	}

out:
	if (__sync_sub_and_fetch(&pd->refs, 1) == 0) {
		clear_tr_pd(pd);
		_free(pd);
	}
}

static int shaper_change_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	struct shaper_pd_t *pd;
	int down_speed = 0, up_speed = 0, down_burst = 0, up_burst = 0;
	int all = 0, temp = 0, found = 0;
	int tr_id;

	if (f_cnt < 4)
		return CLI_CMD_SYNTAX;

	parse_string_simple(f[3], ATTR_DOWN, &down_speed, &down_burst, &tr_id);
	parse_string_simple(f[3], ATTR_UP, &up_speed, &up_burst, &tr_id);

	//if (down_speed == 0 || up_speed == 0)
	//	return CLI_CMD_INVAL;

	if (!strcmp(f[2], "all"))
		all = 1;

	if (f_cnt == 5) {
		if (strcmp(f[4], "temp"))
			return CLI_CMD_SYNTAX;
		else
			temp = 1;
	}

	if (all && temp) {
		temp_down_speed = down_speed;
		temp_up_speed = up_speed;
	}

	pthread_rwlock_rdlock(&shaper_lock);
	list_for_each_entry(pd, &shaper_list, entry) {
		if (all || !strcmp(f[2], pd->ses->ifname)) {
			if (temp) {
				pd->temp_down_speed = down_speed;
				pd->temp_up_speed = up_speed;
			} else {
				pd->temp_down_speed = 0;
				pd->temp_up_speed = 0;
				if (!pd->cur_tr)
					pd->cur_tr = get_tr_pd(pd, 0);
				pd->cur_tr->down_speed = down_speed;
				pd->cur_tr->down_burst = down_burst;
				pd->cur_tr->up_speed = up_speed;
				pd->cur_tr->up_burst = up_burst;
			}
			__sync_add_and_fetch(&pd->refs, 1);
			triton_context_call(pd->ses->ctrl->ctx, (triton_event_func)shaper_change, pd);
			if (!all) {
				found = 1;
				break;
			}
		}
	}
	pthread_rwlock_unlock(&shaper_lock);

	if (!all && !found)
		cli_send(cli, "not found\r\n");

	return CLI_CMD_OK;
}

static void shaper_restore_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "shaper restore <interface> - restores shaper settings on specified interface made by 'shaper change' command with 'temp' flag\r\n");
	cli_send(cli, "shaper restore all - restores shaper settings on all interfaces made by 'shaper change' command with 'temp' flag\r\n");
}

static void shaper_restore(struct shaper_pd_t *pd)
{
	if (!pd->ses || pd->ses->terminating)
		goto out;

	remove_limiter(pd->ses, pd->idx);

	if (pd->cur_tr) {
		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;
		install_limiter(pd->ses, pd->cur_tr->down_speed, pd->cur_tr->down_burst, pd->cur_tr->up_speed, pd->cur_tr->up_burst, pd->idx);
	} else {
		pd->down_speed = 0;
		pd->up_speed = 0;
	}

out:
	if (__sync_sub_and_fetch(&pd->refs, 1) == 0) {
		clear_tr_pd(pd);
		_free(pd);
	}
}

static int shaper_restore_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	struct shaper_pd_t *pd;
	int all, found = 0;;

	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;

	if (strcmp(f[2], "all"))
		all = 0;
	else
		all = 1;

	pthread_rwlock_rdlock(&shaper_lock);
	if (all) {
		temp_down_speed = 0;
		temp_up_speed = 0;
	}
	list_for_each_entry(pd, &shaper_list, entry) {
		if (!pd->temp_down_speed)
			continue;
		if (all || !strcmp(f[2], pd->ses->ifname)) {
			pd->temp_down_speed = 0;
			pd->temp_up_speed = 0;
			__sync_add_and_fetch(&pd->refs, 1);
			triton_context_call(pd->ses->ctrl->ctx, (triton_event_func)shaper_restore, pd);
			if (!all) {
				found = 1;
				break;
			}
		}
	}
	pthread_rwlock_unlock(&shaper_lock);

	if (!all && !found)
		cli_send(cli, "not found\r\n");

	return CLI_CMD_OK;
}

static void print_rate(struct ap_session *ses, char *buf)
{
	struct shaper_pd_t *pd = find_pd((struct ap_session *)ses, 0);

	if (pd && (pd->down_speed || pd->up_speed))
		sprintf(buf, "%i/%i", pd->down_speed, pd->up_speed);
	else
		*buf = 0;
}

static void shaper_ctx_close(struct triton_context_t *ctx)
{
	struct time_range_t *r;

	while (!list_empty(&time_range_list)) {
		r = list_entry(time_range_list.next, typeof(*r), entry);
		list_del(&r->entry);
		if (r->begin.tpd)
			triton_timer_del(&r->begin);
		if (r->end.tpd)
			triton_timer_del(&r->end);
		_free(r);
	}

	triton_context_unregister(ctx);
}

static void update_shaper_tr(struct shaper_pd_t *pd)
{
	struct time_range_pd_t *tr;

	if (!pd->ses || pd->ses->terminating)
		goto out;

	list_for_each_entry(tr, &pd->tr_list, entry) {
		if (tr->id != time_range_id)
			continue;
		pd->cur_tr = tr;
		break;
	}

	if (pd->temp_down_speed || pd->temp_up_speed)
		goto out;

	if (pd->down_speed || pd->up_speed) {
		if (pd->cur_tr && pd->down_speed == pd->cur_tr->down_speed && pd->up_speed == pd->cur_tr->up_speed)
			goto out;
		remove_limiter(pd->ses, pd->idx);
	}

	if (pd->cur_tr && (pd->cur_tr->down_speed || pd->cur_tr->up_speed)) {
		if (!pd->idx)
			pd->idx = alloc_idx(pd->ses->ifindex);

		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;
		if (!install_limiter(pd->ses, pd->cur_tr->down_speed, pd->cur_tr->down_burst, pd->cur_tr->up_speed, pd->cur_tr->up_burst, pd->idx)) {
			if (conf_verbose)
				log_ppp_info2("shaper: changed shaper %i/%i (Kbit)\n", pd->cur_tr->down_speed, pd->cur_tr->up_speed);
		}
	} else {
		if (conf_verbose)
			log_ppp_info2("shaper: removed shaper\n");
	}

out:
	if (__sync_sub_and_fetch(&pd->refs, 1) == 0) {
		clear_tr_pd(pd);
		_free(pd);
	}
}

static void time_range_begin_timer(struct triton_timer_t *t)
{
	struct time_range_t *tr = container_of(t, typeof(*tr), begin);
	struct shaper_pd_t *pd;

	time_range_id = tr->id;

	log_debug("shaper: time_range_begin_timer: id=%i\n", time_range_id);

	pthread_rwlock_rdlock(&shaper_lock);
	list_for_each_entry(pd, &shaper_list, entry) {
		__sync_add_and_fetch(&pd->refs, 1);
		triton_context_call(pd->ses->ctrl->ctx, (triton_event_func)update_shaper_tr, pd);
	}
	pthread_rwlock_unlock(&shaper_lock);
}

static void time_range_end_timer(struct triton_timer_t *t)
{
	struct shaper_pd_t *pd;

	time_range_id = 0;

	log_debug("shaper: time_range_end_timer\n");

	pthread_rwlock_rdlock(&shaper_lock);
	list_for_each_entry(pd, &shaper_list, entry) {
		__sync_add_and_fetch(&pd->refs, 1);
		triton_context_call(pd->ses->ctrl->ctx, (triton_event_func)update_shaper_tr, pd);
	}
	pthread_rwlock_unlock(&shaper_lock);
}

static struct time_range_t *parse_range(time_t t, const char *val)
{
	char *endptr;
	int id;
	struct tm begin_tm, end_tm;
	struct time_range_t *r;

	if (!val)
		return NULL;

	id = strtol(val, &endptr, 10);
	if (*endptr != ',')
		return NULL;
	if (id <= 0)
		return NULL;

	localtime_r(&t, &begin_tm);
	begin_tm.tm_sec = 0;
	end_tm = begin_tm;

	endptr = strptime(endptr + 1, "%H:%M", &begin_tm);
	if (*endptr != '-')
		return NULL;

	endptr = strptime(endptr + 1, "%H:%M", &end_tm);
	if (*endptr)
		return NULL;

	r = _malloc(sizeof(*r));
	memset(r, 0, sizeof(*r));

	r->id = id;
	r->begin.expire_tv.tv_sec = mktime(&begin_tm);
	r->begin.period = 24 * 60 * 60 * 1000;
	r->begin.expire = time_range_begin_timer;
	r->end.expire_tv.tv_sec = mktime(&end_tm);
	r->end.period = 24 * 60 * 60 * 1000;
	r->end.expire = time_range_end_timer;

	return r;
}

static int parse_dflt_shaper(const char *opt, int *down_speed, int *up_speed)
{
	char *endptr;

	*down_speed = strtol(opt, &endptr, 10);

	if (*endptr != '/'){
		*up_speed = *down_speed;
		return 0;
	}

	opt = endptr + 1;
	*up_speed = strtol(opt, &endptr, 10);
	return 0;
}

static void load_time_ranges(void)
{
	struct conf_sect_t *s = conf_get_section("shaper");
	struct conf_option_t *opt;
	struct time_range_t *r, *r1;
	time_t ts;

	if (!s)
		return;

	time(&ts);

	while (!list_empty(&time_range_list)) {
		r = list_entry(time_range_list.next, typeof(*r), entry);
		list_del(&r->entry);
		if (r->begin.tpd)
			triton_timer_del(&r->begin);
		if (r->end.tpd)
			triton_timer_del(&r->end);
		_free(r);
	}

	list_for_each_entry(opt, &s->items, entry) {
		if (strcmp(opt->name, "time-range"))
			continue;
		r = parse_range(ts, opt->val);
		if (r)
			list_add_tail(&r->entry, &time_range_list);
		else
			log_emerg("shaper: failed to parse time-range '%s'\n", opt->val);
	}

	list_for_each_entry(r, &time_range_list, entry) {
		list_for_each_entry(r1, &time_range_list, entry) {
			if (r->end.expire_tv.tv_sec == r1->begin.expire_tv.tv_sec) {
				r->end.period = 0;
				break;
			}
		}
	}

	list_for_each_entry(r, &time_range_list, entry) {
		if (r->begin.expire_tv.tv_sec > r->end.expire_tv.tv_sec) {
			if (ts >= r->begin.expire_tv.tv_sec || ts <= r->end.expire_tv.tv_sec)
				time_range_begin_timer(&r->begin);
		} else {
			if (ts >= r->begin.expire_tv.tv_sec && ts <= r->end.expire_tv.tv_sec)
				time_range_begin_timer(&r->begin);
		}

		if (r->begin.expire_tv.tv_sec < ts)
			r->begin.expire_tv.tv_sec += 24 * 60 * 60;
		if (r->end.expire_tv.tv_sec < ts)
			r->end.expire_tv.tv_sec += 24 * 60 * 60;

		triton_timer_add(&shaper_ctx, &r->begin, 1);

		if (r->end.period)
			triton_timer_add(&shaper_ctx, &r->end, 1);
	}
}

#ifdef RADIUS
static int parse_attr_opt(const char *opt)
{
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;

	if (conf_vendor)
		vendor = rad_dict_find_vendor_id(conf_vendor);
	else
		vendor = NULL;

	if (conf_vendor) {
		if (vendor)
			attr = rad_dict_find_vendor_attr(vendor, opt);
		else
			attr = NULL;
	}else
		attr = rad_dict_find_attr(opt);

	if (attr)
		return attr->id;

	return atoi(opt);
}

static int parse_vendor_opt(const char *opt)
{
	struct rad_dict_vendor_t *vendor;

	vendor = rad_dict_find_vendor_name(opt);
	if (vendor)
		return vendor->id;

	return atoi(opt);
}
#endif

static void load_config(void)
{
	const char *opt;

#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		opt = conf_get_opt("shaper", "vendor");
		if (opt)
			conf_vendor = parse_vendor_opt(opt);

		opt = conf_get_opt("shaper", "attr");
		if (opt) {
			conf_attr_down = parse_attr_opt(opt);
			conf_attr_up = parse_attr_opt(opt);
		}

		opt = conf_get_opt("shaper", "attr-down");
		if (opt)
			conf_attr_down = parse_attr_opt(opt);

		opt = conf_get_opt("shaper", "attr-up");
		if (opt)
			conf_attr_up = parse_attr_opt(opt);

		if (conf_attr_up <= 0 || conf_attr_down <= 0) {
			log_emerg("shaper: incorrect attribute(s), tbf disabled...\n");
			return;
		}
	}
#endif

	opt = conf_get_opt("shaper", "burst-factor");
	if (opt) {
		conf_down_burst_factor = strtod(opt, NULL);
		conf_up_burst_factor = conf_down_burst_factor * 10;
	}

	opt = conf_get_opt("shaper", "down-burst-factor");
	if (opt)
		conf_down_burst_factor = strtod(opt, NULL);

	opt = conf_get_opt("shaper", "up-burst-factor");
	if (opt)
		conf_up_burst_factor = strtod(opt, NULL);

	opt = conf_get_opt("shaper", "latency");
	if (opt && atoi(opt) > 0)
		conf_latency = (double)atoi(opt) / 1000;

	opt = conf_get_opt("shaper", "mpu");
	if (opt && atoi(opt) >= 0)
		conf_mpu = atoi(opt);

	opt = conf_get_opt("shaper", "mtu");
	if (opt)
		conf_mtu = atoi(opt);
	else
		conf_mtu = 0;

	opt = conf_get_opt("shaper", "r2q");
	if (opt)
		conf_r2q = atoi(opt);
	else
		conf_r2q = 10;

	opt = conf_get_opt("shaper", "quantum");
	if (opt)
		conf_quantum = atoi(opt);
	else
		conf_quantum = 0;

	opt = conf_get_opt("shaper", "moderate-quantum");
	if (opt)
		conf_moderate_quantum = atoi(opt);
	else
		conf_moderate_quantum = 0;

	opt = conf_get_opt("shaper", "cburst");
	if (opt && atoi(opt) >= 0)
		conf_cburst = atoi(opt);

	opt = conf_get_opt("shaper", "up-limiter");
	if (opt) {
		if (!strcmp(opt, "police"))
			conf_up_limiter = LIM_POLICE;
		else if (!strcmp(opt, "htb"))
			conf_up_limiter = LIM_HTB;
		else
			log_error("shaper: unknown upstream limiter '%s'\n", opt);
	}

	opt = conf_get_opt("shaper", "down-limiter");
	if (opt) {
		if (!strcmp(opt, "tbf"))
			conf_down_limiter = LIM_TBF;
		else if (!strcmp(opt, "htb"))
			conf_down_limiter = LIM_HTB;
		else if (!strcmp(opt, "clsact"))
			conf_down_limiter = LIM_CLSACT;
		else
			log_error("shaper: unknown downstream limiter '%s'\n", opt);
	}

	if (conf_up_limiter == LIM_HTB && !conf_ifb_ifindex) {
		log_warn("shaper: requested 'htb' upstream limiter, but no 'ifb' specified, falling back to police...\n");
		conf_up_limiter = LIM_POLICE;
	}

	opt = conf_get_opt("shaper", "leaf-qdisc");
	if (opt)
		leaf_qdisc_parse(opt);
	else
		conf_leaf_qdisc = 0;


	opt = conf_get_opt("shaper", "verbose");
	if (opt && atoi(opt) >= 0)
		conf_verbose = atoi(opt) > 0;

	opt = conf_get_opt("shaper", "rate-multiplier");
	if (opt && atof(opt) > 0)
		conf_multiplier = atof(opt);
	else
		conf_multiplier = 1;

	opt = conf_get_opt("shaper", "fwmark");
	if (opt)
		conf_fwmark = atoi(opt);
	else
		conf_fwmark = 0;

	opt = conf_get_opt("shaper", "rate-limit");
	if (opt)
		parse_dflt_shaper(opt, &dflt_down_speed, &dflt_up_speed);

	triton_context_call(&shaper_ctx, (triton_event_func)load_time_ranges, NULL);
}

static void init(void)
{
	const char *opt;

	tc_core_init();

	idx_map = mmap(NULL, MAX_IDX/8, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	memset(idx_map, 0xff, MAX_IDX/8);
	idx_map[0] &= ~3;

	opt = conf_get_opt("shaper", "ifb");
	if (opt && init_ifb(opt))
		_exit(0);

	triton_context_register(&shaper_ctx, NULL);
	triton_context_wakeup(&shaper_ctx);

	load_config();

#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	}
#endif
	triton_event_register_handler(EV_SES_PRE_UP, (triton_event_func)ev_ppp_pre_up);
	triton_event_register_handler(EV_SES_FINISHING, (triton_event_func)ev_ppp_finishing);
	//triton_event_register_handler(EV_CTRL_FINISHED, (triton_event_func)ev_ctrl_finished);
	triton_event_register_handler(EV_SHAPER, (triton_event_func)ev_shaper);
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	cli_register_simple_cmd2(shaper_change_exec, shaper_change_help, 2, "shaper", "change");
	cli_register_simple_cmd2(shaper_restore_exec, shaper_restore_help, 2, "shaper", "restore");
	cli_show_ses_register("rate-limit", "rate limit down-stream/up-stream (Kbit)", print_rate);
}

DEFINE_INIT(100, init);
