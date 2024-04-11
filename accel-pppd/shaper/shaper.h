#ifndef __SHAPER_H
#define __SHAPER_H

#define LIM_POLICE 0
#define LIM_TBF 1
#define LIM_HTB 2
#define LIM_ADV_SHAPER 3

#define LEAF_QDISC_SFQ 1
#define LEAF_QDISC_FQ_CODEL 2

#define ADV_SHAPER_QDISC_HTB 1
#define ADV_SHAPER_QDISC_TBF 2
#define ADV_SHAPER_QDISC_SFQ 3
#define ADV_SHAPER_QDISC_FQ_CODEL 4
#define ADV_SHAPER_QDISC_INGRESS 5

#define ADV_SHAPER_FILTER_NET     1
#define ADV_SHAPER_FILTER_NET6    2
#define ADV_SHAPER_FILTER_FW      3
#define ADV_SHAPER_FILTER_U32_RAW 4

#define ADV_SHAPER_ACTION_PASS   1
#define ADV_SHAPER_ACTION_POLICE 2

#define ADV_SHAPER_DOWNLOAD 1
#define ADV_SHAPER_UPLOAD   0

//Special values for adv_shaper statements
#define ADV_SHAPER_VAR_STANDARD_SPEED 0
#define ADV_SHAPER_VAR_CALCULATED     0

struct rtnl_handle;
struct nlmsghdr;

struct qdisc_opt {
	char *kind;
	int handle;
	int parent;
	double latency;
	int rate;
	int buffer;
	__u32 cbuffer;
	int quantum;
	int defcls;

	int ceil;
	__u32 limit;
	int perturb;
	__u32 flows;
	__u32 target;
	__u32 interval;
	int ecn;
	int (*qdisc)(struct qdisc_opt *opt, struct nlmsghdr *n);
};

struct action_opt {
	struct list_head entry;
	char *kind;

	int rate;
	int burst;
	__u32 mtu;
	__u32 mpu;

	int action;
	int (*action_prepare)(struct action_opt *opt, struct nlmsghdr *n, int *prio);
};

//TC Action
//-------POLICE---------
//	kind;
//	rate;
//	burst;
//	mtu;
//	mpu;
//	action;
//----------------------
//
//-------PASS-----------
//	action;
//----------------------

struct adv_shaper_action {
	struct list_head entry;

	__u8 isdown;
	__u32 parentid;
	__u32 priority;

	char *kind;

	int rate;
	int burst;
	__u32 mtu;
	__u32 mpu;

	int action;
};

//Qdisc kind (htb, tbf, sfq, etc...)
//Qdisc handle format in config XXXX:XXXX
//Qdisc parent format in config XXXX:XXXX
//---------TBF---------
//	kind;
//	handle;
//	parent;
//	latency;
//	rate;
//---------------------
//
//---------HTB---------
//	kind;
//	handle;
//	parent;
//	buffer;
//	cbuffer;
//	defcls;
//	quantum;
//---------------------
//
//---------SFQ---------
//	kind;
//	handle;
//	parent;
//	perturb;
//	limit;
//	quantum;
//---------------------
//
//------FQ_CODEL-------
//	kind;
//	handle;
//	parent;
//	limit;
//	flows
//	quantum;
//	target;
//	interval;
//	ecn;
//---------------------
//
//-------INGRESS-------
//	kind;
//	handle;
//	parent;
//---------------------


struct adv_shaper_qdisc {
	struct list_head entry;
	//isdown - Is limiter for subscriber download
	__u8 isdown;

	char *kind;
	int handle;
	int parent;

	double latency;
	int rate;

	__u32 cbuffer;
	int defcls;

	int perturb;

	__u32 limit;

	int quantum;
	int buffer;

	__u32 flows;
	__u32 target;
	__u32 interval;
	int ecn;
};

struct adv_shaper_class {
	struct list_head entry;
	//isdown - Is limiter for subscriber download
	__u8 isdown;

	__u32 classid;
	__u32 parentid;
	__u32 rate;
	__u32 ceil;
	__u32 burst;
	__u32 cburst;
};

struct adv_shaper_u32_key {
	__be32 val;
	__be32 mask;
	int off;
	int offmask;
};

struct adv_shaper_filter {
	struct list_head entry;
	//isdown - Is limiter for subscriber download
	__u8 isdown;

	__u32 parentid;
	__u32 classid;
	__u32 priority;

	int key_count;
	struct adv_shaper_u32_key *keys;
//	__be32 val;
//	__be32 mask;
//	int off;
//	int offmask;

	__u32 fwmark;
	int kind;
};

extern int conf_up_limiter;
extern int conf_down_limiter;

extern double conf_down_burst_factor;
extern double conf_up_burst_factor;
extern double conf_latency;
extern int conf_mpu;
extern int conf_mtu;
extern int conf_quantum;
extern int conf_moderate_quantum;
extern int conf_r2q;
extern int conf_cburst;
extern int conf_ifb_ifindex;
extern int conf_fwmark;

extern int conf_leaf_qdisc;
extern int conf_lq_arg1;
extern int conf_lq_arg2;
extern int conf_lq_arg3;
extern int conf_lq_arg4;
extern int conf_lq_arg5;
extern int conf_lq_arg6;

extern pthread_rwlock_t adv_shaper_lock;
extern struct list_head conf_adv_shaper_qdisc_list;
extern struct list_head conf_adv_shaper_class_list;
extern struct list_head conf_adv_shaper_filter_list;
extern struct list_head conf_adv_shaper_action_list;

int install_limiter(struct ap_session *ses, int down_speed, int down_burst, int up_speed, int up_burst, int idx);
int remove_limiter(struct ap_session *ses, int idx);
int install_leaf_qdisc(struct rtnl_handle *rth, int ifindex, int parent, int handle);
int init_ifb(const char *);

void leaf_qdisc_parse(const char *);

int tc_qdisc_modify(struct rtnl_handle *rth, int ifindex, int cmd, unsigned flags, struct qdisc_opt *opt);

void load_advanced_shaper();
#endif
