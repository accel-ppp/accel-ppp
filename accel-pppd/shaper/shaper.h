#ifndef __SHAPER_H
#define __SHAPER_H

#define LIM_POLICE 0
#define LIM_TBF 1
#define LIM_HTB 2
#define LIM_CLSACT 3

#define LEAF_QDISC_SFQ 1
#define LEAF_QDISC_FQ_CODEL 2

struct rtnl_handle;
struct nlmsghdr;

struct qdisc_opt {
	char *kind;
	int handle;
	int parent;
	double latency;
	int rate;
	int buffer;
	int quantum;
	int defcls;
	int (*qdisc)(struct qdisc_opt *opt, struct nlmsghdr *n);
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

int install_limiter(struct ap_session *ses, int down_speed, int down_burst, int up_speed, int up_burst, int idx);
int remove_limiter(struct ap_session *ses, int idx);
int install_leaf_qdisc(struct rtnl_handle *rth, int ifindex, int parent, int handle);
int init_ifb(const char *);

void leaf_qdisc_parse(const char *);

int tc_qdisc_modify(struct rtnl_handle *rth, int ifindex, int cmd, unsigned flags, struct qdisc_opt *opt);

#endif
