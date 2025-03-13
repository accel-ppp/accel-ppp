#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_skbedit.h>

#include "log.h"
#include "ppp.h"

#include "shaper.h"
#include "tc_core.h"
#include "libnetlink.h"

static int qdisc_tbf(struct qdisc_opt *qopt, struct nlmsghdr *n)
{
	struct tc_tbf_qopt opt;
	__u32 rtab[256];
	int Rcell_log = -1;
	unsigned int linklayer = LINKLAYER_ETHERNET; /* Assume ethernet */
	struct rtattr *tail;

	memset(&opt, 0, sizeof(opt));

	opt.rate.rate = qopt->rate;
	opt.limit = (double)qopt->rate * qopt->latency + qopt->buffer;
	opt.rate.mpu = conf_mpu;
	if (tc_calc_rtable(&opt.rate, rtab, Rcell_log, conf_mtu, linklayer) < 0) {
		log_ppp_error("shaper: failed to calculate rate table.\n");
		return -1;
	}
	opt.buffer = tc_calc_xmittime(opt.rate.rate, qopt->buffer);

	tail = NLMSG_TAIL(n);
	addattr_l(n, TCA_BUF_MAX, TCA_OPTIONS, NULL, 0);
	addattr_l(n, TCA_BUF_MAX, TCA_TBF_PARMS, &opt, sizeof(opt));
	addattr_l(n, TCA_BUF_MAX, TCA_TBF_RTAB, rtab, 1024);
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;

	return 0;
}

static int qdisc_htb_root(struct qdisc_opt *qopt, struct nlmsghdr *n)
{
	struct tc_htb_glob opt;
	struct rtattr *tail;

	memset(&opt,0,sizeof(opt));

	opt.rate2quantum = qopt->quantum;
	opt.version = 3;
	opt.defcls = qopt->defcls;

	tail = NLMSG_TAIL(n);
	addattr_l(n, TCA_BUF_MAX, TCA_OPTIONS, NULL, 0);
	addattr_l(n, TCA_BUF_MAX, TCA_HTB_INIT, &opt, NLMSG_ALIGN(sizeof(opt)));
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

static int qdisc_htb_class(struct qdisc_opt *qopt, struct nlmsghdr *n)
{
	struct tc_htb_opt opt;
	__u32 rtab[256],ctab[256];
	int cell_log=-1,ccell_log = -1;
	unsigned mtu = conf_mtu ? conf_mtu : 1600;
	unsigned int linklayer  = LINKLAYER_ETHERNET; /* Assume ethernet */
	struct rtattr *tail;

	memset(&opt, 0, sizeof(opt));

	opt.rate.rate = qopt->rate;
	opt.rate.mpu = conf_mpu;
	opt.ceil.rate = qopt->rate;
	opt.ceil.mpu = conf_mpu;

	if (tc_calc_rtable(&opt.rate, rtab, cell_log, mtu, linklayer) < 0) {
		log_ppp_error("shaper: failed to calculate rate table.\n");
		return -1;
	}
	opt.buffer = tc_calc_xmittime(opt.rate.rate, qopt->buffer);

	if (tc_calc_rtable(&opt.ceil, ctab, ccell_log, mtu, linklayer) < 0) {
		log_ppp_error("shaper: failed to calculate ceil rate table.\n");
		return -1;
	}
	opt.cbuffer = tc_calc_xmittime(opt.ceil.rate, conf_cburst ? conf_cburst : qopt->buffer);

	if (qopt->quantum)
		opt.quantum = qopt->quantum;
	else if (conf_moderate_quantum) {
		unsigned int q = qopt->rate / conf_r2q;
		if (q < 1500 || q > 200000)
			opt.quantum = q < 1500 ? 1500 : 200000;
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, TCA_BUF_MAX, TCA_OPTIONS, NULL, 0);
	addattr_l(n, TCA_BUF_MAX, TCA_HTB_PARMS, &opt, sizeof(opt));
	addattr_l(n, TCA_BUF_MAX, TCA_HTB_RTAB, rtab, 1024);
	addattr_l(n, TCA_BUF_MAX, TCA_HTB_CTAB, ctab, 1024);
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

int tc_qdisc_modify(struct rtnl_handle *rth, int ifindex, int cmd, unsigned flags, struct qdisc_opt *opt)
{
	struct {
			struct nlmsghdr 	n;
			struct tcmsg 		t;
			char buf[TCA_BUF_MAX];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = cmd;
	req.t.tcm_family = AF_UNSPEC;

	req.t.tcm_ifindex = ifindex;

	if (opt->handle)
		req.t.tcm_handle = opt->handle;

	req.t.tcm_parent = opt->parent;

	if (opt->kind)
		addattr_l(&req.n, sizeof(req), TCA_KIND, opt->kind, strlen(opt->kind) + 1);

	if (opt->qdisc)
		opt->qdisc(opt, &req.n);

 	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, cmd == RTM_DELQDISC) < 0)
		return -1;

	return 0;
}

static int install_police_clsact(struct rtnl_handle *rth, int ifindex, int rate, int burst, int direction)
{
	__u32 rtab[256];
	struct rtattr *tail, *tail1, *tail2, *tail3;
	int Rcell_log = -1;
	int mtu = conf_mtu;
	unsigned int linklayer  = LINKLAYER_ETHERNET; /* Assume ethernet */

	struct {
			struct nlmsghdr 	n;
			struct tcmsg 		t;
			char buf[TCA_BUF_MAX];
	} req;

	struct tc_police police = {
		.action = TC_POLICE_SHOT,
		.rate.rate = rate,
		.rate.mpu = conf_mpu,
		.limit = (double)rate * conf_latency + burst,
		.burst = tc_calc_xmittime(rate, burst),
	};

	if (tc_calc_rtable(&police.rate, rtab, Rcell_log, mtu, linklayer) < 0) {
		log_ppp_error("shaper: failed to calculate ceil rate table.\n");
		return -1;
	}

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWTFILTER;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_ifindex = ifindex;
	req.t.tcm_handle = 0x1;
	req.t.tcm_parent = TC_H_MAKE(TC_H_CLSACT, direction);


	req.t.tcm_info = TC_H_MAKE(100 << 16, ntohs(ETH_P_ALL));

	addattr_l(&req.n, sizeof(req), TCA_KIND, "matchall", 9);

	tail = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_OPTIONS, NULL, 0);

	tail1 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_FW_POLICE, NULL, 0);

	tail2 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, 1, NULL, 0);
	addattr_l(&req.n, MAX_MSG, TCA_ACT_KIND, "police", 7);

	tail3 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_ACT_OPTIONS, NULL, 0);
	addattr_l(&req.n, MAX_MSG, TCA_POLICE_TBF, &police, sizeof(police));
	addattr_l(&req.n, MAX_MSG, TCA_POLICE_RATE, rtab, 1024);
	tail3->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail3;

	tail2->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail2;

	tail1->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail1;

	tail->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail;

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		return -1;

	return 0;
}

static int install_clsact(struct rtnl_handle *rth, int ifindex, int rate, int burst)
{
	struct qdisc_opt opt = {
		.kind = "clsact",
		.handle = TC_H_MAKE(TC_H_CLSACT, 0),
		.parent = TC_H_CLSACT,
	};

	if (tc_qdisc_modify(rth, ifindex, RTM_NEWQDISC, NLM_F_EXCL|NLM_F_CREATE, &opt)) {
		return -1;
	}

	return install_police_clsact(rth, ifindex, rate, burst, TC_H_MIN_EGRESS);
}

static int install_tbf(struct rtnl_handle *rth, int ifindex, int rate, int burst)
{
	struct qdisc_opt opt = {
		.kind = "tbf",
		.handle = 0x00010000,
		.parent = TC_H_ROOT,
		.rate = rate,
		.buffer = burst,
		.latency = conf_latency,
		.qdisc = qdisc_tbf,
	};

	return tc_qdisc_modify(rth, ifindex, RTM_NEWQDISC, NLM_F_EXCL|NLM_F_CREATE, &opt);
}

static int install_htb(struct rtnl_handle *rth, int ifindex, int rate, int burst)
{
	struct qdisc_opt opt1 = {
		.kind = "htb",
		.handle = 0x00010000,
		.parent = TC_H_ROOT,
		.quantum = conf_r2q,
		.defcls = 1,
		.qdisc = qdisc_htb_root,
	};

	struct qdisc_opt opt2 = {
		.kind = "htb",
		.handle = 0x00010001,
		.parent = 0x00010000,
		.rate = rate,
		.buffer = burst,
		.quantum = conf_quantum,
		.qdisc = qdisc_htb_class,
	};


	if (tc_qdisc_modify(rth, ifindex, RTM_NEWQDISC, NLM_F_EXCL|NLM_F_CREATE, &opt1))
		return -1;

	if (tc_qdisc_modify(rth, ifindex, RTM_NEWTCLASS, NLM_F_EXCL|NLM_F_CREATE, &opt2))
		return -1;

	return 0;
}

static int install_police(struct rtnl_handle *rth, int ifindex, int rate, int burst)
{
	__u32 rtab[256];
	struct rtattr *tail, *tail1, *tail2, *tail3;
	int Rcell_log = -1;
	int mtu = conf_mtu, flowid = 1;
	unsigned int linklayer  = LINKLAYER_ETHERNET; /* Assume ethernet */

	struct {
			struct nlmsghdr 	n;
			struct tcmsg 		t;
			char buf[TCA_BUF_MAX];
	} req;

	struct qdisc_opt opt1 = {
		.kind = "ingress",
		.handle = 0xffff0000,
		.parent = TC_H_INGRESS,
	};

	struct sel {
		struct tc_u32_sel sel;
		struct tc_u32_key key;
	} sel = {
		.sel.nkeys = 1,
		.sel.flags = TC_U32_TERMINAL,
//		.key.off = 12,
	};

	struct tc_police police = {
		.action = TC_POLICE_SHOT,
		.rate.rate = rate,
		.rate.mpu = conf_mpu,
		.limit = (double)rate * conf_latency + burst,
		.burst = tc_calc_xmittime(rate, burst),
	};

	if (tc_qdisc_modify(rth, ifindex, RTM_NEWQDISC, NLM_F_EXCL|NLM_F_CREATE, &opt1))
		return -1;

	if (tc_calc_rtable(&police.rate, rtab, Rcell_log, mtu, linklayer) < 0) {
		log_ppp_error("shaper: failed to calculate ceil rate table.\n");
		return -1;
	}

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWTFILTER;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_ifindex = ifindex;
	req.t.tcm_handle = 1;
	req.t.tcm_parent = 0xffff0000;

	req.t.tcm_info = TC_H_MAKE(100 << 16, ntohs(ETH_P_ALL));

	addattr_l(&req.n, sizeof(req), TCA_KIND, "u32", 4);

	tail = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_OPTIONS, NULL, 0);

	tail1 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_U32_ACT, NULL, 0);

	tail2 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, 1, NULL, 0);
	addattr_l(&req.n, MAX_MSG, TCA_ACT_KIND, "police", 7);

	tail3 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_ACT_OPTIONS, NULL, 0);
	addattr_l(&req.n, MAX_MSG, TCA_POLICE_TBF, &police, sizeof(police));
	addattr_l(&req.n, MAX_MSG, TCA_POLICE_RATE, rtab, 1024);
	tail3->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail3;

	tail2->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail2;

	tail1->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail1;

	addattr_l(&req.n, MAX_MSG, TCA_U32_CLASSID, &flowid, 4);
	addattr_l(&req.n, MAX_MSG, TCA_U32_SEL, &sel, sizeof(sel));
	tail->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail;

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		return -1;

	return 0;
}

static int install_htb_ifb(struct rtnl_handle *rth, int ifindex, __u32 priority, int rate, int burst)
{
	struct rtattr *tail, *tail1, *tail2, *tail3;

	struct {
			struct nlmsghdr 	n;
			struct tcmsg 		t;
			char buf[TCA_BUF_MAX];
	} req;

	struct qdisc_opt opt1 = {
		.kind = "htb",
		.handle = 0x00010000 + priority,
		.parent = 0x00010000,
		.rate = rate,
		.buffer = burst,
		.quantum = conf_quantum,
		.qdisc = qdisc_htb_class,
	};

	struct qdisc_opt opt2 = {
		.kind = "ingress",
		.handle = 0xffff0000,
		.parent = TC_H_INGRESS,
	};

	struct sel {
		struct tc_u32_sel sel;
		struct tc_u32_key key;
	} sel = {
		.sel.nkeys = 1,
		.sel.flags = TC_U32_TERMINAL,
		.key.off = 0,
	};

	struct tc_skbedit p1 = {
		.action = TC_ACT_PIPE,
	};

	struct tc_mirred p2 = {
		.eaction = TCA_EGRESS_REDIR,
		.action = TC_ACT_STOLEN,
		.ifindex = conf_ifb_ifindex,
	};

	if (tc_qdisc_modify(rth, conf_ifb_ifindex, RTM_NEWTCLASS, NLM_F_EXCL|NLM_F_CREATE, &opt1))
		return -1;

	if (tc_qdisc_modify(rth, ifindex, RTM_NEWQDISC, NLM_F_EXCL|NLM_F_CREATE, &opt2))
		return -1;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWTFILTER;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_ifindex = ifindex;
	req.t.tcm_handle = 1;
	req.t.tcm_parent = 0xffff0000;

	req.t.tcm_info = TC_H_MAKE(100 << 16, ntohs(ETH_P_ALL));


	addattr_l(&req.n, sizeof(req), TCA_KIND, "u32", 4);

	tail = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_OPTIONS, NULL, 0);

	tail1 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_U32_ACT, NULL, 0);

	// action skbedit priority X pipe
	tail2 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, 1, NULL, 0);
	addattr_l(&req.n, MAX_MSG, TCA_ACT_KIND, "skbedit", 8);

	tail3 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_ACT_OPTIONS, NULL, 0);
	addattr_l(&req.n, MAX_MSG, TCA_SKBEDIT_PARMS, &p1, sizeof(p1));
	priority--;
	addattr_l(&req.n, MAX_MSG, TCA_SKBEDIT_PRIORITY, &priority, sizeof(priority));
	tail3->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail3;

	tail2->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail2;

	tail1->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail1;

	// action mirred egress redirect dev ifb0
	tail2 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, 2, NULL, 0);
	addattr_l(&req.n, MAX_MSG, TCA_ACT_KIND, "mirred", 7);

	tail3 = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, MAX_MSG, TCA_ACT_OPTIONS, NULL, 0);
	addattr_l(&req.n, MAX_MSG, TCA_MIRRED_PARMS, &p2, sizeof(p2));
	tail3->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail3;

	tail2->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail2;

	tail1->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail1;
  //

	addattr32(&req.n, TCA_BUF_MAX, TCA_U32_CLASSID, 1);
	addattr_l(&req.n, MAX_MSG, TCA_U32_SEL, &sel, sizeof(sel));
	tail->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail;

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		return -1;

	return 0;
}

static int install_fwmark(struct rtnl_handle *rth, int ifindex, int parent)
{
	struct rtattr *tail;

	struct {
			struct nlmsghdr 	n;
			struct tcmsg 		t;
			char buf[1024];
	} req;

	memset(&req, 0, sizeof(req) - 1024);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWTFILTER;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_ifindex = ifindex;
	req.t.tcm_handle = conf_fwmark;
	req.t.tcm_parent = parent;
	req.t.tcm_info = TC_H_MAKE(90 << 16, ntohs(ETH_P_ALL));

	addattr_l(&req.n, sizeof(req), TCA_KIND, "fw", 3);
	tail = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, TCA_BUF_MAX, TCA_OPTIONS, NULL, 0);
	addattr32(&req.n, TCA_BUF_MAX, TCA_FW_CLASSID, TC_H_MAKE(1 << 16, 0));
	tail->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail;
	return rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0);
}

static int remove_root(struct rtnl_handle *rth, int ifindex)
{
	struct qdisc_opt opt = {
		.handle = 0x00010000,
		.parent = TC_H_ROOT,
	};

	return tc_qdisc_modify(rth, ifindex, RTM_DELQDISC, 0, &opt);
}

static int remove_ingress(struct rtnl_handle *rth, int ifindex)
{
	struct qdisc_opt opt = {
		.handle = 0xffff0000,
		.parent = TC_H_INGRESS,
	};

	return tc_qdisc_modify(rth, ifindex, RTM_DELQDISC, 0, &opt);
}

static int remove_htb_ifb(struct rtnl_handle *rth, int ifindex, int priority)
{
	struct qdisc_opt opt = {
		.handle = 0x00010000 + priority,
		.parent = 0x00010000,
	};

	return tc_qdisc_modify(rth, conf_ifb_ifindex, RTM_DELTCLASS, 0, &opt);
}

int install_limiter(struct ap_session *ses, int down_speed, int down_burst, int up_speed, int up_burst, int idx)
{
	struct rtnl_handle *rth = net->rtnl_get();
	int r = 0;

	if (!rth) {
		log_ppp_error("shaper: cannot open rtnetlink\n");
		return -1;
	}

	if (down_speed) {
		down_speed = down_speed * 1000 / 8;
		down_burst = down_burst ? down_burst : conf_down_burst_factor * down_speed;

		if (conf_down_limiter == LIM_TBF) {
			r = install_tbf(rth, ses->ifindex, down_speed, down_burst);
			if (r == 0)
				r = install_leaf_qdisc(rth, ses->ifindex, 0x00010000, 0x00020000);
		} else if (conf_down_limiter == LIM_CLSACT)
			r = install_clsact(rth, ses->ifindex, down_speed, down_burst);
		else {
			r = install_htb(rth, ses->ifindex, down_speed, down_burst);
			if (r == 0)
				r = install_leaf_qdisc(rth, ses->ifindex, 0x00010001, 0x00020000);
		}
	}

	if (up_speed) {
		up_speed = up_speed * 1000 / 8;
		up_burst = up_burst ? up_burst : conf_up_burst_factor * up_speed;

		if (conf_up_limiter == LIM_POLICE) {
			/* if clsact is used for down_limiter then normal policer doesn't work, use clsact version */
			if (conf_down_limiter == LIM_CLSACT && down_speed)
				r = install_police_clsact(rth, ses->ifindex, up_speed, up_burst, TC_H_MIN_INGRESS);
			else
				r = install_police(rth, ses->ifindex, up_speed, up_burst);
		} else {
			r = install_htb_ifb(rth, ses->ifindex, idx, up_speed, up_burst);
			if (r == 0)
				r = install_leaf_qdisc(rth, conf_ifb_ifindex, 0x00010000 + idx, idx << 16);
		}
	}

	if (conf_fwmark) {
		if (conf_down_limiter == LIM_CLSACT)
			install_fwmark(rth, ses->ifindex, TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS));
		else
			install_fwmark(rth, ses->ifindex, 0x00010000);
	}

	net->rtnl_put(rth);

	return r;
}

int remove_limiter(struct ap_session *ses, int idx)
{
	struct rtnl_handle *rth = net->rtnl_get();

	if (!rth) {
		log_ppp_error("shaper: cannot open rtnetlink\n");
		return -1;
	}

	remove_root(rth, ses->ifindex);
	remove_ingress(rth, ses->ifindex);

	if (conf_up_limiter == LIM_HTB)
		remove_htb_ifb(rth, ses->ifindex, idx);

	net->rtnl_put(rth);

	return 0;
}

int init_ifb(const char *name)
{
	struct rtnl_handle rth;
	struct rtattr *tail;
	struct ifreq ifr;
	int r;
	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

	struct {
			struct nlmsghdr 	n;
			struct tcmsg 		t;
			char buf[TCA_BUF_MAX];
	} req;

	struct qdisc_opt opt = {
		.kind = "htb",
		.handle = 0x00010000,
		.parent = TC_H_ROOT,
		.quantum = conf_r2q,
		.qdisc = qdisc_htb_root,
	};

	if (system("modprobe -q ifb"))
		log_warn("failed to load ifb kernel module\n");

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, name);

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_emerg("shaper: ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
		close(sock_fd);
		return -1;
	}

	conf_ifb_ifindex = ifr.ifr_ifindex;

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr)) {
		log_emerg("shaper: ioctl(SIOCSIFINDEX): %s\n", strerror(errno));
		close(sock_fd);
		return -1;
	}

	if (rtnl_open(&rth, 0)) {
		log_emerg("shaper: cannot open rtnetlink\n");
		close(sock_fd);
		return -1;
	}

	tc_qdisc_modify(&rth, conf_ifb_ifindex, RTM_DELQDISC, 0, &opt);

	r = tc_qdisc_modify(&rth, conf_ifb_ifindex, RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, &opt);
	if (r)
		goto out;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWTFILTER;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_ifindex = conf_ifb_ifindex;
	req.t.tcm_handle = 1;
	req.t.tcm_parent = 0x00010000;
	req.t.tcm_info = TC_H_MAKE(100 << 16, ntohs(ETH_P_ALL));

	addattr_l(&req.n, sizeof(req), TCA_KIND, "flow", 5);

	tail = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, TCA_BUF_MAX, TCA_OPTIONS, NULL, 0);
	addattr32(&req.n, TCA_BUF_MAX, TCA_FLOW_KEYS, 1 << FLOW_KEY_PRIORITY);
	addattr32(&req.n, TCA_BUF_MAX, TCA_FLOW_MODE, FLOW_MODE_MAP);
	tail->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)tail;

	r = rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL, 0);

out:
	rtnl_close(&rth);
	close(sock_fd);

	return r;
}
