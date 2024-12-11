#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <linux/genetlink.h>

#include "triton.h"
#include "log.h"
#include "libnetlink.h"

#include "ipoe.h"
#include "if_ipoe.h"

static struct rtnl_handle rth;
static struct triton_md_handler_t mc_hnd;
static interface_mon_notify cb = NULL;

void __export ipoe_netlink_mon_register(interface_mon_notify func)
{
		cb = func;
}

static int ipoe_mc_read_handler(const struct sockaddr_nl *nladdr,
		      struct nlmsghdr *hdr, void *arg)
{
	struct rtattr *tb[IFLA_MAX+1];
	struct ifinfomsg *ifi;
	char ifname[IFNAMSIZ] = {0};

	ifi = NLMSG_DATA(hdr);

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi),
			hdr->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)));

	if (tb[IFLA_IFNAME] && strlen(RTA_DATA(tb[IFLA_IFNAME])) < IFNAMSIZ)
		strncpy(ifname, RTA_DATA(tb[IFLA_IFNAME]), IFNAMSIZ);

	log_debug("ipoe: netlink message RTM_%sLINK for interface %s index %d\n",
			hdr->nlmsg_type == RTM_NEWLINK ? "NEW" : "DEL",
			strlen(ifname) ? ifname : "<unknown>", ifi->ifi_index);

	if (cb && strlen(ifname))
		/* notify ipoe of the event using the callback function */
		cb(ifi->ifi_index, ifname, hdr->nlmsg_type == RTM_NEWLINK);

	return 0;
}

static int ipoe_mc_read(struct triton_md_handler_t *h)
{
	rtnl_listen(&rth, ipoe_mc_read_handler, NULL);

	return 0;
}

static void ipoe_mc_close(struct triton_context_t *ctx)
{
	triton_md_unregister_handler(&mc_hnd, 0);
	triton_context_unregister(ctx);
}

static void ipoe_mc_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	net = def_net;
	log_switch(NULL, NULL);
}

static struct triton_context_t mc_ctx = {
	.close = ipoe_mc_close,
	.before_switch = ipoe_mc_ctx_switch,
};

static struct triton_md_handler_t mc_hnd = {
	.read = ipoe_mc_read,
};

static void init(void)
{
	if (rtnl_open_byproto(&rth, 1 << (RTNLGRP_LINK - 1), NETLINK_ROUTE)) {
		log_error("ipoe: cannot open generic netlink socket\n");
		rth.fd = -1;
		return;
	}

	fcntl(rth.fd, F_SETFL, O_NONBLOCK);
	fcntl(rth.fd, F_SETFD, fcntl(rth.fd, F_GETFD) | FD_CLOEXEC);

	triton_context_register(&mc_ctx, NULL);
	mc_hnd.fd = rth.fd;
	triton_md_register_handler(&mc_ctx, &mc_hnd);
	triton_md_enable_handler(&mc_hnd, MD_MODE_READ);
	triton_context_wakeup(&mc_ctx);
}

DEFINE_INIT(18, init);
