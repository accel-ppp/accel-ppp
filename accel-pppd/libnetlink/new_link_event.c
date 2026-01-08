/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <linux/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "triton.h"
#include "ap_net.h"

#include "new_link_event.h"

static struct rtnl_handle rth;
static struct triton_context_t ctx;
static struct triton_md_handler_t hnd;

LIST_HEAD(nnle_handlers);

static void nnle_emit_callbacks(const char *name, int is_add)
{
	struct nnle_handler_t *e;
	list_for_each_entry(e, &nnle_handlers, entry) {
		if (is_add) {
			e->on_new_link(name);
		} else {
			e->on_del_link(name);
		}
	}
}

static int nnle_nlmsg_handler(const struct sockaddr_nl *nladdr,
		      struct nlmsghdr *hdr)
{
	struct rtattr *tb[IFLA_MAX+1];
	struct ifinfomsg *ifi;
	char ifname[IFNAMSIZ] = {0};

	ifi = NLMSG_DATA(hdr);

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), hdr->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)));

	if (tb[IFLA_IFNAME] && strlen(RTA_DATA(tb[IFLA_IFNAME])) < IFNAMSIZ)
		strncpy(ifname, RTA_DATA(tb[IFLA_IFNAME]), IFNAMSIZ - 1);

	if (hdr->nlmsg_type == RTM_NEWLINK && *(uint32_t *)RTA_DATA(tb[IFLA_OPERSTATE]) == IF_OPER_DOWN) {

		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

		net->sock_ioctl(SIOCGIFFLAGS, &ifr);
		if (ifr.ifr_flags) {
			ifr.ifr_flags |= IFF_UP;
			net->sock_ioctl(SIOCSIFFLAGS, &ifr);
		}
	}

	if (hdr->nlmsg_type == RTM_NEWLINK && *(uint32_t *)RTA_DATA(tb[IFLA_OPERSTATE]) == IF_OPER_UP) {
		nnle_emit_callbacks(ifname, 1);
	} else if (hdr->nlmsg_type == RTM_DELLINK) {
		nnle_emit_callbacks(ifname, 0);
	}

	return 0;
}

static int nnle_read(struct triton_md_handler_t *th)
{
	int status;
	struct nlmsghdr* h;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
	.msg_iovlen = 1,
	};
	char buf[8192];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	for (;;) {
		status = recvmsg(rth.fd, &msg, 0);

		if (status <= 0) {
			if (errno == EINTR || errno == EAGAIN)
				break;
			return -1;
		}

		if (msg.msg_namelen != sizeof(nladdr))
			return -1;

		for (h = (struct nlmsghdr*)buf; status >= sizeof(*h);) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > status)
				return -1;

			err = nnle_nlmsg_handler(&nladdr, h);
			if (err < 0)
				return err;

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
		}

		if (status)
			return -1;
	}

	return 0;
}

static void nnle_close(struct triton_context_t *ctx)
{
	triton_md_disable_handler(&hnd, MD_MODE_READ);
	triton_md_unregister_handler(&hnd, 1);
	triton_context_unregister(ctx);
}

static void nnle_free(struct triton_context_t *ctx)
{
	triton_md_disable_handler(&hnd, MD_MODE_READ);
	triton_md_unregister_handler(&hnd, 1);
	triton_context_unregister(ctx);
}

static void nnle_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	net = def_net;
}

__export void nnle_add_handler(struct nnle_handler_t *h) {
	list_add(&h->entry, &nnle_handlers);
}

__export void nnle_del_handler(struct nnle_handler_t *h) {
	list_del(&h->entry);
}

static void nnle_init()
{
	if (rtnl_open_byproto(&rth, 1 << (RTNLGRP_LINK - 1), NETLINK_ROUTE)) {
		rth.fd = -1;
		return;
	}

	fcntl(rth.fd, F_SETFL, O_NONBLOCK);
	fcntl(rth.fd, F_SETFD, fcntl(rth.fd, F_GETFD) | FD_CLOEXEC);

	memset(&ctx, 0, sizeof(ctx));
	memset(&hnd, 0, sizeof(hnd));

	ctx.close = nnle_close;
	ctx.free = nnle_free;
	ctx.before_switch = nnle_ctx_switch;
	triton_context_register(&ctx, NULL);
	hnd.fd = rth.fd;
	hnd.read = nnle_read;
	triton_md_register_handler(&ctx, &hnd);
	triton_md_enable_handler(&hnd, MD_MODE_READ);
	triton_context_wakeup(&ctx);
}

DEFINE_INIT(20, nnle_init);