/*
 * libnetlink.c	RTnetlink service routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>

#include "libnetlink.h"
#include "log.h"

#define __export __attribute__((visibility("default")))

extern int conf_nl_rcvbuf;
extern int conf_nl_sndbuf;

void __export rtnl_close(struct rtnl_handle *rth)
{
	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}

int __export rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
		      int protocol)
{
	socklen_t addr_len;
	int sndbuf = 32768;

	memset(rth, 0, sizeof(*rth));

	rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (rth->fd < 0) {
		log_debug("libnetlink: ""Cannot open netlink socket: %s\n", strerror(errno));
		return -1;
	}

	if (conf_nl_sndbuf > 0) {
		if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&conf_nl_sndbuf,sizeof(conf_nl_sndbuf)) < 0) {
			log_debug("libnetlink: ""SO_SNDBUF: %s\n", strerror(errno));
			log_debug("libnetlink: unable to set custom sndbuf. Default value %d will be used", sndbuf);
			conf_nl_sndbuf = -1;
		}
	}

	if (conf_nl_sndbuf <= 0) {
		if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
			log_debug("libnetlink: ""SO_SNDBUF: %s\n", strerror(errno));
			return -1;
		}
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&conf_nl_rcvbuf,sizeof(conf_nl_rcvbuf)) < 0) {
		log_debug("libnetlink: ""SO_RCVBUF: %s\n", strerror(errno));
		return -1;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		log_debug("libnetlink: ""Cannot bind netlink socket: %s\n", strerror(errno));
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
		log_debug("libnetlink: ""Cannot getsockname: %s\n", strerror(errno));
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		log_debug("libnetlink: ""Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		log_debug("libnetlink: ""Wrong address family %d\n", rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
	return 0;
}

int __export rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

int __export rtnl_wilddump_request(struct rtnl_handle *rth, int family, int type)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
	req.g.rtgen_family = family;

	return send(rth->fd, (void*)&req, sizeof(req), 0);
}

int __export rtnl_send(struct rtnl_handle *rth, const char *buf, int len)
{
	return send(rth->fd, buf, len, 0);
}

int __export rtnl_send_check(struct rtnl_handle *rth, const char *buf, int len)
{
	struct nlmsghdr *h;
	int status;
	char resp[1024];

	status = send(rth->fd, buf, len, 0);
	if (status < 0)
		return status;

	/* Check for immediate errors */
	status = recv(rth->fd, resp, sizeof(resp), MSG_DONTWAIT|MSG_PEEK);
	if (status < 0) {
		if (errno == EAGAIN)
			return 0;
		return -1;
	}

	for (h = (struct nlmsghdr *)resp; NLMSG_OK(h, status);
	     h = NLMSG_NEXT(h, status)) {
		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
			if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
				log_debug("libnetlink: ""ERROR truncated\n");
			else
				errno = -err->error;
			return -1;
		}
	}

	return 0;
}

int __export rtnl_dump_request(struct rtnl_handle *rth, int type, void *req, int len)
{
	struct nlmsghdr nlh;
	struct sockaddr_nl nladdr;
	struct iovec iov[2] = {
		{ .iov_base = &nlh, .iov_len = sizeof(nlh) },
		{ .iov_base = req, .iov_len = len }
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = 	sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = 2,
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	nlh.nlmsg_len = NLMSG_LENGTH(len);
	nlh.nlmsg_type = type;
	nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	nlh.nlmsg_pid = 0;
	nlh.nlmsg_seq = rth->dump = ++rth->seq;

	return sendmsg(rth->fd, &msg, 0);
}

int __export rtnl_dump_filter_l(struct rtnl_handle *rth,
		       const struct rtnl_dump_filter_arg *arg)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[16384];

	iov.iov_base = buf;
	while (1) {
		int status;
		const struct rtnl_dump_filter_arg *a;
		int found_done = 0;
		int msglen = 0;

		iov.iov_len = sizeof(buf);
		status = recvmsg(rth->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			log_debug("libnetlink: ""netlink receive error %s (%d)\n",
				strerror(errno), errno);
			return -1;
		}

		if (status == 0) {
			log_debug("libnetlink: ""EOF on netlink\n");
			return -1;
		}

		for (a = arg; a->filter; a++) {
			struct nlmsghdr *h = (struct nlmsghdr*)buf;
			msglen = status;

			while (NLMSG_OK(h, msglen)) {
				int err;

				if (nladdr.nl_pid != 0 ||
				    h->nlmsg_pid != rth->local.nl_pid ||
				    h->nlmsg_seq != rth->dump) {
					if (a->junk) {
						err = a->junk(&nladdr, h,
							      a->arg2);
						if (err < 0)
							return err;
					}
					goto skip_it;
				}

				if (h->nlmsg_type == NLMSG_DONE) {
					found_done = 1;
					break; /* process next filter */
				}
				if (h->nlmsg_type == NLMSG_ERROR) {
					struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
					if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
						fprintf(stderr,
							"ERROR truncated\n");
					} else {
						errno = -err->error;
						log_debug("libnetlink: ""RTNETLINK answers: %s\n", strerror(errno));
					}
					return -1;
				}
				err = a->filter(&nladdr, h, a->arg1);
				if (err < 0)
					return err;

skip_it:
				h = NLMSG_NEXT(h, msglen);
			}
		}

		if (found_done)
			return 0;

		if (msg.msg_flags & MSG_TRUNC) {
			log_debug("libnetlink: ""Message truncated\n");
			continue;
		}
		if (msglen) {
			log_debug("libnetlink: ""!!!Remnant of size %d\n", msglen);
			exit(1);
		}
	}
}

int __export rtnl_dump_filter(struct rtnl_handle *rth,
		     rtnl_filter_t filter,
		     void *arg1,
		     rtnl_filter_t junk,
		     void *arg2)
{
	const struct rtnl_dump_filter_arg a[2] = {
		{ .filter = filter, .arg1 = arg1, .junk = junk, .arg2 = arg2 },
		{ .filter = NULL,   .arg1 = NULL, .junk = NULL, .arg2 = NULL }
	};

	return rtnl_dump_filter_l(rth, a);
}

int __export rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
	      unsigned groups, struct nlmsghdr *answer,
	      rtnl_filter_t junk,
	      void *jarg, int ignore_einval)
{
	int status;
	unsigned seq;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = (void*) n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[16384];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = peer;
	nladdr.nl_groups = groups;

	n->nlmsg_seq = seq = ++rtnl->seq;

	if (answer == NULL)
		n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(rtnl->fd, &msg, 0);

	if (status < 0) {
		log_debug("libnetlink: ""Cannot talk to rtnetlink: %s\n", strerror(errno));
		return -1;
	}

	memset(buf,0,sizeof(buf));

	iov.iov_base = buf;

	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(rtnl->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			log_debug("libnetlink: ""netlink receive error %s (%d)\n",
				strerror(errno), errno);
			return -1;
		}
		if (status == 0) {
			log_debug("libnetlink: ""EOF on netlink\n");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			log_debug("libnetlink: ""sender address length == %d\n", msg.msg_namelen);
			exit(1);
		}
		for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l<0 || len>status) {
				if (msg.msg_flags & MSG_TRUNC) {
					log_debug("libnetlink: ""Truncated message\n");
					return -1;
				}
				log_debug("libnetlink: ""!!!malformed message: len=%d\n", len);
				exit(1);
			}

			if (nladdr.nl_pid != peer ||
			    h->nlmsg_pid != rtnl->local.nl_pid ||
			    h->nlmsg_seq != seq) {
				if (junk) {
					err = junk(&nladdr, h, jarg);
					if (err < 0)
						return err;
				}
				/* Don't forget to skip that message. */
				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
				continue;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
				if (l < sizeof(struct nlmsgerr)) {
					log_debug("libnetlink: ""ERROR truncated\n");
				} else {
					errno = -err->error;
					if (errno == 0 || (errno == EINVAL && ignore_einval)) {
						if (answer)
							memcpy(answer, h, h->nlmsg_len);
						return 0;
					}
					if (!ignore_einval)
						log_debug("libnetlink: ""RTNETLINK answers: %s\n", strerror(errno));
				}
				return -1;
			}
			if (answer) {
				memcpy(answer, h, h->nlmsg_len);
				return 0;
			}

			log_debug("libnetlink: ""Unexpected reply!!!\n");

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			log_debug("libnetlink: ""Message truncated\n");
			continue;
		}
		if (status) {
			log_debug("libnetlink: ""!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
}

int __export rtnl_listen(struct rtnl_handle *rtnl,
		rtnl_filter_t handler,
		void *jarg)
{
	int status;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[8192];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	iov.iov_base = buf;
	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(rtnl->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			log_debug("libnetlink: ""netlink receive error %s (%d)\n",
				strerror(errno), errno);
			if (errno == ENOBUFS)
				continue;
			return -1;
		}
		if (status == 0) {
			log_debug("libnetlink: ""EOF on netlink\n");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			log_debug("libnetlink: ""Sender address length == %d\n", msg.msg_namelen);
			exit(1);
		}
		for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l<0 || len>status) {
				if (msg.msg_flags & MSG_TRUNC) {
					log_debug("libnetlink: ""Truncated message\n");
					return -1;
				}
				log_debug("libnetlink: ""!!!malformed message: len=%d\n", len);
				exit(1);
			}

			err = handler(&nladdr, h, jarg);
			if (err < 0)
				return err;

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			log_debug("libnetlink: ""Message truncated\n");
			continue;
		}
		if (status) {
			log_debug("libnetlink: ""!!!Remnant of size %d\n", status);
			exit(1);
		}
	}

	return 0;
}

int __export addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
	int len = RTA_LENGTH(4);
	struct rtattr *rta;
	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
		fprintf(stderr,"addattr32: Error! max allowed bound %d exceeded\n",maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), &data, 4);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
	return 0;
}

int __export addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		log_debug("libnetlink: ""addattr_l ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (data && alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

int __export addraw_l(struct nlmsghdr *n, int maxlen, const void *data, int len)
{
	if (NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len) > maxlen) {
		log_debug("libnetlink: ""addraw_l ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
	}

	memcpy(NLMSG_TAIL(n), data, len);
	memset((void *) NLMSG_TAIL(n) + len, 0, NLMSG_ALIGN(len) - len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len);
	return 0;
}

struct rtattr __export *addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

int __export addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
	return n->nlmsg_len;
}

struct rtattr __export *addattr_nest_compat(struct nlmsghdr *n, int maxlen, int type,
				   const void *data, int len)
{
	struct rtattr *start = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, data, len);
	addattr_nest(n, maxlen, type);
	return start;
}

int __export addattr_nest_compat_end(struct nlmsghdr *n, struct rtattr *start)
{
	struct rtattr *nest = (void *)start + NLMSG_ALIGN(start->rta_len);

	start->rta_len = (void *)NLMSG_TAIL(n) - (void *)start;
	addattr_nest_end(n, nest);
	return n->nlmsg_len;
}

int __export rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data)
{
	int len = RTA_LENGTH(4);
	struct rtattr *subrta;

	if (RTA_ALIGN(rta->rta_len) + len > maxlen) {
		fprintf(stderr,"rta_addattr32: Error! max allowed bound %d exceeded\n",maxlen);
		return -1;
	}
	subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), &data, 4);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + len;
	return 0;
}

int __export rta_addattr_l(struct rtattr *rta, int maxlen, int type,
		  const void *data, int alen)
{
	struct rtattr *subrta;
	int len = RTA_LENGTH(alen);

	if (RTA_ALIGN(rta->rta_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr,"rta_addattr_l: Error! max allowed bound %d exceeded\n",maxlen);
		return -1;
	}
	subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), data, alen);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);
	return 0;
}

int __export parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		log_debug("libnetlink: ""!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

int parse_rtattr_byindex(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	int i = 0;

	memset(tb, 0, sizeof(struct rtattr *) * max);
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max && i < max)
			tb[i++] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		log_debug("libnetlink: ""!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return i;
}

int __parse_rtattr_nested_compat(struct rtattr *tb[], int max, struct rtattr *rta,
			         int len)
{
	if (RTA_PAYLOAD(rta) < len)
		return -1;
	if (RTA_PAYLOAD(rta) >= RTA_ALIGN(len) + sizeof(struct rtattr)) {
		rta = RTA_DATA(rta) + RTA_ALIGN(len);
		return parse_rtattr_nested(tb, max, rta);
	}
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	return 0;
}
