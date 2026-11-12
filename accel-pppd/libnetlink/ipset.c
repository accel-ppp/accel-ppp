#include "config.h"

#ifdef HAVE_IPSET

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <pthread.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

#include "triton.h"
#include "log.h"

#include "libnetlink.h"
#include "ipset.h"

#include "memdebug.h"

static int __ipset_cmd(const char *name, in_addr_t addr, int cmd, int flags)
{
	struct rtnl_handle rth;
	struct req {
		struct nlmsghdr n;
		struct nfgenmsg nf;
		char buf[4096];
	} req;
	struct rtattr *tail1, *tail2;
	uint8_t protocol = IPSET_PROTOCOL;

	if (rtnl_open_byproto(&rth, 0, NETLINK_NETFILTER)) {
		log_error("ipset: cannot open rtnetlink\n");
		return -1;
	}

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	req.n.nlmsg_flags = flags;
	req.n.nlmsg_type = cmd | (NFNL_SUBSYS_IPSET << 8);
	req.nf.nfgen_family = AF_INET;
	req.nf.version = NFNETLINK_V0;
	req.nf.res_id = 0;

	addattr_l(&req.n, 4096, IPSET_ATTR_PROTOCOL, &protocol, 1);
	addattr_l(&req.n, 4096, IPSET_ATTR_SETNAME, name, strlen(name) + 1);

	tail1 = addattr_nest(&req.n, MAX_MSG, IPSET_ATTR_DATA | NLA_F_NESTED);

	tail2 = addattr_nest(&req.n, MAX_MSG, IPSET_ATTR_IP | NLA_F_NESTED);
	addattr32(&req.n, 4096, IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER, addr);
	addattr_nest_end(&req.n, tail2);

	addattr_nest_end(&req.n, tail1);

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, 0, NULL, NULL, 0) < 0)
		goto out_err;

	rtnl_close(&rth);

	return 0;

out_err:
	rtnl_close(&rth);

	return -1;

}

int __export ipset_add(const char *name, in_addr_t addr)
{
	return __ipset_cmd(name, addr, IPSET_CMD_ADD, NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL);
}

int __export ipset_del(const char *name, in_addr_t addr)
{
	return __ipset_cmd(name, addr, IPSET_CMD_DEL, NLM_F_REQUEST | NLM_F_ACK);
}

int __export ipset_flush(const char *name)
{
	struct rtnl_handle rth;
	struct req {
		struct nlmsghdr n;
		struct nfgenmsg nf;
		char buf[4096];
	} req;
	uint8_t protocol = IPSET_PROTOCOL;

	if (rtnl_open_byproto(&rth, 0, NETLINK_NETFILTER)) {
		log_error("ipset: cannot open rtnetlink\n");
		return -1;
	}

	memset(&req, 0, sizeof(req) - 4096);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = IPSET_CMD_FLUSH | (NFNL_SUBSYS_IPSET << 8);
	req.nf.nfgen_family = AF_INET;
	req.nf.version = NFNETLINK_V0;
	req.nf.res_id = 0;

	addattr_l(&req.n, 4096, IPSET_ATTR_PROTOCOL, &protocol, 1);
	addattr_l(&req.n, 4096, IPSET_ATTR_SETNAME, name, strlen(name) + 1);

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, 0, NULL, NULL, 0) < 0)
		goto out_err;

	rtnl_close(&rth);

	return 0;

out_err:
	rtnl_close(&rth);

	return -1;
}

#else

#include <netinet/in.h>
#include "triton.h"

int __export ipset_add(const char *name, in_addr_t addr)
{
	return -1;
}

int __export ipset_del(const char *name, in_addr_t addr)
{
	return -1;
}

int __export ipset_flush(const char *name)
{
	return -1;
}

#endif
