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
#include <linux/genetlink.h>

#include "triton.h"
#include "log.h"

#include "libnetlink.h"

#define GENL_MAX_FAM_GRPS 128

int __export genl_resolve_mcg(const char *family, const char *name, int *fam_id)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct rtattr *tb[CTRL_ATTR_MAX + 1];
	struct rtattr *tb2[GENL_MAX_FAM_GRPS + 1];
	struct rtattr *tb3[CTRL_ATTR_MCAST_GRP_MAX + 1];
	struct rtattr *attrs;
	int i, len, ret = -1;
	struct {
		struct nlmsghdr n;
		char buf[4096];
	} req;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_error("genl: cannot open rtnetlink\n");
		return -1;
	}

	memset(&req, 0, sizeof(req));
	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = GENL_ID_CTRL;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = CTRL_CMD_GETFAMILY;

	addattr_l(nlh, 128, CTRL_ATTR_FAMILY_NAME, family, strlen(family) + 1);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_error("genl: error talking to kernel\n");
		goto out;
	}

	if (nlh->nlmsg_type != GENL_ID_CTRL) {
		log_error("genl: not a controller message %d\n", nlh->nlmsg_type);
		goto out;
	}

	ghdr = NLMSG_DATA(nlh);

	if (ghdr->cmd != CTRL_CMD_NEWFAMILY) {
		log_error("genl: unknown controller command %d\n", ghdr->cmd);
		goto out;
	}

	len = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		log_error("genl: wrong controller message len %d\n", len);
		goto out;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	parse_rtattr(tb, CTRL_ATTR_MAX, attrs, len);

	if (!tb[CTRL_ATTR_FAMILY_ID]) {
		log_error("genl: missing CTRL_FAMILY_ID attribute\n");
		goto out;
	}

	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		goto out;

	if (fam_id)
		*fam_id =	*(uint16_t *)(RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]));

	parse_rtattr_nested(tb2, GENL_MAX_FAM_GRPS, tb[CTRL_ATTR_MCAST_GROUPS]);

	for (i = 1; i < GENL_MAX_FAM_GRPS; i++) {
		if (tb2[i]) {
			parse_rtattr_nested(tb3, CTRL_ATTR_MCAST_GRP_MAX, tb2[i]);
			if (!tb3[CTRL_ATTR_MCAST_GRP_ID] || !tb3[CTRL_ATTR_MCAST_GRP_NAME])
				continue;
			if (strcmp(RTA_DATA(tb3[CTRL_ATTR_MCAST_GRP_NAME]), name))
				continue;
			ret =	*(uint32_t *)(RTA_DATA(tb3[CTRL_ATTR_MCAST_GRP_ID]));
			break;
		}
	}

out:

	rtnl_close(&rth);
	return ret;
}
