#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/genetlink.h>

#include "triton.h"
#include "log.h"
#include "genl.h"
#include "libnetlink.h"
#include "iputils.h"
#include "ap_net.h"

#include "vlan_mon.h"
#include "if_vlan_mon.h"

#include "memdebug.h"

#define PKT_ATTR_MAX 256

static struct rtnl_handle rth;
static struct triton_md_handler_t mc_hnd;
static int vlan_mon_genl_id;

static vlan_mon_notify cb[2];

static void init(void);

void __export vlan_mon_register_proto(uint16_t proto, vlan_mon_notify func)
{
	if (proto == ETH_P_PPP_DISC)
		proto = 1;
	else
		proto = 0;

	cb[proto] = func;

	if (!vlan_mon_genl_id)
		init();
}

int __export vlan_mon_add(int ifindex, uint16_t proto, long *mask, int len)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;
	int r = 0;

	if (vlan_mon_genl_id < 0)
		return -1;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_error("vlan_mon: cannot open generic netlink socket\n");
		return -1;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = vlan_mon_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = VLAN_MON_CMD_ADD;

	addattr32(nlh, 1024, VLAN_MON_ATTR_IFINDEX, ifindex);
	addattr_l(nlh, 1024, VLAN_MON_ATTR_VLAN_MASK, mask, len);
	addattr_l(nlh, 1024, VLAN_MON_ATTR_PROTO, &proto, 2);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, sizeof(req), NULL, NULL, 0) < 0 ) {
		log_error("vlan_mon: nl_add_vlan_mon: error talking to kernel\n");
		r = -1;
	}

	rtnl_close(&rth);

	return r;
}

int __export vlan_mon_add_vid(int ifindex, uint16_t proto, uint16_t vid)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;
	int r = 0;

	if (vlan_mon_genl_id < 0)
		return -1;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_error("vlan_mon: cannot open generic netlink socket\n");
		return -1;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = vlan_mon_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = VLAN_MON_CMD_ADD_VID;

	addattr32(nlh, 1024, VLAN_MON_ATTR_IFINDEX, ifindex);
	addattr_l(nlh, 1024, VLAN_MON_ATTR_VID, &vid, 2);
	addattr_l(nlh, 1024, VLAN_MON_ATTR_PROTO, &proto, 2);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, sizeof(req), NULL, NULL, 0) < 0 ) {
		log_error("vlan_mon: nl_add_vlan_mon_vid: error talking to kernel\n");
		r = -1;
	}

	rtnl_close(&rth);

	return r;
}

int __export vlan_mon_del_vid(int ifindex, uint16_t proto, uint16_t vid)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;
	int r = 0;

	if (vlan_mon_genl_id < 0)
		return -1;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_error("vlan_mon: cannot open generic netlink socket\n");
		return -1;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = vlan_mon_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = VLAN_MON_CMD_DEL_VID;

	addattr32(nlh, 1024, VLAN_MON_ATTR_IFINDEX, ifindex);
	addattr_l(nlh, 1024, VLAN_MON_ATTR_VID, &vid, 2);
	addattr_l(nlh, 1024, VLAN_MON_ATTR_PROTO, &proto, 2);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, sizeof(req), NULL, NULL, 0) < 0 ) {
		log_error("vlan_mon: nl_add_vlan_mon_vid: error talking to kernel\n");
		r = -1;
	}

	rtnl_close(&rth);

	return r;
}

int __export vlan_mon_del(int ifindex, uint16_t proto)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;
	int r = 0;

	if (vlan_mon_genl_id < 0)
		return -1;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_error("vlan_mon: cannot open generic netlink socket\n");
		return -1;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = vlan_mon_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = VLAN_MON_CMD_DEL;

	addattr32(nlh, 1024, VLAN_MON_ATTR_IFINDEX, ifindex);
	addattr_l(nlh, 1024, VLAN_MON_ATTR_PROTO, &proto, 2);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, sizeof(req), NULL, NULL, 0) < 0 ) {
		log_error("vlan_mon: nl_del_vlan_mon: error talking to kernel\n");
		r = -1;
	}

	rtnl_close(&rth);

	return r;
}

void vlan_mon_clean()
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC))
		return;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = vlan_mon_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = VLAN_MON_CMD_DEL;

	rtnl_talk(&rth, nlh, 0, 0, nlh, sizeof(req), NULL, NULL, 0);

	rtnl_close(&rth);
}

int __export vlan_mon_check_busy(int ifindex, uint16_t vid)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;
	int r = 0;

	if (vlan_mon_genl_id < 0)
		return 0;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_error("vlan_mon: cannot open generic netlink socket\n");
		return 0;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = vlan_mon_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = VLAN_MON_CMD_CHECK_BUSY;

	addattr32(nlh, 1024, VLAN_MON_ATTR_IFINDEX, ifindex);
	addattr_l(nlh, 1024, VLAN_MON_ATTR_VID, &vid, 2);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, sizeof(req), NULL, NULL, 1) < 0 ) {
		if (errno == EBUSY)
			r = -1;
	}

	rtnl_close(&rth);

	return r;
}

static void vlan_mon_handler(const struct sockaddr_nl *addr, struct nlmsghdr *h)
{
	struct rtattr *tb[PKT_ATTR_MAX + 1];
	struct rtattr *tb2[VLAN_MON_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(h);
	int len = h->nlmsg_len;
	struct rtattr *attrs;
	int i;
	int ifindex, vid, proto, vlan_ifindex;

	len -= NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		log_warn("vlan_mon: wrong controller message length %d\n", len);
		return;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	parse_rtattr(tb, PKT_ATTR_MAX, attrs, len);

	for (i = 1; i < PKT_ATTR_MAX; i++) {
		if (!tb[i])
			break;

		parse_rtattr_nested(tb2, VLAN_MON_ATTR_MAX, tb[i]);

		if (!tb2[VLAN_MON_ATTR_IFINDEX] || !tb2[VLAN_MON_ATTR_VID] ||
		    !tb2[VLAN_MON_ATTR_PROTO])
			continue;

		ifindex = *(uint32_t *)(RTA_DATA(tb2[VLAN_MON_ATTR_IFINDEX]));
		vid = *(uint16_t *)(RTA_DATA(tb2[VLAN_MON_ATTR_VID]));
		proto = *(uint16_t *)(RTA_DATA(tb2[VLAN_MON_ATTR_PROTO]));

		if (tb2[VLAN_MON_ATTR_VLAN_IFINDEX])
			vlan_ifindex = *(uint32_t *)(RTA_DATA(tb2[VLAN_MON_ATTR_VLAN_IFINDEX]));
		else
			vlan_ifindex = 0;

		log_debug("vlan-mon: notify %i %i %04x %i\n", ifindex, vid, proto, vlan_ifindex);

		if (proto == ETH_P_PPP_DISC)
			proto = 1;
		else
			proto = 0;

		if (cb[proto])
			cb[proto](ifindex, vid, vlan_ifindex);
	}
}


static int vlan_mon_mc_read(struct triton_md_handler_t *h)
{
	int status;
	struct nlmsghdr *hdr;
	struct genlmsghdr *ghdr;
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
		status = recvmsg(h->fd, &msg, 0);

		if (status < 0) {
			if (errno == EAGAIN)
				break;
			log_error("vlan_mon: netlink error: %s\n", strerror(errno));
			if (errno == ENOBUFS)
				continue;
			return 0;
		}

		if (status == 0) {
			log_error("vlan_mon: EOF on netlink\n");
			return 0;
		}

		if (msg.msg_namelen != sizeof(nladdr)) {
			log_error("vlan_mon: netlink sender address length == %d\n", msg.msg_namelen);
			return 0;
		}

		for (hdr = (struct nlmsghdr*)buf; status >= (int)sizeof(*hdr); ) {
			int len = hdr->nlmsg_len;
			int l = len - (int)sizeof(*hdr);

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC)
					log_warn("vlan_mon: truncated netlink message\n");
				else
					log_error("vlan_mon: malformed netlink message\n");
				/* Do not continue without advancing: that spins forever. */
				break;
			}

			if (nladdr.nl_pid) {
				status -= NLMSG_ALIGN(len);
				hdr = (struct nlmsghdr*)((char*)hdr + NLMSG_ALIGN(len));
				continue;
			}

			ghdr = NLMSG_DATA(hdr);

			if (ghdr->cmd == VLAN_MON_NOTIFY)
				vlan_mon_handler(&nladdr, hdr);

			status -= NLMSG_ALIGN(len);
			hdr = (struct nlmsghdr*)((char*)hdr + NLMSG_ALIGN(len));
		}

		if (msg.msg_flags & MSG_TRUNC) {
			log_warn("vlan_mon: netlink message truncated\n");
			continue;
		}

		if (status) {
			log_error("vlan_mon: netlink remnant of size %d\n", status);
			return 0;
		}
	}

	return 0;
}

int __export make_vlan_name(const char *pattern, const char *parent, int svid, int cvid, char *name)
{
	char *ptr1 = name, *endptr = name + IFNAMSIZ;
	const char *ptr2 = pattern;
	char svid_str[5], cvid_str[5], *ptr3;

	sprintf(svid_str, "%i", svid);
	sprintf(cvid_str, "%i", cvid);

	while (ptr1 < endptr && *ptr2) {
		if (ptr2[0] == '%' && ptr2[1] == 'I') {
			while (ptr1 < endptr && *parent)
				*ptr1++ = *parent++;
			ptr2 += 2;
		} else if (ptr2[0] == '%' && ptr2[1] == 'N') {
			ptr3 = cvid_str;
			while (ptr1 < endptr && *ptr3)
				*ptr1++ = *ptr3++;
			ptr2 += 2;
		} else if (ptr2[0] == '%' && ptr2[1] == 'P') {
			ptr3 = svid_str;
			while (ptr1 < endptr && *ptr3)
				*ptr1++ = *ptr3++;
			ptr2 += 2;
		} else
			*ptr1++ = *ptr2++;
	}

	if (ptr1 == endptr)
		return 1;

	*ptr1 = 0;

	return 0;
}

int __export parse_vlan_mon(const char *opt, long *mask)
{
	char *ptr, *ptr2;
	int vid, vid2;

	ptr = strchr(opt, ',');
	if (!ptr)
		ptr = strchr(opt, 0);

	if (*ptr == ',')
		memset(mask, 0xff, 4096/8);
	else if (*ptr == 0) {
		memset(mask, 0, 4096/8);
		return 0;
	} else
		goto out_err;

	while (1) {
		vid = strtol(ptr + 1, &ptr2, 10);
		if (vid <= 0 || vid >= 4096) {
			log_error("vlan-mon=%s: invalid vlan %i\n", opt, vid);
			return -1;
		}

		if (*ptr2 == '-') {
			vid2 = strtol(ptr2 + 1, &ptr2, 10);
			if (vid2 <= 0 || vid2 >= 4096) {
				log_error("vlan-mon=%s: invalid vlan %i\n", opt, vid2);
				return -1;
			}

			for (; vid < vid2; vid++)
				mask[vid / (8*sizeof(long))] &= ~(1lu << (vid % (8*sizeof(long))));
		}

		mask[vid / (8*sizeof(long))] &= ~(1lu << (vid % (8*sizeof(long))));

		if (*ptr2 == 0)
			break;

		if (*ptr2 != ',')
			goto out_err;

		ptr = ptr2;
	}

	return 0;

out_err:
	log_error("vlan-mon=%s: failed to parse\n", opt);
	return -1;
}


static void vlan_mon_mc_close(struct triton_context_t *ctx)
{
	triton_md_unregister_handler(&mc_hnd, 0);
	triton_context_unregister(ctx);
}

static void mc_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	net = def_net;
	log_switch(NULL, NULL);
}

static struct triton_context_t mc_ctx = {
	.close = vlan_mon_mc_close,
};

static struct triton_md_handler_t mc_hnd = {
	.read = vlan_mon_mc_read,
};

static void init(void)
{
	int mcg_id;

	if (access("/sys/module/vlan_mon", F_OK) && system("modprobe -q vlan_mon"))
		log_warn("failed to load vlan_mon module\n");

	mcg_id = genl_resolve_mcg(VLAN_MON_GENL_NAME, VLAN_MON_GENL_MCG, &vlan_mon_genl_id);
	if (mcg_id == -1) {
		log_warn("vlan_mon: kernel module is not loaded\n");
		vlan_mon_genl_id = -1;
		return;
	}

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_error("vlan_mon: cannot open generic netlink socket\n");
		vlan_mon_genl_id = -1;
		return;
	}

	if (setsockopt(rth.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &mcg_id, sizeof(mcg_id)) < 0) {
		log_error("vlan_mon: failed to join multicast group: %s\n", strerror(errno));
		rtnl_close(&rth);
		vlan_mon_genl_id = -1;
		return;
	}

	vlan_mon_clean();

	fcntl(rth.fd, F_SETFL, O_NONBLOCK);
	fcntl(rth.fd, F_SETFD, fcntl(rth.fd, F_GETFD) | FD_CLOEXEC);

	mc_ctx.before_switch = mc_ctx_switch;
	triton_context_register(&mc_ctx, NULL);
	mc_hnd.fd = rth.fd;
	triton_md_register_handler(&mc_ctx, &mc_hnd);
	triton_md_enable_handler(&mc_hnd, MD_MODE_READ);
	triton_context_wakeup(&mc_ctx);
}

