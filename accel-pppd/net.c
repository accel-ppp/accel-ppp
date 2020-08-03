#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <limits.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/if.h>

#include "config.h"
#include "triton.h"
#include "log.h"
#include "libnetlink.h"
#include "ap_net.h"
#include "memdebug.h"

#ifndef HAVE_SETNS
#ifdef SYS_setns
int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}
#endif
#endif

struct kern_net {
	struct ap_net net;
	struct rtnl_handle *rth;
	int ns_fd;
	int sock;
	int sock6;
};

static const char *conf_netns_run_dir;

static LIST_HEAD(nets);
static pthread_mutex_t nets_lock = PTHREAD_MUTEX_INITIALIZER;

__export __thread struct ap_net *net;
__export struct ap_net *def_net;
static int def_ns_fd;

static int def_socket(int domain, int type, int proto)
{
	return socket(domain, type, proto);
}

static int def_connect(int sock, const struct sockaddr *addr, socklen_t len)
{
	return connect(sock, addr, len);
}

static int def_bind(int sock, const struct sockaddr *addr, socklen_t len)
{
	return bind(sock, addr, len);
}

static int def_listen(int sock, int backlog)
{
	return listen(sock, backlog);
}

static ssize_t def_read(int sock, void *buf, size_t len)
{
	return read(sock, buf, len);
}

static ssize_t def_recvfrom(int sock, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	return recvfrom(sock, buf, len, flags, src_addr, addrlen);
}

static ssize_t def_write(int sock, const void *buf, size_t len)
{
	return write(sock, buf, len);
}

static ssize_t def_sendto(int sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return sendto(sock, buf, len, flags, dest_addr, addrlen);
}

static int def_set_nonblocking(int sock, int f)
{
	return fcntl(sock, F_SETFL, O_NONBLOCK);
}

static int def_setsockopt(int sock, int level, int optname, const void *optval, socklen_t optlen)
{
	return setsockopt(sock, level, optname, optval, optlen);
}

static int def_ppp_open()
{
	return open("/dev/ppp", O_RDWR);
}

static int def_ppp_ioctl(int fd, unsigned long request, void *arg)
{
	return ioctl(fd, request, arg);
}

static int def_sock_ioctl(unsigned long request, void *arg)
{
	struct kern_net *n = container_of(net, typeof(*n), net);

	return ioctl(n->sock, request, arg);
}

static int def_sock6_ioctl(unsigned long request, void *arg)
{
	struct kern_net *n = container_of(net, typeof(*n), net);

	return ioctl(n->sock6, request, arg);
}

static void enter_ns()
{
#ifdef SYS_setns
	if (net != def_net) {
		struct kern_net *n = container_of(net, typeof(*n), net);
		setns(n->ns_fd, CLONE_NEWNET);
	}
#endif
}

static void exit_ns()
{
#ifdef SYS_setns
	if (net != def_net)
		setns(def_ns_fd, CLONE_NEWNET);
#endif
}

static struct rtnl_handle *def_rtnl_get()
{
	struct kern_net *n = container_of(net, typeof(*n), net);
	struct rtnl_handle *rth = __sync_lock_test_and_set(&n->rth, NULL);
	int r;

	if (!rth) {
		rth = _malloc(sizeof(*rth));
		enter_ns();
		r = rtnl_open(rth, 0);
		exit_ns();

		if (r) {
			_free(rth);
			return NULL;
		}
	}

	return rth;
}

static void def_rtnl_put(struct rtnl_handle *rth)
{
	struct kern_net *n = container_of(net, typeof(*n), net);

	if (!__sync_bool_compare_and_swap(&n->rth, NULL, rth)) {
		rtnl_close(rth);
		_free(rth);
	}
}

static int def_rtnl_open(struct rtnl_handle *rth, int proto)
{
	struct kern_net *n = container_of(net, typeof(*n), net);
	int r;

	enter_ns();
	r = rtnl_open_byproto(rth, 0, proto);
	exit_ns();

	return r;
}

static int def_move_link(struct ap_net *new_net, int ifindex)
{
#ifdef SYS_setns
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[1024];
	} req;
	struct rtnl_handle *rth = net->rtnl_get();
	struct kern_net *n = container_of(new_net, typeof(*n), net);
	int r = 0;

	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 1024);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_SETLINK;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_index = ifindex;

	addattr_l(&req.n, 4096, IFLA_NET_NS_FD, &n->ns_fd, sizeof(n->ns_fd));

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0)
		r = -1;

	net->rtnl_put(rth);

	return r;
#else
	return -1;
#endif
}

static int def_set_vrf(int ifindex, int vrf_ifindex)
{
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[1024];
	} req;

	log_debug("def_set_vrf started ifindex=%d, vrf_ifindex=%d\n", ifindex, vrf_ifindex);

	struct rtnl_handle *rth = net->rtnl_get();

	int r = 0;

	if (!rth) {
		log_ppp_error("def_set_vrf rtnl_get() failed\n");
		return -1;
	}

	memset(&req, 0, sizeof(req) - 1024);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_index = ifindex;

	addattr_l(&req.n, sizeof(req), IFLA_MASTER, &vrf_ifindex, sizeof(vrf_ifindex));

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0) {
		log_ppp_error("def_set_vrf rtnl_talk failed\n");
		r = -1;
	}

	net->rtnl_put(rth);

	return r;
}

static int def_remove_vrf(int ifindex)
{
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[1024];
	} req;
	int vrf_ifindex;

	log_debug("def_remove_vrf started ifindex=%d\n", ifindex);

	struct rtnl_handle *rth = net->rtnl_get();

	int r = 0;

	if (!rth) {
		log_ppp_error("def_remove_vrf rtnl_get() failed\n");
		return -1;
	}

	memset(&req, 0, sizeof(req) - 1024);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_index = ifindex;

	vrf_ifindex = 0;
	addattr_l(&req.n, sizeof(req), IFLA_MASTER, &vrf_ifindex, sizeof(vrf_ifindex));

	if (rtnl_talk(rth, &req.n, 0, 0, NULL, NULL, NULL, 0) < 0) {
		log_ppp_error("def_remove_vrf rtnl_talk failed\n");
		r = -1;
	}

	net->rtnl_put(rth);

	return r;
}


static int def_get_ifindex(const char *ifname)
{
	struct kern_net *n = container_of(net, typeof(*n), net);
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(n->sock, SIOCGIFINDEX, &ifr)) {
		log_ppp_error("ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
		return -1;
	}
	return ifr.ifr_ifindex;
}


static void def_release(struct ap_net *d)
{
	struct kern_net *n = container_of(d, typeof(*n), net);

	if (d == def_net)
		return;

	pthread_mutex_lock(&nets_lock);
	if (--d->refs) {
		pthread_mutex_unlock(&nets_lock);
		return;
	}

	list_del(&d->entry);
	pthread_mutex_unlock(&nets_lock);

	net = def_net;

	log_debug("close ns %s\n", n->net.name);

	close(n->sock);
	close(n->sock6);
	close(n->ns_fd);

	if (n->rth) {
		rtnl_close(n->rth);
		_free(n->rth);
	}

	_free(n);
}

static struct ap_net *alloc_net(const char *name)
{
	struct kern_net *n;
	struct ap_net *net;
#ifdef SYS_setns
	int ns_fd;

	if (name) {
		char fname[PATH_MAX];
		sprintf(fname, "%s/%s", conf_netns_run_dir, name);
		ns_fd = open(fname, O_RDONLY);
		if (ns_fd == -1) {
			log_ppp_error("open %s: %s\n", fname, strerror(errno));
			return NULL;
		}

		if (setns(ns_fd, CLONE_NEWNET)) {
			log_ppp_error("setns %s: %s\n", fname, strerror(errno));
			close(ns_fd);
			return NULL;
		}
	} else
		def_ns_fd = ns_fd = open("/proc/self/ns/net", O_RDONLY);

	log_debug("open ns %s\n", name);
#endif

	n = _malloc(sizeof(*n));
	net = &n->net;

	net->refs = 1;
	net->name = name ? _strdup(name) : "def";
	net->socket = def_socket;
	net->connect = def_connect;
	net->bind = def_bind;
	net->listen = def_listen;
	net->read = def_read;
	net->recvfrom = def_recvfrom;
	net->write = def_write;
	net->sendto = def_sendto;
	net->set_nonblocking = def_set_nonblocking;
	net->setsockopt = def_setsockopt;
	net->ppp_open = def_ppp_open;
	net->ppp_ioctl = def_ppp_ioctl;
	net->sock_ioctl = def_sock_ioctl;
	net->sock6_ioctl = def_sock6_ioctl;
	net->enter_ns = enter_ns;
	net->exit_ns = exit_ns;
	net->rtnl_get = def_rtnl_get;
	net->rtnl_put = def_rtnl_put;
	net->rtnl_open = def_rtnl_open;
	net->move_link = def_move_link;
	net->get_ifindex = def_get_ifindex;
	net->set_vrf = def_set_vrf;
	net->remove_vrf = def_remove_vrf;
	net->release = def_release;

	n->sock = socket(AF_INET, SOCK_DGRAM, 0);
	n->sock6 = socket(AF_INET6, SOCK_DGRAM, 0);
	n->rth = _malloc(sizeof(*n->rth));
	rtnl_open(n->rth, 0);

#ifdef SYS_setns
	n->ns_fd = ns_fd;
	if (ns_fd != def_ns_fd)
		setns(def_ns_fd, CLONE_NEWNET);
#endif

	list_add_tail(&net->entry, &nets);

	return net;
};

int __export ap_net_register(struct ap_net *net)
{
	pthread_mutex_lock(&nets_lock);
	list_add_tail(&net->entry, &nets);
	pthread_mutex_unlock(&nets_lock);

	return 0;
}

static struct ap_net *find_net(const char *name)
{
	struct ap_net *n;

	list_for_each_entry(n, &nets, entry) {
		if (!strcmp(name, n->name)) {
			n->refs++;
			return n;
		}
	}

	return NULL;
}

__export struct ap_net *ap_net_find(const char *name)
{
	struct ap_net *n;

	pthread_mutex_lock(&nets_lock);
	n = find_net(name);
	pthread_mutex_unlock(&nets_lock);

	return n;
}

__export struct ap_net *ap_net_open_ns(const char *name)
{
#ifdef SYS_setns
	struct ap_net *n;

	pthread_mutex_lock(&nets_lock);
	n = find_net(name);
	if (!n)
		n = alloc_net(name);
	pthread_mutex_unlock(&nets_lock);

	return n;
#else
	log_ppp_error("netns is not suppotred\n");
	return NULL;
#endif
}

static void __init init()
{
	const char *opt;

	opt = conf_get_opt("common", "netns-run-dir");
	if (opt)
		conf_netns_run_dir = opt;
	else
		conf_netns_run_dir = "/var/run/netns";

	def_net = net = alloc_net(NULL);
}

DEFINE_INIT(1, init);
