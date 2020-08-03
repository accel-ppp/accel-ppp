#ifndef __AP_NET_H
#define __AP_NET_H

#include <sys/socket.h>
#include <sys/types.h>

#include "libnetlink.h"
#include "list.h"

struct ap_net {
	struct list_head entry;
	int refs;
	char *name;
	int (*socket)(int domain, int type, int proto);
	int (*connect)(int sock, const struct sockaddr *, socklen_t len);
	int (*bind)(int sock, const struct sockaddr *, socklen_t len);
	int (*listen)(int sock, int backlog);
	ssize_t (*read)(int sock, void *buf, size_t len);
	ssize_t (*recvfrom)(int sock, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
	ssize_t (*write)(int sock, const void *buf, size_t len);
	ssize_t (*sendto)(int sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
	int (*set_nonblocking)(int sock, int f);
	int (*setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
	int (*sock_ioctl)(unsigned long request, void *arg);
	int (*sock6_ioctl)(unsigned long request, void *arg);
	int (*ppp_open)();
	int (*ppp_ioctl)(int fd, unsigned long request, void *arg);
	void (*enter_ns)();
	void (*exit_ns)();
	struct rtnl_handle *(*rtnl_get)();
	void (*rtnl_put)(struct rtnl_handle *);
	int (*rtnl_open)(struct rtnl_handle *h, int proto);
	int (*move_link)(struct ap_net *net, int ifindex);
	int (*get_ifindex)(const char * ifname);
	int (*set_vrf)(int ifindex, int vrf_ifindex);
	int (*remove_vrf)(int ifindex);
	void (*release)(struct ap_net *net);
};

extern __thread struct ap_net *net;
extern struct ap_net *def_net;

int ap_net_register(struct ap_net *net);
struct ap_net *ap_net_find(const char *name);
struct ap_net *ap_net_open_ns(const char *name);

#endif
