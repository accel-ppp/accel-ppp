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

#include <pcre.h>

#include "triton.h"
#include "events.h"
#include "log.h"
#include "genl.h"
#include "libnetlink.h"
#include "iputils.h"
#include "ap_net.h"
#include "cli.h"

//Only for sock_fd
#include "ap_session.h"

#include "vlan_mon.h"
#include "if_vlan_mon.h"

#include "memdebug.h"

#define PKT_ATTR_MAX 256

struct iplink_arg {
    pcre *re;
    const char *opt;
    void *cli;
    long *arg1;
};

LIST_HEAD(vlan_mon_devices);
pthread_rwlock_t vlan_mon_devices_lock = PTHREAD_RWLOCK_INITIALIZER;

LIST_HEAD(vlan_mon_notify_list);
pthread_rwlock_t vlan_mon_notify_lock = PTHREAD_RWLOCK_INITIALIZER;

static struct rtnl_handle rth;
static struct triton_md_handler_t mc_hnd;
static int vlan_mon_genl_id;

//Callbacks for upstream servers (ipoe, pppoe)
static vlan_mon_callbacks vlan_mon_cb[2];

static void vlan_mon_ctx_close(struct triton_context_t *);
static struct triton_context_t vlan_mon_ctx = {
        .close = vlan_mon_ctx_close,
        .before_switch = log_switch,
};

static char conf_vlan_name[IFNAMSIZ];

static int conf_vlan_timeout = 60;

static void vlan_mon_init(void);
static void vlan_mon_timeout(struct triton_timer_t *t);
static void reload_interfaces();

static void vlan_mon_ctx_close(struct triton_context_t *ctx)
{
	log_debug("vlan-mon: vlan_mon_ctx close\n");

	pthread_rwlock_rdlock(&vlan_mon_devices_lock);

	struct vlan_mon_device* vl_dev = NULL;

	list_for_each_entry(vl_dev, &vlan_mon_devices, entry) {
		pthread_mutex_lock(&vl_dev->lock);

		if (vl_dev->timer.tpd)
			triton_timer_del(&vl_dev->timer);

		pthread_mutex_unlock(&vl_dev->lock);
	}

	pthread_rwlock_unlock(&vlan_mon_devices_lock);

	triton_context_unregister(ctx);
}

int vlan_mon_proto_to_proto(int proto)
{
	if (proto == 1)
		return ETH_P_PPP_DISC;
	else
		return ETH_P_IP;
}

int proto_to_vlan_mon_proto(int proto)
{
	if (proto == ETH_P_PPP_DISC)
		return 1;
	else
		return 0;
}

uint16_t get_another_proto(uint16_t proto)
{
	if (proto == ETH_P_PPP_DISC) {
		return ETH_P_IP;
	} else {
		return ETH_P_PPP_DISC;
	}
}

uint8_t vlan_mon_proto_to_mask(int proto)
{
	if (proto == 1)
		return VLAN_MON_DEVICE_SERVER_PPPOE;
	else
		return VLAN_MON_DEVICE_SERVER_IPOE;
}

uint8_t proto_to_mask(int proto)
{
	if (proto == ETH_P_PPP_DISC)
		return VLAN_MON_DEVICE_SERVER_PPPOE;
	else
		return VLAN_MON_DEVICE_SERVER_IPOE;
}

struct vlan_mon_upstream_notify* create_vlan_mon_notify(int ifindex, uint16_t vid, uint16_t proto)
{
	struct vlan_mon_upstream_notify *res = _malloc(sizeof(*res));
	if (!res)
		return NULL;

	memset(res, 0, sizeof(*res));
	res->ifindex = ifindex;
	res->vid     = vid;
	res->proto   = proto;

	return res;
}

void __export vlan_mon_register_proto(uint16_t proto, vlan_mon_callbacks cb)
{
	if (proto == ETH_P_PPP_DISC)
		proto = 1;
	else
		proto = 0;

	vlan_mon_cb[proto].notify       = cb.notify;
	vlan_mon_cb[proto].server_check = cb.server_check;
	vlan_mon_cb[proto].pre_down     = cb.pre_down;

	reload_interfaces();
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
		log_error("vlan-mon: cannot open generic netlink socket\n");
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

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_error("vlan-mon: nl_add_vlan_mon: error talking to kernel\n");
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
		log_error("vlan-mon: cannot open generic netlink socket\n");
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

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_error("vlan-mon: nl_add_vlan_mon_vid: error talking to kernel\n");
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
		log_error("vlan-mon: cannot open generic netlink socket\n");
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

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_error("vlan-mon: nl_add_vlan_mon_vid: error talking to kernel\n");
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
		log_error("vlan-mon: cannot open generic netlink socket\n");
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

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_error("vlan-mon: nl_del_vlan_mon: error talking to kernel\n");
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

	rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0);

	rtnl_close(&rth);
}

int __export vlan_mon_check_busy(int ifindex, uint16_t vid, uint16_t proto)
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
		log_error("vlan-mon: cannot open generic netlink socket\n");
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
	addattr_l(nlh, 1024, VLAN_MON_ATTR_PROTO, &proto, 2);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 1) < 0 ) {
		if (errno == EBUSY)
			r = -1;
	}

	rtnl_close(&rth);

	return r;
}

//====================WARNING==========================
//==============NOT THREAD SAFETY!=====================
//=====================================================
static struct vlan_mon_device* get_vlan_mon_device(int ifindex)
{
	struct vlan_mon_device* vl_dev = NULL;

	list_for_each_entry(vl_dev, &vlan_mon_devices, entry) {
		if (vl_dev->ifindex == ifindex) {
			return vl_dev;
		}
	}

	return NULL;
}

int search_servers_for_proto(int ifindex, uint16_t proto)
{
	int vlan_mon_proto = proto_to_vlan_mon_proto(proto);

	if ( vlan_mon_cb[vlan_mon_proto].server_check ) {

		return vlan_mon_cb[vlan_mon_proto].server_check(ifindex);

	}

	return 0;
}

//====================WARNING==========================
//=================USE WITH LOCK!======================
//=====================================================
static void vlan_mon_start_timer(struct vlan_mon_device *vl_dev)
{
	if (!vlan_mon_ctx.tpd) {
		log_debug("vlan-mon: start_timer: vlan_mon_ctx tpd is NULL\n");
		return;
	}

	vl_dev->timer.expire = vlan_mon_timeout;
	vl_dev->timer.expire_tv.tv_sec = conf_vlan_timeout;
	if (vl_dev->timer.tpd) {
		triton_timer_mod(&vl_dev->timer, 0);
	} else {
		triton_timer_add(&vlan_mon_ctx, &vl_dev->timer, 0);
	}
}

static int search_servers_on_vlan(int ifindex)
{
	for (int i = 0; i < 2; ++i) {
		int proto = vlan_mon_proto_to_proto(i);
		if (search_servers_for_proto(ifindex, proto)) {
			log_info2("vlan-mon: servers for proto=%04x EXISTS!\n", proto);
			return 1;
		}
	}

	return 0;
}

static void pre_down_upstream(int ifindex)
{
	for (int i = 0; i < 2; ++i) {
		if (vlan_mon_cb[i].pre_down) {
			vlan_mon_cb[i].pre_down(ifindex);
		}
	}
}

static void vlan_mon_timeout(struct triton_timer_t *t)
{
	pthread_rwlock_wrlock(&vlan_mon_devices_lock);
	struct vlan_mon_device *vl_dev = container_of(t, typeof(*vl_dev), timer);

	if (!vl_dev) {
		log_error("vlan-mon: timeout: vl_dev is NULL!\n");
		pthread_rwlock_unlock(&vlan_mon_devices_lock);
		return;
	}

	pthread_mutex_lock(&vl_dev->lock);
	if (vl_dev->client_mask) {
		log_warn("vlan-mon: timeout: while vlan deleting some client on server exists! ifindex=%i vid=%i\n", vl_dev->ifindex, vl_dev->vid);
		goto out;
	}

	struct vlan_mon_upstream_notify *notify;

	pthread_rwlock_rdlock(&vlan_mon_notify_lock);
	list_for_each_entry(notify, &vlan_mon_notify_list, entry) {
		if (notify->ifindex != vl_dev->ifindex)
			continue;
		pthread_rwlock_unlock(&vlan_mon_notify_lock);
		log_warn("vlan-mon: timeout: for ifindex=%i vid=%i exists notify. Restarting timer.\n", vl_dev->ifindex, vl_dev->vid);
		if (vl_dev->timer.tpd) {
			triton_timer_mod(&vl_dev->timer, 0);
		}
		goto out;
	}
	pthread_rwlock_unlock(&vlan_mon_notify_lock);

	//Send signal to upstream servers
	pre_down_upstream(vl_dev->ifindex);

out:
	pthread_mutex_unlock(&vl_dev->lock);
	pthread_rwlock_unlock(&vlan_mon_devices_lock);
}

//====================================
//========FOR CONTEXT CALLING=========
//====================================
static void _on_vlan_mon_upstream_server_have_clients(struct vlan_mon_upstream_notify *notify)
{
	if (!notify) {
		log_error("vlan-mon: ctx: vlan_mon_upstream_notify is NULL\n");
		return;
	}

	int ifindex    = notify->ifindex;
	uint16_t proto = notify->proto;

	pthread_rwlock_wrlock(&vlan_mon_notify_lock);
	list_del(&notify->entry);
	pthread_rwlock_unlock(&vlan_mon_notify_lock);

	//Memory was allocated just for calling function in context
	_free(notify);

	pthread_rwlock_rdlock(&vlan_mon_devices_lock);

	struct vlan_mon_device* vl_dev = get_vlan_mon_device(ifindex);
	if (!vl_dev) {
		log_warn("vlan-mon: ctx: have_clients: vlan_mon_device ifindex=%i not found!\n", ifindex);
		pthread_rwlock_unlock(&vlan_mon_devices_lock);
		return;
	}

	pthread_mutex_lock(&vl_dev->lock);
	//Add client by proto in vlan
	vl_dev->client_mask |= proto_to_mask(proto);

	if (vl_dev->timer.tpd) {
		triton_timer_del(&vl_dev->timer);
	}

	pthread_mutex_unlock(&vl_dev->lock);
	pthread_rwlock_unlock(&vlan_mon_devices_lock);
}

int __export on_vlan_mon_upstream_server_have_clients(int ifindex, uint16_t vid, uint16_t proto)
{
	if (!vlan_mon_ctx.tpd) {
		log_error("vlan-mon: have_clients: vlan_mon_ctx->tpd is NULL\n");
		return -1;
	}

	struct vlan_mon_upstream_notify *notify = create_vlan_mon_notify(ifindex, vid, proto);
	if (!notify) {
		log_error("vlan-mon: have_clients: cannot allocate memory for notify\n");
		return -1;
	}

	pthread_rwlock_wrlock(&vlan_mon_notify_lock);
	list_add_tail(&notify->entry, &vlan_mon_notify_list);
	pthread_rwlock_unlock(&vlan_mon_notify_lock);

	triton_context_call(&vlan_mon_ctx, (triton_event_func)_on_vlan_mon_upstream_server_have_clients, notify);

	return 0;
}

//====================================
//========FOR CONTEXT CALLING=========
//====================================
static void _on_vlan_mon_upstream_server_no_clients(struct vlan_mon_upstream_notify *notify)
{
	if (!notify) {
		log_error("vlan-mon: ctx: vlan_mon_upstream_notify is NULL\n");
		return;
	}

	int ifindex    = notify->ifindex;
	uint16_t proto = notify->proto;

	pthread_rwlock_wrlock(&vlan_mon_notify_lock);
	list_del(&notify->entry);
	pthread_rwlock_unlock(&vlan_mon_notify_lock);

	//Memory was allocated just for calling function in context
	_free(notify);

	pthread_rwlock_rdlock(&vlan_mon_devices_lock);

	struct vlan_mon_device* vl_dev = get_vlan_mon_device(ifindex);
	if (!vl_dev) {
		log_warn("vlan-mon: ctx: have_no_clients: vlan_mon_device ifindex=%i not found!\n", ifindex);
		pthread_rwlock_unlock(&vlan_mon_devices_lock);
		return;
	}

	pthread_mutex_lock(&vl_dev->lock);
	//Delete client by protocol in vlan
	vl_dev->client_mask &= ~proto_to_mask(proto);

	//If clients in upstream servers is present in vlan or not need to remove vlan then exit from function
	if (vl_dev->client_mask || !conf_vlan_timeout) {
		pthread_mutex_unlock(&vl_dev->lock);
		pthread_rwlock_unlock(&vlan_mon_devices_lock);
		return;
	}

	vlan_mon_start_timer(vl_dev);

	pthread_mutex_unlock(&vl_dev->lock);
	pthread_rwlock_unlock(&vlan_mon_devices_lock);
}

int __export on_vlan_mon_upstream_server_no_clients(int ifindex, uint16_t vid, uint16_t proto)
{
	if (!vlan_mon_ctx.tpd) {
		log_error("vlan-mon: have_no_clients: vlan_mon_ctx->tpd is NULL\n");
		return -1;
	}

	struct vlan_mon_upstream_notify *notify = create_vlan_mon_notify(ifindex, vid, proto);
	if (!notify) {
		log_error("vlan-mon: have_no_clients: cannot allocate memory for notify\n");
		return -1;
	}

	pthread_rwlock_wrlock(&vlan_mon_notify_lock);
	list_add_tail(&notify->entry, &vlan_mon_notify_list);
	pthread_rwlock_unlock(&vlan_mon_notify_lock);

	triton_context_call(&vlan_mon_ctx, (triton_event_func)_on_vlan_mon_upstream_server_no_clients, notify);

	return 0;
}

//====================================
//========FOR CONTEXT CALLING=========
//====================================
static void _on_vlan_mon_upstream_server_down(struct vlan_mon_upstream_notify *notify)
{
	if (!notify) {
		log_error("vlan-mon: ctx: vlan_mon_upstream_notify is NULL\n");
		return;
	}

	int ifindex    = notify->ifindex;
	uint16_t proto = notify->proto;

	pthread_rwlock_wrlock(&vlan_mon_notify_lock);
	list_del(&notify->entry);
	pthread_rwlock_unlock(&vlan_mon_notify_lock);

	//Memory was allocated just for calling function in context
	_free(notify);

	pthread_rwlock_wrlock(&vlan_mon_devices_lock);
	struct vlan_mon_device* vl_dev = get_vlan_mon_device(ifindex);

	if (!vl_dev) {
		log_warn("vlan-mon: vlan_mon_device ifindex=%i not found!\n", ifindex);
		pthread_rwlock_unlock(&vlan_mon_devices_lock);
		return;
	}

	pthread_mutex_lock(&vl_dev->lock);

	//Delete server for proto from vlan
	vl_dev->server_mask &= ~proto_to_mask(proto);
	vl_dev->client_mask &= ~proto_to_mask(proto);

	if (vl_dev->server_mask || search_servers_on_vlan(vl_dev->ifindex)) {
		log_warn("vlan-mon: ctx: serv_down: servers on vlan ifindex=%i vid=%i EXISTS!\n", vl_dev->ifindex, vl_dev->vid);
		vlan_mon_add_vid(vl_dev->parent_ifindex, proto, vl_dev->vid);
		pthread_mutex_unlock(&vl_dev->lock);
		pthread_rwlock_unlock(&vlan_mon_devices_lock);
		return;
	}

	list_del(&vl_dev->entry);

	if (vl_dev->timer.tpd) {
		triton_timer_del(&vl_dev->timer);
	}

	//If we can remove the interface then we remove it
	log_info2("vlan-mon: ctx: serv_down: remove vlan interface ifindex=%i vid=%i\n", vl_dev->ifindex, vl_dev->vid);
	iplink_vlan_del(vl_dev->ifindex);

	//Adding vlans in vlan_mon driver if protocol registered
	for (int i = 0; i < 2; ++i) {
		if (vlan_mon_cb[i].notify) {
			int proto = vlan_mon_proto_to_proto(i);
			vlan_mon_add_vid(vl_dev->parent_ifindex, proto, vl_dev->vid);
		}
	}

	pthread_mutex_unlock(&vl_dev->lock);

	_free(vl_dev);

	pthread_rwlock_unlock(&vlan_mon_devices_lock);
}

int __export on_vlan_mon_upstream_server_down(int ifindex, uint16_t vid, uint16_t proto)
{
	if (!vlan_mon_ctx.tpd) {
		log_error("vlan-mon: serv_down: vlan_mon_ctx->tpd is NULL\n");
		return -1;
	}

	struct vlan_mon_upstream_notify *notify = create_vlan_mon_notify(ifindex, vid, proto);
	if (!notify) {
		log_error("vlan-mon: serv_down: cannot allocate memory for notify\n");
		return -1;
	}

	pthread_rwlock_wrlock(&vlan_mon_notify_lock);
	list_add_tail(&notify->entry, &vlan_mon_notify_list);
	pthread_rwlock_unlock(&vlan_mon_notify_lock);

	triton_context_call(&vlan_mon_ctx, (triton_event_func)_on_vlan_mon_upstream_server_down, notify);

	return 0;
}


//Create a vlan interface and then make an ipoe or pppoe callback
static void vlan_mon_driver_callback(int proto, int ifindex, int vid, int vlan_ifindex)
{
	struct ifreq ifr;
	int svid, r, len;
	char ifname[IFNAMSIZ];

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;
	if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
		log_error("vlan-mon: failed to get interface name, ifindex=%i\n", ifindex);
		return;
	}

	svid = iplink_vlan_get_vid(ifindex, NULL);

#ifdef USE_LUA
	if (!memcmp(conf_vlan_name, "lua:", 4))
		r = ipoe_lua_make_vlan_name(conf_vlan_name + 4, ifr.ifr_name, svid, vid, ifname);
	else
#endif
	r = make_vlan_name(conf_vlan_name, ifr.ifr_name, svid, vid, ifname);
	if (r) {
		log_error("vlan-mon: %s.%i: interface name is too long\n", ifr.ifr_name, vid);
		return;
	}

	pthread_rwlock_wrlock(&vlan_mon_devices_lock);

	if (vlan_ifindex) {
		log_info2("vlan-mon: using vlan %s parent %s\n", ifname, ifr.ifr_name);

		ifr.ifr_ifindex = vlan_ifindex;
		if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
			log_error("vlan-mon: failed to get interface name, ifindex=%i\n", ifr.ifr_ifindex);
			//Interface maybe deleted
			vlan_mon_add_vid(ifindex, vlan_mon_proto_to_proto(proto), vid);
			goto out;
		}

		if (strcmp(ifr.ifr_name, ifname)) {
			strcpy(ifr.ifr_newname, ifname);
			if (ioctl(sock_fd, SIOCSIFNAME, &ifr, sizeof(ifr))) {
				log_error("vlan-mon: failed to rename interface %s to %s\n", ifr.ifr_name, ifr.ifr_newname);
				//Interface maybe deleted
				vlan_mon_add_vid(ifindex, vlan_mon_proto_to_proto(proto), vid);
				goto out;
			}
			strcpy(ifr.ifr_name, ifname);
		}
	} else {
		log_info2("vlan-mon: create vlan %s parent %s\n", ifname, ifr.ifr_name);

		if (iplink_vlan_add(ifname, ifindex, vid)) {
			log_error("vlan-mon: failed to create interface. Parent=%i name=%s vid=%i\n", ifindex, ifname, vid);
			//Sometimes the vlan_mon driver send notify faster then the previous request be processed.
			//So, device cannot be created because it already exists
			vlan_mon_add_vid(ifindex, vlan_mon_proto_to_proto(proto), vid);
			goto out;
		}

	}

	len = strlen(ifname);
	memcpy(ifr.ifr_name, ifname, len + 1);

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr, sizeof(ifr))) {
		log_error("vlan-mon: %s: failed to get interface index\n", ifr.ifr_name);
		//Interface maybe deleted
		vlan_mon_add_vid(ifindex, vlan_mon_proto_to_proto(proto), vid);
		goto out;
	}

	vlan_ifindex = ifr.ifr_ifindex;

	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr, sizeof(ifr))) {
		log_error("vlan-mon: failed to get interface flags, ifindex=%i\n", ifr.ifr_ifindex);
		//Interface maybe deleted
		vlan_mon_add_vid(ifindex, vlan_mon_proto_to_proto(proto), vid);
		goto out;
	}

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr, sizeof(ifr))) {
			log_error("vlan-mon: failed to set interface flags, ifindex=%i\n", ifr.ifr_ifindex);
			//Interface maybe deleted
			vlan_mon_add_vid(ifindex, vlan_mon_proto_to_proto(proto), vid);
			goto out;
		}
	}

	//Send params to pppoe or ipoe callback
	//ifindex      - vlan interface parent ifindex
	//svid         - vlan id of parent interface
	//vid          - vlan id of new interface
	//vlan_ifindex - ifindex of new interface
	//ifname       - interface name of new vlan interface
	//len          - length of ifname
	//Return 0 if success, not 0 else
	if (vlan_mon_cb[proto].notify) {
		if (!vlan_mon_cb[proto].notify(ifindex, svid, vid, vlan_ifindex, ifname, len)) {
			log_debug("vlan-mon: vlan %s started\n", ifname);

			//Searching vlan_mon_device by ifindex
			struct vlan_mon_device* vl_dev = get_vlan_mon_device(vlan_ifindex);
			if (vl_dev) {
				pthread_mutex_lock(&vl_dev->lock);
				vl_dev->server_mask |= vlan_mon_proto_to_mask(proto);
				pthread_mutex_unlock(&vl_dev->lock);
			} else {
				vl_dev = _malloc(sizeof(struct vlan_mon_device));
				if (!vl_dev) {
					log_error("vlan-mon: failed to create vlan_mon_device ifindex=%i name=%s\n", vlan_ifindex, ifname);
					goto out;
				}

				memset(vl_dev, 0, sizeof(*vl_dev));

				vl_dev->parent_ifindex = ifindex;
				vl_dev->ifindex = vlan_ifindex;
				vl_dev->server_mask = vlan_mon_proto_to_mask(proto);
				vl_dev->vid = vid;
				pthread_mutex_init(&vl_dev->lock, NULL);

				list_add_tail(&vl_dev->entry, &vlan_mon_devices);

				if (conf_vlan_timeout)
					vlan_mon_start_timer(vl_dev);
			}

		} else {
			log_warn("vlan-mon: vlan %s not started\n", ifname);

			struct vlan_mon_device* vl_dev = get_vlan_mon_device(vlan_ifindex);
			//If interface does not match by upstream server then delete and deregister proto in vlan
			if (!vl_dev) {
				iplink_vlan_del(vlan_ifindex);
			}
			//If interface does not match by upstream server, but created by another proto
			//then deregister proto in vlan
			vlan_mon_del_vid(ifindex, vlan_mon_proto_to_proto(proto), vid);
		}
	} else {
		log_debug("vlan-mon: vlan %s does not have a registered callback\n", ifname);

		struct vlan_mon_device* vl_dev = get_vlan_mon_device(vlan_ifindex);
		//If callback is not registered
		//and vlan_mon_device not created by another proto,
		//then delete vlan and deregister proto in vlan
		if (!vl_dev) {
			iplink_vlan_del(vlan_ifindex);
		}
		//If device created by another proto, then deregister vlan for proto
		vlan_mon_del_vid(ifindex, vlan_mon_proto_to_proto(proto), vid);
	}

out:
	pthread_rwlock_unlock(&vlan_mon_devices_lock);
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
		log_warn("vlan-mon: wrong controller message length %d\n", len);
		return;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	parse_rtattr(tb, PKT_ATTR_MAX, attrs, len);

	for (i = 1; i < PKT_ATTR_MAX; i++) {
		if (!tb[i])
			break;

		parse_rtattr_nested(tb2, VLAN_MON_ATTR_MAX, tb[i]);

		//if (!tb2[VLAN_MON_ATTR_IFINDEX] || !tb2[VLAN_MON_ATTR_VID] || !t)
		//	continue;

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

		vlan_mon_driver_callback(proto, ifindex, vid, vlan_ifindex);

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
			log_error("vlan-mon: netlink error: %s\n", strerror(errno));
			if (errno == ENOBUFS)
				continue;
			return 0;
		}

		if (status == 0) {
			log_error("vlan-mon: EOF on netlink\n");
			return 0;
		}

		if (msg.msg_namelen != sizeof(nladdr)) {
			log_error("vlan-mon: netlink sender address length == %d\n", msg.msg_namelen);
			return 0;
		}

		for (hdr = (struct nlmsghdr*)buf; status >= sizeof(*hdr); ) {
			int len = hdr->nlmsg_len;
			int l = len - sizeof(*h);

			if (l<0 || len>status) {
				if (msg.msg_flags & MSG_TRUNC) {
					log_warn("vlan-mon: truncated netlink message\n");
					continue;
				}
				log_error("vlan-mon: malformed netlink message\n");
				continue;
			}

			ghdr = NLMSG_DATA(hdr);

			if (ghdr->cmd == VLAN_MON_NOTIFY)
				vlan_mon_handler(&nladdr, hdr);

			status -= NLMSG_ALIGN(len);
			hdr = (struct nlmsghdr*)((char*)hdr + NLMSG_ALIGN(len));
		}

		if (msg.msg_flags & MSG_TRUNC) {
			log_warn("vlan-mon: netlink message truncated\n");
			continue;
		}

		if (status) {
			log_error("vlan-mon: netlink remnant of size %d\n", status);
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
	log_error("vlan-mon: vlan-mon=%s: failed to parse\n", opt);
	return -1;
}

static int __load_vlan_mon_re(int index, int flags, const char *name, int iflink, int vid, struct iplink_arg *arg)
{
	struct ifreq ifr;
	long mask1[4096/8/sizeof(long)];

	if (pcre_exec(arg->re, NULL, name, strlen(name), 0, 0, NULL, 0) < 0)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, name);

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr);

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	memcpy(mask1, arg->arg1, sizeof(mask1));
	vlan_mon_add(index, ETH_P_PPP_DISC,  mask1, sizeof(mask1));
	vlan_mon_add(index, ETH_P_IP,  mask1, sizeof(mask1));

	return 0;
}

static void load_vlan_mon_re(const char *opt, long *mask, int len)
{
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	const char *ptr;
	int pcre_offset;
	struct iplink_arg arg;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	pattern = _malloc(ptr - (opt + 3) + 1);
	memcpy(pattern, opt + 3, ptr - (opt + 3));
	pattern[ptr - (opt + 3)] = 0;

	re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

	if (!re) {
		log_error("vlan-mon: '%s': %s at %i\r\n", pattern, pcre_err, pcre_offset);
		return;
	}

	arg.re = re;
	arg.opt = opt;
	arg.arg1 = mask;

	iplink_list((iplink_list_func)__load_vlan_mon_re, &arg);

	pcre_free(re);
	_free(pattern);

}

static void add_vlan_mon(const char *opt, long *mask)
{
	const char *ptr;
	struct ifreq ifr;
	int ifindex;
	long mask1[4096/8/sizeof(long)];

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	if (ptr - opt >= IFNAMSIZ) {
		log_error("vlan-mon: vlan-mon=%s: interface name is too long\n", opt);
		return;
	}

	memset(&ifr, 0, sizeof(ifr));

	memcpy(ifr.ifr_name, opt, ptr - opt);
	ifr.ifr_name[ptr - opt] = 0;

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_error("vlan-mon: '%s': ioctl(SIOCGIFINDEX): %s\n", ifr.ifr_name, strerror(errno));
		return;
	}

	ifindex = ifr.ifr_ifindex;

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr);

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	memcpy(mask1, mask, sizeof(mask1));
	vlan_mon_add(ifindex, ETH_P_PPP_DISC, mask1, sizeof(mask1));
	vlan_mon_add(ifindex, ETH_P_IP, mask1, sizeof(mask1));
}

static void clean_interfaces()
{
	//Clean all interfaces
	vlan_mon_del(-1, ETH_P_PPP_DISC);
	vlan_mon_del(-1, ETH_P_IP);
}

static void load_interfaces(struct conf_sect_t *sect)
{
	struct conf_option_t *opt;
	long mask[4096/8/sizeof(long)];

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "vlan-mon"))
			continue;

		if (!opt->val)
			continue;

		if (parse_vlan_mon(opt->val, mask))
			continue;

		if (strlen(opt->val) > 3 && !memcmp(opt->val, "re:", 3)) {
			load_vlan_mon_re(opt->val, mask, sizeof(mask));
		} else {
			add_vlan_mon(opt->val, mask);
		}
	}
}

static void reload_interfaces()
{
	clean_interfaces();

	struct conf_sect_t *s = conf_get_section("pppoe");
	if (s) {
		load_interfaces(s);
	}

	s = conf_get_section("ipoe");
	if (s) {
		load_interfaces(s);
	}

	s = conf_get_section("vlan-mon");
	if (s) {
		clean_interfaces();
		load_interfaces(s);
	}
}

//For backward compatibility
static void load_deprecated_sect(char* sect_name)
{
	char *opt;
	struct conf_sect_t *s = conf_get_section(sect_name);
	int deprecated = 0;

	if (!s)
		return;

	opt = conf_get_opt(sect_name, "vlan-name");
	if (opt) {
		deprecated = 1;
		strncpy(conf_vlan_name, opt, IFNAMSIZ);
		conf_vlan_name[IFNAMSIZ-1] = 0;
	}

	opt = conf_get_opt(sect_name, "vlan-timeout");
	if (opt) {
		deprecated = 1;
		char *p = NULL;
		conf_vlan_timeout = strtol(opt, &p, 10);
		if (*p)
			conf_vlan_timeout = 60;
	}

	opt = conf_get_opt(sect_name, "vlan-mon");
	if (opt) {
		deprecated = 1;
		load_interfaces(s);
	}

	if (deprecated)
		log_warn("vlan-mon: [%s] vlan-mon configuration is deprecated\n", sect_name);
}

static void load_config(void *data)
{
	clean_interfaces();
	load_deprecated_sect("pppoe");
	load_deprecated_sect("ipoe");

	char *opt;
	struct conf_sect_t *s = conf_get_section("vlan-mon");

	if (s) {

		opt = conf_get_opt("vlan-mon", "vlan-name");
		if (opt) {
			strncpy(conf_vlan_name, opt, IFNAMSIZ);
		} else {
			strncpy(conf_vlan_name, "%I.%N", IFNAMSIZ);
		}
		//Make string null-terminated
		conf_vlan_name[IFNAMSIZ-1] = 0;

		//Loading vlan-timeout if specified
		//If there is an error in the value, then conf_vlan_timeout=60
		//If no value is specified, then conf_vlan_timeout=60
		opt = conf_get_opt("vlan-mon", "vlan-timeout");
		if (opt) {
			char *p = NULL;
			conf_vlan_timeout = strtol(opt, &p, 10);
			if (*p)
				conf_vlan_timeout = 60;
		} else {
			conf_vlan_timeout = 60;
		}

		clean_interfaces();
		load_interfaces(s);
	}

	log_debug("vlan-mon: vlan-name=%s vlan-timeout=%i\n", conf_vlan_name, conf_vlan_timeout);
}

static void show_vlan_help(char * const *fields, int fields_cnt, void *client)
{
	cli_sendv(client, "show vlan - shows vlans that registered in vlan-mon\r\n");
}

static int show_vlan_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_sendv(client, "%-16s %-16s %-16s %-16s %-8s %-12s %-12s\r\n", "parent_if", "parent_ifindex", "interface", "ifindex", "vlan_id", "pppoe s/c", "ipoe s/c");

	LIST_HEAD(vl_dev_list);
	struct vlan_mon_device* vl_dev = NULL;
	struct vlan_mon_device* new_vl_dev = NULL;

	//Copy data
	pthread_rwlock_rdlock(&vlan_mon_devices_lock);
	list_for_each_entry(vl_dev, &vlan_mon_devices, entry) {
		pthread_mutex_lock(&vl_dev->lock);

		new_vl_dev = _malloc(sizeof(*vl_dev));
		if (!new_vl_dev) {
			cli_sendv(client, "Cannot allocate memory!\r\n");

			pthread_mutex_unlock(&vl_dev->lock);
			pthread_rwlock_unlock(&vlan_mon_devices_lock);
			goto out;
		}

		memcpy(new_vl_dev, vl_dev, sizeof(*vl_dev));
		list_add_tail(&new_vl_dev->entry, &vl_dev_list);

		pthread_mutex_unlock(&vl_dev->lock);
	}
	pthread_rwlock_unlock(&vlan_mon_devices_lock);


	char parent_ifname[IFNAMSIZ];
	char ifname[IFNAMSIZ];

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	//Show data
	list_for_each_entry(vl_dev, &vl_dev_list, entry) {

		ifr.ifr_ifindex = vl_dev->ifindex;
		if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
			strncpy(ifname, "unknown", IFNAMSIZ);
		} else {
			strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
		}
		ifname[IFNAMSIZ-1] = 0;

		ifr.ifr_ifindex = vl_dev->parent_ifindex;
		if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
			strncpy(parent_ifname, "unknown", IFNAMSIZ);
		} else {
			strncpy(parent_ifname, ifr.ifr_name, IFNAMSIZ);
		}
		parent_ifname[IFNAMSIZ-1] = 0;

		uint8_t pppoe_server_present = vl_dev->server_mask & VLAN_MON_DEVICE_SERVER_PPPOE ? 1 : 0;
		uint8_t ipoe_server_present  = vl_dev->server_mask & VLAN_MON_DEVICE_SERVER_IPOE ? 1 : 0;

		uint8_t pppoe_client_present = vl_dev->client_mask & VLAN_MON_DEVICE_SERVER_PPPOE ? 1 : 0;
		uint8_t ipoe_client_present  = vl_dev->client_mask & VLAN_MON_DEVICE_SERVER_IPOE ? 1 : 0;

		cli_sendv(client, "%-16s %-16u %-16s %-16u %-8u %u/%-10u %u/%-10u\r\n", parent_ifname, vl_dev->parent_ifindex,
					ifname, vl_dev->ifindex, vl_dev->vid, pppoe_server_present, pppoe_client_present, ipoe_server_present, ipoe_client_present);
	}

	//Free local copy
out:
	while (!list_empty(&vl_dev_list)) {
		vl_dev = list_entry(vl_dev_list.next, typeof(*vl_dev), entry);
		list_del(&vl_dev->entry);
		_free(vl_dev);
	}

	return CLI_CMD_OK;
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

static void vlan_mon_init(void)
{
	int mcg_id;

	if (access("/sys/module/vlan_mon", F_OK) && system("modprobe -q vlan_mon"))
		log_warn("failed to load vlan_mon module\n");

	mcg_id = genl_resolve_mcg(VLAN_MON_GENL_NAME, VLAN_MON_GENL_MCG, &vlan_mon_genl_id);
	if (mcg_id == -1) {
		log_warn("vlan-mon: kernel module is not loaded\n");
		vlan_mon_genl_id = -1;
		return;
	}

	if (rtnl_open_byproto(&rth, 1 << (mcg_id - 1), NETLINK_GENERIC)) {
		log_error("vlan-mon: cannot open generic netlink socket\n");
		vlan_mon_genl_id = -1;
		return;
	}

	vlan_mon_clean();
	load_config(NULL);

	triton_context_register(&vlan_mon_ctx, NULL);
	triton_context_wakeup(&vlan_mon_ctx);

	fcntl(rth.fd, F_SETFL, O_NONBLOCK);
	fcntl(rth.fd, F_SETFD, fcntl(rth.fd, F_GETFD) | FD_CLOEXEC);

	mc_ctx.before_switch = mc_ctx_switch;
	triton_context_register(&mc_ctx, NULL);
	mc_hnd.fd = rth.fd;
	triton_md_register_handler(&mc_ctx, &mc_hnd);
	triton_md_enable_handler(&mc_hnd, MD_MODE_READ);
	triton_context_wakeup(&mc_ctx);

	cli_register_simple_cmd2(show_vlan_exec, show_vlan_help, 2, "show", "vlan");

	triton_event_register_handler(EV_CONFIG_RELOAD, load_config);
}

DEFINE_INIT(19, vlan_mon_init);
