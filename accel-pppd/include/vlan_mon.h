#ifndef __VLAN_MON_H
#define __VLAN_MON_H

#include <stdint.h>

#define VLAN_MON_DEVICE_SERVER_PPPOE	0x01
#define VLAN_MON_DEVICE_SERVER_IPOE	0x02

struct vlan_mon_device {
	struct list_head entry;

	pthread_mutex_t lock;

	int parent_ifindex;
	int ifindex;
	uint16_t vid;
	uint8_t client_mask;
	uint8_t server_mask;

	struct triton_timer_t timer;
};

struct vlan_mon_upstream_notify {
	struct list_head entry;

	int ifindex;
	uint16_t vid;
	uint16_t proto;
};

//------------Callbacks for the upstream protocols-------------

//Executed after the interface is created
typedef int (*on_vlan_mon_notify)(int ifindex, int svid, int vid, int vlan_ifindex, char* vlan_ifname, int vlan_ifname_len);
//Checking existing servers on the interface
typedef int (*on_vlan_mon_upstream_server_check)(int ifindex);
//Performed before deleting the interface
typedef int (*on_vlan_mon_interface_pre_down)(int ifindex);

typedef struct {
	on_vlan_mon_notify notify;
	on_vlan_mon_upstream_server_check server_check;
	on_vlan_mon_interface_pre_down pre_down;
} vlan_mon_callbacks;

//-------------------------------------------------------------

//Register callback for proto
void vlan_mon_register_proto(uint16_t proto, vlan_mon_callbacks cb);

//int vlan_mon_serv_down(int ifindex, uint16_t, uint16_t proto);
//Called by upstream servers when they have no clients
int on_vlan_mon_upstream_server_no_clients(int ifindex, uint16_t vid, uint16_t proto);
//Called by upstream servers when they have clients
int on_vlan_mon_upstream_server_have_clients(int ifindex, uint16_t vid, uint16_t proto);
//Called by upstream servers when they down
int on_vlan_mon_upstream_server_down(int ifindex, uint16_t vid, uint16_t proto);

int vlan_mon_add(int ifindex, uint16_t proto, long *mask, int len);
int vlan_mon_add_vid(int ifindex, uint16_t proto, uint16_t vid);
int vlan_mon_del_vid(int ifindex, uint16_t proto, uint16_t vid);
int vlan_mon_del(int ifindex, uint16_t proto);
int vlan_mon_check_busy(int ifindex, uint16_t vid, uint16_t proto);

int make_vlan_name(const char *pattern, const char *parent, int svid, int cvid, char *name);
int parse_vlan_mon(const char *opt, long *mask);

#endif
