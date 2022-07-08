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
	uint8_t serv_mask;
};

extern struct list_head vlan_mon_devices;
extern pthread_rwlock_t vlan_mon_devices_lock;

__export extern int conf_vlan_timeout;

typedef int (*vlan_mon_notify)(int ifindex, int svid, int vid, int vlan_ifindex, char* vlan_ifname, int vlan_ifname_len);

void vlan_mon_register_proto(uint16_t proto, vlan_mon_notify cb);

int vlan_mon_add(int ifindex, uint16_t proto, long *mask, int len);
int vlan_mon_add_vid(int ifindex, uint16_t proto, uint16_t vid);
int vlan_mon_del_vid(int ifindex, uint16_t proto, uint16_t vid);
int vlan_mon_del(int ifindex, uint16_t proto);
int vlan_mon_check_busy(int ifindex, uint16_t vid, uint16_t proto);

int vlan_mon_serv_down(int ifindex, uint16_t, uint16_t proto);

int make_vlan_name(const char *pattern, const char *parent, int svid, int cvid, char *name);
int parse_vlan_mon(const char *opt, long *mask);

#endif
