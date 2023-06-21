#ifndef __LINUX_IPOE_H
#define __LINUX_IPOE_H

#include <linux/types.h>

enum {
	IPOE_CMD_NOOP,
	IPOE_CMD_CREATE,
	IPOE_CMD_DELETE,
	IPOE_CMD_MODIFY,
	IPOE_CMD_GET,
	IPOE_CMD_ADD_IF,
	IPOE_CMD_DEL_IF,
	IPOE_REP_PKT,
	IPOE_CMD_ADD_EXCLUDE,
	IPOE_CMD_DEL_EXCLUDE,
	IPOE_CMD_ADD_NET,
	IPOE_CMD_DEL_NET,
	__IPOE_CMD_MAX,
};

#define IPOE_CMD_MAX			(__IPOE_CMD_MAX - 1)

enum {
	IPOE_ATTR_NONE,			 /* no data */
	IPOE_ATTR_ADDR,		   /* u32 */
	IPOE_ATTR_PEER_ADDR,	 /* u32 */
	IPOE_ATTR_GW_ADDR,	   /* u32 */
	IPOE_ATTR_HWADDR,	   /* u32 */
	IPOE_ATTR_MASK,	   /* u32 */
	IPOE_ATTR_IFINDEX,	   /* u32 */
	IPOE_ATTR_LINK_IFINDEX,	   /* u32 */
	IPOE_ATTR_ETH_HDR,	   /* u32 */
	IPOE_ATTR_IP_HDR,	   /* u32 */
	IPOE_ATTR_MODE,	   /* u8 */
	IPOE_ATTR_ARP_HDR,	   /* u8 */
	__IPOE_ATTR_MAX,
};

#define IPOE_ATTR_MAX			(__IPOE_ATTR_MAX - 1)

/*
 * NETLINK_GENERIC related info
 */
#define IPOE_GENL_NAME		  "IPoE"
#define IPOE_GENL_MCG_PKT		"Packet"
#define IPOE_GENL_VERSION	  0x02

typedef void (*interface_mon_notify)(int ifindex, const char *ifname, bool add);

void ipoe_netlink_mon_register(interface_mon_notify func);

#endif

