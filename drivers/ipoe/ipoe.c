#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/mroute.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/semaphore.h>
#include <linux/netfilter_ipv4.h>
#include <linux/u64_stats_sync.h>
#include <linux/version.h>

#include <net/genetlink.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/flow.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/pkt_sched.h>
#include <net/ip6_route.h>

#include "ipoe.h"
#include "version.h"

#define BEGIN_UPDATE 1
#define UPDATE 2
#define END_UPDATE 3

#define IPOE_HASH_BITS 0xff

#define IPOE_MAGIC 0x55aa
#define IPOE_MAGIC2 0x67f8bc32

#define IPOE_QUEUE_LEN 100
#define IPOE_RATE_U 3000 //3s
#define IPOE_TIMEOUT_U 30 //5s

#define IPOE_NLMSG_SIZE (NLMSG_DEFAULT_SIZE - GENL_HDRLEN - 128)

#ifndef DEFINE_SEMAPHORE
#define DEFINE_SEMAPHORE(name) struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)
#endif

#ifndef RHEL_MAJOR
#define RHEL_MAJOR 0
#endif

struct ipoe_stats {
	struct u64_stats_sync sync;
	u64 packets;
	u64 bytes;
};

struct ipoe_session {
	struct list_head entry; //ipoe_list
	struct list_head entry2; //ipoe_list2
	struct list_head entry3; //ipoe_list3

	__be32 addr;
	__be32 peer_addr;
	__be32 gw;

	union {
		__u8 hwaddr[ETH_ALEN];
		__u64 hwaddr_u;
	} u;

	struct net_device *dev;
	struct net_device *link_dev;

	atomic_t refs;

	struct ipoe_stats __percpu *rx_stats;
	struct ipoe_stats __percpu *tx_stats;
};

struct ipoe_network {
	struct rcu_head rcu_head;
	struct list_head entry;

	__be32 addr;
	__be32 mask;
};

struct ipoe_iface {
	struct rcu_head rcu_head;
	struct list_head entry;

	int ifindex;
	int mode;
};

struct ipoe_entry_u {
	struct rcu_head rcu_head;
	struct list_head entry1;
	struct list_head entry2;

	__be32 addr;
	unsigned long tstamp;
};


struct _arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

	 /*
	  *	 Ethernet looks like this : This bit is variable sized however...
	  */
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	__be32		ar_sip;		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	__be32		ar_tip;		/* target IP address		*/
} __packed;


static struct list_head ipoe_list[IPOE_HASH_BITS + 1];
static struct list_head ipoe_list3[IPOE_HASH_BITS + 1];
static struct list_head ipoe_list1_u[IPOE_HASH_BITS + 1];
static struct list_head ipoe_excl_list[IPOE_HASH_BITS + 1];
static LIST_HEAD(ipoe_list2);
static LIST_HEAD(ipoe_list2_u);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
static DEFINE_SEMAPHORE(ipoe_wlock);
#else
static DEFINE_SEMAPHORE(ipoe_wlock,1);
#endif
static LIST_HEAD(ipoe_interfaces);
static LIST_HEAD(ipoe_networks);
static struct work_struct ipoe_queue_work;
static struct sk_buff_head ipoe_queue;



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void ipoe_start_queue_work(struct timer_list *unused);
static DEFINE_TIMER(ipoe_timer_u, ipoe_start_queue_work);
#else
static void ipoe_start_queue_work(unsigned long);
static DEFINE_TIMER(ipoe_timer_u, ipoe_start_queue_work, 0, 0);
#endif

static struct ipoe_session *ipoe_lookup(__be32 addr);
static int ipoe_do_nat(struct sk_buff *skb, __be32 new_addr, int to_peer);
static int ipoe_queue_u(struct sk_buff *skb, __be32 addr);
static int ipoe_lookup1_u(__be32 addr, unsigned long *ts);

static struct net *pick_net(struct sk_buff *skb);

static const struct net_device_ops ipoe_netdev_ops;

static struct genl_family ipoe_nl_family;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && RHEL_MAJOR < 7
static struct genl_multicast_group ipoe_nl_mcg;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) || RHEL_MAJOR == 7
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
#define u64_stats_fetch_begin_bh u64_stats_fetch_begin
#define u64_stats_fetch_retry_bh u64_stats_fetch_retry
#else
#define u64_stats_fetch_begin_bh u64_stats_fetch_begin_irq
#define u64_stats_fetch_retry_bh u64_stats_fetch_retry_irq
#endif
#endif

#ifndef NETIF_F_HW_VLAN_FILTER
#define NETIF_F_HW_VLAN_FILTER NETIF_F_HW_VLAN_CTAG_FILTER
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
#define nla_nest_start_noflag(skb, attr) nla_nest_start(skb, attr)
#endif

static inline int hash_addr(__be32 addr)
{
#ifdef __LITTLE_ENDIAN
	return ((addr >> 24) ^ (addr >> 16)) & IPOE_HASH_BITS;
#else
	return (addr  ^ (addr >> 8)) & IPOE_HASH_BITS;
#endif
}

static void ipoe_update_stats(struct sk_buff *skb, struct ipoe_stats *st, int corr)
{
	u64_stats_update_begin(&st->sync);
	st->packets++;
	st->bytes += skb->len - corr;
	u64_stats_update_end(&st->sync);
}

static int ipoe_check_network(__be32 addr)
{
	struct ipoe_network *n;
	int r;

	if (list_empty(&ipoe_networks))
		return 1;

	r = 0;
	addr = ntohl(addr);

	rcu_read_lock();
	list_for_each_entry_rcu(n, &ipoe_networks, entry) {
		if ((addr & n->mask) == n->addr) {
			r = 1;
			break;
		}
	}
	rcu_read_unlock();

	return r;
}

static int ipoe_check_exclude(__be32 addr)
{
	struct ipoe_network *n;
	struct list_head *ht;
	int r = 0;

	ht = &ipoe_excl_list[hash_addr(addr)];

	rcu_read_lock();

	list_for_each_entry_rcu(n, ht, entry) {
		if (addr  == n->addr) {
			r = 1;
			break;
		}
	}

	rcu_read_unlock();

	return r;
}

static int check_nat_required(struct sk_buff *skb, struct net_device *link)
{
	struct net *net = pick_net(skb);
	struct rtable *rt;
	struct flowi4 fl4;
	struct iphdr *iph = ip_hdr(skb);
	int r = 0;

	if (!list_empty(&ipoe_networks))
		return ipoe_check_network(iph->daddr) == 0;

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = iph->daddr;
	fl4.flowi4_tos = RT_TOS(0);
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
	if (rt->rt_gateway || (rt->dst.dev != link && rt->dst.dev != skb->dev))
		r = 1;
#else
	if (rt->rt_gw4 || (rt->dst.dev != link && rt->dst.dev != skb->dev))
		r = 1;
#endif

	ip_rt_put(rt);

	return r;
}

static int ipoe_do_nat(struct sk_buff *skb, __be32 new_addr, int to_peer)
{
	struct iphdr  *iph;
	int noff;
	int ihl;
	__be32 addr;

	noff = skb_network_offset(skb);

	iph = ip_hdr(skb);

	if (to_peer)
		addr = iph->daddr;
	else
		addr = iph->saddr;

	if (skb_cloned(skb) &&
			!skb_clone_writable(skb, sizeof(*iph) + noff) &&
			pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -1;

	iph = ip_hdr(skb);

	if (to_peer)
		iph->daddr = new_addr;
	else
		iph->saddr = new_addr;

	csum_replace4(&iph->check, addr, new_addr);

	ihl = iph->ihl * 4;

	switch ((iph->frag_off & htons(IP_OFFSET)) ? 0 : iph->protocol) {
	case IPPROTO_TCP:
	{
		struct tcphdr *tcph;

		if (!pskb_may_pull(skb, ihl + sizeof(*tcph) + noff) ||
				(skb_cloned(skb) &&
				 !skb_clone_writable(skb, ihl + sizeof(*tcph) + noff) &&
				 pskb_expand_head(skb, 0, 0, GFP_ATOMIC)))
			return -1;

		tcph = (void *)(skb_network_header(skb) + ihl);
		inet_proto_csum_replace4(&tcph->check, skb, addr, new_addr, 1);
		break;
	}
	case IPPROTO_UDP:
	{
		struct udphdr *udph;

		if (!pskb_may_pull(skb, ihl + sizeof(*udph) + noff) ||
				(skb_cloned(skb) &&
				 !skb_clone_writable(skb, ihl + sizeof(*udph) + noff) &&
				 pskb_expand_head(skb, 0, 0, GFP_ATOMIC)))
			return -1;

		udph = (void *)(skb_network_header(skb) + ihl);
		if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
			inet_proto_csum_replace4(&udph->check, skb, addr, new_addr, 1);
			if (!udph->check)
				udph->check = CSUM_MANGLED_0;
		}
		break;
	}
	case IPPROTO_ICMP:
	{
		struct icmphdr *icmph;

		if (!pskb_may_pull(skb, ihl + sizeof(*icmph) + noff))
			return -1;

		icmph = (void *)(skb_network_header(skb) + ihl);

		if ((icmph->type != ICMP_DEST_UNREACH) &&
				(icmph->type != ICMP_TIME_EXCEEDED) &&
				(icmph->type != ICMP_PARAMETERPROB))
			break;

		if (!pskb_may_pull(skb, ihl + sizeof(*icmph) + sizeof(*iph) +
					noff))
			return -1;

		icmph = (void *)(skb_network_header(skb) + ihl);
		iph = (void *)(icmph + 1);

		if (skb_cloned(skb) &&
				!skb_clone_writable(skb, ihl + sizeof(*icmph) +
							 sizeof(*iph) + noff) &&
				pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
			return -1;

		icmph = (void *)(skb_network_header(skb) + ihl);
		iph = (void *)(icmph + 1);
		if (to_peer)
			iph->saddr = new_addr;
		else
			iph->daddr = new_addr;

		inet_proto_csum_replace4(&icmph->checksum, skb, addr, new_addr, 0);
		break;
	}
	default:
		break;
	}

	return 0;
}

static struct net *pick_net(struct sk_buff *skb)
{
#ifdef CONFIG_NET_NS
	const struct dst_entry *dst;

	if (skb->dev != NULL)
		return dev_net(skb->dev);
	dst = skb_dst(skb);
	if (dst != NULL && dst->dev != NULL)
		return dev_net(dst->dev);
#endif
	return &init_net;
}

/*static int ipoe_route4(struct sk_buff *skb, __be32 gw, int oif)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct net *net = pick_net(skb);
	struct rtable *rt;

	struct flowi4 fl4;

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = gw;
	fl4.flowi4_oif = oif;
	fl4.flowi4_tos = RT_TOS(iph->tos) | RTO_ONLINK;
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return -1;

	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);
	skb->dev = rt->dst.dev;

	return 0;
}*/

static netdev_tx_t ipoe_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipoe_session *ses = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;
	struct iphdr  *iph;
	struct sk_buff *skb1;
	//struct dst_entry *dst;
	/*struct arphdr *arp;
	unsigned char *arp_ptr;
	__be32 tip;*/
	int noff;

	if (!ses->peer_addr)
		goto drop;

	noff = skb_network_offset(skb);

	if (skb->protocol == htons(ETH_P_IP)) {
		if (!pskb_may_pull(skb, sizeof(*iph) + noff))
			goto drop;

		iph = ip_hdr(skb);

		//pr_info("ipoe: xmit %08x %08x\n", iph->saddr, iph->daddr);

		//pr_info("ipoe: xmit1 %08x %08x\n", iph->saddr, iph->daddr);
		if (iph->daddr == ses->addr) {
			if (skb_shared(skb)) {
				skb1 = skb_clone(skb, GFP_ATOMIC);
				if (!skb1)
					goto drop;
				dev_kfree_skb(skb);
				skb = skb1;
			}

			if (ipoe_do_nat(skb, ses->peer_addr, 1))
				goto drop;
		}

		/*if (ses->gw) {
			iph = ip_hdr(skb);

			ip_send_check(iph);

			if (ipoe_route4(skb, ses->gw, ses->link_dev->ifindex))
				goto drop;

			pskb_pull(skb, ETH_HLEN);
			skb_reset_network_header(skb);

			//skb->skb_iif = dev->ifindex;

			//pr_info("ipoe: xmit2 %08x %08x %p %p\n", iph->saddr, iph->daddr, dev, skb->dev);
			nf_reset(skb);
			secpath_reset(skb);
			skb->vlan_tci = 0;
			skb_set_queue_mapping(skb, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
			ip_local_out(pick_net(skb), skb->sk, skb);
#else
			ip_local_out(skb);
#endif

			return NETDEV_TX_OK;
		} else*/
	}

	ipoe_update_stats(skb, this_cpu_ptr(ses->tx_stats), ETH_HLEN);

	if (ses->link_dev) {
		struct ethhdr *eth = (struct ethhdr *)skb->data;
		memcpy(eth->h_dest, ses->u.hwaddr, ETH_ALEN);
		memcpy(eth->h_source, ses->link_dev->dev_addr, ETH_ALEN);

		skb->dev = ses->link_dev;
		dev_queue_xmit(skb);

		return NETDEV_TX_OK;
	}

drop:
	stats->tx_dropped++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int ipoe_lookup1_u(__be32 addr, unsigned long *ts)
{
	struct ipoe_entry_u *e;
	struct list_head *head = &ipoe_list1_u[hash_addr(addr)];
	int r = 0;

	rcu_read_lock();

	list_for_each_entry_rcu(e, head, entry1) {
		if (e->addr == addr) {
			*ts = e->tstamp;
			r = 1;
			break;
		}
	}

	rcu_read_unlock();

	return r;
}

static struct ipoe_entry_u *ipoe_lookup2_u(__be32 addr)
{
	struct ipoe_entry_u *e;
	struct list_head *head = &ipoe_list1_u[hash_addr(addr)];

	list_for_each_entry_rcu(e, head, entry1) {
		if (e->addr == addr)
			return e;
	}

	return NULL;
}


static int ipoe_queue_u(struct sk_buff *skb, __u32 addr)
{
	unsigned long ts;

	if (ipoe_lookup1_u(addr, &ts) && jiffies_to_msecs(jiffies - ts) < IPOE_RATE_U) {
		//pr_info("not queue %08x\n", addr);
		return -1;
	}

	if (skb_queue_len(&ipoe_queue) > IPOE_QUEUE_LEN)
		return -1;

	//pr_info("queue %08x\n", addr);

	skb_queue_tail(&ipoe_queue, skb);
	schedule_work(&ipoe_queue_work);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void ipoe_start_queue_work(struct timer_list *unused)
#else
static void ipoe_start_queue_work(unsigned long dummy)
#endif
{
	schedule_work(&ipoe_queue_work);
}

static void ipoe_process_queue(struct work_struct *w)
{
	struct sk_buff *skb;
	struct ipoe_entry_u *e;
	struct ethhdr *eth;
	struct iphdr *iph = NULL;
	struct _arphdr *arph = NULL;
	struct sk_buff *report_skb = NULL;
	void *header = NULL;
	struct nlattr *ns;
	int id = 1;
	__be32 saddr;

	do {
		while ((skb = skb_dequeue(&ipoe_queue))) {
			if (likely(skb->protocol == htons(ETH_P_IP))) {
				iph = ip_hdr(skb);
				saddr = iph->saddr;
			} else {
				arph = (struct _arphdr *)skb_network_header(skb);
				saddr = arph->ar_sip;
			}

			e = ipoe_lookup2_u(saddr);

			if (!e) {
				e = kmalloc(sizeof(*e), GFP_KERNEL);
				e->addr = saddr;
				e->tstamp = jiffies;

				list_add_tail_rcu(&e->entry1, &ipoe_list1_u[hash_addr(saddr)]);
				list_add_tail(&e->entry2, &ipoe_list2_u);

				//pr_info("create %08x\n", e->addr);
			} else if (jiffies_to_msecs(jiffies - e->tstamp) < IPOE_RATE_U) {
				//pr_info("skip %08x\n", e->addr);
				kfree_skb(skb);
				continue;
			} else {
				e->tstamp = jiffies;
				list_move_tail(&e->entry2, &ipoe_list2_u);
				//pr_info("update %08x\n", e->addr);
			}

			if (!report_skb) {
				report_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
				if (report_skb)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && RHEL_MAJOR < 7
					header = genlmsg_put(report_skb, 0, ipoe_nl_mcg.id, &ipoe_nl_family, 0, IPOE_REP_PKT);
#else
					header = genlmsg_put(report_skb, 0, ipoe_nl_family.mcgrp_offset, &ipoe_nl_family, 0, IPOE_REP_PKT);
#endif
			}

			if (report_skb) {
				ns = nla_nest_start_noflag(report_skb, id++);
				if (!ns)
					goto nl_err;

				if (nla_put_u32(report_skb, IPOE_ATTR_IFINDEX, skb->dev ? skb->dev->ifindex : skb->skb_iif))
					goto nl_err;

				if (likely(skb->protocol == htons(ETH_P_IP))) {
					eth = eth_hdr(skb);
					if (nla_put(report_skb, IPOE_ATTR_ETH_HDR, sizeof(*eth), eth))
						goto nl_err;

					if (nla_put(report_skb, IPOE_ATTR_IP_HDR, sizeof(*iph), iph))
						goto nl_err;
				} else {
					if (nla_put(report_skb, IPOE_ATTR_ARP_HDR, sizeof(*arph), arph))
						goto nl_err;
				}

				if (nla_nest_end(report_skb, ns) >= IPOE_NLMSG_SIZE) {
					genlmsg_end(report_skb, header);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && RHEL_MAJOR < 7
					genlmsg_multicast(report_skb, 0, ipoe_nl_mcg.id, GFP_KERNEL);
#else
					genlmsg_multicast(&ipoe_nl_family, report_skb, 0, 0, GFP_KERNEL);
#endif
					report_skb = NULL;
					id = 1;
				}

				kfree_skb(skb);
				continue;

nl_err:
				nlmsg_free(report_skb);
				report_skb = NULL;
			}

			kfree_skb(skb);
		}

		while (!list_empty(&ipoe_list2_u)) {
			e = list_entry(ipoe_list2_u.next, typeof(*e), entry2);
			if (jiffies_to_msecs(jiffies - e->tstamp) < IPOE_TIMEOUT_U * 1000)
				break;

			//pr_info("free %08x\n", e->addr);
			list_del(&e->entry2);
			list_del_rcu(&e->entry1);
			kfree_rcu(e, rcu_head);
		}

		synchronize_rcu();
	} while (skb_queue_len(&ipoe_queue));

	if (report_skb) {
		genlmsg_end(report_skb, header);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && RHEL_MAJOR < 7
		genlmsg_multicast(report_skb, 0, ipoe_nl_mcg.id, GFP_KERNEL);
#else
		genlmsg_multicast(&ipoe_nl_family, report_skb, 0, 0, GFP_KERNEL);
#endif
	}

	if (!list_empty(&ipoe_list2_u))
		mod_timer(&ipoe_timer_u, jiffies + IPOE_TIMEOUT_U * HZ);
	else
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,2,0)
		del_timer(&ipoe_timer_u);
#else
		timer_delete(&ipoe_timer_u);
#endif
}

static struct ipoe_session *ipoe_lookup(__be32 addr)
{
	struct ipoe_session *ses;
	struct list_head *head;

	head = &ipoe_list[hash_addr(addr)];

	rcu_read_lock();

	list_for_each_entry_rcu(ses, head, entry) {
		if (ses->peer_addr == addr) {
			atomic_inc(&ses->refs);
			rcu_read_unlock();
			return ses;
		}
	}

	rcu_read_unlock();

	return NULL;
}

static struct ipoe_session *ipoe_lookup_hwaddr(__u8 *hwaddr)
{
	struct ipoe_session *ses;
	struct list_head *head;
	union {
		__u8 hwaddr[ETH_ALEN];
		__u64 hwaddr_u;
	} u;

	u.hwaddr_u = 0;
	memcpy(u.hwaddr, hwaddr, ETH_ALEN);

	head = &ipoe_list3[hwaddr[ETH_ALEN - 1]];

	rcu_read_lock();

	list_for_each_entry_rcu(ses, head, entry3) {
		if (ses->u.hwaddr_u == u.hwaddr_u) {
			atomic_inc(&ses->refs);
			rcu_read_unlock();
			return ses;
		}
	}

	rcu_read_unlock();

	return NULL;
}


static struct ipoe_session *ipoe_lookup_rt4(struct sk_buff *skb, __be32 addr, struct net_device **dev)
{
	struct net *net = pick_net(skb);
	struct rtable *rt;
	struct ipoe_session *ses;

	struct flowi4 fl4;

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = addr;
	fl4.flowi4_tos = RT_TOS(0);
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return NULL;

	*dev      = rt->dst.dev;

	if ((*dev)->netdev_ops != &ipoe_netdev_ops) {
		ip_rt_put(rt);
		return NULL;
	}

	ses = netdev_priv(*dev);
	atomic_inc(&ses->refs);

	ip_rt_put(rt);

	return ses;
}

static struct ipoe_session *ipoe_lookup_rt6(struct sk_buff *skb, const struct in6_addr *addr, struct net_device **dev)
{
	struct net *net = pick_net(skb);
	struct dst_entry *dst;
	struct flowi6 fl6;
	struct ipoe_session *ses;

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = *addr;

	dst = ip6_route_output(net, NULL, &fl6);

	if (!dst)
		return NULL;

	*dev = dst->dev;

	if (dst->error || dst->dev->netdev_ops != &ipoe_netdev_ops) {
		dst_release(dst);
		return NULL;
	}
	ses = netdev_priv(*dev);
	atomic_inc(&ses->refs);

	dst_release(dst);

	return ses;
}

static rx_handler_result_t ipoe_recv(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct net_device *dev = skb->dev;
	struct ipoe_iface *i = rcu_dereference(dev->rx_handler_data);
	struct net_device *out = NULL;
	struct ipoe_session *ses = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct ethhdr *eth = eth_hdr(skb);
	int noff;
	struct net_device_stats *stats;
	__be32 saddr;

	if (!i)
		return RX_HANDLER_PASS;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	noff = skb_network_offset(skb);

	if (likely(skb->protocol == htons(ETH_P_IP))) {
		if (!pskb_may_pull(skb, sizeof(*iph) + noff))
			return RX_HANDLER_PASS;

		iph = ip_hdr(skb);
		saddr = iph->saddr;

		if (!saddr || saddr == 0xffffffff)
			return RX_HANDLER_PASS;

		ses = ipoe_lookup_rt4(skb, saddr, &out);
		if (!ses) {
			if (i->mode == 0)
				return RX_HANDLER_PASS;

			if (out == dev && i->mode == 2)
				return RX_HANDLER_PASS;

			if (out != dev && i->mode == 3) {
				kfree_skb(skb);
				return RX_HANDLER_CONSUMED;
			}

			if (ipoe_check_exclude(saddr))
				return RX_HANDLER_PASS;

			if (ipoe_check_network(saddr) == 0)
				return RX_HANDLER_PASS;

			if (ipoe_queue_u(skb, saddr))
				kfree_skb(skb);

			return RX_HANDLER_CONSUMED;
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (!pskb_may_pull(skb, sizeof(*ip6h) + noff))
			return RX_HANDLER_PASS;

		ip6h = ipv6_hdr(skb);

		if (ip6h->saddr.s6_addr16[0] == htons(0xfe80)) {
			ses = ipoe_lookup_hwaddr(eth->h_source);
			if (!ses)
				return RX_HANDLER_PASS;
		} else {
			ses = ipoe_lookup_rt6(skb, &ip6h->saddr, &out);
			if (!ses) {
				if (i->mode == 0)
					return RX_HANDLER_PASS;

				if (out == dev && i->mode == 2)
					return RX_HANDLER_PASS;

				kfree_skb(skb);
				return RX_HANDLER_CONSUMED;
			}
		}
	} else
		return RX_HANDLER_PASS;


	//pr_info("ipoe: recv %08x %08x\n", iph->saddr, iph->daddr);

	stats = &ses->dev->stats;

	if (ses->gw)
		memcpy(ses->u.hwaddr, eth->h_source, ETH_ALEN);
	else if (memcmp(eth->h_source, ses->u.hwaddr, ETH_ALEN))
		goto drop;

	if (skb->protocol == htons(ETH_P_IP) && ses->addr > 1 && check_nat_required(skb, ses->link_dev) && ipoe_do_nat(skb, ses->addr, 0))
		goto drop;

	skb->dev = ses->dev;
	skb->skb_iif = ses->dev->ifindex;
	memset(skb->cb, 0, sizeof(skb->cb));

	ipoe_update_stats(skb, this_cpu_ptr(ses->rx_stats), 0);

	atomic_dec(&ses->refs);

	return RX_HANDLER_ANOTHER;

drop:
	atomic_dec(&ses->refs);
	stats->rx_dropped++;
	kfree_skb(skb);
	return RX_HANDLER_CONSUMED;
}

/*#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static unsigned int ipt_out_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
static unsigned int ipt_out_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
static unsigned int ipt_out_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
#else
static unsigned int ipt_out_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#endif
{
	int noff, iif;
	struct iphdr *iph;
	struct ipoe_session *ses;
	unsigned char *cb_ptr;
	struct net_device *dev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	struct net_device *out = state->out;
#endif

	if (!out->atalk_ptr)
		return NF_ACCEPT;

	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	cb_ptr = skb->cb + sizeof(skb->cb) - 2;
	if (*(__u16 *)cb_ptr == IPOE_MAGIC)
		return NF_ACCEPT;

	noff = skb_network_offset(skb);

	if (!pskb_may_pull(skb, sizeof(*iph) + noff))
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	if (ipoe_check_exclude(iph->daddr))
		return NF_ACCEPT;

	ses = ipoe_lookup_rt(skb, iph->daddr, &dev);
	if (!ses)
		return NF_ACCEPT;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	iif = skb->skb_iif;
#else
	iif = skb->iif;
#endif

	if (iif == ses->dev->ifindex) {
		atomic_dec(&ses->refs);
		return NF_ACCEPT;
	}

	skb->dev = ses->dev;
	atomic_dec(&ses->refs);

	return NF_ACCEPT;
}*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
static struct rtnl_link_stats64 *ipoe_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
#else
static void ipoe_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
#endif
{
	struct ipoe_session *ses = netdev_priv(dev);
	struct ipoe_stats *st;
	unsigned int start;
	int i;
	u64 packets, bytes;
	u64 rx_packets = 0, rx_bytes = 0, tx_packets = 0, tx_bytes = 0;

	for_each_possible_cpu(i) {
		st = per_cpu_ptr(ses->rx_stats, i);

		do {
			start = u64_stats_fetch_begin_bh(&st->sync);
			packets = st->packets;
			bytes = st->bytes;
		} while (u64_stats_fetch_retry_bh(&st->sync, start));

		rx_packets += packets;
		rx_bytes += bytes;

		st = per_cpu_ptr(ses->tx_stats, i);

		do {
			start = u64_stats_fetch_begin_bh(&st->sync);
			packets = st->packets;
			bytes = st->bytes;
		} while (u64_stats_fetch_retry_bh(&st->sync, start));

		tx_packets += packets;
		tx_bytes += bytes;
	}

	stats->rx_packets = rx_packets;
	stats->rx_bytes = rx_bytes;
	stats->tx_packets = tx_packets;
	stats->tx_bytes = tx_bytes;

	stats->rx_dropped = dev->stats.rx_dropped;
	stats->tx_dropped = dev->stats.tx_dropped;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
	return stats;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
static void ipoe_free_netdev(struct net_device *dev)
{
	struct ipoe_session *ses = netdev_priv(dev);

	if (ses->rx_stats)
		free_percpu(ses->rx_stats);
	if (ses->tx_stats)
		free_percpu(ses->tx_stats);

	free_netdev(dev);
}
#else
static void ipoe_netdev_uninit(struct net_device *dev)
{
	struct ipoe_session *ses = netdev_priv(dev);

	if (ses->rx_stats)
		free_percpu(ses->rx_stats);
	if (ses->tx_stats)
		free_percpu(ses->tx_stats);

	dev_put(dev);
}
#endif

static int ipoe_hard_header(struct sk_buff *skb, struct net_device *dev,
			       unsigned short type, const void *daddr,
			       const void *saddr, unsigned len)
{
	const struct ipoe_session *ses = netdev_priv(dev);

	if (ses->link_dev)
		return dev_hard_header(skb, ses->link_dev, type, daddr,
			       saddr, len);
	else
		return eth_header(skb, dev, type, daddr, saddr, len);
}

static const struct header_ops ipoe_hard_header_ops = {
	.create  	= ipoe_hard_header,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
	.rebuild	= eth_rebuild_header,
#endif
	.parse		= eth_header_parse,
	.cache		= eth_header_cache,
	.cache_update	= eth_header_cache_update,
};

static void ipoe_netdev_setup(struct net_device *dev)
{
	dev->netdev_ops = &ipoe_netdev_ops;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	dev->destructor = ipoe_free_netdev;
#else
	dev->needs_free_netdev = true;
#endif

	dev->type = ARPHRD_ETHER;
	dev->hard_header_len = 0;
	dev->mtu = ETH_DATA_LEN;
	dev->flags = IFF_MULTICAST | IFF_POINTOPOINT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
	dev->iflink = 0;
#endif
	dev->addr_len = ETH_ALEN;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0)
	dev->netns_immutable = true;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)
	dev->netns_local = true;
#else
	dev->features  |= NETIF_F_NETNS_LOCAL;
#endif
	dev->features  &= ~(NETIF_F_HW_VLAN_FILTER | NETIF_F_LRO);
	dev->header_ops	= &ipoe_hard_header_ops;
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
}

static int ipoe_create(__be32 peer_addr, __be32 addr, __be32 gw, int ifindex, const __u8 *hwaddr)
{
	struct ipoe_session *ses;
	struct net_device *dev, *link_dev = NULL;
	char name[IFNAMSIZ];
	int r = -EINVAL;
	int h = hash_addr(peer_addr);
	//struct in_device *in_dev;

	if (ifindex) {
		link_dev = dev_get_by_index(&init_net, ifindex);
		if (!link_dev)
			return -EINVAL;
	}

	sprintf(name, "ipoe%%d");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
	dev = alloc_netdev(sizeof(*ses), name, NET_NAME_UNKNOWN, ipoe_netdev_setup);
#else
	dev = alloc_netdev(sizeof(*ses), name, ipoe_netdev_setup);
#endif
	if (dev == NULL) {
		r = -ENOMEM;
		goto failed;
	}

	dev_net_set(dev, &init_net);

	r = dev_alloc_name(dev, name);
	if (r < 0) {
		r = -ENOMEM;
		goto failed_free;
	}

	ses = netdev_priv(dev);
	memset(ses, 0, sizeof(*ses));
	atomic_set(&ses->refs, 0);
	ses->dev = dev;
	ses->addr = addr;
	ses->peer_addr = peer_addr;
	ses->gw = gw;
	ses->link_dev = link_dev;
	memcpy(ses->u.hwaddr, hwaddr, ETH_ALEN);
	ses->rx_stats = alloc_percpu(struct ipoe_stats);
	ses->tx_stats = alloc_percpu(struct ipoe_stats);
	if (!ses->rx_stats || !ses->tx_stats) {
		r = -ENOMEM;
		goto failed_free;
	}

	if (link_dev) {
		dev->features = link_dev->features & ~(NETIF_F_HW_VLAN_FILTER | NETIF_F_LRO);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
		dev_addr_mod(dev, 0, link_dev->dev_addr, ETH_ALEN);
#else
		memcpy(dev->dev_addr, link_dev->dev_addr, ETH_ALEN);
#endif
		memcpy(dev->broadcast, link_dev->broadcast, ETH_ALEN);
	}

	if (addr)
		dev->flags |= IFF_NOARP;
	else
		dev->flags &= ~IFF_NOARP;

	/*in_dev = __in_dev_get_rtnl(dev);
	if (in_dev) {
		if (addr == 1)
			IPV4_DEVCONF(in_dev->cnf, RP_FILTER) = 0;
		else
			IPV4_DEVCONF(in_dev->cnf, RP_FILTER) = 1;
	}*/

	dev->tx_queue_len = 100;

	rtnl_lock();
	r = register_netdevice(dev);
	rtnl_unlock();
	if (r < 0)
		goto failed_free;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	dev_hold(dev);
#endif


	down(&ipoe_wlock);
	if (peer_addr)
		list_add_tail_rcu(&ses->entry, &ipoe_list[h]);
	list_add_tail(&ses->entry2, &ipoe_list2);
	if (link_dev)
		list_add_tail_rcu(&ses->entry3, &ipoe_list3[ses->u.hwaddr[ETH_ALEN - 1]]);
	r = dev->ifindex;
	up(&ipoe_wlock);

	return r;

failed_free:
	free_netdev(dev);
failed:
	if (link_dev)
		dev_put(link_dev);
	return r;
}

static int ipoe_nl_cmd_noop(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	int ret = -ENOBUFS;

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq, &ipoe_nl_family, 0, IPOE_CMD_NOOP);
#else
	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq, &ipoe_nl_family, 0, IPOE_CMD_NOOP);
#endif
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto err_out;
	}

	genlmsg_end(msg, hdr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);
#endif

err_out:
	nlmsg_free(msg);

out:
	return ret;
}

static int ipoe_nl_cmd_create(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	__be32 peer_addr = 0, addr = 0, gw = 0;
	int ifindex = 0;
	int ret = 0;
	__u8 hwaddr[ETH_ALEN];
	struct ipoe_session *ses;
	//struct net *net = genl_info_net(info);

	if (info->attrs[IPOE_ATTR_PEER_ADDR]) {
		peer_addr = nla_get_be32(info->attrs[IPOE_ATTR_PEER_ADDR]);
		if (peer_addr) {
			ses = ipoe_lookup(peer_addr);
			if (ses) {
				atomic_dec(&ses->refs);
				return -EEXIST;
			}
		}
	}

	if (info->attrs[IPOE_ATTR_ADDR])
		addr = nla_get_be32(info->attrs[IPOE_ATTR_ADDR]);

	if (info->attrs[IPOE_ATTR_GW_ADDR])
		gw = nla_get_be32(info->attrs[IPOE_ATTR_GW_ADDR]);

	if (info->attrs[IPOE_ATTR_IFINDEX])
		ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

	if (info->attrs[IPOE_ATTR_HWADDR])
		nla_memcpy(hwaddr, info->attrs[IPOE_ATTR_HWADDR], ETH_ALEN);
	else
		memset(hwaddr, 0, sizeof(hwaddr));

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq, &ipoe_nl_family, 0, IPOE_CMD_CREATE);
#else
	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq, &ipoe_nl_family, 0, IPOE_CMD_CREATE);
#endif
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto err_out;
	}

	//pr_info("ipoe: create %08x %08x %s\n", peer_addr, addr, info->attrs[IPOE_ATTR_IFNAME] ? ifname : "-");

	ret = ipoe_create(peer_addr, addr, gw, ifindex, hwaddr);

	if (ret < 0) {
		nlmsg_free(msg);
		return ret;
	}

	nla_put_u32(msg, IPOE_ATTR_IFINDEX, ret);

	genlmsg_end(msg, hdr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);
#endif

err_out:
	nlmsg_free(msg);

out:
	return ret;
}

static int ipoe_nl_cmd_delete(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct ipoe_session *ses;
	int ifindex;
	int r = 0;
	int ret = -EINVAL;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

	down(&ipoe_wlock);

	rcu_read_lock();
	dev = dev_get_by_index_rcu(&init_net, ifindex);
	if (!dev || dev->header_ops != &ipoe_hard_header_ops)
		r = 1;
	rcu_read_unlock();

	if (r)
		goto out_unlock;

	ses = netdev_priv(dev);

	//pr_info("ipoe: delete %08x\n", ses->peer_addr);

	if (ses->peer_addr)
		list_del_rcu(&ses->entry);
	list_del(&ses->entry2);
	if (ses->u.hwaddr_u)
		list_del_rcu(&ses->entry3);

	up(&ipoe_wlock);

	synchronize_rcu();

	while (atomic_read(&ses->refs))
		schedule_timeout_uninterruptible(1);

	if (ses->link_dev)
		dev_put(ses->link_dev);

	unregister_netdev(ses->dev);

	ret = 0;

out_unlock:
	up(&ipoe_wlock);
	return ret;
}

static int ipoe_nl_cmd_modify(struct sk_buff *skb, struct genl_info *info)
{
	int ret = -EINVAL, r = 0;
	struct net_device *dev, *link_dev, *old_dev;
	struct in_device *in_dev;
	struct ipoe_session *ses, *ses1;
	int ifindex;
	__be32 peer_addr;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;

	down(&ipoe_wlock);

	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

	rcu_read_lock();
	dev = dev_get_by_index_rcu(&init_net, ifindex);
	if (!dev || dev->header_ops != &ipoe_hard_header_ops)
		r = 1;
	rcu_read_unlock();

	if (r)
		goto out_unlock;

	ses = netdev_priv(dev);

	if (info->attrs[IPOE_ATTR_PEER_ADDR]) {
		peer_addr = nla_get_be32(info->attrs[IPOE_ATTR_PEER_ADDR]);
		if (peer_addr) {
			ses1 = ipoe_lookup(peer_addr);
			if (ses1) {
				atomic_dec(&ses1->refs);
				if (ses1 != ses) {
					ret = -EEXIST;
					goto out_unlock;
				}
			}
		}

		if (ses->peer_addr) {
			list_del_rcu(&ses->entry);
			synchronize_rcu();
		}

		ses->peer_addr = peer_addr;

		if (peer_addr)
			list_add_tail_rcu(&ses->entry, &ipoe_list[hash_addr(peer_addr)]);
		else
			ses->dev->flags &= ~IFF_UP;
	}

	if (info->attrs[IPOE_ATTR_LINK_IFINDEX]) {
		int ifindex = nla_get_u32(info->attrs[IPOE_ATTR_LINK_IFINDEX]);

		if (ifindex) {
			link_dev = dev_get_by_index(&init_net, ifindex);

			if (!link_dev)
				goto out_unlock;
		} else
			link_dev = NULL;

		old_dev = ses->link_dev;
		ses->link_dev = link_dev;

		if (old_dev) {
			dev_put(old_dev);
			list_del_rcu(&ses->entry3);
			ses->u.hwaddr_u = 0;
			synchronize_rcu();
		}

		if (link_dev) {
			ses->dev->features = link_dev->features & ~(NETIF_F_HW_VLAN_FILTER | NETIF_F_LRO);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
			dev_addr_mod(dev, 0, link_dev->dev_addr, ETH_ALEN);
#else
			memcpy(dev->dev_addr, link_dev->dev_addr, ETH_ALEN);
#endif
			memcpy(dev->broadcast, link_dev->broadcast, ETH_ALEN);
		}
	}

	if (info->attrs[IPOE_ATTR_ADDR]) {
		ses->addr = nla_get_be32(info->attrs[IPOE_ATTR_ADDR]);
		if (ses->addr && !ses->link_dev)
			dev->flags |= IFF_NOARP;
		else
			dev->flags &= ~IFF_NOARP;

		in_dev = __in_dev_get_rtnl(dev);
		if (in_dev) {
			if (ses->addr == 1)
				IPV4_DEVCONF(in_dev->cnf, RP_FILTER) = 0;
			else
				IPV4_DEVCONF(in_dev->cnf, RP_FILTER) = 1;
		}
	}

	if (info->attrs[IPOE_ATTR_GW_ADDR])
		ses->gw = nla_get_u32(info->attrs[IPOE_ATTR_GW_ADDR]);

	if (info->attrs[IPOE_ATTR_HWADDR]) {
		nla_memcpy(ses->u.hwaddr, info->attrs[IPOE_ATTR_HWADDR], ETH_ALEN);
		if (ses->link_dev)
			list_add_tail_rcu(&ses->entry3, &ipoe_list3[ses->u.hwaddr[ETH_ALEN - 1]]);
	}

	//pr_info("ipoe: modify %08x %08x\n", ses->peer_addr, ses->addr);

	ret = 0;

out_unlock:
	up(&ipoe_wlock);
	return ret;
}

static int fill_info(struct sk_buff *skb, struct ipoe_session *ses, u32 pid, u32 seq)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &ipoe_nl_family, NLM_F_MULTI, IPOE_CMD_GET);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32(skb, IPOE_ATTR_IFINDEX, ses->dev->ifindex) ||
	    nla_put_u32(skb, IPOE_ATTR_PEER_ADDR, ses->peer_addr) ||
	    nla_put_u32(skb, IPOE_ATTR_ADDR, ses->addr))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ipoe_nl_cmd_dump_sessions(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ipoe_session *ses;
	int idx = 0, start_idx = cb->args[0];

	down(&ipoe_wlock);

	list_for_each_entry(ses, &ipoe_list2, entry2) {
		if (idx > start_idx)
			start_idx = 0;

		if (idx++ < start_idx)
			continue;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
		if (fill_info(skb, ses, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq) < 0)
#else
		if (fill_info(skb, ses, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq) < 0)
#endif
			break;
	}

	up(&ipoe_wlock);

	cb->args[0] = idx;

	return skb->len;
}

static int ipoe_nl_cmd_add_exclude(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_network *n;
	struct list_head *ht;

	if (!info->attrs[IPOE_ATTR_ADDR])
		return -EINVAL;

	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	n->addr = nla_get_u32(info->attrs[IPOE_ATTR_ADDR]);

	ht = &ipoe_excl_list[hash_addr(n->addr)];

	down(&ipoe_wlock);
	list_add_tail_rcu(&n->entry, ht);
	up(&ipoe_wlock);

	return 0;
}

static void clean_excl_list(void)
{
	struct ipoe_network *n;
	struct list_head *ht;
	int i;

	down(&ipoe_wlock);
	rcu_read_lock();
	for (i = 0; i <= IPOE_HASH_BITS; i++) {
		ht = &ipoe_excl_list[i];
		list_for_each_entry_rcu(n, ht, entry) {
			list_del_rcu(&n->entry);
			kfree_rcu(n, rcu_head);
		}
	}
	rcu_read_unlock();
	up(&ipoe_wlock);
}

static int ipoe_nl_cmd_del_exclude(struct sk_buff *skb, struct genl_info *info)
{
	struct list_head *ht;
	struct ipoe_network *n;
	u32 addr;

	if (!info->attrs[IPOE_ATTR_ADDR])
		return -EINVAL;

	addr = nla_get_u32(info->attrs[IPOE_ATTR_ADDR]);
	if (!addr) {
		clean_excl_list();
		return 0;
	}

	ht = &ipoe_excl_list[hash_addr(addr)];

	down(&ipoe_wlock);
	rcu_read_lock();
	list_for_each_entry_rcu(n, ht, entry) {
		if (n->addr == addr) {
			list_del_rcu(&n->entry);
			kfree_rcu(n, rcu_head);
			break;
		}
	}
	rcu_read_unlock();
	up(&ipoe_wlock);

	return 0;
}

static int ipoe_nl_cmd_add_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_iface *i;
	struct net_device *dev;
	int ret = 0;
	int ifindex;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

	rtnl_lock();

	dev = __dev_get_by_index(&init_net, ifindex);

	if (!dev) {
		rtnl_unlock();
		return -ENODEV;
	}

	i = kmalloc(sizeof(*i), GFP_KERNEL);
	if (!i) {
		ret = -ENOMEM;
		goto out;
	}

	i->ifindex = ifindex;

	if (info->attrs[IPOE_ATTR_MODE])
		i->mode = nla_get_u8(info->attrs[IPOE_ATTR_MODE]);
	else
		i->mode = 2;

	ret = netdev_rx_handler_register(dev, ipoe_recv, i);

	if (ret)
		kfree(i);
	else
		list_add_tail(&i->entry, &ipoe_interfaces);

out:
	rtnl_unlock();

	return ret;
}

static int ipoe_nl_cmd_del_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_iface *i;
	int ifindex;
	struct list_head *pos, *n;
	struct net_device *dev;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

	rtnl_lock();
	list_for_each_safe(pos, n, &ipoe_interfaces) {
		i = list_entry(pos, typeof(*i), entry);
		if (ifindex == -1 || ifindex == i->ifindex) {
			dev = __dev_get_by_index(&init_net, i->ifindex);

			if (dev && rcu_dereference(dev->rx_handler) == ipoe_recv)
				netdev_rx_handler_unregister(dev);

			list_del(&i->entry);

			kfree_rcu(i, rcu_head);

			if (ifindex != -1)
				break;
		}
	}
	rtnl_unlock();

	return 0;
}

static int ipoe_nl_cmd_add_net(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_network *n;

	if (!info->attrs[IPOE_ATTR_ADDR] || !info->attrs[IPOE_ATTR_MASK])
		return -EINVAL;

	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	n->addr = nla_get_u32(info->attrs[IPOE_ATTR_ADDR]);
	n->mask = nla_get_u32(info->attrs[IPOE_ATTR_MASK]);
	n->addr = ntohl(n->addr) & n->mask;

	down(&ipoe_wlock);
	list_add_tail_rcu(&n->entry, &ipoe_networks);
	up(&ipoe_wlock);

	return 0;
}

static int ipoe_nl_cmd_del_net(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_network *n;
	__be32 addr;

	if (!info->attrs[IPOE_ATTR_ADDR])
		return -EINVAL;

	addr = ntohl(nla_get_u32(info->attrs[IPOE_ATTR_ADDR]));

	down(&ipoe_wlock);
	rcu_read_lock();
	list_for_each_entry_rcu(n, &ipoe_networks, entry) {
		if (!addr || (addr & n->mask) == n->addr) {
			list_del_rcu(&n->entry);
			kfree_rcu(n, rcu_head);
			if (addr)
				break;
		}
	}
	rcu_read_unlock();
	up(&ipoe_wlock);

	return 0;
}

static const struct nla_policy ipoe_nl_policy[IPOE_ATTR_MAX + 1] = {
	[IPOE_ATTR_NONE]		    = { .type = NLA_UNSPEC,                     },
	[IPOE_ATTR_ADDR]	      = { .type = NLA_U32,                        },
	[IPOE_ATTR_PEER_ADDR]	  = { .type = NLA_U32,                        },
	[IPOE_ATTR_MASK]	      = { .type = NLA_U32,                        },
	[IPOE_ATTR_MODE]	      = { .type = NLA_U8,                         },
	[IPOE_ATTR_GW_ADDR]     = { .type = NLA_U32,                        },
	[IPOE_ATTR_HWADDR]      = { .type = NLA_BINARY, .len = ETH_ALEN,    },
	[IPOE_ATTR_IFINDEX]     = { .type = NLA_U32,                        },
	[IPOE_ATTR_LINK_IFINDEX]= { .type = NLA_U32,                        },
};

static const struct genl_ops ipoe_nl_ops[] = {
	{
		.cmd = IPOE_CMD_NOOP,
		.doit = ipoe_nl_cmd_noop,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
		/* can be retrieved by unprivileged users */
	},
	{
		.cmd = IPOE_CMD_CREATE,
		.doit = ipoe_nl_cmd_create,
		.flags = GENL_ADMIN_PERM,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
	{
		.cmd = IPOE_CMD_DELETE,
		.doit = ipoe_nl_cmd_delete,
		.flags = GENL_ADMIN_PERM,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
	{
		.cmd = IPOE_CMD_MODIFY,
		.doit = ipoe_nl_cmd_modify,
		.flags = GENL_ADMIN_PERM,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
	{
		.cmd = IPOE_CMD_GET,
		.dumpit = ipoe_nl_cmd_dump_sessions,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
	{
		.cmd = IPOE_CMD_ADD_IF,
		.doit = ipoe_nl_cmd_add_interface,
		.flags = GENL_ADMIN_PERM,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
	{
		.cmd = IPOE_CMD_DEL_IF,
		.doit = ipoe_nl_cmd_del_interface,
		.flags = GENL_ADMIN_PERM,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
	{
		.cmd = IPOE_CMD_ADD_EXCLUDE,
		.doit = ipoe_nl_cmd_add_exclude,
		.flags = GENL_ADMIN_PERM,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
	{
		.cmd = IPOE_CMD_DEL_EXCLUDE,
		.doit = ipoe_nl_cmd_del_exclude,
		.flags = GENL_ADMIN_PERM,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
	{
		.cmd = IPOE_CMD_ADD_NET,
		.doit = ipoe_nl_cmd_add_net,
		.flags = GENL_ADMIN_PERM,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
	{
		.cmd = IPOE_CMD_DEL_NET,
		.doit = ipoe_nl_cmd_del_net,
		.flags = GENL_ADMIN_PERM,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		.policy = ipoe_nl_policy,
#endif
	},
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && RHEL_MAJOR < 7
static struct genl_multicast_group ipoe_nl_mcg = {
	.name = IPOE_GENL_MCG_PKT,
};
#else
static struct genl_multicast_group ipoe_nl_mcgs[] = {
	{ .name = IPOE_GENL_MCG_PKT, }
};
#endif

static struct genl_family ipoe_nl_family = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
	.id		= GENL_ID_GENERATE,
#endif
	.name		= IPOE_GENL_NAME,
	.version	= IPOE_GENL_VERSION,
	.hdrsize	= 0,
	.maxattr	= IPOE_ATTR_MAX,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	.module = THIS_MODULE,
	.ops = ipoe_nl_ops,
	.n_ops = ARRAY_SIZE(ipoe_nl_ops),
	.mcgrps = ipoe_nl_mcgs,
	.n_mcgrps = ARRAY_SIZE(ipoe_nl_mcgs),
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	.policy = ipoe_nl_policy,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
	.resv_start_op = CTRL_CMD_GETPOLICY + 1,
#endif
};

static const struct net_device_ops ipoe_netdev_ops = {
	.ndo_start_xmit	= ipoe_xmit,
	.ndo_get_stats64 = ipoe_stats64,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	.ndo_uninit = ipoe_netdev_uninit,
#endif
};

/*static struct pernet_operations ipoe_net_ops = {
	.init = ipoe_init_net,
	.exit = ipoe_exit_net,
	.id   = &ipoe_net_id,
	.size = sizeof(struct ipoe_net),
};*/

static int __init ipoe_init(void)
{
	int err, i;

	printk("IPoE session driver v%s\n", ACCEL_PPP_VERSION);

	/*err = register_pernet_device(&ipoe_net_ops);
	if (err < 0)
		return err;*/

	for (i = 0; i <= IPOE_HASH_BITS; i++) {
		INIT_LIST_HEAD(&ipoe_list[i]);
		INIT_LIST_HEAD(&ipoe_list3[i]);
		INIT_LIST_HEAD(&ipoe_list1_u[i]);
		INIT_LIST_HEAD(&ipoe_excl_list[i]);
	}

	skb_queue_head_init(&ipoe_queue);
	INIT_WORK(&ipoe_queue_work, ipoe_process_queue);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && RHEL_MAJOR < 7
	err = genl_register_family_with_ops(&ipoe_nl_family, ipoe_nl_ops, ARRAY_SIZE(ipoe_nl_ops));
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
	err = genl_register_family_with_ops_groups(&ipoe_nl_family, ipoe_nl_ops, ipoe_nl_mcgs);
#else
	err = genl_register_family(&ipoe_nl_family);
#endif
	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register netlink interface\n");
		return err;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && RHEL_MAJOR < 7
	err = genl_register_mc_group(&ipoe_nl_family, &ipoe_nl_mcg);
	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register netlink multicast group\n");
		genl_unregister_family(&ipoe_nl_family);
		return err;
	}
#endif

	return 0;
}

static void __exit ipoe_fini(void)
{
	struct ipoe_entry_u *e;
	struct ipoe_session *ses;
	struct net_device *dev;
	int i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && RHEL_MAJOR < 7
	genl_unregister_mc_group(&ipoe_nl_family, &ipoe_nl_mcg);
#endif
	genl_unregister_family(&ipoe_nl_family);

	down(&ipoe_wlock);
	up(&ipoe_wlock);

	rtnl_lock();
	while (!list_empty(&ipoe_interfaces)) {
		struct ipoe_iface *i = list_entry(ipoe_interfaces.next, typeof(*i), entry);

		dev = __dev_get_by_index(&init_net, i->ifindex);

		if (dev && rcu_dereference(dev->rx_handler) == ipoe_recv)
			netdev_rx_handler_unregister(dev);

		list_del(&i->entry);

		kfree_rcu(i, rcu_head);
	}
	rtnl_unlock();

	synchronize_net();

	flush_work(&ipoe_queue_work);
	skb_queue_purge(&ipoe_queue);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,2,0)
	del_timer(&ipoe_timer_u);
#else
	timer_delete(&ipoe_timer_u);
#endif

	for (i = 0; i <= IPOE_HASH_BITS; i++)
		rcu_assign_pointer(ipoe_list[i].next, &ipoe_list[i]);

	rcu_barrier();

	while (!list_empty(&ipoe_list2)) {
		ses = list_entry(ipoe_list2.next, typeof(*ses), entry2);
		list_del(&ses->entry2);

		if (ses->link_dev)
			dev_put(ses->link_dev);

		unregister_netdev(ses->dev);
	}

	while (!list_empty(&ipoe_list2_u)) {
		e = list_entry(ipoe_list2_u.next, typeof(*e), entry2);
		list_del(&e->entry2);
		kfree(e);
	}

	clean_excl_list();

	synchronize_rcu();
}

module_init(ipoe_init);
module_exit(ipoe_fini);
MODULE_LICENSE("GPL");
