#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>

#include "list.h"
#include "triton.h"
#include "mempool.h"
#include "log.h"
#include "rbtree.h"

#include "ipoe.h"

#include "memdebug.h"

struct arp_node {
	struct rb_node node;
	struct ipoe_serv *ipoe;
};

struct arp_tree {
	pthread_mutex_t lock;
	struct rb_root root;
};

static mempool_t arp_pool;
static mempool_t arp_hdr_pool;

static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#define HASH_BITS 0xff
static struct arp_tree *arp_tree;

static struct triton_md_handler_t arp_hnd;

static void arp_ctx_read(struct _arphdr *ah)
{
	struct _arphdr ah2;
	struct ipoe_session *ses, *ses1 = NULL, *ses2 = NULL;
	struct ipoe_serv *ipoe = container_of(triton_context_self(), typeof(*ipoe), ctx);
	struct sockaddr_ll dst;

	if (ah->ar_spa == ah->ar_tpa)
		goto out;

	memset(&dst, 0, sizeof(dst));
	dst.sll_family = AF_PACKET;
	dst.sll_ifindex = ipoe->ifindex;
	dst.sll_halen = ETH_ALEN;
	dst.sll_protocol = htons(ETH_P_ARP);

	ah2.ar_hrd = htons(ARPHRD_ETHER);
	ah2.ar_pro = htons(ETH_P_IP);
	ah2.ar_hln = ETH_ALEN;
	ah2.ar_pln = 4;
	ah2.ar_op = htons(ARPOP_REPLY);

	pthread_mutex_lock(&ipoe->lock);
	if (ah->ar_op == htons(ARPOP_REPLY)) {
		ipoe_serv_recv_arp(ipoe, ah);
		pthread_mutex_unlock(&ipoe->lock);
		goto out;
	}

	list_for_each_entry(ses, &ipoe->sessions, entry) {
		if (ses->yiaddr == ah->ar_spa) {
			ses1 = ses;
			if (ses->ses.state != AP_STATE_ACTIVE)
				break;
		}

		if (ses->yiaddr == ah->ar_tpa) {
			ses2 = ses;
			if (ses->ses.state != AP_STATE_ACTIVE)
				break;
		}

		if (ses1 && ses2)
			break;
	}

	if (!ses1 && ipoe->opt_up && ipoe_check_localnet(ah->ar_spa)) {
		ipoe_serv_recv_arp(ipoe, ah);
		pthread_mutex_unlock(&ipoe->lock);
		goto out;
	}

	if (!ipoe->opt_arp || !ses1 || ses1->arph ||
		(ses2 && ses2->ses.state != AP_STATE_ACTIVE)) {
		pthread_mutex_unlock(&ipoe->lock);
		goto out;
	}

	if (ses2) {
		if (ipoe->opt_arp == 1) {
			pthread_mutex_unlock(&ipoe->lock);
			goto out;
		}
	}
	memcpy(ah2.ar_sha, ipoe->hwaddr, ETH_ALEN);

	pthread_mutex_unlock(&ipoe->lock);

	memcpy(dst.sll_addr, ah->ar_sha, ETH_ALEN);
	memcpy(ah2.ar_tha, ah->ar_sha, ETH_ALEN);
	ah2.ar_spa = ah->ar_tpa;
	ah2.ar_tpa = ah->ar_spa;

	sendto(arp_hnd.fd, &ah2, sizeof(ah2), MSG_DONTWAIT, (struct sockaddr *)&dst, sizeof(dst));

out:
	mempool_free(ah);
}

void arp_send(int ifindex, struct _arphdr *arph, int broadcast)
{
	struct sockaddr_ll dst;

	memset(&dst, 0, sizeof(dst));
	dst.sll_family = AF_PACKET;
	dst.sll_ifindex = ifindex;
	dst.sll_halen = ETH_ALEN;
	dst.sll_protocol = htons(ETH_P_ARP);
	if (broadcast)
		memcpy(dst.sll_addr, bc_addr, ETH_ALEN);
	else
		memcpy(dst.sll_addr, arph->ar_tha, ETH_ALEN);

	arph->ar_op = htons(ARPOP_REPLY);

	sendto(arp_hnd.fd, arph, sizeof(*arph), MSG_DONTWAIT, (struct sockaddr *)&dst, sizeof(dst));
}

static int arp_read(struct triton_md_handler_t *h)
{
	int r, i;
	struct _arphdr *ah = NULL;
	struct sockaddr_ll src;
	socklen_t slen = sizeof(src);
	struct arp_tree *t;
	struct arp_node *n;
	struct rb_node **p, *parent;

	while (1) {
		if (!ah)
			ah = mempool_alloc(arp_hdr_pool);

		r = recvfrom(h->fd, ah, sizeof(*ah), MSG_DONTWAIT, (struct sockaddr *)&src, &slen);
		if (r < 0) {
			if (errno == EAGAIN)
				break;
			continue;
		}

		if (r < sizeof(*ah))
			continue;

		if (ah->ar_op != htons(ARPOP_REQUEST)) {
			if (ah->ar_op != htons(ARPOP_REPLY))
				continue;

			if (memcmp(src.sll_addr, bc_addr, ETH_ALEN))
				continue;
		}

		if (ah->ar_pln != 4)
			continue;

		if (ah->ar_pro != htons(ETH_P_IP))
			continue;

		if (ah->ar_hln != ETH_ALEN)
			continue;

		if (memcmp(ah->ar_sha, src.sll_addr, ETH_ALEN))
			continue;

		if (ah->ar_spa == 0)
			continue;

		t = &arp_tree[src.sll_ifindex & HASH_BITS];

		parent = NULL;

		pthread_mutex_lock(&t->lock);

		p = &t->root.rb_node;

		while (*p) {
			parent = *p;
			n = rb_entry(parent, typeof(*n), node);
			i = n->ipoe->ifindex;

			if (src.sll_ifindex < i)
				p = &(*p)->rb_left;
			else if (src.sll_ifindex > i)
				p = &(*p)->rb_right;
			else {
				triton_context_call(&n->ipoe->ctx, (triton_event_func)arp_ctx_read, ah);
				ah = NULL;
				break;
			}
		}

		pthread_mutex_unlock(&t->lock);
	}

	mempool_free(ah);

	return 0;
}

void *arpd_start(struct ipoe_serv *ipoe)
{
	struct rb_node **p, *parent = NULL;
	struct arp_node *n = NULL;
	struct arp_tree *t;
	int fd, ifindex = ipoe->ifindex, i;
	char fname[1024];

	sprintf(fname, "/proc/sys/net/ipv4/conf/%s/proxy_arp", ipoe->ifname);
	fd = open(fname, O_WRONLY);
	if (fd >= 0) {
		fname[0] = '0';
		write(fd, fname, 1);
		close(fd);
	}

	t = &arp_tree[ifindex & HASH_BITS];

	pthread_mutex_lock(&t->lock);

	p = &t->root.rb_node;

	while (*p) {
		parent = *p;
		n = rb_entry(parent, typeof(*n), node);
		i = n->ipoe->ifindex;

		if (ifindex < i)
			p = &(*p)->rb_left;
		else if (ifindex > i)
			p = &(*p)->rb_right;
		else {
			pthread_mutex_unlock(&t->lock);
			log_ppp_error("arp: attempt to add duplicate ifindex\n");
			return NULL;
		}
	}

	n = mempool_alloc(arp_pool);
	if (!n) {
		pthread_mutex_unlock(&t->lock);
		log_emerg("out of memory\n");
		return NULL;
	}

	n->ipoe = ipoe;

	rb_link_node(&n->node, parent, p);
	rb_insert_color(&n->node, &t->root);

	pthread_mutex_unlock(&t->lock);

	return n;
}

void arpd_stop(void *arg)
{
	struct arp_node *n = arg;
	struct arp_tree *t = &arp_tree[n->ipoe->ifindex & HASH_BITS];

	pthread_mutex_lock(&t->lock);
	rb_erase(&n->node, &t->root);
	pthread_mutex_unlock(&t->lock);

	mempool_free(n);
}

static void arp_close(struct triton_context_t *ctx);

static struct triton_context_t arp_ctx = {
	.close = arp_close,
};

static struct triton_md_handler_t arp_hnd = {
	.read = arp_read,
};

static void arp_close(struct triton_context_t *ctx)
{
	triton_md_unregister_handler(&arp_hnd, 1);
	triton_context_unregister(ctx);
}

static void init()
{
	struct sockaddr_ll addr;
	int i, f = 1;
	int sock;

	arp_pool = mempool_create(sizeof(struct arp_node));
	arp_hdr_pool = mempool_create(sizeof(struct _arphdr));

	arp_tree = malloc((HASH_BITS + 1) * sizeof(struct arp_tree));
	for (i = 0; i <= HASH_BITS; i++) {
		pthread_mutex_init(&arp_tree[i].lock, NULL);
		arp_tree[i].root = RB_ROOT;
	}

	sock = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_error("arp: socket: %s\n", strerror(errno));
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ARP);

	setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &f, sizeof(f));

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		log_error("arp: bind: %s\n", strerror(errno));
		close(sock);
		return;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);
	fcntl(sock, F_SETFD, FD_CLOEXEC);

	arp_hnd.fd = sock;

	triton_context_register(&arp_ctx, NULL);
	triton_md_register_handler(&arp_ctx, &arp_hnd);
	triton_md_enable_handler(&arp_hnd, MD_MODE_READ);
	triton_context_wakeup(&arp_ctx);
}

DEFINE_INIT(1, init);
