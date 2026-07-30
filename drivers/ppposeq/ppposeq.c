/*
 * ppposeq - PPP over SEQPACKET socket driver.
 *
 * Replaces the pty + ppp_async transport for userspace PPP terminators.
 * A pty is a byte stream: the tty flip buffer merges frames written
 * back to back (flush_to_ldisc hands receive_buf everything committed
 * since the last flush in one call), so PPP over a pty needs HDLC
 * framing to re-delimit frames. Here the socket is the PPP endpoint
 * and one datagram is one PPP frame, so no HDLC framing is needed.
 *
 * Copyright (C) 2026 Vladislav Grishenko
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/version.h>
#include <linux/ppp_defs.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
#include <linux/if.h>
#include <linux/if_ppp.h>
#else
#include <linux/ppp-ioctl.h>
#endif
#include <linux/ppp_channel.h>
#include <linux/if_pppox.h>

#include <net/sock.h>

#include "ppposeq.h"

/* proto_ops connect/bind signatures changed to sockaddr_unsized in 6.19 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,19,0)
#define sockaddr_unsized sockaddr
#endif

/* the noblock argument was folded into flags in 5.19 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
#define ppposeq_recv_datagram(sk, flags, err) \
	skb_recv_datagram(sk, (flags), (flags) & MSG_DONTWAIT, err)
#else
#define ppposeq_recv_datagram(sk, flags, err) \
	skb_recv_datagram(sk, flags, err)
#endif

/* __sock_queue_rcv_skb was introduced in 4.7 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
#define ppposeq_queue_rcv_skb(sk, skb) \
	sock_queue_rcv_skb(sk, skb)
#else
#define ppposeq_queue_rcv_skb(sk, skb) \
	__sock_queue_rcv_skb(sk, skb)
#endif

/* sk_alloc gained a trailing kern argument in 4.2 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
#define ppposeq_sk_alloc(net, fam, prio, prot, kern) \
	sk_alloc(net, fam, prio, prot)
#else
#define ppposeq_sk_alloc(net, fam, prio, prot, kern) \
	sk_alloc(net, fam, prio, prot, kern)
#endif

/* memcpy_from_msg appeared in 3.19, replacing memcpy_fromiovec */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
#define memcpy_from_msg(data, msg, len) \
	memcpy_fromiovec(data, (msg)->msg_iov, len)
#define skb_copy_datagram_msg(skb, off, msg, len) \
	skb_copy_datagram_iovec(skb, off, (msg)->msg_iov, len)
#endif

/* smp_mb__after_atomic was introduced in 3.16 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
#define smp_mb__after_atomic() smp_mb()
#endif

/* U16_MAX was introduced in 3.14 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#define U16_MAX ((u16)~0U)
#endif

#define XMIT_WAKEUP	0

#define XMIT_PULL_PROT	(1 << 0)
#define XMIT_PUSH_AC	(1 << 1)

#define SC_RCV_BITS	(SC_RCV_B7_1|SC_RCV_B7_0|SC_RCV_ODDP|SC_RCV_EVNP)

struct ppposeq_opt {
	int		mru;
	unsigned int	flags;
	unsigned long	xmit_flags;
};

/*
 * pppox_sock's proto union is fixed by the core, so keep our state
 * alongside the socket rather than in it.
 */
struct ppposeq_sock {
	struct pppox_sock	po;
	struct ppposeq_opt	opt;
};

static inline struct ppposeq_sock *ppposeq_sk(struct sock *sk)
{
	return (struct ppposeq_sock *)sk;
}

static const struct proto_ops ppposeq_ops;

static struct proto ppposeq_sk_proto = {
	.name	  = "PPPOSEQ",
	.owner	  = THIS_MODULE,
	.obj_size = sizeof(struct ppposeq_sock),
};

/*
 * Transmit: kernel -> userspace. Called from ppp_generic with
 * spin_lock(&pch->downl) held, so this must not sleep. Queue the frame on
 * the socket's receive queue; userspace picks it up with recvmsg. One skb
 * in, one datagram out.
 */
static int ppposeq_xmit(struct ppp_channel *chan, struct sk_buff *skb)
{
	struct sock *sk = (struct sock *)chan->private;
	struct ppposeq_sock *ps = ppposeq_sk(sk);
	int err, proto, islcp, flags = 0;
	u8 *data;

	if (sock_flag(sk, SOCK_DEAD) || !(sk->sk_state & PPPOX_CONNECTED))
		goto drop;

	/* Ensure we can safely access protocol field and LCP code */
	if (!pskb_may_pull(skb, 3))
		goto drop;

	/* Apply negotiated PFC/ACFC, like ppp_sync_txmunge. */
	data = skb->data;
	proto = (data[0] << 8) + data[1];

	/* LCP codes 1..7 must be sent uncompressed. */
	islcp = (proto == PPP_LCP) && data[2] >= 1 && data[2] <= 7;

	/* compress protocol field if PFC is in effect */
	if ((ps->opt.flags & SC_COMP_PROT) && data[0] == 0 && !islcp) {
		skb_pull(skb, 1);
		flags |= XMIT_PULL_PROT;
	}

	/* prepend address/control unless ACFC is in effect (or it's LCP) */
	if ((ps->opt.flags & SC_COMP_AC) == 0 || islcp) {
		if (skb_cow_head(skb, 2))
			goto drop;
		skb_push(skb, 2);
		skb->data[0] = PPP_ALLSTATIONS;
		skb->data[1] = PPP_UI;
		flags |= XMIT_PUSH_AC;
	}

	/*
	 * Set the wakeup flag before attempting to queue and clear on success,
	 * so a concurrent ppposeq_recvmsg that frees space cannot miss it.
	 * Spurious wakeups may only happen during the brief queue window,
	 * not on every frame.
	 */
	set_bit(XMIT_WAKEUP, &ps->opt.xmit_flags);
	smp_mb__after_atomic();

	/* Bypass receive filter machinery where the helper is available. */
	err = ppposeq_queue_rcv_skb(sk, skb);
	if (unlikely(err < 0)) {
		/*
		 * Receive queue full. Restore the frame and ask ppp_generic to
		 * retry: it requeues the skb, so do not free it here.
		 */
		if (flags & XMIT_PUSH_AC)
			__skb_pull(skb, 2);
		if (flags & XMIT_PULL_PROT)
			*(u8 *)skb_push(skb, 1) = 0;
		return 0;
	}

	clear_bit(XMIT_WAKEUP, &ps->opt.xmit_flags);
	return 1;

drop:
	kfree_skb(skb);
	return 1;
}

/*
 * Channel ioctls. The framing-related ones ppp_synctty implements
 * (PPPIOC[GS]ASYNCMAP, PPPIOC[GS]RASYNCMAP, PPPIOC[GS]XASYNCMAP) have no
 * meaning without async framing, so only flags and MRU carry over.
 */
static int ppposeq_chan_ioctl(struct ppp_channel *chan, unsigned int cmd,
			     unsigned long arg)
{
	struct sock *sk = (struct sock *)chan->private;
	struct ppposeq_sock *ps = ppposeq_sk(sk);
	void __user *argp = (void __user *)arg;
	int err, val;

	err = -EFAULT;
	switch (cmd) {
	case PPPIOCGFLAGS:
		if (put_user(ps->opt.flags, (int __user *)argp))
			break;
		err = 0;
		break;
	case PPPIOCSFLAGS:
		if (get_user(val, (int __user *)argp))
			break;
		ps->opt.flags = val & ~SC_RCV_BITS;
		err = 0;
		break;
	case PPPIOCGMRU:
		if (put_user(ps->opt.mru, (int __user *)argp))
			break;
		err = 0;
		break;
	case PPPIOCSMRU:
		if (get_user(val, (int __user *)argp))
			break;
		if (val > U16_MAX) {
			err = -EINVAL;
			break;
		}
		if (val < PPP_MRU)
			val = PPP_MRU;
		ps->opt.mru = val;
		err = 0;
		break;
	default:
		err = -ENOTTY;
		break;
	}

	return err;
}

static const struct ppp_channel_ops ppposeq_chan_ops = {
	.start_xmit = ppposeq_xmit,
	.ioctl	    = ppposeq_chan_ioctl,
};

/*
 * Receive: userspace -> kernel. One sendmsg is one frame, so there is no
 * reassembly to do -- just validate and hand it to the ppp layer.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
static int ppposeq_sendmsg(struct kiocb *iocb, struct socket *sock,
			  struct msghdr *m, size_t total_len)
#else
static int ppposeq_sendmsg(struct socket *sock, struct msghdr *m,
			  size_t total_len)
#endif
{
	struct sock *sk = sock->sk;
	struct ppposeq_sock *ps = ppposeq_sk(sk);
	struct pppox_sock *po = pppox_sk(sk);
	struct sk_buff *skb;
	int err;
	u8 *data;

	if (total_len == 0)
		return 0;

	lock_sock(sk);

	if (sock_flag(sk, SOCK_DEAD) || !(sk->sk_state & PPPOX_CONNECTED)) {
		err = -ENOTCONN;
		goto out;
	}

	if (total_len > ps->opt.mru + PPP_HDRLEN) {
		err = -EMSGSIZE;
		goto out;
	}

	/* plus headroom for network and PFC decompression */
	skb = sock_alloc_send_skb(sk, NET_SKB_PAD + 2 + total_len,
				  m->msg_flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto out;
	skb_reserve(skb, NET_SKB_PAD + 2);

	err = memcpy_from_msg(skb_put(skb, total_len), m, total_len);
	if (err) {
		kfree_skb(skb);
		goto out;
	}

	/* strip address/control field if present */
	data = skb->data;
	if (data[0] == PPP_ALLSTATIONS) {
		/* chop off address/control */
		if (skb->len < 3 || data[1] != PPP_UI) {
			kfree_skb(skb);
			err = -EINVAL;
			goto out;
		}
		data = skb_pull(skb, 2);
	}

	/* decompress protocol field if compressed */
	if (data[0] & 0x01) {
		*(u8 *)skb_push(skb, 1) = 0;
	} else if (skb->len < 2) {
		kfree_skb(skb);
		err = -EINVAL;
		goto out;
	}

	ppp_input(&po->chan, skb);
	err = total_len;

out:
	release_sock(sk);
	return err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
static int ppposeq_recvmsg(struct kiocb *iocb, struct socket *sock,
			  struct msghdr *m, size_t total_len, int flags)
#else
static int ppposeq_recvmsg(struct socket *sock, struct msghdr *m,
			  size_t total_len, int flags)
#endif
{
	struct sock *sk = sock->sk;
	struct ppposeq_sock *ps = ppposeq_sk(sk);
	struct pppox_sock *po = pppox_sk(sk);
	struct sk_buff *skb;
	int err;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	skb = ppposeq_recv_datagram(sk, flags, &err);
	if (!skb)
		return err;

	if (total_len > skb->len)
		total_len = skb->len;
	else if (total_len < skb->len)
		m->msg_flags |= MSG_TRUNC;

	err = skb_copy_datagram_msg(skb, 0, m, total_len);
	if (likely(err == 0))
		err = (flags & MSG_TRUNC) ? skb->len : total_len;

	skb_free_datagram(sk, skb);
	if (flags & MSG_PEEK)
		return err;

	/* Pair with the barrier after XMIT_WAKEUP is set in xmit. */
	smp_mb();

	/* Room freed: let ppp_generic retry the restored PPP frame. */
	if (test_bit(XMIT_WAKEUP, &ps->opt.xmit_flags))
		ppp_output_wakeup(&po->chan);

	return err;
}

/*
 * connect() registers the ppp channel. There is no transport to look up --
 * this socket is the endpoint -- so the address carries nothing but the
 * family and protocol.
 */
static int ppposeq_connect(struct socket *sock, struct sockaddr_unsized *uservaddr,
			  int sockaddr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_pppox *sp = (struct sockaddr_pppox *)uservaddr;
	struct ppposeq_sock *ps = ppposeq_sk(sk);
	struct pppox_sock *po = pppox_sk(sk);
	int err;

	if (sockaddr_len < sizeof(struct sockaddr_ppposeq))
		return -EINVAL;

	if (sp->sa_protocol != PX_PROTO_OSEQ)
		return -EINVAL;

	lock_sock(sk);

	if (sk->sk_state & PPPOX_CONNECTED) {
		err = -EBUSY;
		goto out;
	}

	if (sk->sk_state & PPPOX_DEAD) {
		err = -EALREADY;
		goto out;
	}

	po->chan.private = sk;
	po->chan.ops = &ppposeq_chan_ops;
	po->chan.mtu = ps->opt.mru;
	/* reserve the address/control bytes ppposeq_xmit prepends, so the
	 * core leaves us the headroom to skb_push them without a copy */
	po->chan.hdrlen = 2;

	err = ppp_register_net_channel(sock_net(sk), &po->chan);
	if (err)
		goto out;

	sk->sk_state = PPPOX_CONNECTED;
	sock->state = SS_CONNECTED;

out:
	release_sock(sk);
	return err;
}

static int ppposeq_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	lock_sock(sk);

	if (sock_flag(sk, SOCK_DEAD)) {
		release_sock(sk);
		return -EBADF;
	}

	if (sk->sk_state & PPPOX_CONNECTED)
		pppox_unbind_sock(sk);

	/* signal the death of the socket before dropping the lock */
	sk->sk_state = PPPOX_DEAD;
	sock_orphan(sk);
	sock->sk = NULL;

	skb_queue_purge(&sk->sk_receive_queue);
	release_sock(sk);
	sock_put(sk);

	return 0;
}

/* getname returned the length via *len until 4.17, by return value after */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
static int ppposeq_getname(struct socket *sock, struct sockaddr *uaddr,
			  int *len, int peer)
#else
static int ppposeq_getname(struct socket *sock, struct sockaddr *uaddr,
			  int peer)
#endif
{
	struct sockaddr_ppposeq sp;

	memset(&sp, 0, sizeof(sp));
	sp.sa_family = AF_PPPOX;
	sp.sa_protocol = PX_PROTO_OSEQ;
	memcpy(uaddr, &sp, sizeof(sp));

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
	*len = sizeof(sp);
	return 0;
#else
	return sizeof(sp);
#endif
}

/* pppox_proto.create gained a trailing kern argument in 4.2 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
static int ppposeq_create(struct net *net, struct socket *sock)
#else
static int ppposeq_create(struct net *net, struct socket *sock, int kern)
#endif
{
	struct sock *sk;

	sk = ppposeq_sk_alloc(net, PF_PPPOX, GFP_KERNEL, &ppposeq_sk_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	sock->state	= SS_UNCONNECTED;
	sock->ops	= &ppposeq_ops;

	sk->sk_state	= PPPOX_NONE;
	sk->sk_type	= SOCK_SEQPACKET;
	sk->sk_family	= PF_PPPOX;
	sk->sk_protocol	= PX_PROTO_OSEQ;

	ppposeq_sk(sk)->opt.mru = PPP_MRU;

	return 0;
}

static const struct proto_ops ppposeq_ops = {
	.family		= AF_PPPOX,
	.owner		= THIS_MODULE,
	.release	= ppposeq_release,
	.bind		= sock_no_bind,
	.connect	= ppposeq_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= ppposeq_getname,
	.poll		= datagram_poll,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	/* sock_no_setsockopt/getsockopt were removed and the proto_ops
	 * signatures changed to sockptr_t in 5.9 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
#endif
	.sendmsg	= ppposeq_sendmsg,
	.recvmsg	= ppposeq_recvmsg,
	.mmap		= sock_no_mmap,
	.ioctl		= pppox_ioctl,
	/* pppox_compat_ioctl was added in 5.3; before that the core
	 * routed compat ioctls through .ioctl itself */
#if defined(CONFIG_COMPAT) && LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
	.compat_ioctl	= pppox_compat_ioctl,
#endif
};

static const struct pppox_proto ppposeq_proto = {
	.create	= ppposeq_create,
	.ioctl	= NULL,		/* pppox_ioctl handles PPPIOCGCHAN for us */
	.owner	= THIS_MODULE,
};

static int __init ppposeq_init(void)
{
	int err;

	err = proto_register(&ppposeq_sk_proto, 0);
	if (err)
		return err;

	err = register_pppox_proto(PX_PROTO_OSEQ, &ppposeq_proto);
	if (err)
		goto out_unregister_proto;

	pr_info("PPP over SEQPACKET socket driver\n");
	return 0;

out_unregister_proto:
	proto_unregister(&ppposeq_sk_proto);
	return err;
}

static void __exit ppposeq_exit(void)
{
	unregister_pppox_proto(PX_PROTO_OSEQ);
	proto_unregister(&ppposeq_sk_proto);
}

module_init(ppposeq_init);
module_exit(ppposeq_exit);

MODULE_DESCRIPTION("PPP over SEQPACKET socket driver");
MODULE_AUTHOR("Vladislav Grishenko");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO(PF_PPPOX, PX_PROTO_OSEQ);
