/*
 * ppposeq - PPP over a SEQPACKET AF_PPPOX socket.
 *
 * Replaces the pty + ppp_async transport for userspace PPP terminators.
 * A pty is a byte stream, so frame boundaries are lost in the tty flip
 * buffer and have to be rebuilt with HDLC escape+FCS framing.
 * Here the socket itself is the PPP endpoint and each datagram carries
 * exactly one PPP frame, so no HDLC framing is needed on either side.
 *
 *	fd = socket(AF_PPPOX, SOCK_SEQPACKET, PX_PROTO_OSEQ);
 *	connect(fd, &sa, sizeof(sa));		// registers the channel
 *	ioctl(fd, PPPIOCGCHAN, &idx);
 *	chan = open("/dev/ppp"); ioctl(chan, PPPIOCATTCHAN, &idx);
 *	// frames flow over fd with send()/recv()
 *
 * Only the protocol number is new; everything else uses the common
 * AF_PPPOX and PPPIOC* interfaces.
 */

#ifndef __PPPOSEQ_H
#define __PPPOSEQ_H

#include <linux/if_pppox.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
typedef sa_family_t __kernel_sa_family_t;
#endif

#ifndef PX_PROTO_OSEQ
#define PX_PROTO_OSEQ	3
#endif

struct sockaddr_ppposeq {
	__kernel_sa_family_t sa_family;		/* AF_PPPOX */
	unsigned int	sa_protocol;		/* PX_PROTO_OSEQ */
} __attribute__((packed));

#endif
