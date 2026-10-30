#include <pthread.h>
#include <sched.h>

#include "l2tp_switch_peer_test.h"

#define FLOOD_BATCH 64

int fin_flood_on = FIN_FLOOD_OFF;
int fin_flood_stopccn_ms;
int fin_flood_start_ms;
int fin_flood_len_ms;
int fin_flood_no_stopccn;
int flood_heavy;

/* "A:S:W": ms after the anchor to send StopCCN, start the flood, and flood length */
int parse_fin_flood(const char *spec)
{
	if (sscanf(spec, "%d:%d:%d", &fin_flood_stopccn_ms,
		   &fin_flood_start_ms, &fin_flood_len_ms) != 3 ||
	    fin_flood_stopccn_ms < 0 || fin_flood_start_ms < 0 ||
	    fin_flood_len_ms <= 0)
		return die("invalid --fin-flood (expected A:S:W, all in ms)");

	return 0;
}

static int send_stopccn_now(int fd, const struct sockaddr_in *their_addr,
			    uint16_t their_tid, uint16_t our_tid,
			    uint16_t ns, uint16_t nr)
{
	struct l2tp_avp_result_code rc = { htons(1), htons(6) };
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
				 their_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("StopCCN alloc failed");
	l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, our_tid, 1);
	l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc, sizeof(rc), 1);
	pack->hdr.tid = htons(their_tid);
	pack->hdr.sid = 0;
	pack->hdr.Ns = htons(ns);
	pack->hdr.Nr = htons(nr);
	if (l2tp_packet_send(fd, pack) < 0) {
		l2tp_packet_free(pack);
		return die("StopCCN send failed");
	}
	l2tp_packet_free(pack);

	return 0;
}

/* wire bytes of one junk datagram carrying as many valid AVPs as fit in a UDP
 * datagram, each of which the receiver allocates and frees before it can drop
 * the datagram for its unknown tid: it costs the receiver far more than it
 * costs this sender, and the few such datagrams its socket buffer holds keep
 * it busy for much longer than the sender's pacing period (see below) */
#define HEAVY_AVPS 9000
#define HEAVY_AVP_LEN 7
static uint8_t heavy_buf[sizeof(struct l2tp_hdr_t) + HEAVY_AVPS * HEAVY_AVP_LEN];

static size_t build_heavy_junk(const struct l2tp_hdr_t *wire)
{
	/* flags (length 7, no M/H), vendor 0, type 8 (Vendor-Name), 1 value byte */
	static const uint8_t avp[HEAVY_AVP_LEN] = { 0x00, 0x07, 0x00, 0x00,
						    0x00, 0x08, 'x' };
	struct l2tp_hdr_t hdr = *wire;
	size_t len = sizeof(heavy_buf);
	int i;

	hdr.length = htons(len);
	memcpy(heavy_buf, &hdr, sizeof(hdr));
	for (i = 0; i < HEAVY_AVPS; i++)
		memcpy(heavy_buf + sizeof(hdr) + i * HEAVY_AVP_LEN, avp,
		       HEAVY_AVP_LEN);

	return len;
}

static int init_junk(struct mmsghdr *msgs, struct iovec *iov,
		     struct l2tp_hdr_t *wire,
		     const struct sockaddr_in *their_addr)
{
	struct l2tp_packet_t *junk;
	int i;

	junk = l2tp_packet_alloc(2, 0, their_addr, 0, NULL, 0);
	if (!junk)
		return die("flood junk alloc failed");
	junk->hdr.tid = htons(0xffff);
	junk->hdr.sid = 0;
	*wire = junk->hdr;
	wire->length = htons(sizeof(*wire));
	wire->flags = htons(junk->hdr.flags);
	l2tp_packet_free(junk);

	if (flood_heavy) {
		iov->iov_len = build_heavy_junk(wire);
		iov->iov_base = heavy_buf;
	} else {
		iov->iov_base = wire;
		iov->iov_len = sizeof(*wire);
	}
	memset(msgs, 0, FLOOD_BATCH * sizeof(*msgs));
	for (i = 0; i < FLOOD_BATCH; i++) {
		msgs[i].msg_hdr.msg_name = (void *)their_addr;
		msgs[i].msg_hdr.msg_namelen = sizeof(*their_addr);
		msgs[i].msg_hdr.msg_iov = iov;
		msgs[i].msg_hdr.msg_iovlen = 1;
	}

	return 0;
}

/* Extra senders. A flooded context only stays inside its read handler while
 * the socket never runs empty; on a CPU-starved runner one sender is not
 * scheduled often enough to guarantee that, so a few more keep the queue
 * full whenever the receiver runs. On a single CPU that is still not enough:
 * the senders only run while the receiver is off the CPU, and a receiver that
 * runs for a whole scheduling slice drains the few datagrams the socket holds
 * and leaves the handler. A sender that preempts the receiver whenever it is
 * due (a real-time one, when the process may become one) does not depend on
 * that: it wakes every FLOOD_RT_PERIOD_US, tops the socket up and sleeps, and
 * the receiver, which needs longer than that for the datagrams the socket
 * holds, never finds it empty. */
#define FLOOD_EXTRA_SENDERS 4
#define FLOOD_RT_BATCH 8
#define FLOOD_RT_PERIOD_US 300
#define FLOOD_RT_PRIO 1

struct flood_sender_t {
	int fd;
	double until;
	struct mmsghdr msgs[FLOOD_BATCH];
};

static void *flood_sender(void *arg)
{
	struct flood_sender_t *s = arg;

	while (now_monotonic() < s->until)
		sendmmsg(s->fd, s->msgs, FLOOD_BATCH, 0);

	return NULL;
}

/* returns the number of threads started; they are joined by the caller */
static int start_extra_senders(pthread_t *tids, struct flood_sender_t *senders,
			       int fd, double until,
			       const struct mmsghdr *msgs)
{
	int i, started = 0;

	for (i = 0; i < FLOOD_EXTRA_SENDERS; i++) {
		senders[i].fd = fd;
		senders[i].until = until;
		memcpy(senders[i].msgs, msgs, sizeof(senders[i].msgs));
		if (pthread_create(&tids[started], NULL, flood_sender,
				   &senders[i]) == 0)
			started++;
	}

	return started;
}

/* returns 1 if the calling thread now preempts ordinary ones */
static int enter_realtime(void)
{
	struct sched_param param = { .sched_priority = FLOOD_RT_PRIO };

	return sched_setscheduler(0, SCHED_FIFO, &param) == 0;
}

static void leave_realtime(void)
{
	struct sched_param param = { .sched_priority = 0 };

	sched_setscheduler(0, SCHED_OTHER, &param);
}

/* triton runs timers and md handlers before pending context calls */
int run_fin_flood(int fd, const struct sockaddr_in *their_addr,
		  uint16_t their_tid, uint16_t our_tid,
		  uint16_t ns, uint16_t nr)
{
	double started = now_monotonic();
	double stop_at = started + (double)fin_flood_stopccn_ms / 1000.0;
	double flood_from = started + (double)fin_flood_start_ms / 1000.0;
	double flood_until = flood_from + (double)fin_flood_len_ms / 1000.0;
	struct mmsghdr msgs[FLOOD_BATCH];
	struct l2tp_hdr_t wire;
	struct iovec iov;
	unsigned long sent = 0;
	int stopped = 0, flooding = 0, extra = 0, realtime = 0, i;
	pthread_t tids[FLOOD_EXTRA_SENDERS];
	struct flood_sender_t senders[FLOOD_EXTRA_SENDERS];

	if (init_junk(msgs, &iov, &wire, their_addr))
		return 1;

	for (;;) {
		double now = now_monotonic();

		if (!stopped && now >= stop_at) {
			/* flood only: the tunnel's context is kept busy
			 * without the peer closing the tunnel */
			if (!fin_flood_no_stopccn &&
			    send_stopccn_now(fd, their_addr, their_tid,
					     our_tid, ns, nr))
				return 1;
			stopped = 1;
			if (!fin_flood_no_stopccn) {
				printf("event=fin_flood_stopccn t=%.6f\n",
				       now_monotonic());
				fflush(stdout);
			}
		}
		if (stopped && now >= flood_until)
			break;
		if (now >= flood_from && now < flood_until) {
			int n;

			if (!flooding) {
				flooding = 1;
				if (flood_heavy) {
					realtime = enter_realtime();
					if (!realtime)
						extra = start_extra_senders(
							tids, senders, fd,
							flood_until, msgs);
				}
				printf("event=fin_flood_start t=%.6f realtime=%d\n",
				       now, realtime);
				fflush(stdout);
			}
			n = sendmmsg(fd, msgs,
				     realtime ? FLOOD_RT_BATCH : FLOOD_BATCH, 0);
			if (n > 0)
				sent += (unsigned long)n;
			if (realtime)
				usleep(FLOOD_RT_PERIOD_US);
			continue;
		}
		usleep(500);
	}

	for (i = 0; i < extra; i++)
		pthread_join(tids[i], NULL);
	if (realtime)
		leave_realtime();

	printf("event=fin_flood_end t=%.6f junk=%lu\n", now_monotonic(), sent);
	fflush(stdout);

	return 0;
}

int busy_flood_ms;

int run_busy_flood(int fd, const struct sockaddr_in *their_addr, int ms)
{
	double until = now_monotonic() + (double)ms / 1000.0;
	struct mmsghdr msgs[FLOOD_BATCH];
	struct l2tp_hdr_t wire;
	struct iovec iov;

	if (init_junk(msgs, &iov, &wire, their_addr))
		return 1;

	while (now_monotonic() < until)
		sendmmsg(fd, msgs, FLOOD_BATCH, 0);

	return 0;
}
