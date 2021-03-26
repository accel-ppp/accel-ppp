#include <unistd.h>
#include <search.h>
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
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>

#include "triton.h"
#include "mempool.h"
#include "log.h"
#include "ppp.h"
#include "events.h"
#include "utils.h"
#include "iprange.h"
#include "cli.h"
#include "crypto.h"

#include "connlimit.h"

#include "memdebug.h"

#include "l2tp.h"
#include "attr_defs.h"

#ifndef SOL_PPPOL2TP
#define SOL_PPPOL2TP 273
#endif

#define STATE_INIT       1
#define STATE_WAIT_SCCRP 2
#define STATE_WAIT_SCCCN 3
#define STATE_WAIT_ICRP  4
#define STATE_WAIT_ICCN  5
#define STATE_WAIT_OCRP  6
#define STATE_WAIT_OCCN  7
#define STATE_ESTB       8
#define STATE_FIN        9
#define STATE_FIN_WAIT   10
#define STATE_CLOSE      11

#define APSTATE_INIT      1
#define APSTATE_STARTING  2
#define APSTATE_STARTED   3
#define APSTATE_FINISHING 4

/* Default size of receive window for peer not sending the
 * Receive Window Size AVP (defined in RFC 2661 section 4.4.3).
 */
#define DEFAULT_PEER_RECV_WINDOW_SIZE 4

/* Maximum value of the Receive Window Size AVP.
 * The Ns field value of received messages must lie in the range of the tunnel
 * Nr field and the following 32768 values inclusive. Other values mean that
 * the message is a duplicate (see comment in nsnr_cmp()).
 * So it wouldn't make sense to have a receive window larger than 32768, as
 * messages that could fill the 32768+ slots would be rejected as duplicates.
 */
#define RECV_WINDOW_SIZE_MAX 32768

#define DEFAULT_RECV_WINDOW 16
#define DEFAULT_PPP_MAX_MTU 1420
#define DEFAULT_RTIMEOUT 1
#define DEFAULT_RTIMEOUT_CAP 16
#define DEFAULT_RETRANSMIT 5

int conf_verbose = 0;
int conf_hide_avps = 0;
int conf_avp_permissive = 0;
static uint16_t conf_recv_window = DEFAULT_RECV_WINDOW;
static int conf_ppp_max_mtu = DEFAULT_PPP_MAX_MTU;
static int conf_port = L2TP_PORT;
static int conf_ephemeral_ports = 0;
static int conf_timeout = 60;
static int conf_rtimeout = DEFAULT_RTIMEOUT;
static int conf_rtimeout_cap = DEFAULT_RTIMEOUT_CAP;
static int conf_retransmit = DEFAULT_RETRANSMIT;
static int conf_hello_interval = 60;
static int conf_dir300_quirk = 0;
static const char *conf_host_name = "accel-ppp";
static const char *conf_secret = NULL;
static size_t conf_secret_len = 0;
static int conf_mppe = MPPE_UNSET;
static int conf_dataseq = L2TP_DATASEQ_ALLOW;
static int conf_reorder_timeout = 0;
static const char *conf_ip_pool;
static const char *conf_ipv6_pool;
static const char *conf_dpv6_pool;
static const char *conf_ifname;

static unsigned int stat_conn_starting;
static unsigned int stat_conn_active;
static unsigned int stat_conn_finishing;

static unsigned int stat_sess_starting;
static unsigned int stat_sess_active;
static unsigned int stat_sess_finishing;

static unsigned int stat_active;
static unsigned int stat_starting;
static unsigned int stat_finishing;

struct l2tp_serv_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct sockaddr_in addr;
};

struct l2tp_sess_t
{
	struct l2tp_conn_t *paren_conn;
	uint16_t sid;
	uint16_t peer_sid;

	unsigned int ref_count;
	int state1;
	uint16_t lns_mode:1;
	uint16_t hide_avps:1;
	uint16_t send_seq:1;
	uint16_t recv_seq:1;
	int reorder_timeout;

	struct triton_timer_t timeout_timer;
	struct list_head send_queue;

	pthread_mutex_t apses_lock;
	struct triton_context_t apses_ctx;
	int apses_state;
	struct ap_ctrl ctrl;
	struct ppp_t ppp;
};

struct l2tp_conn_t
{
	pthread_mutex_t ctx_lock;
	struct triton_context_t ctx;

	struct triton_md_handler_t hnd;
	struct triton_timer_t timeout_timer;
	struct triton_timer_t rtimeout_timer;
	struct triton_timer_t hello_timer;
	int rtimeout;
	int rtimeout_cap;
	int max_retransmit;

	struct sockaddr_in peer_addr;
	struct sockaddr_in host_addr;
	uint16_t tid;
	uint16_t peer_tid;
	uint32_t framing_cap;
	uint16_t lns_mode:1;
	uint16_t hide_avps:1;
	uint16_t port_set:1;
	uint16_t challenge_len;
	uint8_t *challenge;
	size_t secret_len;
	char *secret;

	int retransmit;
	uint16_t Ns, Nr;
	uint16_t peer_Nr;
	struct list_head send_queue;
	struct list_head rtms_queue;
	unsigned int send_queue_len;
	struct l2tp_packet_t **recv_queue;
	uint16_t recv_queue_sz;
	uint16_t recv_queue_offt;
	uint16_t peer_rcv_wnd_sz;

	unsigned int ref_count;
	int state;
	void *sessions;
	unsigned int sess_count;
};

static pthread_mutex_t l2tp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct l2tp_conn_t **l2tp_conn;

static mempool_t l2tp_conn_pool;
static mempool_t l2tp_sess_pool;

static void l2tp_tunnel_timeout(struct triton_timer_t *t);
static void l2tp_rtimeout(struct triton_timer_t *t);
static void l2tp_send_HELLO(struct triton_timer_t *t);
static int l2tp_conn_read(struct triton_md_handler_t *);
static void l2tp_session_free(struct l2tp_sess_t *sess);
static void l2tp_tunnel_free(struct l2tp_conn_t *conn);
static void apses_stop(void *data);


#define log_tunnel(log_func, conn, fmt, ...)				\
	do {								\
		char addr[17];						\
		u_inet_ntoa(conn->peer_addr.sin_addr.s_addr, addr);	\
		log_func("l2tp tunnel %hu-%hu (%s:%hu): " fmt,		\
			 conn->tid, conn->peer_tid, addr,		\
			 ntohs(conn->peer_addr.sin_port),		\
			 ##__VA_ARGS__);				\
	} while (0)

#define log_session(log_func, sess, fmt, ...)				\
	do {								\
		log_func("l2tp session %hu-%hu, %hu-%hu: "		\
			 fmt, sess->paren_conn->tid,			\
			 sess->paren_conn->peer_tid, sess->sid,		\
			 sess->peer_sid, ##__VA_ARGS__);		\
	} while (0)

static inline void comp_chap_md5(uint8_t *md5, uint8_t ident,
				 const void *secret, size_t secret_len,
				 const void *chall, size_t chall_len)
{
	MD5_CTX md5_ctx;

	memset(md5, 0, MD5_DIGEST_LENGTH);

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, &ident, sizeof(ident));
	MD5_Update(&md5_ctx, secret, secret_len);
	MD5_Update(&md5_ctx, chall, chall_len);
	MD5_Final(md5, &md5_ctx);
}

static inline int nsnr_cmp(uint16_t ns, uint16_t nr)
{
/*
 * RFC 2661, section 5.8:
 *
 * The sequence number in the header of a received message is considered
 * less than or equal to the last received number if its value lies in
 * the range of the last received number and the preceding 32767 values,
 * inclusive. For example, if the last received sequence number was 15,
 * then messages with sequence numbers 0 through 15, as well as 32784
 * through 65535, would be considered less than or equal.
 */
	uint16_t sub_nsnr = ns - nr;
	uint16_t ref = -32767;        /* 32769 */

	/* Compare Ns - Nr with -32767 (which equals 32769 for uint16_t):
	 *
	 * Ns == Nr  <==>  Ns - Nr == 0,
	 * Ns > Nr   <==>  Ns - Nr in ]0, 32769[   <==>  0 < Ns - Nr < ref
	 * Ns < Nr   <==>  Ns - Nr in [-32767, 0[  <==> (Ns - Nr) >= ref,
	 */
	return (sub_nsnr != 0 && sub_nsnr < ref) - (sub_nsnr >= ref);
}

static void l2tp_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	struct ap_session *apses = arg;

	if (apses)
		net = apses->net;
	else
		net = def_net;

	log_switch(ctx, arg);
}

static inline struct l2tp_conn_t *l2tp_tunnel_self(void)
{
	return container_of(triton_context_self(), struct l2tp_conn_t, ctx);
}

static int sess_cmp(const void *a, const void *b)
{
	const struct l2tp_sess_t *sess_a = a;
	const struct l2tp_sess_t *sess_b = b;

	return (sess_a->sid > sess_b->sid) - (sess_a->sid < sess_b->sid);
}

static struct l2tp_sess_t *l2tp_tunnel_get_session(struct l2tp_conn_t *conn,
						   uint16_t sid)
{
	struct l2tp_sess_t sess = {.sid = sid, 0};
	struct l2tp_sess_t **res = NULL;

	res = tfind(&sess, &conn->sessions, sess_cmp);

	return (res) ? *res : NULL;
}

static int l2tp_tunnel_genchall(uint16_t chall_len,
				struct l2tp_conn_t *conn,
				struct l2tp_packet_t *pack)
{
	void *ptr = NULL;
	int err;

	if (chall_len == 0
	    || conn->secret == NULL || conn->secret_len == 0) {
		if (conn->challenge) {
			_free(conn->challenge);
			conn->challenge = NULL;
		}
		conn->challenge_len = 0;
		return 0;
	}

	if (conn->challenge_len != chall_len) {
		ptr = _realloc(conn->challenge, chall_len);
		if (ptr == NULL) {
			log_tunnel(log_error, conn,
				   "impossible to generate Challenge:"
				   " memory allocation failed\n");
			goto err;
		}
		conn->challenge = ptr;
		conn->challenge_len = chall_len;
	}

	if (u_randbuf(conn->challenge, chall_len, &err) < 0) {
		if (err)
			log_tunnel(log_error, conn,
				   "impossible to generate Challenge:"
				   " reading from urandom failed: %s\n",
				   strerror(err));
		else
			log_tunnel(log_error, conn,
				   "impossible to generate Challenge:"
				   " end of file reached while reading"
				   " from urandom\n");
		goto err;
	}

	if (l2tp_packet_add_octets(pack, Challenge, conn->challenge,
				   conn->challenge_len, 1) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to generate Challenge:"
			   " adding data to packet failed\n");
		goto err;
	}

	return 0;

err:
	if (conn->challenge) {
		_free(conn->challenge);
		conn->challenge = NULL;
	}
	conn->challenge_len = 0;
	return -1;
}

static int l2tp_tunnel_storechall(struct l2tp_conn_t *conn,
				  const struct l2tp_attr_t *chall)
{
	void *ptr = NULL;

	if (chall == NULL) {
		if (conn->challenge) {
			_free(conn->challenge);
			conn->challenge = NULL;
		}
		conn->challenge_len = 0;
		return 0;
	}

	if (conn->secret == NULL || conn->secret_len == 0) {
		log_tunnel(log_error, conn, "authentication required by peer,"
			   " but no secret has been set for this tunnel\n");
		goto err;
	}

	if (conn->challenge_len != chall->length) {
		ptr = _realloc(conn->challenge, chall->length);
		if (ptr == NULL) {
			log_tunnel(log_error, conn,
				   "impossible to store received"
				   " Challenge: memory allocation failed\n");
			goto err;
		}
		conn->challenge = ptr;
		conn->challenge_len = chall->length;
	}

	memcpy(conn->challenge, chall->val.octets, chall->length);

	return 0;

err:
	if (conn->challenge) {
		_free(conn->challenge);
		conn->challenge = NULL;
	}
	conn->challenge_len = 0;
	return -1;
}

static int l2tp_tunnel_genchallresp(uint8_t msgident,
				    const struct l2tp_conn_t *conn,
				    struct l2tp_packet_t *pack)
{
	uint8_t challresp[MD5_DIGEST_LENGTH];

	if (conn->challenge == NULL) {
		if (conn->secret && conn->secret_len > 0) {
			log_tunnel(log_warn, conn,
				   "no Challenge sent by peer\n");
		}
		return 0;
	}

	if (conn->secret == NULL || conn->secret_len == 0) {
		log_tunnel(log_error, conn,
			   "impossible to generate Challenge Response:"
			   " no secret set for this tunnel\n");
		return -1;
	}

	comp_chap_md5(challresp, msgident, conn->secret, conn->secret_len,
		      conn->challenge, conn->challenge_len);
	if (l2tp_packet_add_octets(pack, Challenge_Response, challresp,
				   MD5_DIGEST_LENGTH, 1) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to generate Challenge Response:"
			   " adding data to packet failed\n");
		return -1;
	}

	return 0;
}

static int l2tp_tunnel_checkchallresp(uint8_t msgident,
				      const struct l2tp_conn_t *conn,
				      const struct l2tp_attr_t *challresp)
{
	uint8_t challref[MD5_DIGEST_LENGTH];

	if (conn->secret == NULL || conn->secret_len == 0) {
		if (challresp) {
			log_tunnel(log_warn, conn,
				   "discarding unexpected Challenge Response"
				   " sent by peer\n");
		}
		return 0;
	}

	if (conn->challenge == NULL) {
		log_tunnel(log_error, conn, "impossible to authenticate peer:"
			   " Challenge is unavailable\n");
		return -1;
	}

	if (challresp == NULL) {
		log_tunnel(log_error, conn, "impossible to authenticate peer:"
			   " no Challenge Response sent by peer\n");
		return -1;
	} else if (challresp->length != MD5_DIGEST_LENGTH) {
		log_tunnel(log_error, conn, "impossible to authenticate peer:"
			   " invalid Challenge Response sent by peer"
			   " (inconsistent length: %i bytes)\n",
			   challresp->length);
		return -1;
	}

	comp_chap_md5(challref, msgident, conn->secret, conn->secret_len,
		      conn->challenge, conn->challenge_len);
	if (memcmp(challref, challresp->val.octets, MD5_DIGEST_LENGTH) != 0) {
		log_tunnel(log_error, conn, "impossible to authenticate peer:"
			   " invalid Challenge Response sent by peer"
			   " (wrong secret)\n");
		return -1;
	}

	return 0;
}

static void l2tp_tunnel_clear_recvqueue(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	uint16_t id;

	for (id = 0; id < conn->recv_queue_sz; ++id) {
		pack = conn->recv_queue[id];
		if (pack) {
			l2tp_packet_free(pack);
			conn->recv_queue[id] = NULL;
		}
	}
	conn->recv_queue_offt = 0;
}

static void l2tp_tunnel_clear_sendqueue(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	while (!list_empty(&conn->send_queue)) {
		pack = list_first_entry(&conn->send_queue, typeof(*pack),
					entry);
		if (pack->sess_entry.next)
			list_del(&pack->sess_entry);
		list_del(&pack->entry);
		l2tp_packet_free(pack);
	}
	conn->send_queue_len = 0;
}

static void l2tp_session_clear_sendqueue(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	while (!list_empty(&sess->send_queue)) {
		pack = list_first_entry(&sess->send_queue, typeof(*pack),
					sess_entry);
		list_del(&pack->sess_entry);
		list_del(&pack->entry);
		--sess->paren_conn->send_queue_len;
		l2tp_packet_free(pack);
	}
}

static int __l2tp_tunnel_send(const struct l2tp_conn_t *conn,
			      struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *msg_type;
	void (*log_func)(const char *fmt, ...);

	pack->hdr.Nr = htons(conn->Nr);

	if (conf_verbose) {
		if (l2tp_packet_is_ZLB(pack)) {
			log_func = log_debug;
		} else {
			msg_type = list_first_entry(&pack->attrs,
						    typeof(*msg_type), entry);
			if (msg_type->val.uint16 == Message_Type_Hello)
				log_func = log_debug;
			else
				log_func = log_info2;
		}
		log_tunnel(log_func, conn, "send ");
		l2tp_packet_print(pack, log_func);
	}

	return l2tp_packet_send(conn->hnd.fd, pack);
}

/* Drop acknowledged packets from tunnel's retransmission queue */
static int l2tp_tunnel_clean_rtmsqueue(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	unsigned int pkt_freed = 0;

	while (!list_empty(&conn->rtms_queue)) {
		pack = list_first_entry(&conn->rtms_queue, typeof(*pack),
					entry);
		if (nsnr_cmp(ntohs(pack->hdr.Ns), conn->peer_Nr) >= 0)
			break;

		list_del(&pack->entry);
		l2tp_packet_free(pack);
		++pkt_freed;
	}

	log_tunnel(log_debug, conn, "%u message%s acked by peer\n", pkt_freed,
		   pkt_freed > 1 ? "s" : "");

	if (pkt_freed == 0)
		return 0;

	/* Oldest message from retransmission queue has been acknowledged,
	 * reset retransmission counter and timer.
	 */
	conn->retransmit = 0;

	/* Stop timer if retransmission queue is empty */
	if (list_empty(&conn->rtms_queue)) {
		if (conn->rtimeout_timer.tpd)
			triton_timer_del(&conn->rtimeout_timer);

		return 0;
	}

	/* Some messages haven't been acknowledged yet, restart timer */
	conn->rtimeout_timer.period = conn->rtimeout;
	if (conn->rtimeout_timer.tpd) {
		if (triton_timer_mod(&conn->rtimeout_timer, 0) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to clean retransmission queue:"
				   " updating retransmission timer failed\n");

			return -1;
		}
	} else {
		if (triton_timer_add(&conn->ctx,
				     &conn->rtimeout_timer, 0) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to clean retransmission queue:"
				   " starting retransmission timer failed\n");

			return -1;
		}
	}

	return 0;
}

static int l2tp_tunnel_push_sendqueue(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	uint16_t Nr_max = conn->peer_Nr + conn->peer_rcv_wnd_sz;
	unsigned int pkt_sent = 0;

	while (!list_empty(&conn->send_queue)) {
		pack = list_first_entry(&conn->send_queue, typeof(*pack),
					entry);
		if (nsnr_cmp(conn->Ns, Nr_max) >= 0)
			break;

		pack->hdr.Ns = htons(conn->Ns);

		if (__l2tp_tunnel_send(conn, pack) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to process the send queue:"
				   " sending packet %hu failed\n", conn->Ns);

			return -1;
		}

		if (pack->sess_entry.next) {
			list_del(&pack->sess_entry);
			pack->sess_entry.next = NULL;
			pack->sess_entry.prev = NULL;
		}
		list_move_tail(&pack->entry, &conn->rtms_queue);
		--conn->send_queue_len;
		++conn->Ns;
		++pkt_sent;
	}

	log_tunnel(log_debug, conn, "%u message%s sent from send queue\n",
		   pkt_sent, pkt_sent > 1 ? "s" : "");

	if (pkt_sent == 0) {
		if (!list_empty(&conn->send_queue))
			log_tunnel(log_info2, conn,
				   "no message sent while processing the send queue (%u outstanding messages):"
				   " peer's receive window is full (%hu messages)\n",
				   conn->send_queue_len, conn->peer_rcv_wnd_sz);

		return 0;
	}

	/* At least one message sent, restart retransmission timer if necessary
	 * (timer may be stopped, e.g. because there was no message left in the
	 * retransmission queue).
	 */
	if (conn->rtimeout_timer.tpd == NULL) {
		conn->rtimeout_timer.period = conn->rtimeout;
		if (triton_timer_add(&conn->ctx,
				     &conn->rtimeout_timer, 0) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to process the send queue:"
				   " setting retransmission timer failed\n");

			return -1;
		}
	}

	return 1;
}

static int l2tp_tunnel_send(struct l2tp_conn_t *conn,
			    struct l2tp_packet_t *pack)
{
	if (conn->state == STATE_FIN || conn->state == STATE_FIN_WAIT ||
	    conn->state == STATE_CLOSE) {
		log_tunnel(log_info2, conn,
			   "discarding outgoing message, tunnel is closing\n");
		l2tp_packet_free(pack);

		return -1;
	}

	pack->hdr.tid = htons(conn->peer_tid);
	list_add_tail(&pack->entry, &conn->send_queue);
	++conn->send_queue_len;

	return 0;
}

static int l2tp_session_send(struct l2tp_sess_t *sess,
			     struct l2tp_packet_t *pack)
{
	if (sess->state1 == STATE_CLOSE) {
		log_session(log_info2, sess,
			    "discarding outgoing message,"
			    " session is closing\n");
		l2tp_packet_free(pack);

		return -1;
	}

	pack->hdr.sid = htons(sess->peer_sid);

	if (l2tp_tunnel_send(sess->paren_conn, pack) < 0)
		return -1;

	list_add_tail(&pack->sess_entry, &sess->send_queue);

	return 0;
}

static int l2tp_session_try_send(struct l2tp_sess_t *sess,
				 struct l2tp_packet_t *pack)
{
	if (sess->paren_conn->send_queue_len >= sess->paren_conn->peer_rcv_wnd_sz)
		return -1;

	l2tp_session_send(sess, pack);

	return 0;
}

static int l2tp_send_StopCCN(struct l2tp_conn_t *conn,
			     uint16_t res, uint16_t err)
{
	struct l2tp_packet_t *pack = NULL;
	struct l2tp_avp_result_code rc = {htons(res), htons(err)};

	log_tunnel(log_info2, conn, "sending StopCCN (res: %hu, err: %hu)\n",
		   res, err);

	pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (pack == NULL) {
		log_tunnel(log_error, conn, "impossible to send StopCCN:"
			   " packet allocation failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID,
				  conn->tid, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send StopCCN:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
				   sizeof(rc), 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send StopCCN:"
			   " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_tunnel_send(conn, pack);

	return 0;

out_err:
	if (pack)
		l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_CDN(struct l2tp_sess_t *sess, uint16_t res, uint16_t err)
{
	struct l2tp_packet_t *pack = NULL;
	struct l2tp_avp_result_code rc = {htons(res), htons(err)};

	log_session(log_info2, sess, "sending CDN (res: %hu, err: %hu)\n",
		    res, err);

	pack = l2tp_packet_alloc(2, Message_Type_Call_Disconnect_Notify,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == NULL) {
		log_session(log_error, sess, "impossible to send CDN:"
			    " packet allocation failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send CDN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
				   sizeof(rc), 1) < 0) {
		log_session(log_error, sess, "impossible to send CDN:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	if (pack)
		l2tp_packet_free(pack);
	return -1;
}

static int l2tp_tunnel_send_CDN(uint16_t sid, uint16_t peer_sid,
				uint16_t res, uint16_t err)
{
	struct l2tp_packet_t *pack = NULL;
	struct l2tp_avp_result_code rc = {htons(res), htons(err)};
	struct l2tp_conn_t *conn = l2tp_tunnel_self();

	log_tunnel(log_info2, conn, "sending CDN (res: %hu, err: %hu)\n",
		   res, err);

	pack = l2tp_packet_alloc(2, Message_Type_Call_Disconnect_Notify,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (pack == NULL) {
		log_tunnel(log_error, conn, "impossible to send CDN:"
			   " packet allocation failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack, Assigned_Session_ID, sid, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send CDN:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
				   sizeof(rc), 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send CDN:"
			   " adding data to packet failed\n");
		goto out_err;
	}

	pack->hdr.sid = htons(peer_sid);

	l2tp_tunnel_send(conn, pack);

	return 0;

out_err:
	if (pack)
		l2tp_packet_free(pack);
	return -1;
}

static void l2tp_tunnel_free_sessions(struct l2tp_conn_t *conn)
{
	void *sessions = conn->sessions;

	conn->sessions = NULL;
	tdestroy(sessions, (__free_fn_t)l2tp_session_free);
	/* Let l2tp_session_free() handle the session counter and
	 * the reference held by the tunnel.
	 */
}

static int l2tp_tunnel_disconnect(struct l2tp_conn_t *conn,
				  uint16_t res, uint16_t err)
{
	switch (conn->state) {
	case STATE_INIT:
	case STATE_WAIT_SCCRP:
	case STATE_WAIT_SCCCN:
		__sync_sub_and_fetch(&stat_conn_starting, 1);
		__sync_add_and_fetch(&stat_conn_finishing, 1);
		break;
	case STATE_ESTB:
		__sync_sub_and_fetch(&stat_conn_active, 1);
		__sync_add_and_fetch(&stat_conn_finishing, 1);
		break;
	case STATE_FIN:
	case STATE_FIN_WAIT:
	case STATE_CLOSE:
		return 0;
	default:
		log_tunnel(log_error, conn,
			   "impossible to disconnect tunnel:"
			   " invalid state %i\n",
			   conn->state);
		return 0;
	}

	/* Discard unsent messages so that StopCCN will be the only one in the
	 * send queue (to minimise delay in case of congestion).
	 */
	l2tp_tunnel_clear_sendqueue(conn);

	if (l2tp_send_StopCCN(conn, res, err) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to notify peer of tunnel disconnection:"
			   " sending StopCCN failed,"
			   " deleting tunnel anyway\n");

		conn->state = STATE_FIN;
		l2tp_tunnel_free(conn);

		return -1;
	}

	conn->state = STATE_FIN;

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	if (conn->sessions)
		l2tp_tunnel_free_sessions(conn);

	return 0;
}

static int l2tp_tunnel_disconnect_push(struct l2tp_conn_t *conn,
				       uint16_t res, uint16_t err)
{
	if (l2tp_tunnel_disconnect(conn, res, err) < 0)
		return -1;

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to notify peer of tunnel disconnection:"
			   " transmitting messages from send queue failed,"
			   " deleting tunnel anyway\n");
		l2tp_tunnel_free(conn);

		return -1;
	}

	return 0;
}

static void __tunnel_destroy(struct l2tp_conn_t *conn)
{
	pthread_mutex_destroy(&conn->ctx_lock);

	if (conn->hnd.fd >= 0)
		close(conn->hnd.fd);
	if (conn->challenge)
		_free(conn->challenge);
	if (conn->secret)
		_free(conn->secret);
	if (conn->recv_queue)
		_free(conn->recv_queue);

	log_tunnel(log_info2, conn, "tunnel destroyed\n");

	mempool_free(conn);

	__sync_sub_and_fetch(&stat_conn_finishing, 1);
}

static void tunnel_put(struct l2tp_conn_t *conn)
{
	if (__sync_sub_and_fetch(&conn->ref_count, 1) == 0)
		__tunnel_destroy(conn);
}

static void tunnel_hold(struct l2tp_conn_t *conn)
{
	__sync_add_and_fetch(&conn->ref_count, 1);
}

static void __session_destroy(struct l2tp_sess_t *sess)
{
	struct l2tp_conn_t *conn = sess->paren_conn;

	pthread_mutex_destroy(&sess->apses_lock);

	if (sess->ppp.fd >= 0)
		close(sess->ppp.fd);
	if (sess->ppp.ses.chan_name)
		_free(sess->ppp.ses.chan_name);
	if (sess->ctrl.calling_station_id)
		_free(sess->ctrl.calling_station_id);
	if (sess->ctrl.called_station_id)
		_free(sess->ctrl.called_station_id);

	log_session(log_info2, sess, "session destroyed\n");

	mempool_free(sess);

	__sync_sub_and_fetch(&stat_sess_finishing, 1);

	/* Now that the session is fully destroyed,
	 * drop the reference to the tunnel.
	 */
	tunnel_put(conn);
}

static void session_put(struct l2tp_sess_t *sess)
{
	if (__sync_sub_and_fetch(&sess->ref_count, 1) == 0)
		__session_destroy(sess);
}

static void session_hold(struct l2tp_sess_t *sess)
{
	__sync_add_and_fetch(&sess->ref_count, 1);
}

static void l2tp_session_free(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;
	intptr_t cause = TERM_NAS_REQUEST;
	int res = 1;

	switch (sess->state1) {
	case STATE_INIT:
	case STATE_WAIT_ICRP:
	case STATE_WAIT_ICCN:
	case STATE_WAIT_OCRP:
	case STATE_WAIT_OCCN:
		log_session(log_info2, sess, "deleting session\n");

		__sync_sub_and_fetch(&stat_sess_starting, 1);
		__sync_add_and_fetch(&stat_sess_finishing, 1);
		break;
	case STATE_ESTB:
		log_session(log_info2, sess, "deleting session\n");

		triton_event_fire(EV_CTRL_FINISHED, &sess->ppp.ses);
		__sync_sub_and_fetch(&stat_sess_active, 1);
		__sync_add_and_fetch(&stat_sess_finishing, 1);

		pthread_mutex_lock(&sess->apses_lock);
		if (sess->apses_ctx.tpd)
			res = triton_context_call(&sess->apses_ctx, apses_stop,
						  (void *)cause);
		pthread_mutex_unlock(&sess->apses_lock);

		if (res < 0)
			log_session(log_error, sess,
				    "impossible to delete data channel:"
				    " call to data channel context failed\n");
		else if (res == 0)
			log_session(log_info2, sess,
				    "deleting data channel\n");
		break;
	case STATE_CLOSE:
		/* Session already removed. Will be freed once its reference
		 * counter drops to 0.
		 */
		return;
	default:
		log_session(log_error, sess,
			    "impossible to delete session: invalid state %i\n",
			    sess->state1);
		return;
	}

	sess->state1 = STATE_CLOSE;

	if (sess->timeout_timer.tpd)
		triton_timer_del(&sess->timeout_timer);

	/* Packets in the send queue must not reference the session anymore.
	 * They aren't removed from tunnel's queue because they have to be sent
	 * even though session is getting destroyed (useless messages are
	 * dropped from send queues before calling l2tp_session_free()).
	 */
	while (!list_empty(&sess->send_queue)) {
		pack = list_first_entry(&sess->send_queue, typeof(*pack),
					sess_entry);
		list_del(&pack->sess_entry);
		pack->sess_entry.next = NULL;
		pack->sess_entry.prev = NULL;
	}

	if (sess->paren_conn->sessions) {
		if (!tdelete(sess, &sess->paren_conn->sessions, sess_cmp)) {
			log_session(log_error, sess,
				    "impossible to delete session:"
				    " session unreachable from its parent tunnel\n");
			return;
		}
	}
	/* Parent tunnel doesn't hold the session anymore. This is true even
	 * if sess->paren_conn->sessions was NULL (which means that
	 * l2tp_session_free() is being called by tdestroy()).
	 */
	session_put(sess);

	if (--sess->paren_conn->sess_count == 0) {
		switch (sess->paren_conn->state) {
		case STATE_ESTB:
			log_tunnel(log_info1, sess->paren_conn,
				   "no more session, disconnecting tunnel\n");
			l2tp_tunnel_disconnect_push(sess->paren_conn, 1, 0);
			break;
		case STATE_FIN:
		case STATE_FIN_WAIT:
		case STATE_CLOSE:
			break;
		default:
			log_tunnel(log_warn, sess->paren_conn,
				   "avoiding disconnection of empty tunnel:"
				   " invalid state %i\n",
				   sess->paren_conn->state);
			break;
		}
	}

	/* Only drop the reference the session holds to itself.
	 * Reference to the parent tunnel will be dropped by
	 * __session_destroy().
	 */
	session_put(sess);
}

static void l2tp_tunnel_free(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	switch (conn->state) {
	case STATE_INIT:
	case STATE_WAIT_SCCRP:
	case STATE_WAIT_SCCCN:
		__sync_sub_and_fetch(&stat_conn_starting, 1);
		__sync_add_and_fetch(&stat_conn_finishing, 1);
		break;
	case STATE_ESTB:
		__sync_sub_and_fetch(&stat_conn_active, 1);
		__sync_add_and_fetch(&stat_conn_finishing, 1);
		break;
	case STATE_FIN:
	case STATE_FIN_WAIT:
		break;
	case STATE_CLOSE:
		/* Tunnel already removed. Will be freed once its reference
		 * counter drops to 0.
		 */
		return;
	default:
		log_tunnel(log_error, conn,
			   "impossible to delete tunnel: invalid state %i\n",
			   conn->state);
		return;
	}

	log_tunnel(log_info2, conn, "deleting tunnel\n");

	conn->state = STATE_CLOSE;

	pthread_mutex_lock(&l2tp_lock);
	l2tp_conn[conn->tid] = NULL;
	pthread_mutex_unlock(&l2tp_lock);

	if (conn->hnd.tpd)
		triton_md_unregister_handler(&conn->hnd, 0);
	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	if (conn->rtimeout_timer.tpd)
		triton_timer_del(&conn->rtimeout_timer);
	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	while (!list_empty(&conn->rtms_queue)) {
		pack = list_first_entry(&conn->rtms_queue, typeof(*pack),
					entry);
		list_del(&pack->entry);
		l2tp_packet_free(pack);
	}
	l2tp_tunnel_clear_sendqueue(conn);

	if (conn->recv_queue)
		l2tp_tunnel_clear_recvqueue(conn);

	if (conn->sessions)
		l2tp_tunnel_free_sessions(conn);

	pthread_mutex_lock(&conn->ctx_lock);
	if (conn->ctx.tpd)
		triton_context_unregister(&conn->ctx);
	pthread_mutex_unlock(&conn->ctx_lock);

	/* Drop the reference the tunnel holds to itself */
	tunnel_put(conn);
}

static void l2tp_session_disconnect(struct l2tp_sess_t *sess,
				    uint16_t res, uint16_t err)
{
	/* Session is closing, unsent messages are now useless */
	l2tp_session_clear_sendqueue(sess);

	if (l2tp_send_CDN(sess, res, err) < 0)
		log_session(log_error, sess,
			    "impossible to notify peer of session disconnection:"
			    " sending CDN failed, deleting session anyway\n");

	l2tp_session_free(sess);
}

static void l2tp_session_disconnect_push(struct l2tp_sess_t *sess,
					 uint16_t res, uint16_t err)
{
	if (l2tp_send_CDN(sess, res, err) < 0)
		log_session(log_error, sess,
			    "impossible to notify peer of session disconnection,"
			    " sending CDN failed, deleting session anyway\n");
	else if (l2tp_tunnel_push_sendqueue(sess->paren_conn) < 0)
		log_session(log_error, sess,
			    "impossible to notify peer of session disconnection:"
			    " transmitting messages from send queue failed,"
			    " deleting session anyway\n");

	l2tp_session_free(sess);
}

static void l2tp_session_apses_finished(void *data)
{
	struct l2tp_conn_t *conn = l2tp_tunnel_self();
	struct l2tp_sess_t *sess;
	intptr_t sid = (intptr_t)data;

	sess = l2tp_tunnel_get_session(conn, sid);
	if (sess == NULL)
		return;

	/* Here, the only valid session state is STATE_ESTB. If the session's
	 * state was STATE_CLOSE (which happens if session gets closed before
	 * l2tp_session_apses_finished() gets scheduled), it wouldn't be found
	 * by l2tp_tunnel_get_session().
	 */
	if (sess->state1 == STATE_ESTB) {
		log_session(log_info1, sess,
			    "data channel closed, disconnecting session\n");
		l2tp_session_disconnect_push(sess, 2, 0);
	} else {
		log_session(log_warn, sess,
			    "avoiding disconnection of session with no data channel:"
			    " invalid state %i\n", sess->state1);
	}
}

static void __apses_destroy(void *data)
{
	struct l2tp_sess_t *sess = data;

	pthread_mutex_lock(&sess->apses_lock);
	triton_context_unregister(&sess->apses_ctx);
	pthread_mutex_unlock(&sess->apses_lock);

	log_ppp_info2("session destroyed\n");

	__sync_sub_and_fetch(&stat_finishing, 1);

	/* Drop reference to the L2TP session */
	session_put(sess);
}

static void apses_finished(struct ap_session *apses)
{
	struct l2tp_sess_t *sess = container_of(apses->ctrl, typeof(*sess),
						ctrl);
	intptr_t sid = sess->sid;
	int res = 1;

	switch (sess->apses_state) {
	case APSTATE_STARTING:
		__sync_sub_and_fetch(&stat_starting, 1);
		__sync_add_and_fetch(&stat_finishing, 1);
		break;
	case APSTATE_STARTED:
		__sync_sub_and_fetch(&stat_active, 1);
		__sync_add_and_fetch(&stat_finishing, 1);
		break;
	case APSTATE_FINISHING:
		break;
	default:
		log_ppp_error("impossible to delete session:"
			      " invalid state %i\n",
			      sess->apses_state);
		return;
	}

	sess->apses_state = APSTATE_FINISHING;

	pthread_mutex_lock(&sess->paren_conn->ctx_lock);
	if (sess->paren_conn->ctx.tpd)
		res = triton_context_call(&sess->paren_conn->ctx,
					  l2tp_session_apses_finished,
					  (void *)sid);
	pthread_mutex_unlock(&sess->paren_conn->ctx_lock);
	if (res < 0)
		log_ppp_warn("deleting session without notifying L2TP layer:"
			     " call to L2TP control channel context failed\n");

	/* Don't drop the reference to the session now: session_put() may
	 * destroy the L2TP session, but the caller expects it to remain valid
	 * after we return.
	 */
	if (triton_context_call(&sess->apses_ctx, __apses_destroy, sess) < 0)
		log_ppp_error("impossible to delete session:"
			      " scheduling session destruction failed\n");
}

static void apses_stop(void *data)
{
	struct l2tp_sess_t *sess = container_of(triton_context_self(),
						typeof(*sess), apses_ctx);
	intptr_t cause = (intptr_t)data;

	switch (sess->apses_state) {
	case APSTATE_INIT:
	case APSTATE_STARTING:
		__sync_sub_and_fetch(&stat_starting, 1);
		__sync_add_and_fetch(&stat_finishing, 1);
		break;
	case APSTATE_STARTED:
		__sync_sub_and_fetch(&stat_active, 1);
		__sync_add_and_fetch(&stat_finishing, 1);
		break;
	case APSTATE_FINISHING:
		break;
	default:
		log_ppp_error("impossible to delete session:"
			      " invalid state %i\n",
			      sess->apses_state);
		return;
	}

	if (sess->apses_state == APSTATE_STARTING ||
	    sess->apses_state == APSTATE_STARTED) {
		sess->apses_state = APSTATE_FINISHING;
		ap_session_terminate(&sess->ppp.ses, cause, 1);
	} else {
		intptr_t sid = sess->sid;
		int res = 1;

		pthread_mutex_lock(&sess->paren_conn->ctx_lock);
		if (sess->paren_conn->ctx.tpd)
			res = triton_context_call(&sess->paren_conn->ctx,
						  l2tp_session_apses_finished,
						  (void *)sid);
		pthread_mutex_unlock(&sess->paren_conn->ctx_lock);
		if (res < 0)
			log_ppp_warn("deleting session without notifying L2TP layer:"
				     " call to L2TP control channel context failed\n");
	}

	/* Execution of __apses_destroy() may have been scheduled by
	 * ap_session_terminate() (via apses_finished()). We can
	 * nevertheless call __apses_destroy() synchronously here,
	 * so that the data channel gets destroyed without uselessly
	 * waiting for scheduling.
	 */
	__apses_destroy(sess);
}

static void apses_ctx_stop(struct triton_context_t *ctx)
{
	intptr_t cause = TERM_ADMIN_RESET;

	log_ppp_info1("context thread is closing, disconnecting session\n");
	apses_stop((void *)cause);
}

static void apses_started(struct ap_session *apses)
{
	struct l2tp_sess_t *sess = container_of(apses->ctrl, typeof(*sess),
						ctrl);

	if (sess->apses_state != APSTATE_STARTING) {
		log_ppp_error("impossible to activate session:"
			      " invalid state %i\n",
			      sess->apses_state);
		return;
	}

	__sync_sub_and_fetch(&stat_starting, 1);
	__sync_add_and_fetch(&stat_active, 1);
	sess->apses_state = APSTATE_STARTED;

	log_ppp_info1("session started over l2tp session %hu-%hu, %hu-%hu\n",
		      sess->paren_conn->tid, sess->paren_conn->peer_tid,
		      sess->sid, sess->peer_sid);
}

static void apses_start(void *data)
{
	struct ap_session *apses = data;
	struct l2tp_sess_t *sess = container_of(apses->ctrl, typeof(*sess),
						ctrl);

	if (sess->apses_state != APSTATE_INIT) {
		log_ppp_error("impossible to start session:"
			      " invalid state %i\n",
			      sess->apses_state);
		return;
	}

	log_ppp_info2("starting data channel for l2tp(%s)\n",
		      apses->chan_name);

	if (establish_ppp(&sess->ppp) < 0) {
		intptr_t cause = TERM_NAS_ERROR;

		log_ppp_error("session startup failed,"
			      " disconnecting session\n");
		apses_stop((void *)cause);
	} else
		sess->apses_state = APSTATE_STARTING;
}

static void l2tp_session_timeout(struct triton_timer_t *t)
{
	struct l2tp_sess_t *sess = container_of(t, typeof(*sess),
						timeout_timer);

	triton_timer_del(t);
	log_session(log_info1, sess, "session establishment timeout,"
		    " disconnecting session\n");
	l2tp_session_disconnect_push(sess, 10, 0);
}

static struct l2tp_sess_t *l2tp_tunnel_new_session(struct l2tp_conn_t *conn)
{
	struct l2tp_sess_t *sess = NULL;
	struct l2tp_sess_t **sess_search = NULL;
	ssize_t rdlen = 0;
	uint16_t count;

	sess = mempool_alloc(l2tp_sess_pool);
	if (sess == NULL) {
		log_tunnel(log_error, conn,
			   "impossible to allocate new session:"
			   " memory allocation failed\n");
		goto out_err;
	}
	memset(sess, 0, sizeof(*sess));

	for (count = UINT16_MAX; count > 0; --count) {
		rdlen = read(urandom_fd, &sess->sid, sizeof(sess->sid));
		if (rdlen != sizeof(sess->sid)) {
			log_tunnel(log_error, conn,
				   "impossible to allocate new session:"
				   " reading from urandom failed: %s\n",
				   (rdlen < 0) ? strerror(errno) : "short read");
			goto out_err;
		}

		if (sess->sid == 0)
			continue;

		sess_search = tsearch(sess, &conn->sessions, sess_cmp);
		if (*sess_search != sess)
			continue;

		break;
	}

	if (count == 0) {
		log_tunnel(log_error, conn,
			   "impossible to allocate new session:"
			   " could not find any unused session ID\n");
		goto out_err;
	}

	++conn->sess_count;

	return sess;

out_err:
	if (sess)
		mempool_free(sess);
	return NULL;
}

static struct l2tp_sess_t *l2tp_tunnel_alloc_session(struct l2tp_conn_t *conn)
{
	struct l2tp_sess_t *sess = NULL;

	sess = l2tp_tunnel_new_session(conn);
	if (sess == NULL)
		return NULL;

	sess->paren_conn = conn;
	sess->peer_sid = 0;
	sess->state1 = STATE_INIT;
	sess->lns_mode = conn->lns_mode;
	sess->hide_avps = conn->hide_avps;
	sess->send_seq = (conf_dataseq == L2TP_DATASEQ_PREFER) ||
			 (conf_dataseq == L2TP_DATASEQ_REQUIRE);
	sess->recv_seq = (conf_dataseq == L2TP_DATASEQ_REQUIRE);
	sess->reorder_timeout = conf_reorder_timeout;
	INIT_LIST_HEAD(&sess->send_queue);

	sess->timeout_timer.expire = l2tp_session_timeout;
	sess->timeout_timer.period = conf_timeout * 1000;

	pthread_mutex_init(&sess->apses_lock, NULL);
	ppp_init(&sess->ppp);

	/* The tunnel holds a reference to the session */
	session_hold(sess);
	/* The session holds a reference to the tunnel and to itself */
	tunnel_hold(conn);
	session_hold(sess);

	__sync_add_and_fetch(&stat_sess_starting, 1);

	return sess;
}

static void l2tp_conn_close(struct triton_context_t *ctx)
{
	struct l2tp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	log_tunnel(log_info1, conn, "context thread is closing,"
		   " disconnecting tunnel\n");
	l2tp_tunnel_disconnect_push(conn, 0, 0);
}

static int l2tp_tunnel_start(struct l2tp_conn_t *conn,
			     triton_event_func start_func,
			     void *start_param)
{
	if (triton_context_register(&conn->ctx, NULL) < 0) {
		log_error("l2tp: impossible to start new tunnel:"
			  " context registration failed\n");
		goto err;
	}
	triton_md_register_handler(&conn->ctx, &conn->hnd);
	if (triton_md_enable_handler(&conn->hnd, MD_MODE_READ) < 0) {
		log_error("l2tp: impossible to start new tunnel:"
			  " enabling handler failed\n");
		goto err_ctx;
	}
	triton_context_wakeup(&conn->ctx);
	if (triton_timer_add(&conn->ctx, &conn->timeout_timer, 0) < 0) {
		log_error("l2tp: impossible to start new tunnel:"
			  " setting tunnel establishment timer failed\n");
		goto err_ctx_md;
	}
	if (triton_context_call(&conn->ctx, start_func, start_param) < 0) {
		log_error("l2tp: impossible to start new tunnel:"
			  " call to tunnel context failed\n");
		goto err_ctx_md_timer;
	}

	return 0;

err_ctx_md_timer:
	triton_timer_del(&conn->timeout_timer);
err_ctx_md:
	triton_md_unregister_handler(&conn->hnd, 0);
err_ctx:
	triton_context_unregister(&conn->ctx);
err:
	return -1;
}

static struct l2tp_conn_t *l2tp_tunnel_alloc(const struct sockaddr_in *peer,
					     const struct sockaddr_in *host,
					     uint32_t framing_cap,
					     int lns_mode, int port_set,
					     int hide_avps)
{
	struct l2tp_conn_t *conn;
	socklen_t hostaddrlen = sizeof(conn->host_addr);
	uint16_t count;
	ssize_t rdlen;
	int flag;

	conn = mempool_alloc(l2tp_conn_pool);
	if (!conn) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " memory allocation failed\n");
		goto err;
	}

	memset(conn, 0, sizeof(*conn));
	pthread_mutex_init(&conn->ctx_lock, NULL);
	INIT_LIST_HEAD(&conn->send_queue);
	INIT_LIST_HEAD(&conn->rtms_queue);

	conn->hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (conn->hnd.fd < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " socket(PF_INET) failed: %s\n", strerror(errno));
		goto err_conn;
	}

	flag = fcntl(conn->hnd.fd, F_GETFD);
	if (flag < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " fcntl(F_GETFD) failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}
	flag = fcntl(conn->hnd.fd, F_SETFD, flag | FD_CLOEXEC);
	if (flag < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " fcntl(F_SETFD) failed: %s\n",
			  strerror(errno));
		goto err_conn_fd;
	}

	flag = 1;
	if (setsockopt(conn->hnd.fd, SOL_SOCKET, SO_REUSEADDR,
		       &flag, sizeof(flag)) < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " setsockopt(SO_REUSEADDR) failed: %s\n",
			  strerror(errno));
		goto err_conn_fd;
	}
	if (bind(conn->hnd.fd, host, sizeof(*host))) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " bind() failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}

	memcpy(&conn->peer_addr, peer, sizeof(*peer));
	if (!port_set)
		/* 'peer.sin_port' is set to a default destination port but the
		   source port that will be used by the peer isn't known yet */
		conn->peer_addr.sin_port = 0;
	if (connect(conn->hnd.fd, (struct sockaddr *)&conn->peer_addr,
		    sizeof(conn->peer_addr))) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " connect() failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}
	if (!port_set)
		conn->peer_addr.sin_port = peer->sin_port;

	flag = fcntl(conn->hnd.fd, F_GETFL);
	if (flag < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " fcntl(F_GETFL) failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}
	flag = fcntl(conn->hnd.fd, F_SETFL, flag | O_NONBLOCK);
	if (flag < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " fcntl(F_SETFL) failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}

	if (getsockname(conn->hnd.fd, &conn->host_addr, &hostaddrlen) < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " getsockname() failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}
	if (hostaddrlen != sizeof(conn->host_addr)) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " inconsistent address length returned by"
			  " getsockname(): %i bytes instead of %zu\n",
			  hostaddrlen, sizeof(conn->host_addr));
		goto err_conn_fd;
	}

	conn->recv_queue_sz = conf_recv_window;
	conn->recv_queue = _malloc(conn->recv_queue_sz *
				   sizeof(*conn->recv_queue));
	if (conn->recv_queue == NULL) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " allocating reception queue (%zu bytes) failed\n",
			  conn->recv_queue_sz * sizeof(*conn->recv_queue));
		goto err_conn_fd;
	}
	memset(conn->recv_queue, 0,
	       conn->recv_queue_sz * sizeof(*conn->recv_queue));
	conn->recv_queue_offt = 0;

	for (count = UINT16_MAX; count > 0; --count) {
		rdlen = read(urandom_fd, &conn->tid, sizeof(conn->tid));
		if (rdlen != sizeof(conn->tid)) {
			log_error("l2tp: impossible to allocate new tunnel:"
				  " reading from urandom failed: %s\n",
				  (rdlen < 0) ? strerror(errno) : "short read");
			goto err_conn_fd_queue;
		}

		if (conn->tid == 0)
			continue;

		pthread_mutex_lock(&l2tp_lock);
		if (l2tp_conn[conn->tid]) {
			pthread_mutex_unlock(&l2tp_lock);
			continue;
		}
		l2tp_conn[conn->tid] = conn;
		pthread_mutex_unlock(&l2tp_lock);

		break;
	}

	if (count == 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			   " could not find any unused tunnel ID\n");
		goto err_conn_fd_queue;
	}

	conn->state = STATE_INIT;
	conn->framing_cap = framing_cap;

	conn->ctx.before_switch = l2tp_ctx_switch;
	conn->ctx.close = l2tp_conn_close;
	conn->hnd.read = l2tp_conn_read;
	conn->timeout_timer.expire = l2tp_tunnel_timeout;
	conn->timeout_timer.period = conf_timeout * 1000;
	conn->rtimeout_timer.expire = l2tp_rtimeout;
	conn->rtimeout_timer.period = conf_rtimeout * 1000;
	conn->hello_timer.expire = l2tp_send_HELLO;
	conn->hello_timer.period = conf_hello_interval * 1000;

	conn->rtimeout = conf_rtimeout * 1000;
	conn->rtimeout_cap = conf_rtimeout_cap * 1000;
	conn->max_retransmit = conf_retransmit;

	conn->sessions = NULL;
	conn->sess_count = 0;
	conn->lns_mode = lns_mode;
	conn->port_set = port_set;
	conn->hide_avps = hide_avps;
	conn->peer_rcv_wnd_sz = DEFAULT_PEER_RECV_WINDOW_SIZE;
	tunnel_hold(conn);

	__sync_add_and_fetch(&stat_conn_starting, 1);

	return conn;

err_conn_fd_queue:
	_free(conn->recv_queue);
err_conn_fd:
	close(conn->hnd.fd);
err_conn:
	mempool_free(conn);
err:
	return NULL;
}

static inline int l2tp_tunnel_update_peerport(struct l2tp_conn_t *conn,
					      uint16_t port_nbo)
{
	in_port_t old_port = conn->peer_addr.sin_port;
	int res;

	conn->peer_addr.sin_port = port_nbo;
	res = connect(conn->hnd.fd, &conn->peer_addr, sizeof(conn->peer_addr));
	if (res < 0) {
		log_tunnel(log_error, conn,
			   "impossible to update peer port from %hu to %hu:"
			   " connect() failed: %s\n",
			   ntohs(old_port), ntohs(port_nbo), strerror(errno));
		conn->peer_addr.sin_port = old_port;
	}

	return res;
}

static int l2tp_session_start_data_channel(struct l2tp_sess_t *sess)
{
	sess->apses_ctx.before_switch = l2tp_ctx_switch;
	sess->apses_ctx.close = apses_ctx_stop;

	sess->ctrl.ctx = &sess->apses_ctx;
	sess->ctrl.type = CTRL_TYPE_L2TP;
	sess->ctrl.ppp = 1;
	sess->ctrl.name = "l2tp";
	sess->ctrl.ifname = "";
	sess->ctrl.started = apses_started;
	sess->ctrl.finished = apses_finished;
	sess->ctrl.terminate = ppp_terminate;
	sess->ctrl.max_mtu = conf_ppp_max_mtu;
	sess->ctrl.mppe = conf_mppe;

	sess->ctrl.calling_station_id = _malloc(17);
	if (sess->ctrl.calling_station_id == NULL) {
		log_session(log_error, sess,
			    "impossible to start data channel:"
			    " allocation of calling station ID failed\n");
		goto err;
	}
	u_inet_ntoa(sess->paren_conn->peer_addr.sin_addr.s_addr,
		    sess->ctrl.calling_station_id);

	sess->ctrl.called_station_id = _malloc(17);
	if (sess->ctrl.called_station_id == NULL) {
		log_session(log_error, sess,
			    "impossible to start data channel:"
			    " allocation of called station ID failed\n");
		goto err;
	}
	u_inet_ntoa(sess->paren_conn->host_addr.sin_addr.s_addr,
		    sess->ctrl.called_station_id);

	if (conf_ip_pool) {
		sess->ppp.ses.ipv4_pool_name = _strdup(conf_ip_pool);
		if (sess->ppp.ses.ipv4_pool_name == NULL) {
		err_pool:
			log_session(log_error, sess,
				    "impossible to start data channel:"
				    " allocation of pool name failed\n");
			goto err;
		}
	}
	if (conf_ipv6_pool) {
		sess->ppp.ses.ipv6_pool_name = _strdup(conf_ipv6_pool);
		if (sess->ppp.ses.ipv6_pool_name == NULL)
			goto err_pool;
	}
	if (conf_dpv6_pool) {
		sess->ppp.ses.dpv6_pool_name = _strdup(conf_dpv6_pool);
		if (sess->ppp.ses.dpv6_pool_name == NULL)
			goto err_pool;
	}
	if (conf_ifname)
		sess->ppp.ses.ifname_rename = _strdup(conf_ifname);

	sess->ppp.ses.ctrl = &sess->ctrl;
	sess->apses_state = APSTATE_INIT;

	/* The data channel holds a reference to the control session */
	session_hold(sess);

	if (triton_context_register(&sess->apses_ctx, &sess->ppp.ses) < 0) {
		log_session(log_error, sess,
			    "impossible to start data channel:"
			    " context registration failed\n");
		goto err_put;
	}

	triton_context_wakeup(&sess->apses_ctx);

	if (triton_context_call(&sess->apses_ctx, apses_start,
				&sess->ppp.ses) < 0) {
		log_session(log_error, sess,
			    "impossible to start data channel:"
			    " call to data channel context failed\n");
		goto err_put_ctx;
	}

	__sync_add_and_fetch(&stat_starting, 1);

	return 0;

err_put_ctx:
	triton_context_unregister(&sess->apses_ctx);
err_put:
	session_put(sess);
err:
	if (sess->ppp.ses.ipv4_pool_name) {
		_free(sess->ppp.ses.ipv4_pool_name);
		sess->ppp.ses.ipv4_pool_name = NULL;
	}
	if (sess->ppp.ses.ipv6_pool_name) {
		_free(sess->ppp.ses.ipv6_pool_name);
		sess->ppp.ses.ipv6_pool_name = NULL;
	}
	if (sess->ppp.ses.dpv6_pool_name) {
		_free(sess->ppp.ses.dpv6_pool_name);
		sess->ppp.ses.dpv6_pool_name = NULL;
	}
	if (sess->ctrl.called_station_id) {
		_free(sess->ctrl.called_station_id);
		sess->ctrl.called_station_id = NULL;
	}
	if (sess->ctrl.calling_station_id) {
		_free(sess->ctrl.calling_station_id);
		sess->ctrl.calling_station_id = NULL;
	}

	return -1;
}

static int l2tp_session_connect(struct l2tp_sess_t *sess)
{
	struct sockaddr_pppol2tp pppox_addr;
	struct l2tp_conn_t *conn = sess->paren_conn;
	int lns_mode = sess->lns_mode;
	int flg;
	uint16_t peer_port;
	char addr[17];

	if (sess->timeout_timer.tpd)
		triton_timer_del(&sess->timeout_timer);

	sess->ppp.fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (sess->ppp.fd < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " socket(AF_PPPOX) failed: %s\n", strerror(errno));
		goto out_err;
	}

	flg = fcntl(sess->ppp.fd, F_GETFD);
	if (flg < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " fcntl(F_GETFD) failed: %s\n", strerror(errno));
		goto out_err;
	}
	flg = fcntl(sess->ppp.fd, F_SETFD, flg | FD_CLOEXEC);
	if (flg < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " fcntl(F_SETFD) failed: %s\n", strerror(errno));
		goto out_err;
	}

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = conn->hnd.fd;
	memcpy(&pppox_addr.pppol2tp.addr, &conn->peer_addr,
	       sizeof(conn->peer_addr));
	pppox_addr.pppol2tp.s_tunnel = conn->tid;
	pppox_addr.pppol2tp.d_tunnel = conn->peer_tid;
	pppox_addr.pppol2tp.s_session = sess->sid;
	pppox_addr.pppol2tp.d_session = sess->peer_sid;

	if (connect(sess->ppp.fd,
		    (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " connect() failed: %s\n", strerror(errno));
		goto out_err;
	}

	if (setsockopt(sess->ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_LNSMODE,
		       &lns_mode, sizeof(lns_mode))) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setsockopt(PPPOL2TP_SO_LNSMODE) failed: %s\n",
			    strerror(errno));
		goto out_err;
	}

	flg = 1;
	if (sess->send_seq &&
	    setsockopt(sess->ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_SENDSEQ,
		       &flg, sizeof(flg))) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setsockopt(PPPOL2TP_SO_SENDSEQ) failed: %s\n",
			    strerror(errno));
		goto out_err;
	}
	if (sess->recv_seq &&
	    setsockopt(sess->ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_RECVSEQ,
		       &flg, sizeof(flg))) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setsockopt(PPPOL2TP_SO_RECVSEQ) failed: %s\n",
			    strerror(errno));
		goto out_err;
	}
	if (sess->reorder_timeout &&
	    setsockopt(sess->ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_REORDERTO,
		       &sess->reorder_timeout, sizeof(sess->reorder_timeout))) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setsockopt(PPPOL2TP_REORDERTO) failed: %s\n",
			    strerror(errno));
		goto out_err;
	}

	u_inet_ntoa(conn->peer_addr.sin_addr.s_addr, addr);
	peer_port = ntohs(conn->peer_addr.sin_port);
	if (_asprintf(&sess->ppp.ses.chan_name,
		      "%s:%hu session %hu-%hu, %hu-%hu",
		      addr, peer_port,
		      sess->paren_conn->tid, sess->paren_conn->peer_tid,
		      sess->sid, sess->peer_sid) < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setting session's channel name failed\n");
		goto out_err;
	}

	triton_event_fire(EV_CTRL_STARTED, &sess->ppp.ses);
	__sync_sub_and_fetch(&stat_sess_starting, 1);
	__sync_add_and_fetch(&stat_sess_active, 1);
	sess->state1 = STATE_ESTB;

	if (l2tp_session_start_data_channel(sess) < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " starting data channel failed\n");
		goto out_err;
	}

	return 0;

out_err:
	if (sess->ppp.ses.chan_name) {
		_free(sess->ppp.ses.chan_name);
		sess->ppp.ses.chan_name = NULL;
	}
	if (sess->ppp.fd >= 0) {
		close(sess->ppp.fd);
		sess->ppp.fd = -1;
	}
	return -1;
}

static int l2tp_tunnel_connect(struct l2tp_conn_t *conn)
{
	struct sockaddr_pppol2tp pppox_addr;
	int tunnel_fd;
	int flg;

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = conn->hnd.fd;
	memcpy(&pppox_addr.pppol2tp.addr, &conn->peer_addr,
	       sizeof(conn->peer_addr));
	pppox_addr.pppol2tp.s_tunnel = conn->tid;
	pppox_addr.pppol2tp.d_tunnel = conn->peer_tid;

	tunnel_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (tunnel_fd < 0) {
		log_tunnel(log_error, conn, "impossible to connect tunnel:"
			   " socket(AF_PPPOX) failed: %s\n", strerror(errno));
		goto err;
	}

	flg = fcntl(tunnel_fd, F_GETFD);
	if (flg < 0) {
		log_tunnel(log_error, conn, "impossible to connect tunnel:"
			   " fcntl(F_GETFD) failed: %s\n", strerror(errno));
		goto err_fd;
	}
	flg = fcntl(tunnel_fd, F_SETFD, flg | FD_CLOEXEC);
	if (flg < 0) {
		log_tunnel(log_error, conn, "impossible to connect tunnel:"
			   " fcntl(F_SETFD) failed: %s\n", strerror(errno));
		goto err_fd;
	}

	if (connect(tunnel_fd,
		    (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		log_tunnel(log_error, conn, "impossible to connect tunnel:"
			   " connect() failed: %s\n", strerror(errno));
		goto err_fd;
	}

	if (conf_hello_interval)
		if (triton_timer_add(&conn->ctx, &conn->hello_timer, 0) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to connect tunnel:"
				   " setting HELLO timer failed\n");
			goto err_fd;
		}

	close(tunnel_fd);

	__sync_sub_and_fetch(&stat_conn_starting, 1);
	__sync_add_and_fetch(&stat_conn_active, 1);
	conn->state = STATE_ESTB;

	return 0;

err_fd:
	close(tunnel_fd);
err:
	return -1;
}

static void l2tp_rtimeout(struct triton_timer_t *tm)
{
	struct l2tp_conn_t *conn = container_of(tm, typeof(*conn),
						rtimeout_timer);
	struct l2tp_packet_t *pack;

	if (list_empty(&conn->rtms_queue)) {
		log_tunnel(log_warn, conn,
			   "impossible to handle retransmission:"
			   " retransmission queue is empty\n");

		return;
	}

	pack = list_first_entry(&conn->rtms_queue, typeof(*pack), entry);

	if (++conn->retransmit > conn->max_retransmit) {
		log_tunnel(log_warn, conn,
			   "no acknowledgement from peer after %i retransmissions,"
			   " deleting tunnel\n", conn->retransmit - 1);
		goto err;
	}

	log_tunnel(log_info2, conn, "retransmission #%i\n", conn->retransmit);
	if (conf_verbose) {
		log_tunnel(log_info2, conn, "retransmit (timeout) ");
		l2tp_packet_print(pack, log_info2);
	}

	if (__l2tp_tunnel_send(conn, pack) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to handle retransmission:"
			   " sending packet failed, deleting tunnel\n");
		goto err;
	}

	conn->rtimeout_timer.period *= 2;
	if (conn->rtimeout_timer.period > conn->rtimeout_cap)
		conn->rtimeout_timer.period = conn->rtimeout_cap;

	if (triton_timer_mod(&conn->rtimeout_timer, 0) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to handle retransmission:"
			   " updating retransmission timer failed,"
			   " deleting tunnel\n");
		goto err;
	}

	return;

err:
	triton_timer_del(tm);
	l2tp_tunnel_free(conn);
}

static void l2tp_tunnel_timeout(struct triton_timer_t *t)
{
	struct l2tp_conn_t *conn = container_of(t, typeof(*conn),
						timeout_timer);

	triton_timer_del(t);
	log_tunnel(log_info1, conn, "tunnel establishment timeout,"
		   " disconnecting tunnel\n");
	l2tp_tunnel_disconnect_push(conn, 1, 0);
}

static int l2tp_send_ZLB(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	int res;

	log_tunnel(log_debug, conn, "sending ZLB\n");

	pack = l2tp_packet_alloc(2, 0, &conn->peer_addr, 0, NULL, 0);
	if (!pack) {
		log_tunnel(log_error, conn, "impossible to send ZLB:"
			   " packet allocation failed\n");
		return -1;
	}

	/* ZLB messages are special: they take no slot in the control message
	 * sequence number space and never have to be retransmitted. So they're
	 * sent directly by __l2tp_tunnel_send(), thus bypassing the send and
	 * retransmission queues.
	 */
	pack->hdr.tid = htons(conn->peer_tid);
	pack->hdr.Ns = htons(conn->Ns);

	res = __l2tp_tunnel_send(conn, pack);
	if (res < 0)
		log_tunnel(log_error, conn, "impossible to send ZLB:"
			   " sending packet failed\n");

	l2tp_packet_free(pack);

	return res;
}

static void l2tp_send_HELLO(struct triton_timer_t *t)
{
	struct l2tp_conn_t *conn = container_of(t, typeof(*conn), hello_timer);
	struct l2tp_packet_t *pack;

	log_tunnel(log_debug, conn, "sending HELLO\n");

	pack = l2tp_packet_alloc(2, Message_Type_Hello, &conn->peer_addr,
				 conn->hide_avps, conn->secret,
				 conn->secret_len);
	if (!pack) {
		log_tunnel(log_error, conn, "impossible to send HELLO:"
			   " packet allocation failed, deleting tunnel\n");
		goto err;
	}

	l2tp_tunnel_send(conn, pack);

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to send HELLO:"
			   " transmitting messages from send queue failed,"
			   " deleting tunnel\n");
		goto err;
	}

	return;

err:
	l2tp_tunnel_free(conn);
}

static void l2tp_send_SCCRQ(void *peer_addr)
{
	struct l2tp_conn_t *conn = l2tp_tunnel_self();
	struct l2tp_packet_t *pack = NULL;
	uint16_t chall_len;
	int err;

	log_tunnel(log_info2, conn, "sending SCCRQ\n");

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Request,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (pack == NULL) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " packet allocation failed\n");
		goto err;
	}

	if (l2tp_packet_add_int16(pack, Protocol_Version,
				  L2TP_V2_PROTOCOL_VERSION, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_string(pack, Host_Name, conf_host_name, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Capabilities,
				  conn->framing_cap, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID,
				  conn->tid, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_string(pack, Vendor_Name, "accel-ppp", 0) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_int16(pack, Recv_Window_Size, conn->recv_queue_sz,
				  1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}

	if (u_randbuf(&chall_len, sizeof(chall_len), &err) < 0) {
		if (err)
			log_tunnel(log_error, conn, "impossible to send SCCRQ:"
				   " reading from urandom failed: %s\n",
				   strerror(err));
		else
			log_tunnel(log_error, conn, "impossible to send SCCRQ:"
				   " end of file reached while reading"
				   " from urandom\n");
		goto pack_err;
	}
	chall_len = (chall_len & 0x007F) + MD5_DIGEST_LENGTH;
	if (l2tp_tunnel_genchall(chall_len, conn, pack) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " Challenge generation failed\n");
		goto pack_err;
	}

	l2tp_tunnel_send(conn, pack);

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " transmitting messages from send queue failed\n");
		goto err;
	}

	conn->state = STATE_WAIT_SCCRP;

	return;

pack_err:
	l2tp_packet_free(pack);
err:
	l2tp_tunnel_free(conn);
}

static void l2tp_send_SCCRP(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	uint16_t chall_len;
	int err;

	log_tunnel(log_info2, conn, "sending SCCRP\n");

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Reply,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (!pack) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " packet allocation failed\n");
		goto out;
	}

	if (l2tp_packet_add_int16(pack, Protocol_Version,
				  L2TP_V2_PROTOCOL_VERSION, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_string(pack, Host_Name, conf_host_name, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Capabilities,
				  conn->framing_cap, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack,
				  Assigned_Tunnel_ID, conn->tid, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_string(pack, Vendor_Name, "accel-ppp", 0) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack, Recv_Window_Size, conn->recv_queue_sz,
				  1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}

	if (l2tp_tunnel_genchallresp(Message_Type_Start_Ctrl_Conn_Reply,
				     conn, pack) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " Challenge Response generation failed\n");
		goto out_err;
	}

	if (u_randbuf(&chall_len, sizeof(chall_len), &err) < 0) {
		if (err)
			log_tunnel(log_error, conn, "impossible to send SCCRP:"
				   " reading from urandom failed: %s\n",
				   strerror(err));
		else
			log_tunnel(log_error, conn, "impossible to send SCCRP:"
				   " end of file reached while reading"
				   " from urandom\n");
		goto out_err;
	}
	chall_len = (chall_len & 0x007F) + MD5_DIGEST_LENGTH;
	if (l2tp_tunnel_genchall(chall_len, conn, pack) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " Challenge generation failed\n");
		goto out_err;
	}

	l2tp_tunnel_send(conn, pack);

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " transmitting messages from send queue failed\n");
		goto out;
	}

	conn->state = STATE_WAIT_SCCCN;

	return;

out_err:
	l2tp_packet_free(pack);
out:
	l2tp_tunnel_free(conn);
}

static int l2tp_send_SCCCN(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack = NULL;

	log_tunnel(log_info2, conn, "sending SCCCN\n");

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Connected,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (pack == NULL) {
		log_tunnel(log_error, conn, "impossible to send SCCCN:"
			   " packet allocation failed\n");
		goto err;
	}

	if (l2tp_tunnel_genchallresp(Message_Type_Start_Ctrl_Conn_Connected,
				     conn, pack) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCCN:"
			   " Challenge Response generation failed\n");
		goto pack_err;
	}
	l2tp_tunnel_storechall(conn, NULL);

	l2tp_tunnel_send(conn, pack);

	return 0;

pack_err:
	l2tp_packet_free(pack);
err:
	return -1;
}

static int l2tp_send_ICRQ(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	log_session(log_info2, sess, "sending ICRQ\n");

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Request,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == NULL) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Call_Serial_Number, 0, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	if (l2tp_session_try_send(sess, pack) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " too many outstanding packets in send queue\n");
		goto out_err;
	}

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_ICRP(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	log_session(log_info2, sess, "sending ICRP\n");

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Reply,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (!pack) {
		log_session(log_error, sess, "impossible to send ICRP:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICRP:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_ICCN(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	log_session(log_info2, sess, "sending ICCN\n");

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == 0) {
		log_session(log_error, sess, "impossible to send ICCN:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int32(pack, TX_Speed, 1000, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Type, 3, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (sess->send_seq &&
	    l2tp_packet_add_octets(pack, Sequencing_Required, NULL, 0, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_OCRQ(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	log_session(log_info2, sess, "sending OCRQ\n");

	pack = l2tp_packet_alloc(2, Message_Type_Outgoing_Call_Request,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (!pack) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Call_Serial_Number, 0, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Minimum_BPS, 100, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Maximum_BPS, 100000, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Bearer_Type, 3, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Type, 3, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_string(pack, Called_Number, "", 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	if (l2tp_session_try_send(sess, pack) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " too many outstanding packets in send queue\n");
		goto out_err;
	}

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_OCRP(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack = NULL;

	log_session(log_info2, sess, "sending OCRP\n");

	pack = l2tp_packet_alloc(2, Message_Type_Outgoing_Call_Reply,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == NULL) {
		log_session(log_error, sess, "impossible to send OCRP:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRP:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_OCCN(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack = NULL;

	log_session(log_info2, sess, "sending OCCN\n");

	pack = l2tp_packet_alloc(2, Message_Type_Outgoing_Call_Connected,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == NULL) {
		log_session(log_error, sess, "impossible to send OCCN:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int32(pack, TX_Speed, 1000, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Type, 3, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (sess->send_seq &&
	    l2tp_packet_add_octets(pack, Sequencing_Required, NULL, 0, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static void l2tp_tunnel_finwait_timeout(struct triton_timer_t *tm)
{
	struct l2tp_conn_t *conn = container_of(tm, typeof(*conn),
						timeout_timer);

	triton_timer_del(tm);
	log_tunnel(log_info2, conn, "tunnel disconnection timeout\n");
	l2tp_tunnel_free(conn);
}

static void l2tp_tunnel_finwait(struct l2tp_conn_t *conn)
{
	int rtimeout;
	int indx;

	switch (conn->state) {
	case STATE_WAIT_SCCRP:
	case STATE_WAIT_SCCCN:
		__sync_sub_and_fetch(&stat_conn_starting, 1);
		__sync_add_and_fetch(&stat_conn_finishing, 1);
		break;
	case STATE_ESTB:
		__sync_sub_and_fetch(&stat_conn_active, 1);
		__sync_add_and_fetch(&stat_conn_finishing, 1);
		break;
	case STATE_FIN:
		break;
	case STATE_FIN_WAIT:
	case STATE_CLOSE:
		return;
	default:
		log_tunnel(log_error, conn,
			   "impossible to disconnect tunnel:"
			   " invalid state %i\n",
			   conn->state);
		return;
	}

	conn->state = STATE_FIN_WAIT;

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	/* Too late to send outstanding messages */
	l2tp_tunnel_clear_sendqueue(conn);

	if (conn->sessions)
		l2tp_tunnel_free_sessions(conn);

	/* Keep tunnel up during a full retransmission cycle */
	conn->timeout_timer.period = 0;
	rtimeout = conn->rtimeout;
	for (indx = 0; indx < conn->max_retransmit; ++indx) {
		conn->timeout_timer.period += rtimeout;
		rtimeout *= 2;
		if (rtimeout > conn->rtimeout_cap)
			rtimeout = conn->rtimeout_cap;
	}
	conn->timeout_timer.expire = l2tp_tunnel_finwait_timeout;

	if (triton_timer_add(&conn->ctx, &conn->timeout_timer, 0) < 0) {
		log_tunnel(log_warn, conn,
			   "impossible to start the disconnection timer,"
			   " disconnecting immediately\n");

		/* FIN-WAIT state occurs upon reception of a StopCCN message
		 * which has to be acknowledged. This is normally handled by
		 * the caller, but here l2tp_tunnel_free() will close the L2TP
		 * socket. So we have to manually send the acknowledgement
		 * first.
		 */
		l2tp_send_ZLB(conn);
		l2tp_tunnel_free(conn);
	}
}

static int l2tp_recv_SCCRQ(const struct l2tp_serv_t *serv,
			   const struct l2tp_packet_t *pack,
			   const struct in_pktinfo *pkt_info)
{
	const struct l2tp_attr_t *attr;
	const struct l2tp_attr_t *protocol_version = NULL;
	const struct l2tp_attr_t *assigned_tid = NULL;
	const struct l2tp_attr_t *assigned_cid = NULL;
	const struct l2tp_attr_t *framing_cap = NULL;
	const struct l2tp_attr_t *router_id = NULL;
	const struct l2tp_attr_t *recv_window_size = NULL;
	const struct l2tp_attr_t *challenge = NULL;
	struct l2tp_conn_t *conn = NULL;
	struct sockaddr_in host_addr = { 0 };
	uint16_t tid;
	char src_addr[17];

	u_inet_ntoa(pack->addr.sin_addr.s_addr, src_addr);

	if (ap_shutdown) {
		log_warn("l2tp: shutdown in progress,"
			 " discarding SCCRQ from %s\n", src_addr);
		return 0;
	}

	if (conf_max_starting && ap_session_stat.starting >= conf_max_starting)
		return 0;

	if (conf_max_sessions && ap_session_stat.active + ap_session_stat.starting >= conf_max_sessions)
		return 0;

	if (triton_module_loaded("connlimit")
	    && connlimit_check(cl_key_from_ipv4(pack->addr.sin_addr.s_addr))) {
		log_warn("l2tp: connection limits reached,"
			 " discarding SCCRQ from %s\n", src_addr);
		return 0;
	}

	log_info2("l2tp: handling SCCRQ from %s\n", src_addr);

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
			case Random_Vector:
				break;
			case Protocol_Version:
				protocol_version = attr;
				break;
			case Framing_Capabilities:
				framing_cap = attr;
				break;
			case Assigned_Tunnel_ID:
				assigned_tid = attr;
				break;
			case Recv_Window_Size:
				recv_window_size = attr;
				break;
			case Challenge:
				challenge = attr;
				break;
			case Assigned_Connection_ID:
				assigned_cid = attr;
				break;
			case Router_ID:
				router_id = attr;
				break;
			case Message_Digest:
				log_error("l2tp: impossible to handle SCCRQ from %s:"
					  " Message Digest is not supported\n",
					  src_addr);
				return -1;
		}
	}

	if (assigned_tid) {
		if (!protocol_version) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " no Protocol Version present in message\n",
				  src_addr);
			return -1;
		}
		if (protocol_version->val.uint16 != L2TP_V2_PROTOCOL_VERSION) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " unknown Protocol Version %hhu.%hhu\n",
				  src_addr, protocol_version->val.uint16 >> 8,
				  protocol_version->val.uint16 & 0x00FF);
			return -1;
		}
		if (!framing_cap) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " no Framing Capabilities present in message\n",
				  src_addr);
			return -1;
		}

		host_addr.sin_family = AF_INET;
		host_addr.sin_addr = pkt_info->ipi_addr;
		if (conf_ephemeral_ports)
			host_addr.sin_port = 0;
		else
			host_addr.sin_port = serv->addr.sin_port;

		conn = l2tp_tunnel_alloc(&pack->addr, &host_addr,
					 framing_cap->val.uint32, 1, 1,
					 conf_hide_avps);
		if (conn == NULL) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " tunnel allocation failed\n", src_addr);
			return -1;
		}
		tid = conn->tid;

		if (recv_window_size) {
			conn->peer_rcv_wnd_sz = recv_window_size->val.uint16;
			if (conn->peer_rcv_wnd_sz == 0 ||
			    conn->peer_rcv_wnd_sz > RECV_WINDOW_SIZE_MAX) {
				log_error("l2tp: impossible to handle SCCRQ from %s:"
					  " invalid Receive Window Size %hu\n",
					  src_addr, conn->peer_rcv_wnd_sz);
				l2tp_tunnel_free(conn);
				return -1;
			}
		}

		if (conf_secret) {
			conn->secret = _strdup(conf_secret);
			if (conn->secret == NULL) {
				log_error("l2tp: impossible to handle SCCRQ from %s:"
					  " secret allocation failed\n",
					  src_addr);
				l2tp_tunnel_free(conn);
				return -1;
			}
			conn->secret_len = strlen(conn->secret);
		}

		if (l2tp_tunnel_storechall(conn, challenge) < 0) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " storing challenge failed\n", src_addr);
			l2tp_tunnel_free(conn);
			return -1;
		}

		conn->peer_tid = assigned_tid->val.uint16;
		conn->port_set = 1;
		conn->Nr = 1;

		if (l2tp_tunnel_start(conn, (triton_event_func)l2tp_send_SCCRP, conn) < 0) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " starting tunnel failed\n", src_addr);
			l2tp_tunnel_free(conn);
			return -1;
		}
		log_info1("l2tp: new tunnel %hu-%hu created following"
			  " reception of SCCRQ from %s:%hu\n", tid,
			  assigned_tid->val.uint16, src_addr,
			  ntohs(pack->addr.sin_port));
	} else if (assigned_cid || router_id) {
		log_error("l2tp: impossible to handle SCCRQ from %s:"
			  " no support for L2TPv3 attributes\n", src_addr);
		return -1;
	} else {
		log_error("l2tp: impossible to handle SCCRQ from %s:"
			  " no Assigned-Tunnel-ID or Assigned-Connection-ID present in message\n",
			  src_addr);
		return -1;
	}

	return 0;
}

static int l2tp_recv_SCCRP(struct l2tp_conn_t *conn,
			   const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *protocol_version = NULL;
	const struct l2tp_attr_t *assigned_tid = NULL;
	const struct l2tp_attr_t *framing_cap = NULL;
	const struct l2tp_attr_t *recv_window_size = NULL;
	const struct l2tp_attr_t *challenge = NULL;
	const struct l2tp_attr_t *challenge_resp = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;
	char host_addr[17];

	if (conn->state != STATE_WAIT_SCCRP) {
		log_tunnel(log_warn, conn, "discarding unexpected SCCRP\n");
		return 0;
	}

	log_tunnel(log_info2, conn, "handling SCCRP\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Random_Vector:
		case Host_Name:
		case Bearer_Capabilities:
		case Firmware_Revision:
		case Vendor_Name:
			break;
		case Protocol_Version:
			protocol_version = attr;
			break;
		case Framing_Capabilities:
			framing_cap = attr;
			break;
		case Assigned_Tunnel_ID:
			assigned_tid = attr;
			break;
		case Recv_Window_Size:
			recv_window_size = attr;
			break;
		case Challenge:
			challenge = attr;
			break;
		case Challenge_Response:
			challenge_resp = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_tunnel(log_warn, conn,
					   "discarding unknown attribute type"
					   " %i in SCCRP\n", attr->attr->id);
			break;
		}
	}

	if (assigned_tid == NULL) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " no Assigned Tunnel ID present in message,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}

	/* Set peer_tid as soon as possible so that StopCCCN
	   will be sent to the right tunnel in case of error */
	log_tunnel(log_info2, conn, "peer-tid set to %hu by SCCRP\n",
		   assigned_tid->val.uint16);
	conn->peer_tid = assigned_tid->val.uint16;

	if (unknown_attr) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " unknown mandatory attribute type %i,"
			   " disconnecting tunnel\n",
			   unknown_attr->attr->id);
		l2tp_tunnel_disconnect(conn, 2, 8);
		return -1;
	}
	if (framing_cap == NULL) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " no Framing Capabilities present in message,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	if (protocol_version == NULL) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " no Protocol Version present in message,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	if (protocol_version->val.uint16 != L2TP_V2_PROTOCOL_VERSION) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " unknown Protocol Version %hhu.%hhu,"
			   " disconnecting tunnel\n",
			   protocol_version->val.uint16 >> 8,
			   protocol_version->val.uint16 & 0x00FF);
		l2tp_tunnel_disconnect(conn, 5, 0);
		return -1;
	}
	if (recv_window_size) {
		conn->peer_rcv_wnd_sz = recv_window_size->val.uint16;
		if (conn->peer_rcv_wnd_sz == 0 ||
		    conn->peer_rcv_wnd_sz > RECV_WINDOW_SIZE_MAX) {
			log_error("impossible to handle SCCRP:"
				  " invalid Receive Window Size %hu\n",
				  conn->peer_rcv_wnd_sz);
			conn->peer_rcv_wnd_sz = DEFAULT_PEER_RECV_WINDOW_SIZE;
			l2tp_tunnel_disconnect(conn, 2, 3);
			return -1;
		}
	}

	if (l2tp_tunnel_checkchallresp(Message_Type_Start_Ctrl_Conn_Reply,
				       conn, challenge_resp) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " checking Challenge Response failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 4, 0);
		return -1;
	}
	if (l2tp_tunnel_storechall(conn, challenge) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " storing Challenge failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 4);
		return -1;
	}

	if (l2tp_send_SCCCN(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " sending SCCCN failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	if (l2tp_tunnel_connect(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " connecting tunnel failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}

	u_inet_ntoa(conn->host_addr.sin_addr.s_addr, host_addr);
	log_tunnel(log_info1, conn, "established at %s:%hu\n",
		   host_addr, ntohs(conn->host_addr.sin_port));

	return 0;
}

static int l2tp_recv_SCCCN(struct l2tp_conn_t *conn,
			   const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *attr = NULL;
	const struct l2tp_attr_t *challenge_resp = NULL;
	char host_addr[17];

	if (conn->state != STATE_WAIT_SCCCN) {
		log_tunnel(log_warn, conn, "discarding unexpected SCCCN\n");
		return 0;
	}

	log_tunnel(log_info2, conn, "handling SCCCN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Host_Name:
		case Vendor_Name:
		case Bearer_Capabilities:
		case Recv_Window_Size:
		case Protocol_Version:
		case Framing_Capabilities:
		case Assigned_Tunnel_ID:
		case Random_Vector:
			break;
		case Challenge_Response:
			challenge_resp = attr;
			break;
		default:
			if (attr->M) {
				log_tunnel(log_error, conn,
					   "impossible to handle SCCCN:"
					   " unknown mandatory attribute type %i,"
					   " disconnecting tunnel\n",
					   attr->attr->id);
				l2tp_tunnel_disconnect(conn, 2, 8);
				return -1;
			}
		}
	}

	if (l2tp_tunnel_checkchallresp(Message_Type_Start_Ctrl_Conn_Connected,
				       conn, challenge_resp) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCCN:"
			   " checking Challenge Response failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 4, 0);
		return -1;
	}
	l2tp_tunnel_storechall(conn, NULL);

	if (l2tp_tunnel_connect(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCCN:"
			   " connecting tunnel failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}

	u_inet_ntoa(conn->host_addr.sin_addr.s_addr, host_addr);
	log_tunnel(log_info1, conn, "established at %s:%hu\n",
		   host_addr, ntohs(conn->host_addr.sin_port));

	return 0;
}

static int rescode_get_data(const struct l2tp_attr_t *result_attr,
			    uint16_t *res, uint16_t *err, char **err_msg)
{
	struct l2tp_avp_result_code *resavp = NULL;
	int msglen;

	if (result_attr->length != 2 && result_attr->length < sizeof(*resavp))
		return -1;

	if (result_attr->length == 2) {
		/* No Error Code */
		*res = ntohs(*(const uint16_t *)result_attr->val.octets);
		return 1;
	}

	resavp = (struct l2tp_avp_result_code *)result_attr->val.octets;
	*res = ntohs(resavp->result_code);
	*err = ntohs(resavp->error_code);
	msglen = result_attr->length - sizeof(*resavp);
	if (msglen <= 0)
		return 2;

	*err_msg = _malloc(msglen + 1);
	if (*err_msg) {
		memcpy(*err_msg, resavp->error_msg, msglen);
		(*err_msg)[msglen] = '\0';
	}

	return 3;
}

static int l2tp_recv_StopCCN(struct l2tp_conn_t *conn,
			     const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_tid = NULL;
	const struct l2tp_attr_t *result_code = NULL;
	const struct l2tp_attr_t *attr = NULL;
	char *err_msg = NULL;
	uint16_t res = 0;
	uint16_t err = 0;

	if (conn->state == STATE_CLOSE || conn->state == STATE_FIN_WAIT) {
		log_tunnel(log_warn, conn, "discarding unexpected StopCCN\n");

		return 0;
	}

	log_tunnel(log_info2, conn, "handling StopCCN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
		case Random_Vector:
			break;
		case Assigned_Tunnel_ID:
			assigned_tid = attr;
			break;
		case Result_Code:
			result_code = attr;
			break;
		default:
			if (attr->M) {
				log_tunnel(log_warn, conn,
					   "discarding unknown attribute type"
					   " %i in StopCCN\n", attr->attr->id);
			}
			break;
		}
	}

	if (assigned_tid) {
		if (conn->peer_tid == 0) {
			log_tunnel(log_info2, conn,
				   "peer-tid set to %hu by StopCCN\n",
				   assigned_tid->val.uint16);
			conn->peer_tid = assigned_tid->val.uint16;
		} else if (conn->peer_tid != assigned_tid->val.uint16) {
			log_tunnel(log_warn, conn,
				   "discarding invalid Assigned Tunnel ID %hu"
				   " in StopCCN\n", assigned_tid->val.uint16);
		}
	} else {
		log_tunnel(log_warn, conn,
			   "no Assigned Tunnel ID present in StopCCN\n");
	}

	if (result_code) {
		if (rescode_get_data(result_code, &res, &err, &err_msg) < 0) {
			log_tunnel(log_warn, conn,
				   "invalid Result Code in StopCCN\n");
		}
	} else {
		log_tunnel(log_warn, conn,
			   "no Result Code present in StopCCN\n");
	}

	log_tunnel(log_info1, conn, "StopCCN received from peer (result: %hu,"
		   " error: %hu%s%s%s), disconnecting tunnel\n",
		   res, err, err_msg ? ", message: \"" : "",
		   err_msg ? err_msg : "", err_msg ? "\"" : "");

	if (err_msg)
		_free(err_msg);

	l2tp_tunnel_finwait(conn);

	return -1;
}

static int l2tp_recv_HELLO(struct l2tp_conn_t *conn,
			   const struct l2tp_packet_t *pack)
{
	if (conn->state != STATE_ESTB) {
		log_tunnel(log_warn, conn, "discarding unexpected HELLO\n");

		return 0;
	}

	log_tunnel(log_debug, conn, "handling HELLO\n");

	if (conn->hello_timer.tpd)
		triton_timer_mod(&conn->hello_timer, 0);

	return 0;
}

static int l2tp_session_incall_reply(struct l2tp_sess_t *sess)
{
	if (triton_timer_add(&sess->paren_conn->ctx,
			     &sess->timeout_timer, 0) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to incoming call:"
			    " setting establishment timer failed\n");
		goto err;
	}

	if (l2tp_send_ICRP(sess) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to incoming call:"
			    " sending ICRP failed\n");
		goto err_timer;
	}

	sess->state1 = STATE_WAIT_ICCN;

	return 0;

err_timer:
	triton_timer_del(&sess->timeout_timer);
err:
	return -1;
}

static int l2tp_recv_ICRQ(struct l2tp_conn_t *conn,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *attr;
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	struct l2tp_sess_t *sess = NULL;
	uint16_t peer_sid = 0;
	uint16_t sid = 0;
	uint16_t res = 0;
	uint16_t err = 0;

	if (conn->state != STATE_ESTB && conn->lns_mode) {
		log_tunnel(log_warn, conn, "discarding unexpected ICRQ\n");
		return 0;
	}

	if (ap_shutdown) {
		log_tunnel(log_warn, conn, "shutdown in progress,"
			   " discarding ICRQ\n");
		return 0;
	}

	if (conf_max_starting && ap_session_stat.starting >= conf_max_starting)
		return 0;

	if (conf_max_sessions && ap_session_stat.active + ap_session_stat.starting >= conf_max_sessions)
		return 0;

	if (triton_module_loaded("connlimit")
	    && connlimit_check(cl_key_from_ipv4(conn->peer_addr.sin_addr.s_addr))) {
		log_tunnel(log_warn, conn, "connection limits reached,"
			   " discarding ICRQ\n");
		return 0;
	}

	log_tunnel(log_info2, conn, "handling ICRQ\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
			case Assigned_Session_ID:
				assigned_sid = attr;
				break;
			case Message_Type:
			case Random_Vector:
			case Call_Serial_Number:
			case Bearer_Type:
			case Calling_Number:
			case Called_Number:
			case Sub_Address:
			case Physical_Channel_ID:
				break;
			default:
				if (attr->M)
					unknown_attr = attr;
				else
					log_tunnel(log_warn, conn,
						   "discarding unknown attribute type"
						   " %i in ICRQ\n", attr->attr->id);
				break;
		}
	}

	if (!assigned_sid) {
		log_tunnel(log_error, conn, "impossible to handle ICRQ:"
			   " no Assigned Session ID present in message,"
			   " disconnecting session\n");
		res = 2;
		err = 6;
		goto out_reject;
	}

	peer_sid = assigned_sid->val.uint16;

	sess = l2tp_tunnel_alloc_session(conn);
	if (sess == NULL) {
		log_tunnel(log_error, conn, "impossible to handle ICRQ:"
			   " session allocation failed,"
			   " disconnecting session\n");
		res = 2;
		err = 4;
		goto out_reject;
	}

	sess->peer_sid = peer_sid;
	sid = sess->sid;

	if (unknown_attr) {
		log_tunnel(log_error, conn, "impossible to handle ICRQ:"
			   " unknown mandatory attribute type %i,"
			   " disconnecting session\n",
			   unknown_attr->attr->id);
		res = 2;
		err = 8;
		goto out_reject;
	}

	if (l2tp_session_incall_reply(sess) < 0) {
		log_tunnel(log_error, conn, "impossible to handle ICRQ:"
			   " starting session failed,"
			   " disconnecting session\n");
		res = 2;
		err = 4;
		goto out_reject;
	}

	log_tunnel(log_info1, conn, "new session %hu-%hu created following"
		   " reception of ICRQ\n", sid, peer_sid);

	return 0;

out_reject:
	if (l2tp_tunnel_send_CDN(sid, peer_sid, res, err) < 0)
		log_tunnel(log_warn, conn,
			   "impossible to reject ICRQ:"
			   " sending CDN failed\n");
	if (sess)
		l2tp_session_free(sess);

	return -1;
}

static int l2tp_recv_ICRP(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_ICRP) {
		log_session(log_warn, sess, "discarding unexpected ICRP\n");
		return 0;
	}

	log_session(log_info2, sess, "handling ICRP\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
		case Random_Vector:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					     " %i in ICRP\n", attr->attr->id);
			break;
		}
	}

	if (assigned_sid == NULL) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " no Assigned Session ID present in message,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	/* Set peer_sid as soon as possible so that CDN
	   will be sent to the right tunnel in case of error */
	log_session(log_info2, sess, "peer-sid set to %hu by ICRP\n",
		    assigned_sid->val.uint16);
	sess->peer_sid = assigned_sid->val.uint16;

	if (unknown_attr) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " unknown mandatory attribute type %i,"
			    " disconnecting session\n",
			    unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);

		return -1;
	}

	if (l2tp_send_ICCN(sess) < 0) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " sending ICCN failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	if (l2tp_session_connect(sess) < 0) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " connecting session failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	return 0;
}

static int l2tp_recv_ICCN(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_ICCN) {
		log_session(log_warn, sess, "discarding unexpected ICCN\n");
		return 0;
	}

	log_session(log_info2, sess, "handling ICCN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Random_Vector:
		case TX_Speed:
		case Framing_Type:
		case Init_Recv_LCP:
		case Last_Sent_LCP:
		case Last_Recv_LCP:
		case Proxy_Authen_Type:
		case Proxy_Authen_Name:
		case Proxy_Authen_Challenge:
		case Proxy_Authen_ID:
		case Proxy_Authen_Response:
		case Private_Group_ID:
		case RX_Speed:
			break;
		case Sequencing_Required:
			if (conf_dataseq != L2TP_DATASEQ_DENY)
				sess->send_seq = 1;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					     " %i in ICCN\n", attr->attr->id);
			break;
		}
	}

	if (unknown_attr) {
		log_session(log_error, sess, "impossible to handle ICCN:"
			    " unknown mandatory attribute type %i,"
			    " disconnecting session\n",
			    unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);

		return -1;
	}

	if (l2tp_session_connect(sess)) {
		log_session(log_error, sess, "impossible to handle ICCN:"
			    " connecting session failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	return 0;
}

static int l2tp_session_outcall_reply(struct l2tp_sess_t *sess)
{
	if (triton_timer_add(&sess->paren_conn->ctx,
			     &sess->timeout_timer, 0) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to outgoing call:"
			    " setting establishment timer failed\n");
		goto err;
	}

	if (l2tp_send_OCRP(sess) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to outgoing call:"
			    " sending OCRP failed\n");
		goto err_timer;
	}
	if (l2tp_send_OCCN(sess) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to outgoing call:"
			    " sending OCCN failed\n");
		goto err_timer;
	}

	if (l2tp_session_connect(sess) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to outgoing call:"
			    " connecting session failed\n");
		goto err_timer;
	}

	return 0;

err_timer:
	triton_timer_del(&sess->timeout_timer);
err:
	return -1;
}

static int l2tp_recv_OCRQ(struct l2tp_conn_t *conn,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;
	struct l2tp_sess_t *sess = NULL;
	uint16_t peer_sid = 0;
	uint16_t sid = 0;
	uint16_t res;
	uint16_t err;

	if (conn->state != STATE_ESTB && !conn->lns_mode) {
		log_tunnel(log_warn, conn, "discarding unexpected OCRQ\n");
		return 0;
	}

	if (ap_shutdown) {
		log_tunnel(log_warn, conn, "shutdown in progress,"
			   " discarding OCRQ\n");
		return 0;
	}

	if (conf_max_starting && ap_session_stat.starting >= conf_max_starting)
		return 0;

	if (conf_max_sessions && ap_session_stat.active + ap_session_stat.starting >= conf_max_sessions)
		return 0;

	if (triton_module_loaded("connlimit")
	    && connlimit_check(cl_key_from_ipv4(conn->peer_addr.sin_addr.s_addr))) {
		log_tunnel(log_warn, conn, "connection limits reached,"
			   " discarding OCRQ\n");
		return 0;
	}

	log_tunnel(log_info2, conn, "handling OCRQ\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Random_Vector:
		case Call_Serial_Number:
		case Minimum_BPS:
		case Maximum_BPS:
		case Bearer_Type:
		case Framing_Type:
		case Called_Number:
		case Sub_Address:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else {
				log_tunnel(log_warn, conn,
					   "discarding unknown attribute type"
					   " %i in OCRQ\n", attr->attr->id);
			}
			break;
		}
	}

	if (assigned_sid == NULL) {
		log_tunnel(log_error, conn, "impossible to handle OCRQ:"
			   " no Assigned Session ID present in message,"
			   " disconnecting session\n");
		res = 2;
		err = 6;
		goto out_cancel;
	}

	peer_sid = assigned_sid->val.uint16;

	sess = l2tp_tunnel_alloc_session(conn);
	if (sess == NULL) {
		log_tunnel(log_error, conn, "impossible to handle OCRQ:"
			   " session allocation failed,"
			   " disconnecting session\n");
		res = 2;
		err = 4;
		goto out_cancel;
	}

	sess->peer_sid = peer_sid;
	sid = sess->sid;

	if (unknown_attr) {
		log_tunnel(log_error, conn, "impossible to handle OCRQ:"
			   " unknown mandatory attribute type %i,"
			   " disconnecting session\n",
			   unknown_attr->attr->id);
		res = 2;
		err = 8;
		goto out_cancel;
	}

	if (l2tp_session_outcall_reply(sess) < 0) {
		log_tunnel(log_error, conn, "impossible to handle OCRQ:"
			   " starting session failed,"
			   " disconnecting session\n");
		res = 2;
		err = 4;
		goto out_cancel;
	}

	log_tunnel(log_info1, conn, "new session %hu-%hu created following"
		   " reception of OCRQ\n", sid, peer_sid);

	return 0;

out_cancel:
	if (l2tp_tunnel_send_CDN(sid, peer_sid, res, err) < 0)
		log_tunnel(log_warn, conn,
			   "impossible to reject OCRQ:"
			   " sending CDN failed\n");
	if (sess)
		l2tp_session_free(sess);

	return -1;
}

static int l2tp_recv_OCRP(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_OCRP) {
		log_session(log_warn, sess, "discarding unexpected OCRP\n");
		return 0;
	}

	log_session(log_info2, sess, "handling OCRP\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
		case Random_Vector:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					    " %i in OCRP\n", attr->attr->id);
			break;
		}
	}

	if (assigned_sid == NULL) {
		log_session(log_error, sess, "impossible to handle OCRP:"
			    " no Assigned Session ID present in message,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	/* Set peer_sid as soon as possible so that CDN
	   will be sent to the right tunnel in case of error */
	log_session(log_info2, sess, "peer-sid set to %hu by OCRP\n",
		    assigned_sid->val.uint16);
	sess->peer_sid = assigned_sid->val.uint16;

	if (unknown_attr) {
		log_session(log_error, sess, "impossible to handle OCRP:"
			    " unknown mandatory attribute type %i,"
			    " disconnecting session\n",
			    unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);

		return -1;
	}

	sess->state1 = STATE_WAIT_OCCN;

	return 0;
}

static int l2tp_recv_OCCN(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_OCCN) {
		log_session(log_warn, sess, "discarding unexpected OCCN\n");
		return 0;
	}

	log_session(log_info2, sess, "handling OCCN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Random_Vector:
		case TX_Speed:
		case Framing_Type:
			break;
		case Sequencing_Required:
			if (conf_dataseq != L2TP_DATASEQ_DENY)
				sess->send_seq = 1;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					     " %i in OCCN\n", attr->attr->id);
			break;
		}
	}

	if (unknown_attr) {
		log_session(log_error, sess, "impossible to handle OCCN:"
			    " unknown mandatory attribute type %i,"
			    " disconnecting session\n",
			    unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);

		return -1;
	}

	if (l2tp_session_connect(sess) < 0) {
		log_session(log_error, sess, "impossible to handle OCCN:"
			    " connecting session failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	return 0;
}

static int l2tp_recv_CDN(struct l2tp_sess_t *sess,
			 const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *result_code = NULL;
	const struct l2tp_attr_t *attr = NULL;
	char *err_msg = NULL;
	uint16_t res = 0;
	uint16_t err = 0;

	if (sess->state1 == STATE_CLOSE) {
		log_session(log_warn, sess, "discarding unexpected CDN\n");

		return 0;
	}

	log_session(log_info2, sess, "handling CDN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
		case Random_Vector:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		case Result_Code:
			result_code = attr;
			break;
		default:
			if (attr->M) {
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					    " %i in CDN\n", attr->attr->id);
			}
			break;
		}
	}

	if (assigned_sid) {
		if (sess->peer_sid == 0) {
			log_session(log_info2, sess,
				    "peer-sid set to %hu by CDN\n",
				    assigned_sid->val.uint16);
			sess->peer_sid = assigned_sid->val.uint16;
		} else if (sess->peer_sid != assigned_sid->val.uint16) {
			log_session(log_warn, sess,
				    "discarding invalid Assigned Session ID"
				    " %hu in CDN\n", assigned_sid->val.uint16);
		}
	} else {
		log_session(log_warn, sess,
			    "no Assigned Session ID present in CDN\n");
	}

	if (result_code) {
		if (rescode_get_data(result_code, &res, &err, &err_msg) < 0) {
			log_session(log_warn, sess,
				    "invalid Result Code in CDN\n");
		}
	} else {
		log_session(log_warn, sess,
			    "no Result Code present in CDN\n");
	}

	log_session(log_info1, sess, "CDN received from peer (result: %hu,"
		    " error: %hu%s%s%s), disconnecting session\n",
		    res, err, err_msg ? ", message: \"" : "",
		    err_msg ? err_msg : "", err_msg ? "\"" : "");

	if (err_msg)
		_free(err_msg);

	/* Too late to send outstanding messages */
	l2tp_session_clear_sendqueue(sess);

	l2tp_session_free(sess);

	return 0;
}

static int l2tp_tunnel_recv_CDN(struct l2tp_conn_t *conn,
				const struct l2tp_packet_t *pack)
{
	if (conn->state != STATE_ESTB) {
		log_tunnel(log_warn, conn, "discarding unexpected CDN\n");

		return 0;
	}

	log_tunnel(log_warn, conn, "discarding CDN with no Session ID:"
		   " disconnecting sessions using Assigned Session ID is currently not supported\n");

	return 0;
}

static int l2tp_recv_WEN(struct l2tp_sess_t *sess,
			 const struct l2tp_packet_t *pack)
{
	if (sess->state1 != STATE_ESTB || !sess->paren_conn->lns_mode) {
		log_session(log_warn, sess, "discarding unexpected WEN\n");

		return 0;
	}

	log_session(log_info2, sess, "handling WEN\n");

	return 0;
}

static int l2tp_recv_SLI(struct l2tp_sess_t *sess,
			 const struct l2tp_packet_t *pack)
{
	if (sess->state1 != STATE_ESTB || sess->paren_conn->lns_mode) {
		log_session(log_warn, sess, "discarding unexpected SLI\n");

		return 0;
	}

	log_session(log_info2, sess, "handling SLI\n");

	return 0;
}

static int l2tp_session_place_call(struct l2tp_sess_t *sess)
{
	int res;

	if (triton_timer_add(&sess->paren_conn->ctx,
			     &sess->timeout_timer, 0) < 0) {
		log_session(log_error, sess,
			    "impossible to place %s call:"
			    " setting establishment timer failed\n",
			    sess->lns_mode ? "outgoing" : "incoming");
		goto err;
	}

	if (sess->lns_mode)
		res = l2tp_send_OCRQ(sess);
	else
		res = l2tp_send_ICRQ(sess);

	if (res < 0) {
		log_session(log_error, sess,
			    "impossible to place %s call:"
			    " sending %cCRQ failed\n",
			    sess->lns_mode ? "outgoing" : "incoming",
			    sess->lns_mode ? 'O' : 'I');
		goto err_timer;
	}

	sess->state1 = sess->lns_mode ? STATE_WAIT_OCRP : STATE_WAIT_ICRP;

	return 0;

err_timer:
	triton_timer_del(&sess->timeout_timer);
err:
	return -1;
}

static void l2tp_tunnel_create_session(void *data)
{
	struct l2tp_conn_t *conn = data;
	struct l2tp_sess_t *sess = NULL;
	uint16_t sid;

	if (conn->state != STATE_ESTB) {
		log_tunnel(log_error, conn, "impossible to create session:"
			   " tunnel is not connected\n");
		return;
	}

	sess = l2tp_tunnel_alloc_session(conn);
	if (sess == NULL) {
		log_tunnel(log_error, conn, "impossible to create session:"
			   " session allocation failed\n");
		return;
	}
	sid = sess->sid;

	if (l2tp_session_place_call(sess) < 0) {
		log_tunnel(log_error, conn, "impossible to create session:"
			   " starting session failed\n");
		l2tp_session_free(sess);

		return;
	}

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to create session:"
			   " transmitting messages from send queue failed\n");
		l2tp_session_free(sess);

		return;
	}

	log_tunnel(log_info1, conn, "new session %hu created following"
		   " request from command line interface\n", sid);
}

static void l2tp_session_recv(struct l2tp_sess_t *sess,
			      const struct l2tp_packet_t *pack,
			      uint16_t msg_type, int mandatory)
{
	switch (msg_type) {
	case Message_Type_Start_Ctrl_Conn_Request:
	case Message_Type_Start_Ctrl_Conn_Reply:
	case Message_Type_Start_Ctrl_Conn_Connected:
	case Message_Type_Stop_Ctrl_Conn_Notify:
	case Message_Type_Hello:
	case Message_Type_Outgoing_Call_Request:
	case Message_Type_Incoming_Call_Request:
		log_session(log_warn, sess,
			    "discarding tunnel specific message type %hu\n",
			    msg_type);
		break;
	case Message_Type_Outgoing_Call_Reply:
		l2tp_recv_OCRP(sess, pack);
		break;
	case Message_Type_Outgoing_Call_Connected:
		l2tp_recv_OCCN(sess, pack);
		break;
	case Message_Type_Incoming_Call_Reply:
		l2tp_recv_ICRP(sess, pack);
		break;
	case Message_Type_Incoming_Call_Connected:
		l2tp_recv_ICCN(sess, pack);
		break;
	case Message_Type_Call_Disconnect_Notify:
		l2tp_recv_CDN(sess, pack);
		break;
	case Message_Type_WAN_Error_Notify:
		l2tp_recv_WEN(sess, pack);
		break;
	case Message_Type_Set_Link_Info:
		l2tp_recv_SLI(sess, pack);
		break;
	default:
		if (mandatory) {
			log_session(log_error, sess,
				    "impossible to handle unknown mandatory message type %hu,"
				    " disconnecting session\n", msg_type);
			l2tp_session_disconnect(sess, 2, 8);
		} else {
			log_session(log_warn, sess,
				    "discarding unknown message type %hu\n",
				    msg_type);
		}
		break;
	}
}

static void l2tp_tunnel_recv(struct l2tp_conn_t *conn,
			     const struct l2tp_packet_t *pack,
			     uint16_t msg_type, int mandatory)
{
	switch (msg_type) {
	case Message_Type_Start_Ctrl_Conn_Request:
		log_tunnel(log_warn, conn, "discarding unexpected SCCRQ\n");
		break;
	case Message_Type_Start_Ctrl_Conn_Reply:
		l2tp_recv_SCCRP(conn, pack);
		break;
	case Message_Type_Start_Ctrl_Conn_Connected:
		l2tp_recv_SCCCN(conn, pack);
		break;
	case Message_Type_Stop_Ctrl_Conn_Notify:
		l2tp_recv_StopCCN(conn, pack);
		break;
	case Message_Type_Hello:
		l2tp_recv_HELLO(conn, pack);
		break;
	case Message_Type_Outgoing_Call_Request:
		l2tp_recv_OCRQ(conn, pack);
		break;
	case Message_Type_Incoming_Call_Request:
		l2tp_recv_ICRQ(conn, pack);
		break;
	case Message_Type_Call_Disconnect_Notify:
		l2tp_tunnel_recv_CDN(conn, pack);
		break;
	case Message_Type_Outgoing_Call_Reply:
	case Message_Type_Outgoing_Call_Connected:
	case Message_Type_Incoming_Call_Reply:
	case Message_Type_Incoming_Call_Connected:
	case Message_Type_WAN_Error_Notify:
	case Message_Type_Set_Link_Info:
		log_tunnel(log_warn, conn,
			   "discarding session specific message type %hu\n",
			   msg_type);
		break;
	default:
		if (mandatory) {
			log_tunnel(log_error, conn,
				   "impossible to handle unknown mandatory message type %hu,"
				   " disconnecting tunnel\n", msg_type);
			l2tp_tunnel_disconnect(conn, 2, 8);
		} else {
			log_tunnel(log_warn, conn,
				   "discarding unknown message type %hu\n",
				   msg_type);
		}
		break;
	}
}

static int l2tp_tunnel_store_msg(struct l2tp_conn_t *conn,
				 struct l2tp_packet_t *pack,
				 int *need_ack)
{
	uint16_t pack_Ns = ntohs(pack->hdr.Ns);
	uint16_t pack_Nr = ntohs(pack->hdr.Nr);
	uint16_t indx;

	/* Drop packets which acknowledge more packets than have actually
	 * been sent.
	 */
	if (nsnr_cmp(conn->Ns, pack_Nr) < 0) {
		log_tunnel(log_warn, conn,
			   "discarding message acknowledging unsent packets"
			   " (packet Ns/Nr: %hu/%hu, tunnel Ns/Nr: %hu/%hu)\n",
			   pack_Ns, pack_Nr, conn->Ns, conn->Nr);

		return -1;
	}

	/* Update peer Nr only when new packets are acknowledged */
	if (nsnr_cmp(pack_Nr, conn->peer_Nr) > 0)
		conn->peer_Nr = pack_Nr;

	if (l2tp_packet_is_ZLB(pack)) {
		log_tunnel(log_debug, conn, "handling ZLB\n");
		if (conf_verbose) {
			log_tunnel(log_debug, conn, "recv ");
			l2tp_packet_print(pack, log_debug);
		}

		return -1;
	}

	/* From now on, acknowledgement has to be sent in any case:
	 * -If the received packet is a duplicated message, the ack will
	 *  let the peer know we received its message (in case our
	 *  previous ack was lost).
	 *
	 * -If the received packet is an out of order message (whether or not
	 *  it fits in our reception window), the ack will explicitly tell the
	 *  peer which message number we're missing.
	 */
	*need_ack = 1;

	/* Drop duplicate messages */
	if (nsnr_cmp(pack_Ns, conn->Nr) < 0) {
		log_tunnel(log_info2, conn, "handling duplicate message"
			   " (packet Ns/Nr: %hu/%hu, tunnel Ns/Nr: %hu/%hu)\n",
			   pack_Ns, pack_Nr, conn->Ns, conn->Nr);

		return -1;
	}

	/* Drop out of order messages which don't fit in our reception queue.
	 * This means that the peer doesn't respect our receive window, so use
	 * log_warn.
	 */
	indx = pack_Ns - conn->Nr;
	if (indx >= conn->recv_queue_sz) {
		log_tunnel(log_warn, conn, "discarding out of order message"
			   " (packet Ns/Nr: %hu/%hu, tunnel Ns/Nr: %hu/%hu,"
			   " tunnel reception window size: %hu bytes)\n",
			   pack_Ns, pack_Nr, conn->Ns, conn->Nr,
			   conn->recv_queue_sz);

		return -1;
	}

	/* Drop duplicate out of order messages */
	indx = (indx + conn->recv_queue_offt) % conn->recv_queue_sz;
	if (conn->recv_queue[indx]) {
		log_tunnel(log_info2, conn,
			   "discarding duplicate out of order message"
			   " (packet Ns/Nr: %hu/%hu, tunnel Ns/Nr: %hu/%hu)\n",
			   pack_Ns, pack_Nr, conn->Ns, conn->Nr);

		return -1;
	}

	conn->recv_queue[indx] = pack;

	return 0;
}

static int l2tp_tunnel_reply(struct l2tp_conn_t *conn, int need_ack)
{
	const struct l2tp_attr_t *msg_attr = NULL;
	struct l2tp_packet_t *pack;
	struct l2tp_sess_t *sess;
	uint16_t msg_sid;
	uint16_t msg_type;
	uint16_t id = conn->recv_queue_offt;
	unsigned int pkt_count = 0;
	int res;

	/* Loop over reception queue, break as as soon as there is no more
	 * message to process or if tunnel gets closed.
	 */
	do {
		if (conn->recv_queue[id] == NULL || conn->state == STATE_CLOSE)
			break;

		pack = conn->recv_queue[id];
		conn->recv_queue[id] = NULL;
		++conn->Nr;
		++pkt_count;
		id = (id + 1) % conn->recv_queue_sz;

		/* We may receive packets even while disconnecting (e.g.
		 * packets sent by peer before we disconnect, but received
		 * later on, or peer retransmissions due to our acknowledgement
		 * getting lost).
		 * We don't have to process these messages, but we still
		 * dequeue them all to send proper acknowledgement (to avoid
		 * useless retransmissions from peer). Log with log_info2 since
		 * there's nothing wrong with receiving messages at this stage.
		 */
		if (conn->state == STATE_FIN ||
		    conn->state == STATE_FIN_WAIT) {
			log_tunnel(log_info2, conn,
				   "discarding message received while disconnecting\n");
			l2tp_packet_free(pack);
			continue;
		}

		/* ZLB aren't stored in the reception queue, so we're sure that
		 * pack->attrs isn't an empty list.
		 */
		msg_attr = list_first_entry(&pack->attrs, typeof(*msg_attr),
					    entry);
		if (msg_attr->attr->id != Message_Type) {
			log_tunnel(log_warn, conn,
				   "discarding message with invalid first attribute type %hu\n",
				   msg_attr->attr->id);
			l2tp_packet_free(pack);
			continue;
		}
		msg_type = msg_attr->val.uint16;

		if (conf_verbose) {
			if (msg_type == Message_Type_Hello) {
				log_tunnel(log_debug, conn, "recv ");
				l2tp_packet_print(pack, log_debug);
			} else {
				log_tunnel(log_info2, conn, "recv ");
				l2tp_packet_print(pack, log_info2);
			}
		}

		msg_sid = ntohs(pack->hdr.sid);
		if (msg_sid) {
			sess = l2tp_tunnel_get_session(conn, msg_sid);
			if (sess == NULL) {
				log_tunnel(log_warn, conn,
					   "discarding message with invalid Session ID %hu\n",
					   msg_sid);
				l2tp_packet_free(pack);
				continue;
			}
			l2tp_session_recv(sess, pack, msg_type, msg_attr->M);
		} else {
			l2tp_tunnel_recv(conn, pack, msg_type, msg_attr->M);
		}

		l2tp_packet_free(pack);
	} while (id != conn->recv_queue_offt);

	conn->recv_queue_offt = (conn->recv_queue_offt + pkt_count) % conn->recv_queue_sz;

	log_tunnel(log_debug, conn,
		   "%u message%s processed from reception queue\n",
		   pkt_count, pkt_count > 1 ? "s" : "");

	res = l2tp_tunnel_push_sendqueue(conn);
	if (res == 0 && need_ack)
		res = l2tp_send_ZLB(conn);

	return res;
}

static int l2tp_conn_read(struct triton_md_handler_t *h)
{
	struct l2tp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct l2tp_packet_t *pack;
	unsigned int pkt_count = 0;
	int need_ack = 0;
	int res;

	/* Hold the tunnel. This allows any function we call to free the
	 * tunnel while still keeping the tunnel valid until we return.
	 */
	tunnel_hold(conn);

	while (1) {
		res = l2tp_recv(h->fd, &pack, NULL,
				conn->secret, conn->secret_len);
		if (res) {
			if (res == -2) {
				log_tunnel(log_info1, conn,
					   "peer is unreachable,"
					   " disconnecting tunnel\n");
				goto err_tunfree;
			}

			break;
		}

		if (!pack)
			continue;

		if (conn->port_set == 0) {
			/* Get peer's first reply source port and use it as
			   destination port for further outgoing messages */
			log_tunnel(log_info2, conn,
				   "setting peer port to %hu\n",
				   ntohs(pack->addr.sin_port));
			res = l2tp_tunnel_update_peerport(conn,
							  pack->addr.sin_port);
			if (res < 0) {
				log_tunnel(log_error, conn,
					   "peer port update failed,"
					   " disconnecting tunnel\n");
				l2tp_packet_free(pack);
				goto err_tunfree;
			}
			conn->port_set = 1;
		}

		if (ntohs(pack->hdr.tid) != conn->tid && (pack->hdr.tid || !conf_dir300_quirk)) {
			log_tunnel(log_warn, conn,
				   "discarding message with invalid tid %hu\n",
				   ntohs(pack->hdr.tid));
			l2tp_packet_free(pack);
			continue;
		}

		if (l2tp_tunnel_store_msg(conn, pack, &need_ack) < 0) {
			l2tp_packet_free(pack);
			continue;
		}

		++pkt_count;
	}

	log_tunnel(log_debug, conn, "%u message%s added to reception queue\n",
		   pkt_count, pkt_count > 1 ? "s" : "");

	/* Drop acknowledged packets from retransmission queue */
	if (l2tp_tunnel_clean_rtmsqueue(conn) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to handle incoming message:"
			   " cleaning retransmission queue failed,"
			   " deleting tunnel\n");
		goto err_tunfree;
	}

	if (l2tp_tunnel_reply(conn, need_ack) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to reply to incoming messages:"
			   " message transmission failed,"
			   " deleting tunnel\n");
		goto err_tunfree;
	}

	if (conn->state == STATE_FIN && list_empty(&conn->send_queue) &&
	    list_empty(&conn->rtms_queue)) {
		log_tunnel(log_info2, conn,
			   "tunnel disconnection acknowledged by peer,"
			   " deleting tunnel\n");
		goto err_tunfree;
	}

	/* Use conn->state to detect tunnel deletion */
	if (conn->state == STATE_CLOSE)
		goto err;

	tunnel_put(conn);

	return 0;

err_tunfree:
	l2tp_tunnel_free(conn);
err:
	tunnel_put(conn);

	return -1;
}

static int l2tp_udp_read(struct triton_md_handler_t *h)
{
	struct l2tp_serv_t *serv = container_of(h, typeof(*serv), hnd);
	struct l2tp_packet_t *pack;
	const struct l2tp_attr_t *msg_type = NULL;
	struct in_pktinfo pkt_info;
	char src_addr[17];

	while (1) {
		if (l2tp_recv(h->fd, &pack, &pkt_info,
			      conf_secret, conf_secret_len) < 0)
			break;

		if (!pack)
			continue;

		u_inet_ntoa(pack->addr.sin_addr.s_addr, src_addr);

		if (iprange_client_check(pack->addr.sin_addr.s_addr)) {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " IP address is out of client-ip-range\n",
				 src_addr);
			goto skip;
		}

		if (pack->hdr.tid) {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " invalid tid %hu\n",
				 src_addr, ntohs(pack->hdr.tid));
			goto skip;
		}

		if (list_empty(&pack->attrs)) {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " message is empty\n", src_addr);
			goto skip;
		}

		msg_type = list_entry(pack->attrs.next, typeof(*msg_type), entry);
		if (msg_type->attr->id != Message_Type) {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " invalid first attribute type %i\n",
				 src_addr, msg_type->attr->id);
			goto skip;
		}

		if (conf_verbose) {
			log_info2("l2tp: recv ");
			l2tp_packet_print(pack, log_info2);
		}
		if (msg_type->val.uint16 == Message_Type_Start_Ctrl_Conn_Request)
			l2tp_recv_SCCRQ(serv, pack, &pkt_info);
		else {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " invalid Message Type %i\n",
				 src_addr, msg_type->val.uint16);
		}
skip:
		l2tp_packet_free(pack);
	}

	return 0;
}

static void l2tp_udp_close(struct triton_context_t *ctx)
{
	struct l2tp_serv_t *serv = container_of(ctx, typeof(*serv), ctx);
	triton_md_unregister_handler(&serv->hnd, 1);
	triton_context_unregister(&serv->ctx);
}

static struct l2tp_serv_t udp_serv =
{
	.hnd.read = l2tp_udp_read,
	.ctx.close = l2tp_udp_close,
	.ctx.before_switch = l2tp_ctx_switch,
};

/*static struct l2tp_serv_t ip_serv =
{
	.hnd.read=l2t_ip_read,
	.ctx.close=l2tp_ip_close,
};*/

static int start_udp_server(void)
{
	struct sockaddr_in addr;
	const char *opt;
	int flag;

	udp_serv.hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (udp_serv.hnd.fd < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " socket(PF_INET) failed: %s\n", strerror(errno));
		return -1;
	}

	flag = fcntl(udp_serv.hnd.fd, F_GETFD);
	if (flag < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " fcntl(F_GETFD) failed: %s\n", strerror(errno));
		goto err_fd;
	}
	flag = fcntl(udp_serv.hnd.fd, F_SETFD, flag | FD_CLOEXEC);
	if (flag < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " fcntl(F_SETFD) failed: %s\n", strerror(errno));
		goto err_fd;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	opt = conf_get_opt("l2tp", "bind");
	if (opt)
		addr.sin_addr.s_addr = inet_addr(opt);
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

	opt = conf_get_opt("l2tp", "port");
	if (opt && atoi(opt) > 0)
		conf_port = atoi(opt);
	addr.sin_port = htons(conf_port);

	if (setsockopt(udp_serv.hnd.fd, SOL_SOCKET, SO_REUSEADDR,
		       &udp_serv.hnd.fd, sizeof(udp_serv.hnd.fd)) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " setsockopt(SO_REUSEADDR) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}
	if (setsockopt(udp_serv.hnd.fd, SOL_SOCKET, SO_NO_CHECK,
		       &udp_serv.hnd.fd, sizeof(udp_serv.hnd.fd)) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " setsockopt(SO_NO_CHECK) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}

	if (bind(udp_serv.hnd.fd,
		 (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " bind() failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}

	flag = fcntl(udp_serv.hnd.fd, F_GETFL);
	if (flag < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " fcntl(F_GETFL) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}
	flag = fcntl(udp_serv.hnd.fd, F_SETFL, flag | O_NONBLOCK);
	if (flag < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " fcntl(F_SETFL) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}

	flag = 1;
	if (setsockopt(udp_serv.hnd.fd, IPPROTO_IP,
		       IP_PKTINFO, &flag, sizeof(flag)) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " setsockopt(IP_PKTINFO) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}

	memcpy(&udp_serv.addr, &addr, sizeof(addr));

	if (triton_context_register(&udp_serv.ctx, NULL) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " context registration failed\n");
		goto err_fd;
	}
	triton_md_register_handler(&udp_serv.ctx, &udp_serv.hnd);
	if (triton_md_enable_handler(&udp_serv.hnd, MD_MODE_READ) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " enabling handler failed\n");
		goto err_hnd;
	}
	triton_context_wakeup(&udp_serv.ctx);

	return 0;

err_hnd:
	triton_md_unregister_handler(&udp_serv.hnd, 1);
	triton_context_unregister(&udp_serv.ctx);

	return -1;

err_fd:
	close(udp_serv.hnd.fd);
	udp_serv.hnd.fd = -1;

	return -1;
}

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "l2tp:\r\n");
	cli_send(client, "  tunnels:\r\n");
	cli_sendv(client, "    starting: %u\r\n", stat_conn_starting);
	cli_sendv(client, "    active: %u\r\n", stat_conn_active);
	cli_sendv(client, "    finishing: %u\r\n", stat_conn_finishing);

	cli_send(client, "  sessions (control channels):\r\n");
	cli_sendv(client, "    starting: %u\r\n", stat_sess_starting);
	cli_sendv(client, "    active: %u\r\n", stat_sess_active);
	cli_sendv(client, "    finishing: %u\r\n", stat_sess_finishing);

	cli_send(client, "  sessions (data channels):\r\n");
	cli_sendv(client, "    starting: %u\r\n", stat_starting);
	cli_sendv(client, "    active: %u\r\n", stat_active);
	cli_sendv(client, "    finishing: %u\r\n", stat_finishing);

	return CLI_CMD_OK;
}

static int l2tp_create_tunnel_exec(const char *cmd, char * const *fields,
				   int fields_cnt, void *client)
{
	struct l2tp_conn_t *conn = NULL;
	struct sockaddr_in peer = {
		.sin_family = AF_INET,
		.sin_port = htons(L2TP_PORT),
		.sin_addr = { htonl(INADDR_ANY) }
	};
	struct sockaddr_in host = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = { htonl(INADDR_ANY) }
	};
	const char *opt = NULL;
	const char *secret = conf_secret;
	int peer_indx = -1;
	int host_indx = -1;
	int lns_mode = 0;
	int hide_avps = conf_hide_avps;
	uint16_t tid;
	int indx;

	opt = conf_get_opt("l2tp", "bind");
	if (opt)
		if (inet_aton(opt, &host.sin_addr) == 0) {
			host.sin_family = AF_INET;
			host.sin_port = 0;
		}

	for (indx = 3; indx + 1 < fields_cnt; ++indx) {
		if (strcmp("mode", fields[indx]) == 0) {
			++indx;
			if (strcmp("lns", fields[indx]) == 0)
				lns_mode = 1;
			else if (strcmp("lac", fields[indx]) == 0)
				lns_mode = 0;
			else {
				cli_sendv(client, "invalid mode: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
		} else if (strcmp("peer-addr", fields[indx]) == 0) {
			peer_indx = ++indx;
			if (inet_aton(fields[indx], &peer.sin_addr) == 0) {
				cli_sendv(client,
					  "invalid peer address: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
		} else if (strcmp("host-addr", fields[indx]) == 0) {
			host_indx = ++indx;
			if (inet_aton(fields[indx], &host.sin_addr) == 0) {
				cli_sendv(client,
					  "invalid host address: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
		} else if (strcmp("peer-port", fields[indx]) == 0) {
			long port;
			++indx;
			if (u_readlong(&port, fields[indx],
				       0, UINT16_MAX) < 0) {
				cli_sendv(client,
					  "invalid peer port: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
			peer.sin_port = htons(port);
		} else if (strcmp("host-port", fields[indx]) == 0) {
			long port;
			++indx;
			if (u_readlong(&port, fields[indx],
				       0, UINT16_MAX) < 0) {
				cli_sendv(client,
					  "invalid host port: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
			host.sin_port = htons(port);
		} else if (strcmp("hide-avps", fields[indx]) == 0) {
			++indx;
			hide_avps = atoi(fields[indx]) > 0;
		} else if (strcmp("secret", fields[indx]) == 0) {
			++indx;
			secret = fields[indx];
		} else {
			cli_sendv(client, "invalid option: \"%s\"\r\n",
				  fields[indx]);
			return CLI_CMD_SYNTAX;
		}
	}

	if (indx != fields_cnt) {
		cli_send(client, "argument missing for last option\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (peer_indx < 0) {
		cli_send(client, "missing option \"peer-addr\"\r\n");
		return CLI_CMD_SYNTAX;
	}

	conn = l2tp_tunnel_alloc(&peer, &host, 3, lns_mode, 0, hide_avps);
	if (conn == NULL) {
		cli_send(client, "tunnel allocation failed\r\n");
		return CLI_CMD_FAILED;
	}
	tid = conn->tid;

	if (secret) {
		conn->secret = _strdup(secret);
		if (conn->secret == NULL) {
			cli_send(client, "secret allocation failed\r\n");
			l2tp_tunnel_free(conn);
			return CLI_CMD_FAILED;
		}
		conn->secret_len = strlen(conn->secret);
	}

	if (l2tp_tunnel_start(conn, l2tp_send_SCCRQ, &peer) < 0) {
		cli_send(client, "starting tunnel failed\r\n");
		l2tp_tunnel_free(conn);
		return CLI_CMD_FAILED;
	}

	log_info1("l2tp: new tunnel %hu created following request"
		  " from command line interface (peer-addr: %s,"
		  " host-addr: %s, mode: %s)\n", tid, fields[peer_indx],
		  host_indx < 0 ? "default" : fields[host_indx],
		  lns_mode ? "lns" : "lac");

	return CLI_CMD_OK;
}

static int l2tp_create_session_exec(const char *cmd, char * const *fields,
				    int fields_cnt, void *client)
{
	struct l2tp_conn_t *conn = NULL;
	long int tid;
	int res;

	if (fields_cnt != 5) {
		cli_send(client, "invalid number of arguments\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (strcmp("tid", fields[3]) != 0) {
		cli_sendv(client, "invalid option: \"%s\"\r\n", fields[3]);
		return CLI_CMD_SYNTAX;
	}

	if (u_readlong(&tid, fields[4], 1, UINT16_MAX) < 0) {
		cli_sendv(client, "invalid Tunnel ID: \"%s\"\r\n", fields[4]);
		return CLI_CMD_INVAL;
	}

	pthread_mutex_lock(&l2tp_lock);
	conn = l2tp_conn[tid];
	if (conn) {
		if (triton_context_call(&conn->ctx, l2tp_tunnel_create_session,
					conn) < 0)
			res = CLI_CMD_FAILED;
		else
			res = CLI_CMD_OK;
	} else {
		res = CLI_CMD_INVAL;
	}
	pthread_mutex_unlock(&l2tp_lock);

	if (res == CLI_CMD_FAILED)
		cli_send(client, "session creation failed\r\n");
	else if (res == CLI_CMD_INVAL)
		cli_sendv(client, "tunnel %li not found\r\n", tid);

	return res;
}

static void l2tp_create_tunnel_help(char * const *fields, int fields_cnt,
				    void *client)
{
	cli_send(client,
		 "l2tp create tunnel peer-addr <ip_addr> [OPTIONS...]"
		 " - initiate new tunnel to peer\r\n"
		 "\tOPTIONS:\r\n"
		 "\t\tpeer-port <port> - destination port (default 1701)\r\n"
		 "\t\thost-addr <ip_addr> - source address\r\n"
		 "\t\thost-port <port> - source port\r\n"
		 "\t\tsecret <secret> - tunnel secret\r\n"
		 "\t\thide-avps <0|1> - activation of AVP hiding\r\n"
		 "\t\tmode <lac|lns> - tunnel mode\r\n");
}

static void l2tp_create_session_help(char * const *fields, int fields_cnt,
				     void *client)
{
	cli_send(client,
		 "l2tp create session tid <tid>"
		 " - place new call in tunnel <tid>\r\n");
}

void __export l2tp_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("l2tp", "verbose");
	if (opt && atoi(opt) >= 0)
		conf_verbose = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "use-ephemeral-ports");
	if (opt && atoi(opt) >= 0)
		conf_ephemeral_ports = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "hide-avps");
	if (opt && atoi(opt) >= 0)
		conf_hide_avps = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "dataseq");
	if (opt) {
		if (strcmp(opt, "deny") == 0)
			conf_dataseq = L2TP_DATASEQ_DENY;
		else if (strcmp(opt, "allow") == 0)
			conf_dataseq = L2TP_DATASEQ_ALLOW;
		else if (strcmp(opt, "prefer") == 0)
			conf_dataseq = L2TP_DATASEQ_PREFER;
		else if (strcmp(opt, "require") == 0)
			conf_dataseq = L2TP_DATASEQ_REQUIRE;
	}

	opt = conf_get_opt("l2tp", "reorder-timeout");
	if (opt && atoi(opt) >= 0)
		conf_reorder_timeout = atoi(opt);

	opt = conf_get_opt("l2tp", "avp_permissive");
	if (opt && atoi(opt) >= 0)
		conf_avp_permissive = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "hello-interval");
	if (opt && atoi(opt) > 0)
		conf_hello_interval = atoi(opt);

	opt = conf_get_opt("l2tp", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("l2tp", "rtimeout");
	if (opt && atoi(opt) > 0)
		conf_rtimeout = atoi(opt);
	else
		conf_rtimeout = DEFAULT_RTIMEOUT;

	opt = conf_get_opt("l2tp", "rtimeout-cap");
	if (opt && atoi(opt) > 0)
		conf_rtimeout_cap = atoi(opt);
	else
		conf_rtimeout_cap = DEFAULT_RTIMEOUT_CAP;
	if (conf_rtimeout_cap < conf_rtimeout) {
		log_warn("l2tp: rtimeout-cap (%i) is smaller than rtimeout (%i),"
			 " resetting rtimeout-cap to %i\n",
			 conf_rtimeout_cap, conf_rtimeout, conf_rtimeout);
		conf_rtimeout_cap = conf_rtimeout;
	}

	opt = conf_get_opt("l2tp", "retransmit");
	if (opt && atoi(opt) > 0)
		conf_retransmit = atoi(opt);
	else
		conf_retransmit = DEFAULT_RETRANSMIT;

	opt = conf_get_opt("l2tp", "recv-window");
	if (opt && atoi(opt) > 0 && atoi(opt) <= RECV_WINDOW_SIZE_MAX)
		conf_recv_window = atoi(opt);
	else
		conf_recv_window = DEFAULT_RECV_WINDOW;

	opt = conf_get_opt("l2tp", "ppp-max-mtu");
	if (opt && atoi(opt) > 0)
		conf_ppp_max_mtu = atoi(opt);
	else
		conf_ppp_max_mtu = DEFAULT_PPP_MAX_MTU;

	opt = conf_get_opt("l2tp", "host-name");
	if (opt)
		conf_host_name = opt;
	else
		conf_host_name = "accel-ppp";

	opt = conf_get_opt("l2tp", "secret");
	if (opt) {
		conf_secret = opt;
		conf_secret_len = strlen(opt);
	} else {
		conf_secret = NULL;
		conf_secret_len = 0;
	}

	opt = conf_get_opt("l2tp", "dir300_quirk");
	if (opt)
		conf_dir300_quirk = atoi(opt);

	conf_mppe = MPPE_UNSET;
	opt = conf_get_opt("l2tp", "mppe");
	if (opt) {
		if (strcmp(opt, "deny") == 0)
			conf_mppe = MPPE_DENY;
		else if (strcmp(opt, "allow") == 0)
			conf_mppe = MPPE_ALLOW;
		else if (strcmp(opt, "prefer") == 0)
			conf_mppe = MPPE_PREFER;
		else if (strcmp(opt, "require") == 0)
			conf_mppe = MPPE_REQUIRE;
	}

	conf_ip_pool = conf_get_opt("l2tp", "ip-pool");
	conf_ipv6_pool = conf_get_opt("l2tp", "ipv6-pool");
	conf_dpv6_pool = conf_get_opt("l2tp", "ipv6-pool-delegate");
	conf_ifname = conf_get_opt("l2tp", "ifname");

	switch (iprange_check_activation()) {
	case IPRANGE_DISABLED:
		log_warn("l2tp: iprange module disabled, improper IP configuration of PPP interfaces may cause kernel soft lockup\n");
		break;
	case IPRANGE_NO_RANGE:
		log_warn("l2tp: no IP address range defined in section [%s], incoming L2TP connections will be rejected\n",
			 IPRANGE_CONF_SECTION);
		break;
	default:
		/* Makes compiler happy */
		break;
	}
}

static void reload_config(void)
{
        config_lock();
        load_config();
        config_unlock();
}

static void l2tp_init(void)
{
	int fd;

	fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (fd >= 0)
		close(fd);
	else if (system("modprobe -q pppol2tp || modprobe -q l2tp_ppp"))
		log_warn("unable to load l2tp kernel module\n");

	l2tp_conn = _malloc((UINT16_MAX + 1) * sizeof(struct l2tp_conn_t *));
	memset(l2tp_conn, 0, (UINT16_MAX + 1) * sizeof(struct l2tp_conn_t *));

	l2tp_conn_pool = mempool_create(sizeof(struct l2tp_conn_t));
	l2tp_sess_pool = mempool_create(sizeof(struct l2tp_sess_t));

	load_config();

	start_udp_server();

	cli_register_simple_cmd2(&show_stat_exec, NULL, 2, "show", "stat");
	cli_register_simple_cmd2(l2tp_create_tunnel_exec,
				 l2tp_create_tunnel_help, 3,
				 "l2tp", "create", "tunnel");
	cli_register_simple_cmd2(l2tp_create_session_exec,
				 l2tp_create_session_help, 3,
				 "l2tp", "create", "session");

	if (triton_event_register_handler(EV_CONFIG_RELOAD,
					  (triton_event_func)reload_config) < 0)
		log_warn("l2tp: registration of CONFIG_RELOAD event failed,"
			 " configuration reloading deactivated\n");
}

DEFINE_INIT(22, l2tp_init);
