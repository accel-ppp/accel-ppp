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
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>

#include <openssl/md5.h>

#include "triton.h"
#include "mempool.h"
#include "log.h"
#include "ppp.h"
#include "events.h"
#include "utils.h"
#include "iprange.h"
#include "cli.h"

#include "connlimit.h"

#include "memdebug.h"

#include "l2tp.h"
#include "attr_defs.h"
#include "l2tp_switch_conf.h"

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

#define L2TP_SWITCH_PENDING_MAX 64
/* calls placed on a target's tunnel and not yet answered with an ICRP */
#define L2TP_SWITCH_INFLIGHT_MAX L2TP_SWITCH_PENDING_MAX

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
static int conf_session_timeout;
static const char *conf_ip_pool;
static const char *conf_ipv6_pool;
static const char *conf_dpv6_pool;
static const char *conf_ifname;

struct l2tp_stat_t
{
	unsigned int conn_starting;
	unsigned int conn_active;
	unsigned int conn_finishing;

	unsigned int sess_starting;
	unsigned int sess_active;
	unsigned int sess_finishing;

	unsigned int data_starting;
	unsigned int data_active;
	unsigned int data_finishing;

	unsigned int switch_matched;
	unsigned int switch_placed;
	unsigned int switch_refused;
	unsigned int switch_downstream_connected;


	uint64_t switch_lns_rx_bytes;
	uint64_t switch_lns_tx_bytes;
};

static struct l2tp_stat_t l2tp_stat;

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
/* We will keep l2tp attributes Calling-Number/Called-Number and their length while the session exists */
	char *calling_num;
	int calling_num_len;
	char *called_num;
	int called_num_len;

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
	pthread_mutex_t switch_fd_lock; /* serializes splice() into ppp.fd with close() of it; leaf lock */
	struct triton_context_t apses_ctx;
	int apses_state;
	struct ap_ctrl ctrl;
	struct ppp_t ppp;

	struct l2tp_switch_target_t *switch_target;
	struct l2tp_switch_avps *switch_avps;
	/* result of the CDN received on this leg, then handed to the other leg
	 * for the CDN it sends in turn; 0 if there is none */
	uint16_t switch_cdn_res;
	uint16_t switch_cdn_err;
	/* set while this matched call is counted in l2tp_switch_starting */
	int switch_starting;
	/* set while this call is counted in its target's inflight_count */
	int switch_inflight;
	/* EV_CTRL_STARTED was fired, so EV_CTRL_FINISHED is due */
	unsigned int ctrl_started:1;
	/* on l2tp_switch_calls from the match until the session is freed */
	struct list_head switch_call_entry;
	struct l2tp_sess_t *switch_downstream;
	struct l2tp_sess_t *switch_upstream;
	struct l2tp_switch_link_t *switch_link;
	struct list_head switch_pending_entry;
};

/*
 * state1 of a switched leg is stored on one tunnel's context and loaded on
 * another's (and by the shutdown hook), so every access goes through these.
 * Relaxed is enough: readers only compare against STATE_CLOSE and the pair
 * lock orders a later unpair after the earlier CLOSE.
 */
/* acquire/release: a leg that sees the other one in STATE_CLOSE also sees
 * what it stored before closing (switch_cdn_res, switch_cdn_err) */
static inline int l2tp_sess_state(const struct l2tp_sess_t *sess)
{
	return __atomic_load_n(&sess->state1, __ATOMIC_ACQUIRE);
}

static inline void l2tp_sess_set_state(struct l2tp_sess_t *sess, int state)
{
	__atomic_store_n(&sess->state1, state, __ATOMIC_RELEASE);
}

struct l2tp_switch_avp_t {
	int id;
	int M;
	uint8_t *val;
	int len;
	int is_int16;
	int is_int32;
};

struct l2tp_switch_avps {
	/* the proxy AVPs (8) and the other optional ICCN ones */
	struct l2tp_switch_avp_t avp[12];
	int count;

	/* from the upstream ICCN, for the downstream one */
	uint32_t tx_speed;
	uint32_t framing;
	unsigned int have_tx_speed:1;
	unsigned int have_framing:1;
};

struct l2tp_conn_t
{
	pthread_mutex_t ctx_lock;
	pthread_mutex_t sessions_lock; /* held for ->sessions writes and the CLI tree walk */
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
	/* reached STATE_ESTB at some point */
	uint16_t was_estb:1;
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

	struct l2tp_switch_target_t *switch_target;
	struct list_head switch_hops; /* under ctx_lock */
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
static void l2tp_send_SCCRQ(void *peer_addr);
static int l2tp_session_place_call(struct l2tp_sess_t *sess);

struct l2tp_switch_link_t;

static unsigned int l2tp_switch_active_total(void);
static void l2tp_switch_link_free(struct l2tp_switch_link_t *link);
static void l2tp_switch_teardown_peer(void *data);
static void l2tp_switch_place_call_on(struct l2tp_sess_t *upstream,
				      struct l2tp_conn_t *conn);
static int l2tp_switch_target_arm_idle_linger(struct l2tp_switch_target_t *target,
					      struct l2tp_conn_t *conn);
static void l2tp_switch_target_idle_timer(struct triton_timer_t *t);
static int l2tp_switch_target_is_persistent(const struct l2tp_switch_target_t *target);
static void l2tp_switch_target_detach(struct l2tp_conn_t *conn);
static int l2tp_switch_requeue_call(struct l2tp_sess_t *upstream);
static int l2tp_switch_inflight_begin(struct l2tp_sess_t *upstream, int force);
static void l2tp_switch_target_connect(struct l2tp_switch_target_t *target);

/* switched calls have no ap_session, so the core never counts them as
 * starting: from the match until the relay is up they are counted here */
static unsigned int l2tp_switch_starting;

/* the upstream legs of all matched calls, for the graceful shutdown, which
 * has to wait for them and cannot find them through the ap_session list */
static LIST_HEAD(l2tp_switch_calls);
static pthread_mutex_t l2tp_switch_calls_lock = PTHREAD_MUTEX_INITIALIZER;

/* hops queued to a tunnel context and not yet run or cancelled: a shutdown
 * must not complete under one, it still sends CDNs and logs while triton
 * closes the log contexts */
static unsigned int l2tp_switch_hops_pending;

/* ap_shutdown is set before the shutdown walk takes l2tp_switch_calls_lock,
 * so a call that is refused here is not in the list for the walk to miss and
 * one that is accepted is seen by it. Returns -1 when a shutdown is pending;
 * the call is then not counted or listed. */
static int l2tp_switch_starting_begin(struct l2tp_sess_t *sess)
{
	pthread_mutex_lock(&l2tp_switch_calls_lock);
	if (ap_shutdown) {
		pthread_mutex_unlock(&l2tp_switch_calls_lock);
		return -1;
	}
	if (list_empty(&sess->switch_call_entry))
		list_add_tail(&sess->switch_call_entry, &l2tp_switch_calls);
	pthread_mutex_unlock(&l2tp_switch_calls_lock);

	if (!__atomic_exchange_n(&sess->switch_starting, 1, __ATOMIC_RELAXED))
		__atomic_add_fetch(&l2tp_switch_starting, 1, __ATOMIC_RELAXED);

	return 0;
}

/* callable from any context; may complete a pending shutdown */
static void l2tp_switch_call_forget(struct l2tp_sess_t *sess)
{
	int forgot = 0;

	pthread_mutex_lock(&l2tp_switch_calls_lock);
	if (!list_empty(&sess->switch_call_entry)) {
		list_del_init(&sess->switch_call_entry);
		forgot = 1;
	}
	pthread_mutex_unlock(&l2tp_switch_calls_lock);

	if (forgot)
		ap_shutdown_check();
}

static int l2tp_switch_shutdown_busy(void)
{
	int busy;

	pthread_mutex_lock(&l2tp_switch_calls_lock);
	busy = !list_empty(&l2tp_switch_calls);
	pthread_mutex_unlock(&l2tp_switch_calls_lock);

	return busy ||
	       __atomic_load_n(&l2tp_switch_hops_pending, __ATOMIC_ACQUIRE) != 0;
}

/* idempotent, callable from any context */
static void l2tp_switch_starting_end(struct l2tp_sess_t *sess)
{
	if (__atomic_exchange_n(&sess->switch_starting, 0, __ATOMIC_RELAXED))
		__atomic_sub_fetch(&l2tp_switch_starting, 1, __ATOMIC_RELAXED);
}

/* idempotent, callable from any context */
static void l2tp_switch_inflight_end(struct l2tp_sess_t *sess)
{
	if (sess->switch_target &&
	    __atomic_exchange_n(&sess->switch_inflight, 0, __ATOMIC_RELAXED))
		__atomic_sub_fetch(&sess->switch_target->inflight_count, 1,
				   __ATOMIC_RELAXED);
}

static unsigned int l2tp_starting_in_use(void)
{
	return ap_session_stat_starting() +
	       __atomic_load_n(&l2tp_switch_starting, __ATOMIC_RELAXED);
}

/* switched calls hold sockets and buffers like any other call */
static unsigned int l2tp_sessions_in_use(void)
{
	return ap_session_stat_active() + l2tp_starting_in_use() +
	       l2tp_switch_active_total();
}

static void l2tp_stat_inc(unsigned int *stat)
{
	__atomic_add_fetch(stat, 1, __ATOMIC_RELAXED);
}

static void l2tp_stat_dec(unsigned int *stat)
{
	__atomic_sub_fetch(stat, 1, __ATOMIC_RELAXED);
}

static void l2tp_stat_move(unsigned int *from, unsigned int *to)
{
	l2tp_stat_dec(from);
	l2tp_stat_inc(to);
}

static void l2tp_stat_get(struct l2tp_stat_t *stat)
{
	stat->conn_starting = __atomic_load_n(&l2tp_stat.conn_starting, __ATOMIC_RELAXED);
	stat->conn_active = __atomic_load_n(&l2tp_stat.conn_active, __ATOMIC_RELAXED);
	stat->conn_finishing = __atomic_load_n(&l2tp_stat.conn_finishing, __ATOMIC_RELAXED);
	stat->sess_starting = __atomic_load_n(&l2tp_stat.sess_starting, __ATOMIC_RELAXED);
	stat->sess_active = __atomic_load_n(&l2tp_stat.sess_active, __ATOMIC_RELAXED);
	stat->sess_finishing = __atomic_load_n(&l2tp_stat.sess_finishing, __ATOMIC_RELAXED);
	stat->data_starting = __atomic_load_n(&l2tp_stat.data_starting, __ATOMIC_RELAXED);
	stat->data_active = __atomic_load_n(&l2tp_stat.data_active, __ATOMIC_RELAXED);
	stat->data_finishing = __atomic_load_n(&l2tp_stat.data_finishing, __ATOMIC_RELAXED);
	stat->switch_matched = __atomic_load_n(&l2tp_stat.switch_matched, __ATOMIC_RELAXED);
	stat->switch_placed = __atomic_load_n(&l2tp_stat.switch_placed, __ATOMIC_RELAXED);
	stat->switch_downstream_connected = __atomic_load_n(&l2tp_stat.switch_downstream_connected, __ATOMIC_RELAXED);
	stat->switch_lns_rx_bytes = __atomic_load_n(&l2tp_stat.switch_lns_rx_bytes, __ATOMIC_RELAXED);
	stat->switch_lns_tx_bytes = __atomic_load_n(&l2tp_stat.switch_lns_tx_bytes, __ATOMIC_RELAXED);
}

unsigned int __export l2tp_stat_starting(void)
{
	return __atomic_load_n(&l2tp_stat.data_starting, __ATOMIC_RELAXED);
}

unsigned int __export l2tp_stat_active(void)
{
	return __atomic_load_n(&l2tp_stat.data_active, __ATOMIC_RELAXED);
}

unsigned int __export l2tp_switch_stat_active(void)
{
	return l2tp_switch_active_total();
}

uint64_t __export l2tp_switch_stat_lns_rx_bytes(void)
{
	return __atomic_load_n(&l2tp_stat.switch_lns_rx_bytes, __ATOMIC_RELAXED);
}

uint64_t __export l2tp_switch_stat_lns_tx_bytes(void)
{
	return __atomic_load_n(&l2tp_stat.switch_lns_tx_bytes, __ATOMIC_RELAXED);
}

typedef void (*l2tp_switch_target_stat_cb)(const char *name, int up,
					   unsigned int active,
					   uint64_t rx_bytes, uint64_t tx_bytes,
					   void *arg);

void __export l2tp_switch_stat_targets_foreach(l2tp_switch_target_stat_cb cb,
					       void *arg)
{
	struct l2tp_switch_target_t *t;

	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		int up;

		/* metrics thread; t->lock guards t->tunnel, not ->state: an
		 * aligned int read that may be stale */
		pthread_mutex_lock(&t->lock);
		up = t->tunnel != NULL && t->tunnel->state == STATE_ESTB;
		pthread_mutex_unlock(&t->lock);

		cb(t->name, up,
		   __atomic_load_n(&t->active, __ATOMIC_RELAXED),
		   __atomic_load_n(&t->rx_bytes, __ATOMIC_RELAXED),
		   __atomic_load_n(&t->tx_bytes, __ATOMIC_RELAXED),
		   arg);
	}
}


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
	if (l2tp_sess_state(sess) == STATE_CLOSE) {
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
	/* a switched call has a peer waiting on it and up to
	 * L2TP_SWITCH_PENDING_MAX of them can be placed at once: they queue
	 * and go out as the window opens */
	if (!sess->switch_upstream &&
	    sess->paren_conn->send_queue_len >= sess->paren_conn->peer_rcv_wnd_sz)
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

static void l2tp_session_free_ptr(void *ptr)
{
	l2tp_session_free((struct l2tp_sess_t *) ptr);
}

static void l2tp_tunnel_free_sessions(struct l2tp_conn_t *conn)
{
	void *sessions;

	pthread_mutex_lock(&conn->sessions_lock);
	sessions = conn->sessions;
	conn->sessions = NULL;
	pthread_mutex_unlock(&conn->sessions_lock);
	tdestroy(sessions, l2tp_session_free_ptr);
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
		l2tp_stat_move(&l2tp_stat.conn_starting, &l2tp_stat.conn_finishing);
		break;
	case STATE_ESTB:
		l2tp_stat_move(&l2tp_stat.conn_active, &l2tp_stat.conn_finishing);
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
	pthread_mutex_destroy(&conn->sessions_lock);

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

	l2tp_stat_dec(&l2tp_stat.conn_finishing);
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
	pthread_mutex_destroy(&sess->switch_fd_lock);

	if (sess->ppp.fd >= 0)
		close(sess->ppp.fd);
	if (sess->ppp.ses.chan_name)
		_free(sess->ppp.ses.chan_name);
	if (sess->ctrl.calling_station_id)
		_free(sess->ctrl.calling_station_id);
	if (sess->ctrl.called_station_id)
		_free(sess->ctrl.called_station_id);
	if (sess->calling_num)
		_free(sess->calling_num);
	if (sess->called_num)
		_free(sess->called_num);

	log_session(log_info2, sess, "session destroyed\n");

	mempool_free(sess);

	l2tp_stat_dec(&l2tp_stat.sess_finishing);

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

/* pairing state (switch_upstream/downstream, switch_link, switch_avps) is
 * torn down on the session's own context but set up from the other leg's;
 * guarded by this leaf lock */
static pthread_mutex_t l2tp_switch_pair_lock = PTHREAD_MUTEX_INITIALIZER;

struct l2tp_switch_unpaired {
	struct l2tp_sess_t *peer; /* caller owes a session_put() */
	struct l2tp_switch_link_t *link;
	struct l2tp_switch_avps *avps;
};

/* close_it also sets STATE_CLOSE under the pair lock, so the liveness check
 * in l2tp_switch_place_call_on() is atomic against teardown */
static struct l2tp_switch_unpaired l2tp_switch_unpair(struct l2tp_sess_t *sess,
						      int close_it)
{
	struct l2tp_switch_unpaired u;

	pthread_mutex_lock(&l2tp_switch_pair_lock);
	if (close_it)
		l2tp_sess_set_state(sess, STATE_CLOSE);
	u.peer = sess->switch_downstream ? sess->switch_downstream :
		 sess->switch_upstream;
	u.link = sess->switch_link;
	u.avps = sess->switch_avps;
	sess->switch_downstream = NULL;
	sess->switch_upstream = NULL;
	sess->switch_avps = NULL;
	pthread_mutex_unlock(&l2tp_switch_pair_lock);

	return u;
}

/* wipe that the compiler cannot elide; explicit_bzero() needs a recent libc */
static void l2tp_secure_wipe(void *p, size_t len)
{
	volatile uint8_t *v = p;

	while (len--)
		*v++ = 0;
}

static void l2tp_switch_avps_free(struct l2tp_switch_avps *avps)
{
	int i;

	if (!avps)
		return;

	for (i = 0; i < avps->count; i++) {
		/* Proxy-Authen-Response is the cleartext PAP password */
		l2tp_secure_wipe(avps->avp[i].val, avps->avp[i].len);
		_free(avps->avp[i].val);
	}
	_free(avps);
}

/* triton_context_unregister() drops queued calls without running them, so
 * calls to another tunnel's context are recorded in switch_hops under
 * ctx_lock; if the tunnel is freed first, l2tp_tunnel_free() runs each
 * cancel, which must release what func would have */
struct l2tp_switch_hop {
	struct list_head entry;
	void (*func)(void *arg);
	void (*cancel)(void *arg);
	void *arg;
};

/* last statement of a hop: whatever it logged is out, so a shutdown that was
 * waiting for it can complete */
static void l2tp_switch_hop_done(void)
{
	if (__atomic_sub_fetch(&l2tp_switch_hops_pending, 1,
			       __ATOMIC_ACQ_REL) == 0)
		ap_shutdown_check();
}

static void l2tp_switch_hop_run(void *data)
{
	struct l2tp_switch_hop *hop = data;
	struct l2tp_conn_t *conn = l2tp_tunnel_self();
	void (*func)(void *) = hop->func;
	void *arg = hop->arg;

	pthread_mutex_lock(&conn->ctx_lock);
	list_del(&hop->entry);
	pthread_mutex_unlock(&conn->ctx_lock);
	_free(hop);

	func(arg);
	l2tp_switch_hop_done();
}

/* returns 0 if func or cancel will run and take over the caller's holds, -1
 * if nothing was scheduled (errno is ESRCH if conn's context is already
 * gone, which is not an error for a teardown); the hold does not keep conn's
 * context registered, hence the ctx.tpd check */
static int l2tp_switch_hop(struct l2tp_conn_t *conn, void (*func)(void *),
			   void (*cancel)(void *), void *arg)
{
	struct l2tp_switch_hop *hop = _malloc(sizeof(*hop));
	int res = -1;
	int err = ESRCH;

	if (!hop) {
		errno = ENOMEM;
		return -1;
	}
	hop->func = func;
	hop->cancel = cancel;
	hop->arg = arg;

	pthread_mutex_lock(&conn->ctx_lock);
	if (conn->ctx.tpd) {
		list_add_tail(&hop->entry, &conn->switch_hops);
		res = triton_context_call(&conn->ctx, l2tp_switch_hop_run, hop);
		if (res < 0) {
			list_del(&hop->entry);
			err = EIO;
		} else {
			__atomic_add_fetch(&l2tp_switch_hops_pending, 1,
					   __ATOMIC_ACQ_REL);
		}
	}
	pthread_mutex_unlock(&conn->ctx_lock);

	if (res < 0) {
		_free(hop);
		errno = err;
	}

	return res;
}

static void l2tp_switch_hops_cancel(struct list_head *hops)
{
	while (!list_empty(hops)) {
		struct l2tp_switch_hop *hop = list_first_entry(hops, typeof(*hop),
							       entry);

		list_del(&hop->entry);
		hop->cancel(hop->arg);
		_free(hop);
		l2tp_switch_hop_done();
	}
}

static void l2tp_switch_teardown_peer_cancel(void *data)
{
	session_put(data);
}

static void l2tp_session_free(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;
	struct l2tp_switch_unpaired u;
	intptr_t cause = TERM_NAS_REQUEST;
	int res = 1;

	l2tp_switch_starting_end(sess);
	l2tp_switch_inflight_end(sess);

	switch (l2tp_sess_state(sess)) {
	case STATE_INIT:
	case STATE_WAIT_ICRP:
	case STATE_WAIT_ICCN:
	case STATE_WAIT_OCRP:
	case STATE_WAIT_OCCN:
		log_session(log_info2, sess, "deleting session\n");

		l2tp_stat_move(&l2tp_stat.sess_starting, &l2tp_stat.sess_finishing);
		break;
	case STATE_ESTB:
		log_session(log_info2, sess, "deleting session\n");

		if (sess->ctrl_started)
			triton_event_fire(EV_CTRL_FINISHED, &sess->ppp.ses);
		l2tp_stat_move(&l2tp_stat.sess_active, &l2tp_stat.sess_finishing);

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
			    l2tp_sess_state(sess));
		return;
	}

	u = l2tp_switch_unpair(sess, 1);
	if (u.link)
		l2tp_switch_link_free(u.link);
	l2tp_switch_avps_free(u.avps);

	if (u.peer) {
		/* take the hold that survives the hop before dropping the
		 * pointer hold */
		int cascade = l2tp_sess_state(u.peer) != STATE_CLOSE;

		/* the result this leg ended with is not copied into the peer:
		 * the peer's hop and its link read it from this session, which
		 * the peer's pair pointer keeps alive (see
		 * l2tp_switch_cdn_of()) */
		if (cascade)
			session_hold(u.peer);
		session_put(u.peer);

		if (cascade) {
			int res = -1;

			res = l2tp_switch_hop(u.peer->paren_conn,
					      l2tp_switch_teardown_peer,
					      l2tp_switch_teardown_peer_cancel,
					      u.peer);
			if (res < 0)
				session_put(u.peer);
		}
	}

	/* after the other leg is told, so a shutdown it completes does not
	 * cut that CDN off */
	l2tp_switch_call_forget(sess);

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

	pthread_mutex_lock(&sess->paren_conn->sessions_lock);
	if (sess->paren_conn->sessions) {
		if (!tdelete(sess, &sess->paren_conn->sessions, sess_cmp)) {
			pthread_mutex_unlock(&sess->paren_conn->sessions_lock);
			log_session(log_error, sess,
				    "impossible to delete session:"
				    " session unreachable from its parent tunnel\n");
			return;
		}
	}
	pthread_mutex_unlock(&sess->paren_conn->sessions_lock);
	/* Parent tunnel doesn't hold the session anymore. This is true even
	 * if sess->paren_conn->sessions was NULL (which means that
	 * l2tp_session_free() is being called by tdestroy()).
	 */
	session_put(sess);

	/* a persistent target's tunnel outlives its calls */
	if (--sess->paren_conn->sess_count == 0 &&
	    !l2tp_switch_target_is_persistent(sess->paren_conn->switch_target) &&
	    l2tp_switch_target_arm_idle_linger(sess->paren_conn->switch_target,
					       sess->paren_conn) < 0) {
		switch (sess->paren_conn->state) {
		case STATE_ESTB:
			log_tunnel(log_info1, sess->paren_conn,
				   "no more session, disconnecting tunnel\n");
			l2tp_tunnel_disconnect_push(sess->paren_conn, 1, 0);
			/* the linger could not be armed: free the connect slot
			 * as the idle-linger close does, a call arriving while
			 * the tunnel awaits its StopCCN ack would wait for it */
			if (sess->paren_conn->switch_target)
				l2tp_switch_target_detach(sess->paren_conn);
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

/* monotonic ms, same clock as triton timers */
static uint64_t l2tp_switch_monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int l2tp_switch_target_is_persistent(const struct l2tp_switch_target_t *target)
{
	return target && target->mode == L2TP_SWITCH_MODE_PERSISTENT;
}

static int l2tp_switch_target_should_retry(struct l2tp_switch_target_t *target)
{
	int pending;

	if (l2tp_switch_target_is_persistent(target))
		return 1;

	pthread_mutex_lock(&target->lock);
	pending = target->pending_count > 0;
	pthread_mutex_unlock(&target->lock);

	return pending;
}

/* triton_timer_del() is unsafe for a timer that may be dispatching: target
 * timers are deleted only from their own callback on the default context,
 * other contexts close the window (idle_deadline = 0, connect_budget_open);
 * adds and dels are under target->lock */
static void l2tp_switch_target_schedule_retry(struct l2tp_switch_target_t *target)
{
	pthread_mutex_lock(&target->lock);
	if (!target->reconnect_timer.tpd) {
		if (triton_timer_add(NULL, &target->reconnect_timer, 0) < 0)
			log_error("l2tp-switch: target \"%s\": failed to"
				  " schedule reconnect\n", target->name);
	}
	pthread_mutex_unlock(&target->lock);
}

/* conn is leaving ESTB but stays around until its disconnection timer fires:
 * let its target connect a new tunnel right away instead of when conn is
 * freed, since calls wait for it and the reconnect timer is only started
 * then. Callers: the peer's StopCCN and the idle-linger close (local StopCCN,
 * the tunnel stays until it is acked); runs on conn's context and is a no-op
 * if conn no longer holds the target's slot */
static void l2tp_switch_target_detach(struct l2tp_conn_t *conn)
{
	struct l2tp_switch_target_t *target = conn->switch_target;
	int pending;

	pthread_mutex_lock(&target->lock);
	if (target->tunnel != conn) {
		pthread_mutex_unlock(&target->lock);
		return;
	}
	target->tunnel = NULL;
	pending = target->pending_count > 0;
	pthread_mutex_unlock(&target->lock);

	/* a tunnel that never came up goes through the reconnect timer: a peer
	 * that answers every SCCRQ with a StopCCN must not be hammered */
	if (pending && conn->was_estb)
		l2tp_switch_target_connect(target);
	else if (l2tp_switch_target_should_retry(target))
		l2tp_switch_target_schedule_retry(target);
}

/* returns 0 only if a linger is pending for conn; conn may be NULL for the
 * target's current tunnel; callable from any context */
static int l2tp_switch_target_arm_idle_linger(struct l2tp_switch_target_t *target,
					      struct l2tp_conn_t *conn)
{
	uint64_t now;
	int res;

	if (!target || target->mode != L2TP_SWITCH_MODE_ON_DEMAND)
		return -1;

	pthread_mutex_lock(&target->lock);

	if (!target->tunnel || (conn && target->tunnel != conn))
		goto err;
	if (target->tunnel->state != STATE_ESTB)
		goto err;
	if (target->connect_budget_open)
		goto err;

	now = l2tp_switch_monotonic_ms();
	target->idle_timer.expire = l2tp_switch_target_idle_timer;
	target->idle_timer.period = l2tp_switch_conf_idle_linger_ms();

	if (target->idle_timer.tpd)
		res = triton_timer_mod(&target->idle_timer, 0);
	else
		res = triton_timer_add(NULL, &target->idle_timer, 0);

	if (res < 0) {
		log_error("l2tp-switch: target \"%s\": failed to arm idle"
			  " linger\n", target->name);
		goto err;
	}

	/* read before arming so the deadline is never later than the expiry */
	target->idle_deadline = now + l2tp_switch_conf_idle_linger_ms();

	pthread_mutex_unlock(&target->lock);

	return 0;

err:
	pthread_mutex_unlock(&target->lock);

	return -1;
}

static void l2tp_tunnel_free(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	LIST_HEAD(hops);

	switch (conn->state) {
	case STATE_INIT:
	case STATE_WAIT_SCCRP:
	case STATE_WAIT_SCCCN:
		l2tp_stat_move(&l2tp_stat.conn_starting, &l2tp_stat.conn_finishing);
		break;
	case STATE_ESTB:
		l2tp_stat_move(&l2tp_stat.conn_active, &l2tp_stat.conn_finishing);
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

	if (conn->switch_target) {
		struct l2tp_switch_target_t *target = conn->switch_target;

		pthread_mutex_lock(&target->lock);
		if (target->tunnel == conn)
			target->tunnel = NULL;
		pthread_mutex_unlock(&target->lock);

		if (l2tp_switch_target_should_retry(target))
			l2tp_switch_target_schedule_retry(target);
	}

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

	/* unregistering drops queued calls; take the switch hops off in the
	 * same critical section */
	pthread_mutex_lock(&conn->ctx_lock);
	/* also when l2tp_tunnel_start() failed and already unregistered the
	 * context: a hop queued before that was dropped with it */
	list_splice_init(&conn->switch_hops, &hops);
	if (conn->ctx.tpd)
		triton_context_unregister(&conn->ctx);
	pthread_mutex_unlock(&conn->ctx_lock);

	l2tp_switch_hops_cancel(&hops);

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
	if (l2tp_sess_state(sess) == STATE_ESTB) {
		log_session(log_info1, sess,
			    "data channel closed, disconnecting session\n");
		l2tp_session_disconnect_push(sess, 2, 0);
	} else {
		log_session(log_warn, sess,
			    "avoiding disconnection of session with no data channel:"
			    " invalid state %i\n", l2tp_sess_state(sess));
	}
}

/* payload is a session id only, nothing to release */
static void l2tp_switch_apses_finished_cancel(void *data)
{
}

static void __apses_destroy(void *data)
{
	struct l2tp_sess_t *sess = data;

	pthread_mutex_lock(&sess->apses_lock);
	triton_context_unregister(&sess->apses_ctx);
	pthread_mutex_unlock(&sess->apses_lock);

	log_ppp_info2("session destroyed\n");

	l2tp_stat_dec(&l2tp_stat.data_finishing);

	/* Drop reference to the L2TP session */
	session_put(sess);
}

static void apses_finished(struct ap_session *apses)
{
	struct l2tp_sess_t *sess = container_of(apses->ctrl, typeof(*sess),
						ctrl);
	intptr_t sid = sess->sid;

	switch (sess->apses_state) {
	case APSTATE_STARTING:
		l2tp_stat_move(&l2tp_stat.data_starting, &l2tp_stat.data_finishing);
		break;
	case APSTATE_STARTED:
		l2tp_stat_move(&l2tp_stat.data_active, &l2tp_stat.data_finishing);
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

	/* payload is a session id, not a reference */
	if (l2tp_switch_hop(sess->paren_conn, l2tp_session_apses_finished,
			    l2tp_switch_apses_finished_cancel, (void *)sid) < 0 &&
	    errno != ESRCH)
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
		l2tp_stat_move(&l2tp_stat.data_starting, &l2tp_stat.data_finishing);
		break;
	case APSTATE_STARTED:
		l2tp_stat_move(&l2tp_stat.data_active, &l2tp_stat.data_finishing);
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

		if (l2tp_switch_hop(sess->paren_conn, l2tp_session_apses_finished,
				    l2tp_switch_apses_finished_cancel,
				    (void *)sid) < 0 && errno != ESRCH)
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

	l2tp_stat_move(&l2tp_stat.data_starting, &l2tp_stat.data_active);
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

		pthread_mutex_lock(&conn->sessions_lock);
		sess_search = tsearch(sess, &conn->sessions, sess_cmp);
		pthread_mutex_unlock(&conn->sessions_lock);
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
	l2tp_sess_set_state(sess, STATE_INIT);
	sess->lns_mode = conn->lns_mode;
	sess->hide_avps = conn->hide_avps;
	sess->send_seq = (conf_dataseq == L2TP_DATASEQ_PREFER) ||
			 (conf_dataseq == L2TP_DATASEQ_REQUIRE);
	sess->recv_seq = (conf_dataseq == L2TP_DATASEQ_REQUIRE);
	sess->reorder_timeout = conf_reorder_timeout;
	INIT_LIST_HEAD(&sess->send_queue);
	INIT_LIST_HEAD(&sess->switch_pending_entry);
	INIT_LIST_HEAD(&sess->switch_call_entry);

	sess->timeout_timer.expire = l2tp_session_timeout;
	sess->timeout_timer.period = conf_timeout * 1000;

	pthread_mutex_init(&sess->apses_lock, NULL);
	pthread_mutex_init(&sess->switch_fd_lock, NULL);
	ppp_init(&sess->ppp);

	/* The tunnel holds a reference to the session */
	session_hold(sess);
	/* The session holds a reference to the tunnel and to itself */
	tunnel_hold(conn);
	session_hold(sess);

	l2tp_stat_inc(&l2tp_stat.sess_starting);

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
	/* under ctx_lock so l2tp_switch_hop() either queued its hop before
	 * (l2tp_tunnel_free() cancels it) or sees the context gone */
	pthread_mutex_lock(&conn->ctx_lock);
	triton_context_unregister(&conn->ctx);
	pthread_mutex_unlock(&conn->ctx_lock);
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
	pthread_mutex_init(&conn->sessions_lock, NULL);
	INIT_LIST_HEAD(&conn->send_queue);
	INIT_LIST_HEAD(&conn->rtms_queue);
	INIT_LIST_HEAD(&conn->switch_hops);

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
	if (bind(conn->hnd.fd, (struct sockaddr*)host, sizeof(*host))) {
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

	if (getsockname(conn->hnd.fd, (struct sockaddr*)&conn->host_addr, &hostaddrlen) < 0) {
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

	l2tp_stat_inc(&l2tp_stat.conn_starting);

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

static void l2tp_switch_target_connect(struct l2tp_switch_target_t *target)
{
	struct sockaddr_in host = {
		.sin_family = AF_INET,
		.sin_addr = { htonl(INADDR_ANY) },
	};
	struct l2tp_conn_t *conn;
	int taken;

	/* try again later rather than drop the reconnect chain: the shutdown
	 * can still be cancelled */
	if (ap_shutdown)
		goto retry;

	pthread_mutex_lock(&target->lock);
	taken = target->tunnel != NULL;
	pthread_mutex_unlock(&target->lock);
	if (taken)
		return;

	conn = l2tp_tunnel_alloc(&target->peer_addr, &host, 3, 0, 0,
				 conf_hide_avps);
	if (conn == NULL) {
		log_error("l2tp-switch: target \"%s\": tunnel allocation"
			  " failed, retrying in %ds\n", target->name,
			  l2tp_switch_conf_reconnect_interval_ms() / 1000);
		goto retry;
	}

	conn->secret = _strdup(target->secret);
	if (conn->secret == NULL) {
		log_error("l2tp-switch: target \"%s\": secret allocation"
			  " failed\n", target->name);
		l2tp_tunnel_free(conn);
		goto retry;
	}
	conn->secret_len = target->secret_len;

	/* publish before l2tp_tunnel_start(): a fast peer can drain the
	 * queued calls before the pointer is stored */
	pthread_mutex_lock(&target->lock);
	if (target->tunnel) {
		pthread_mutex_unlock(&target->lock);
		l2tp_tunnel_free(conn); /* switch_target is unset, teardown must not touch the target */
		return;
	}
	conn->switch_target = target;
	target->tunnel = conn;
	pthread_mutex_unlock(&target->lock);

	if (l2tp_tunnel_start(conn, l2tp_send_SCCRQ, &target->peer_addr) < 0) {
		log_error("l2tp-switch: target \"%s\": starting tunnel"
			  " failed, retrying in %ds\n", target->name,
			  l2tp_switch_conf_reconnect_interval_ms() / 1000);
		pthread_mutex_lock(&target->lock);
		if (target->tunnel == conn)
			target->tunnel = NULL;
		pthread_mutex_unlock(&target->lock);
		l2tp_tunnel_free(conn);
		goto retry;
	}

	return;

retry:
	if (l2tp_switch_target_should_retry(target))
		l2tp_switch_target_schedule_retry(target);
}

static void l2tp_switch_target_reconnect_timer(struct triton_timer_t *t)
{
	struct l2tp_switch_target_t *target =
		container_of(t, typeof(*target), reconnect_timer);

	pthread_mutex_lock(&target->lock);
	if (target->reconnect_timer.tpd)
		triton_timer_del(t);
	pthread_mutex_unlock(&target->lock);

	if (!l2tp_switch_target_should_retry(target))
		return;

	l2tp_switch_target_connect(target);
}

static void l2tp_switch_targets_connect(void)
{
	struct l2tp_switch_target_t *target;

	list_for_each_entry(target, &l2tp_switch_targets, entry) {
		target->reconnect_timer.expire =
			l2tp_switch_target_reconnect_timer;
		target->reconnect_timer.period =
			l2tp_switch_conf_reconnect_interval_ms();
		if (target->mode == L2TP_SWITCH_MODE_PERSISTENT)
			l2tp_switch_target_connect(target);
	}
}

static inline int l2tp_tunnel_update_peerport(struct l2tp_conn_t *conn,
					      uint16_t port_nbo)
{
	in_port_t old_port = conn->peer_addr.sin_port;
	int res;

	conn->peer_addr.sin_port = port_nbo;
	res = connect(conn->hnd.fd, (struct sockaddr*)&conn->peer_addr, sizeof(conn->peer_addr));
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

	/* If l2tp calling number avp exists, we use it, otherwise we use lac ip */
	if (sess->calling_num != NULL) {
		sess->ctrl.calling_station_id = _malloc(sess->calling_num_len+1);
		if (sess->ctrl.calling_station_id == NULL) {
			log_session(log_error, sess,
				    "impossible to start data channel:"
				    " allocation of calling station ID failed\n");
			goto err;
		}else {
			strcpy(sess->ctrl.calling_station_id, sess->calling_num);
		}
	} else {
		sess->ctrl.calling_station_id = _malloc(17);
		if (sess->ctrl.calling_station_id == NULL) {
			log_session(log_error, sess,
				"impossible to start data channel:"
				" allocation of calling station ID failed\n");
			goto err;
		} else {
			u_inet_ntoa(sess->paren_conn->peer_addr.sin_addr.s_addr,
				sess->ctrl.calling_station_id);
		}
	}
	/* If l2tp called number avp exists, we use it, otherwise we use my ip */
	if (sess->called_num != NULL) {
		sess->ctrl.called_station_id = _malloc(sess->called_num_len+1);
		if (sess->ctrl.called_station_id == NULL) {
			log_session(log_error, sess,
				    "impossible to start data channel:"
				    " allocation of called station ID failed\n");
			goto err;
		} else {
			strcpy(sess->ctrl.called_station_id, sess->called_num);
		}
	} else {
		sess->ctrl.called_station_id = _malloc(17);
		if (sess->ctrl.called_station_id == NULL) {
			log_session(log_error, sess,
				"impossible to start data channel:"
				" allocation of called station ID failed\n");
			goto err;
		} else {
			u_inet_ntoa(sess->paren_conn->host_addr.sin_addr.s_addr,
				sess->ctrl.called_station_id);
		}
	}

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

	if (conf_session_timeout)
		sess->ppp.ses.session_timeout = conf_session_timeout;

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

	l2tp_stat_inc(&l2tp_stat.data_starting);

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

/* switched sessions splice() in userspace, so a short burst has to fit in
 * the buffer */
#define L2TP_SWITCH_SOCKBUF_SIZE (4 * 1024 * 1024)

/* the FORCE options bypass rmem_max/wmem_max, fall back if not permitted */
static void l2tp_switch_set_sockbuf(struct l2tp_sess_t *sess, int fd)
{
	int size = L2TP_SWITCH_SOCKBUF_SIZE;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0 &&
	    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0)
		log_session(log_warn, sess,
			    "l2tp-switch: setsockopt(SO_RCVBUF) failed: %s\n",
			    strerror(errno));

	size = L2TP_SWITCH_SOCKBUF_SIZE;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &size, sizeof(size)) < 0 &&
	    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0)
		log_session(log_warn, sess,
			    "l2tp-switch: setsockopt(SO_SNDBUF) failed: %s\n",
			    strerror(errno));
}

static int l2tp_session_connect_socket(struct l2tp_sess_t *sess, int start_ppp)
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

	/* switched sessions splice() from userspace, so the socket must be
	 * O_NONBLOCK or splice() blocks a triton worker */
	if (!start_ppp) {
		flg = fcntl(sess->ppp.fd, F_GETFL);
		if (flg < 0) {
			log_session(log_error, sess,
				    "impossible to connect session:"
				    " fcntl(F_GETFL) failed: %s\n",
				    strerror(errno));
			goto out_err;
		}
		if (fcntl(sess->ppp.fd, F_SETFL, flg | O_NONBLOCK) < 0) {
			log_session(log_error, sess,
				    "impossible to connect session:"
				    " fcntl(F_SETFL) failed: %s\n",
				    strerror(errno));
			goto out_err;
		}

		l2tp_switch_set_sockbuf(sess, sess->ppp.fd);
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

	/* a switched leg has no ap_session: the event handlers would work on
	 * a session list that was never initialised */
	if (start_ppp) {
		triton_event_fire(EV_CTRL_STARTED, &sess->ppp.ses);
		sess->ctrl_started = 1;
	}
	l2tp_stat_move(&l2tp_stat.sess_starting, &l2tp_stat.sess_active);
	l2tp_sess_set_state(sess, STATE_ESTB);

	if (start_ppp && l2tp_session_start_data_channel(sess) < 0) {
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

static int l2tp_session_connect(struct l2tp_sess_t *sess)
{
	return l2tp_session_connect_socket(sess, 1);
}

/* runs on conn's context; connect_timeout_timer belongs to the default
 * context and retires itself */
static void l2tp_switch_drain_pending_calls(struct l2tp_conn_t *conn)
{
	struct l2tp_switch_target_t *target = conn->switch_target;
	LIST_HEAD(drained);
	struct l2tp_sess_t *sess;

	pthread_mutex_lock(&target->lock);
	if (target->tunnel != conn) {
		pthread_mutex_unlock(&target->lock);
		return;
	}
	target->connect_budget_open = 0;
	list_splice_init(&target->pending_calls, &drained);
	target->pending_count = 0;
	pthread_mutex_unlock(&target->lock);

	while (!list_empty(&drained)) {
		sess = list_first_entry(&drained, typeof(*sess),
					switch_pending_entry);
		list_del(&sess->switch_pending_entry);
		l2tp_switch_inflight_begin(sess, 1);
		l2tp_switch_place_call_on(sess, conn);
	}

	if (conn->state == STATE_ESTB && conn->sess_count == 0)
		l2tp_switch_target_arm_idle_linger(target, conn);
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

	l2tp_stat_move(&l2tp_stat.conn_starting, &l2tp_stat.conn_active);
	conn->state = STATE_ESTB;
	conn->was_estb = 1;

	if (conn->switch_target)
		l2tp_switch_drain_pending_calls(conn);

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
	if (sess->calling_num &&
	    l2tp_packet_add_string(pack, Calling_Number, sess->calling_num,
				   1) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (sess->called_num &&
	    l2tp_packet_add_string(pack, Called_Number, sess->called_num,
				   1) < 0) {
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

	/* a switched call reports its upstream line, anything else the
	 * defaults */
	if (l2tp_packet_add_int32(pack, TX_Speed,
				  sess->switch_avps && sess->switch_avps->have_tx_speed ?
				  (int32_t)sess->switch_avps->tx_speed : 1000, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Type,
				  sess->switch_avps && sess->switch_avps->have_framing ?
				  (int32_t)sess->switch_avps->framing : 3, 1) < 0) {
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

	if (sess->switch_avps) {
		int i;

		for (i = 0; i < sess->switch_avps->count; i++) {
			struct l2tp_switch_avp_t *a = &sess->switch_avps->avp[i];
			int res;

			/* l2tp_packet_add_octets() fills val.octets but the
			 * encoder reads val.int16 and val.int32 for those */
			if (a->is_int16 && a->len == sizeof(uint16_t))
				res = l2tp_packet_add_int16(pack, a->id,
					(int16_t)ntohs(*(uint16_t *)a->val),
					a->M);
			else if (a->is_int32 && a->len == sizeof(uint32_t))
				res = l2tp_packet_add_int32(pack, a->id,
					(int32_t)ntohl(*(uint32_t *)a->val),
					a->M);
			else
				res = l2tp_packet_add_octets(pack, a->id,
							     a->val, a->len,
							     a->M);
			if (res < 0) {
				log_session(log_error, sess,
					    "impossible to send ICCN:"
					    " re-injecting proxy AVP %d"
					    " failed\n", a->id);
				goto out_err;
			}
		}
	}

	l2tp_session_send(sess, pack);

	/* the packet holds its own copy: do not keep the proxied credentials
	 * (incl. a cleartext PAP password) for the rest of the call */
	l2tp_switch_avps_free(sess->switch_avps);
	sess->switch_avps = NULL;

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
	switch (conn->state) {
	case STATE_WAIT_SCCRP:
	case STATE_WAIT_SCCCN:
		l2tp_stat_move(&l2tp_stat.conn_starting, &l2tp_stat.conn_finishing);
		break;
	case STATE_ESTB:
		l2tp_stat_move(&l2tp_stat.conn_active, &l2tp_stat.conn_finishing);
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

	/* stay up for a full retransmission cycle to re-ack a retransmitted
	 * StopCCN */
	{
		int rtimeout = conn->rtimeout;
		int indx;

		conn->timeout_timer.period = 0;
		for (indx = 0; indx < conn->max_retransmit; ++indx) {
			conn->timeout_timer.period += rtimeout;
			rtimeout *= 2;
			if (rtimeout > conn->rtimeout_cap)
				rtimeout = conn->rtimeout_cap;
		}
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
		return;
	}

	if (conn->switch_target)
		l2tp_switch_target_detach(conn);
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

	if (conf_max_starting && l2tp_starting_in_use() >= conf_max_starting)
		return 0;

	if (conf_max_sessions && l2tp_sessions_in_use() >= conf_max_sessions)
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

	l2tp_sess_set_state(sess, STATE_WAIT_ICCN);

	return 0;

err_timer:
	triton_timer_del(&sess->timeout_timer);
err:
	return -1;
}

/* An outbound target tunnel only carries calls we place; a call request from
 * its peer is refused whatever the match rules say. The CDN is addressed to
 * the peer's Assigned Session ID, if it gave one. */
static int l2tp_reject_on_target_tunnel(struct l2tp_conn_t *conn,
					const struct l2tp_packet_t *pack,
					const char *what)
{
	const struct l2tp_attr_t *attr;
	uint16_t peer_sid = 0;

	if (!conn->switch_target)
		return 0;

	list_for_each_entry(attr, &pack->attrs, entry)
		if (attr->attr->id == Assigned_Session_ID) {
			peer_sid = attr->val.uint16;
			break;
		}

	log_tunnel(log_warn, conn, "l2tp-switch: %s on an outbound target"
		   " tunnel, rejecting\n", what);
	if (l2tp_tunnel_send_CDN(0, peer_sid, 2, 6) < 0)
		log_tunnel(log_warn, conn, "impossible to reject %s:"
			   " sending CDN failed\n", what);

	return 1;
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
	uint8_t	calling[L2TP_AVP_LEN_MASK] = {0};
	uint8_t	called[L2TP_AVP_LEN_MASK] = {0};
	int n = 0;
	int m = 0;
	int seen_calling = 0;
	int seen_called = 0;

	if (l2tp_reject_on_target_tunnel(conn, pack, "ICRQ"))
		return 0;

	if (conn->state != STATE_ESTB && conn->lns_mode) {
		log_tunnel(log_warn, conn, "discarding unexpected ICRQ\n");
		return 0;
	}

	if (ap_shutdown) {
		log_tunnel(log_warn, conn, "shutdown in progress,"
			   " discarding ICRQ\n");
		return 0;
	}

	if (conf_max_starting && l2tp_starting_in_use() >= conf_max_starting)
		return 0;

	if (conf_max_sessions && l2tp_sessions_in_use() >= conf_max_sessions)
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
			/* Save Calling-Number L2TP attribute locally; the first
			 * one wins, as for the match rules */
				if (attr->attr->id == Calling_Number &&
				    !seen_calling) {
					seen_calling = 1;
					n = attr->length;
					memcpy(calling,attr->val.octets,n);
				}
			case Called_Number:
			/* Save Called-Number L2TP attribute locally; the first
			 * one wins, as for the match rules */
				if (attr->attr->id == Called_Number &&
				    !seen_called) {
					seen_called = 1;
					m = attr->length;
					memcpy(called,attr->val.octets,m);
				}
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

	/* passing val.octets for any AVP type is safe, rules are limited to
	 * string AVPs */
	l2tp_switch_match_lock();
	sess->switch_target = l2tp_switch_match_attrs_locked(&pack->attrs);
	if (sess->switch_target) {
		if (l2tp_switch_starting_begin(sess) < 0) {
			/* a shutdown began after the check at the top */
			l2tp_switch_match_unlock();
			log_tunnel(log_warn, conn, "shutdown in progress,"
				   " disconnecting session\n");
			res = 3;
			err = 0;
			goto out_reject;
		}
		l2tp_stat_inc(&l2tp_stat.switch_matched);
		log_tunnel(log_info1, conn,
			   "call matches l2tp-switch target \"%s\"\n",
			   sess->switch_target->name);
	}
	l2tp_switch_match_unlock();

	/* Allocate memory for Calling-Number if exists, and put it to l2tp_sess_t structure */
	if (n > 0) {
		sess->calling_num = _malloc(n+1);
		if (sess->calling_num == NULL) {
			log_tunnel(log_warn, conn, "can't allocate memory for Calling Number attribute. Will use LAC IP instead\n");
		}else{
			memcpy(sess->calling_num, calling, n);
			sess->calling_num[n] = '\0';
			sess->calling_num_len = n;
		}
	}

	/* Allocate memory for Called-Number if exists, and put it to l2tp_sess_t structure */
	if (m > 1) {
		sess->called_num = _malloc(m+1);
		if (sess->called_num == NULL) {
			log_tunnel(log_warn, conn, "can't allocate memory for Called Number attribute. Will use my IP instead\n");
		} else {
			memcpy(sess->called_num, called, m);
			sess->called_num[m] = '\0';
			sess->called_num_len = m;
		}
	}

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

	log_tunnel(log_info1, conn, "new session %hu-%hu with calling num %s len %d, called num %s len %d created following"
		   " reception of ICRQ\n", sid, peer_sid, sess->calling_num, sess->calling_num_len, sess->called_num, sess->called_num_len);

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

struct l2tp_switch_link_t {
	struct triton_md_handler_t hnd;
	struct l2tp_sess_t *src;
	struct l2tp_sess_t *dst;
	int pipe_rd, pipe_wr;
	uint64_t bytes;

	/* retry_timer lives on src->paren_conn->ctx, armed and deleted only
	 * there; reads from src stop while write_pending is set;
	 * pipe_pending is what is left in pipe_rd */
	struct triton_timer_t retry_timer;
	unsigned int write_pending:1;
	/* set and cleared on src->paren_conn->ctx: the read handler is off
	 * until l2tp_switch_link_resume() has run there */
	unsigned int yielded:1;
	ssize_t pipe_pending;
	int eagain_waits;
	int enomem_retries;

	/* a frame bigger than a page, read out of the pipe and not yet
	 * written; see l2tp_switch_link_write_frame() */
	uint8_t *frame_buf;
	ssize_t frame_len;

	struct l2tp_switch_target_t *target;
	int from_upstream;

	struct l2tp_sess_t *downstream_sess;
	unsigned int logged_conf_req:1;
	int peek_pipe_rd, peek_pipe_wr;
};

#define L2TP_SWITCH_SPLICE_LEN (1 << 16)
#define L2TP_SWITCH_READ_BUDGET 128
#define L2TP_SWITCH_EAGAIN_POLL_MS 100
#define L2TP_SWITCH_EAGAIN_MAX_WAITS 50

static void l2tp_switch_link_fail(struct l2tp_switch_link_t *link);
static void l2tp_switch_link_peer_gone(struct l2tp_switch_link_t *link);
static void l2tp_switch_link_retry_timer(struct triton_timer_t *t);
static int l2tp_switch_link_read(struct triton_md_handler_t *h);

/* local copy of the ppp_lcp.h definitions, which would pull in the ppp
 * layer */
struct l2tp_switch_lcp_hdr {
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

#define L2TP_SWITCH_PPP_LCP 0xc021
#define L2TP_SWITCH_PPP_PAP 0xc023
#define L2TP_SWITCH_PPP_CHAP 0xc223
#define L2TP_SWITCH_LCP_CONFREQ 1
#define L2TP_SWITCH_LCP_TERMREQ 5
#define L2TP_SWITCH_LCP_PROTREJ 8
#define L2TP_SWITCH_LCP_OPT_AUTH 3

static int l2tp_switch_lcp_find_auth(const uint8_t *buf, size_t len,
				     uint16_t *proto, uint8_t *algo,
				     int *truncated)
{
	const struct l2tp_switch_lcp_hdr *lcp = (const struct l2tp_switch_lcp_hdr *)buf;
	size_t end = sizeof(lcp->proto) + ntohs(lcp->len);
	size_t o = sizeof(*lcp);

	*truncated = end > len;
	if (*truncated)
		end = len;

	while (o + 2 <= end) {
		size_t olen = buf[o + 1];

		if (olen < 2 || o + olen > end)
			break;
		if (buf[o] == L2TP_SWITCH_LCP_OPT_AUTH && olen >= 4) {
			*proto = (buf[o + 2] << 8) | buf[o + 3];
			*algo = olen > 4 ? buf[o + 4] : 0;
			return 1;
		}
		o += olen;
	}

	return 0;
}

/* only called for downstream-fed frames, on the link's context */
static void l2tp_switch_link_log_lcp_auth(struct l2tp_switch_link_t *link,
					  const uint8_t *buf, size_t len)
{
	const struct l2tp_switch_lcp_hdr *lcp = (const struct l2tp_switch_lcp_hdr *)buf;
	uint16_t proto;
	uint8_t algo;
	int truncated;
	size_t end, o;

	if (link->from_upstream || len < sizeof(*lcp) ||
	    lcp->proto != htons(L2TP_SWITCH_PPP_LCP))
		return;

	if (lcp->code == L2TP_SWITCH_LCP_CONFREQ) {
		if (link->logged_conf_req)
			return;
		link->logged_conf_req = 1;
	} else if (lcp->code != L2TP_SWITCH_LCP_PROTREJ &&
		   lcp->code != L2TP_SWITCH_LCP_TERMREQ) {
		return;
	}

	end = sizeof(lcp->proto) + ntohs(lcp->len);
	o = sizeof(*lcp);
	if (end > len)
		end = len;

	switch (lcp->code) {
	case L2TP_SWITCH_LCP_CONFREQ:
		if (l2tp_switch_lcp_find_auth(buf, len, &proto, &algo, &truncated)) {
			if (proto == L2TP_SWITCH_PPP_PAP)
				log_session(log_info1, link->downstream_sess,
					    "l2tp-switch: downstream LCP"
					    " Configure-Request asks for PAP\n");
			else if (proto == L2TP_SWITCH_PPP_CHAP)
				log_session(log_info1, link->downstream_sess,
					    "l2tp-switch: downstream LCP"
					    " Configure-Request asks for CHAP"
					    " (algorithm 0x%02x)\n", algo);
			else
				log_session(log_info1, link->downstream_sess,
					    "l2tp-switch: downstream LCP"
					    " Configure-Request asks for"
					    " authentication protocol 0x%04x\n",
					    proto);
			break;
		}
		log_session(log_info1, link->downstream_sess,
			    "l2tp-switch: downstream LCP Configure-Request has"
			    " no authentication-protocol option%s\n",
			    truncated ? " in the bytes inspected" : "");
		break;
	case L2TP_SWITCH_LCP_PROTREJ:
		if (o + 2 <= end)
			log_session(log_warn, link->downstream_sess,
				    "l2tp-switch: downstream rejected PPP"
				    " protocol 0x%04x (LCP Protocol-Reject)\n",
				    (buf[o] << 8) | buf[o + 1]);
		break;
	case L2TP_SWITCH_LCP_TERMREQ:
		log_session(log_warn, link->downstream_sess,
			    "l2tp-switch: downstream sent an LCP"
			    " Terminate-Request\n");
		break;
	}
}

#define L2TP_SWITCH_ENOMEM_MAX_RETRIES 20

static void l2tp_switch_link_count_bytes(struct l2tp_switch_link_t *link, ssize_t n)
{
	__atomic_add_fetch(&link->bytes, n, __ATOMIC_RELAXED);
	if (link->from_upstream) {
		__atomic_add_fetch(&l2tp_stat.switch_lns_rx_bytes,
				   (uint64_t)n, __ATOMIC_RELAXED);
		__atomic_add_fetch(&link->target->tx_bytes,
				   (uint64_t)n, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&link->target->rx_bytes,
				   (uint64_t)n, __ATOMIC_RELAXED);
		__atomic_add_fetch(&l2tp_stat.switch_lns_tx_bytes,
				   (uint64_t)n, __ATOMIC_RELAXED);
	}
}

/* tee() does not consume the frame; must run before the splice that drains
 * pipe_rd */
static void l2tp_switch_link_peek(struct l2tp_switch_link_t *link, ssize_t n)
{
	uint8_t peek[64];
	ssize_t teed, got;

	if (link->from_upstream || n > 128)
		return;

	teed = tee(link->pipe_rd, link->peek_pipe_wr, sizeof(peek),
		   SPLICE_F_NONBLOCK);
	if (teed > 0) {
		got = read(link->peek_pipe_rd, peek, sizeof(peek));
		if (got > 0)
			l2tp_switch_link_log_lcp_auth(link, peek, (size_t)got);
	}
}

/* Before Linux 6.5, splice() into a datagram socket sends one datagram per
 * page, which cuts a frame bigger than a page into several. Such a frame goes
 * out with write() instead, from a buffer kept across retries since write()
 * has taken it out of the pipe. Returns n once all of it is written, -1
 * (frame kept) if the write failed. */
static ssize_t l2tp_switch_link_write_frame(struct l2tp_switch_link_t *link,
					    ssize_t n, int dst_fd)
{
	ssize_t r;

	if (link->frame_len == 0) {
		if (!link->frame_buf) {
			link->frame_buf = _malloc(L2TP_SWITCH_SPLICE_LEN);
			if (!link->frame_buf) {
				errno = ENOMEM;
				return -1;
			}
		}
		r = read(link->pipe_rd, link->frame_buf, n);
		if (r <= 0) {
			if (r == 0)
				errno = EIO;
			return -1;
		}
		link->frame_len = r;
	}

	r = write(dst_fd, link->frame_buf, link->frame_len);
	if (r < 0)
		return -1;

	r = link->frame_len;
	link->frame_len = 0;

	return r;
}

/* the fd is read and used under dst->switch_fd_lock, as the destination
 * closes it on another context; *dst_fd is -1 if already closed */
static ssize_t l2tp_switch_link_splice_out(struct l2tp_switch_link_t *link,
					   ssize_t n, int *dst_fd)
{
	struct l2tp_sess_t *dst = link->dst;
	ssize_t w = -1;
	int err = EBADF;

	pthread_mutex_lock(&dst->switch_fd_lock);
	*dst_fd = __atomic_load_n(&dst->ppp.fd, __ATOMIC_RELAXED);
	if (*dst_fd >= 0) {
		if (link->frame_len > 0 || n > sysconf(_SC_PAGESIZE))
			w = l2tp_switch_link_write_frame(link, n, *dst_fd);
		else
			w = splice(link->pipe_rd, NULL, *dst_fd, NULL, n,
				   SPLICE_F_MOVE);
		err = errno;
	}
	pthread_mutex_unlock(&dst->switch_fd_lock);

	errno = err;
	return w;
}

/* link's own context only; returns -1, with the link untouched, if the timer
 * cannot be armed, since reads would then stay disabled for good */
static int l2tp_switch_link_arm_retry(struct l2tp_switch_link_t *link,
				      ssize_t n, int ms)
{
	int res;

	link->retry_timer.expire_tv.tv_sec = ms / 1000;
	link->retry_timer.expire_tv.tv_usec = (ms % 1000) * 1000;
	if (link->retry_timer.tpd)
		res = triton_timer_mod(&link->retry_timer, 0);
	else {
		link->retry_timer.expire = l2tp_switch_link_retry_timer;
		res = triton_timer_add(&link->src->paren_conn->ctx,
				       &link->retry_timer, 0);
	}
	if (res < 0) {
		log_session(log_error, link->src,
			    "l2tp-switch: arming the retry timer failed,"
			    " dropping call\n");
		return -1;
	}

	link->pipe_pending = n;
	link->write_pending = 1;
	triton_md_disable_handler(&link->hnd, MD_MODE_READ);

	return 0;
}

/* returns 0 when all reached dst, -1 after failing the link (already
 * freed), 1 if retry_timer is armed for the rest; pipe_rd must be left
 * alone then */
static int l2tp_switch_link_write_out(struct l2tp_switch_link_t *link, ssize_t n)
{
	while (n > 0) {
		/* dst's fd is set to -1 on the other tunnel's context; gone
		 * means peer closed */
		int dst_fd;
		ssize_t w = l2tp_switch_link_splice_out(link, n, &dst_fd);

		if (dst_fd < 0)
			goto peer_gone;

		if (w >= 0) {
			l2tp_switch_link_count_bytes(link, w);
			link->enomem_retries = 0;
			n -= w;
			continue;
		}

		if (errno == EINTR)
			continue;

		if (errno == EAGAIN) {
			if (++link->eagain_waits >= L2TP_SWITCH_EAGAIN_MAX_WAITS) {
				log_session(log_error, link->src,
					    "l2tp-switch: destination not"
					    " writable for %ims, dropping call\n",
					    L2TP_SWITCH_EAGAIN_POLL_MS *
					    L2TP_SWITCH_EAGAIN_MAX_WAITS);
				goto fail;
			}
			if (l2tp_switch_link_arm_retry(link, n,
						       L2TP_SWITCH_EAGAIN_POLL_MS) < 0)
				goto fail;
			return 1;
		}

		if ((errno == ENOMEM || errno == ENOBUFS) &&
		    link->enomem_retries < L2TP_SWITCH_ENOMEM_MAX_RETRIES) {
			link->enomem_retries++;
			if (l2tp_switch_link_arm_retry(link, n, 50) < 0)
				goto fail;
			return 1;
		}

		if (errno == EBADF &&
		    (__atomic_load_n(&link->dst->ppp.fd, __ATOMIC_RELAXED) < 0 ||
		     l2tp_sess_state(link->dst) == STATE_CLOSE))
			goto peer_gone;

		log_session(log_error, link->src,
			    "l2tp-switch: splice(out) failed: %s\n",
			    strerror(errno));
		goto fail;
	}

	return 0;

peer_gone:
	l2tp_switch_link_peer_gone(link);
	return -1;

fail:
	l2tp_switch_link_fail(link);
	return -1;
}

/* link's own context frees the link and deletes the timer, so link is valid
 * here */
static void l2tp_switch_link_retry_timer(struct triton_timer_t *t)
{
	struct l2tp_switch_link_t *link =
		container_of(t, typeof(*link), retry_timer);
	ssize_t n = link->pipe_pending;
	int res = l2tp_switch_link_write_out(link, n);

	if (res < 0)
		return;

	if (res == 1)
		return;

	triton_timer_del(&link->retry_timer);
	link->write_pending = 0;
	triton_md_enable_handler(&link->hnd, MD_MODE_READ);

	/* edge-triggered: data that arrived while draining is not signalled
	 * again */
	l2tp_switch_link_read(&link->hnd);
}

/* runs on src's tunnel context behind every call queued there before the
 * yield; the hold on src is the hop's, the link may be gone by now */
static void l2tp_switch_link_resume(void *data)
{
	struct l2tp_sess_t *src = data;
	struct l2tp_switch_link_t *link;

	pthread_mutex_lock(&l2tp_switch_pair_lock);
	link = src->switch_link;
	pthread_mutex_unlock(&l2tp_switch_pair_lock);

	/* a link is freed only on this context, so it stays valid here */
	if (link && link->yielded) {
		link->yielded = 0;
		/* adding the fd to epoll again reports the frames still
		 * queued on it */
		triton_md_enable_handler(&link->hnd, MD_MODE_READ);
	}

	session_put(src);
}

static void l2tp_switch_link_resume_cancel(void *data)
{
	session_put(data);
}

/* stops reading and queues the resume behind the calls already queued on
 * this context; the link is already freed if the hop cannot be queued */
static void l2tp_switch_link_yield(struct l2tp_switch_link_t *link)
{
	struct l2tp_sess_t *src = link->src;

	triton_md_disable_handler(&link->hnd, MD_MODE_READ);
	link->yielded = 1;

	session_hold(src);
	if (l2tp_switch_hop(src->paren_conn, l2tp_switch_link_resume,
			    l2tp_switch_link_resume_cancel, src) < 0) {
		session_put(src);
		log_session(log_error, src, "l2tp-switch: yielding the relay"
			    " failed, dropping call\n");
		l2tp_switch_link_fail(link);
	}
}

static int l2tp_switch_link_read(struct triton_md_handler_t *h)
{
	struct l2tp_switch_link_t *link = container_of(h, typeof(*link), hnd);
	ssize_t n;
	int budget = L2TP_SWITCH_READ_BUDGET;

	if (link->write_pending || link->yielded)
		return 0;

	while (1) {
		/* One busy call must not hold up the other work queued on
		 * this tunnel's context (placing and ending calls, shutdown):
		 * triton runs queued calls only when no read handler is
		 * pending, and a registered handler of a busy call is pending
		 * again after every slice. So after budget frames stop reading
		 * and queue the resume as a call, which runs behind every call
		 * queued so far: each of those waits for at most one slice.
		 * A timer would put a floor under the delay and a ceiling of
		 * budget frames per tick on the throughput of a call. */
		if (!budget--) {
			l2tp_switch_link_yield(link);
			return 0;
		}

		n = splice(link->src->ppp.fd, NULL, link->pipe_wr, NULL,
			  L2TP_SWITCH_SPLICE_LEN,
			  SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		if (n < 0) {
			if (errno == EAGAIN)
				return 0;
			if (errno == EINTR)
				continue;
			log_session(log_error, link->src,
				    "l2tp-switch: splice(in) failed: %s\n",
				    strerror(errno));
			l2tp_switch_link_fail(link);
			return 0;
		}
		/* an empty frame is consumed like any other; stopping here
		 * would leave the frames queued behind it unsignalled */
		if (n == 0)
			continue;

		l2tp_switch_link_peek(link, n);

		link->eagain_waits = 0;
		link->enomem_retries = 0;
		if (l2tp_switch_link_write_out(link, n) != 0)
			return 0;
	}
}

static void l2tp_switch_link_free(struct l2tp_switch_link_t *link)
{
	if (link->retry_timer.tpd)
		triton_timer_del(&link->retry_timer);

	/* CLI walk reads src->switch_link under the pair lock */
	pthread_mutex_lock(&l2tp_switch_pair_lock);
	link->src->switch_link = NULL;
	pthread_mutex_unlock(&l2tp_switch_pair_lock);

	/* count on from_upstream so target->active drops once per pair */
	if (link->from_upstream &&
	    __atomic_sub_fetch(&link->target->active, 1,
			       __ATOMIC_RELAXED) == 0) {
		/* may run on either session's context, so the target's
		 * tunnel is looked up under its lock */
		l2tp_switch_target_arm_idle_linger(link->target, NULL);
	}

	if (link->hnd.tpd) {
		/* reset ppp.fd under switch_fd_lock so the other leg's
		 * splice cannot hit a reused fd */
		triton_md_unregister_handler(&link->hnd, 0);
		pthread_mutex_lock(&link->src->switch_fd_lock);
		__atomic_store_n(&link->src->ppp.fd, -1, __ATOMIC_RELAXED);
		close(link->hnd.fd);
		pthread_mutex_unlock(&link->src->switch_fd_lock);
		link->hnd.fd = -1;
	}
	close(link->pipe_rd);
	close(link->pipe_wr);
	close(link->peek_pipe_rd);
	close(link->peek_pipe_wr);
	if (link->frame_buf)
		_free(link->frame_buf);
	_free(link);
}

/* Ends a switched leg from its own tunnel context. Unlike a regular session
 * it is exempt from the send-window check, so its ICRQ or ICCN can still be
 * queued behind a full window: sending them before the CDN would only open a
 * call on the peer that this CDN (which cannot name a session the peer never
 * assigned) leaves behind. Ns is assigned when a packet is sent, so dropping
 * the unsent ones leaves no gap. */
static void l2tp_switch_session_cancel(struct l2tp_sess_t *sess,
				       uint16_t res, uint16_t err)
{
	l2tp_session_clear_sendqueue(sess);
	l2tp_session_disconnect_push(sess, res, err);
}

/* CDN Result Codes of RFC 2661 4.4.2 */
#define L2TP_CDN_RES_MIN 1
#define L2TP_CDN_RES_MAX 11

/* The result code the leg that ended gave (a CDN it received, or the
 * administrative one of a shutdown), a general error if it gave none. It is
 * stored by gone's own context before l2tp_session_free(gone) starts, and
 * read on the other leg's context only after the hop that
 * l2tp_session_free(gone) queues has run, or after l2tp_switch_link_splice_out()
 * took gone->switch_fd_lock and saw the fd that l2tp_switch_link_free() reset
 * under it: either way ordered, without atomics. gone is kept alive by the
 * pair pointer of the leg that reads. */
static void l2tp_switch_cdn_of(const struct l2tp_sess_t *gone,
			       uint16_t *res, uint16_t *err)
{
	uint16_t r = gone ? gone->switch_cdn_res : 0;

	/* only the CDN Result Codes of RFC 2661 4.4.2 are relayed */
	if (r >= L2TP_CDN_RES_MIN && r <= L2TP_CDN_RES_MAX) {
		*res = r;
		*err = gone->switch_cdn_err;
	} else {
		*res = 2;
		*err = 6;
	}
}

/* runs on the context of the session in data; clears the pointers as the
 * peer's l2tp_session_free() hook would have */
static void l2tp_switch_teardown_peer(void *data)
{
	struct l2tp_sess_t *peer = data;
	struct l2tp_switch_unpaired u = l2tp_switch_unpair(peer, 0);

	if (u.link)
		l2tp_switch_link_free(u.link);
	l2tp_switch_avps_free(u.avps);

	if (l2tp_sess_state(peer) != STATE_CLOSE) {
		uint16_t res, err;

		/* u.peer is the leg that ended, still held by peer's pointer */
		l2tp_switch_cdn_of(u.peer, &res, &err);

		/* _push(): not called from l2tp_conn_read(), nothing else
		 * flushes the CDN */
		l2tp_switch_session_cancel(peer, res, err);
	}

	if (u.peer)
		session_put(u.peer);
	session_put(peer);
}

static void l2tp_switch_link_teardown(struct l2tp_switch_link_t *link,
				      uint16_t res, uint16_t err)
{
	struct l2tp_sess_t *src = link->src;

	l2tp_switch_link_free(link);
	if (l2tp_sess_state(src) != STATE_CLOSE)
		l2tp_switch_session_cancel(src, res, err);
}

static void l2tp_switch_link_fail(struct l2tp_switch_link_t *link)
{
	log_session(log_error, link->src, "l2tp-switch: splice failed,"
		    " disconnecting session\n");
	l2tp_switch_link_teardown(link, 2, 6);
}

/* dst is already closing, but src must come down too, with the reason dst
 * gave: the hop that l2tp_session_free(dst) queued finds src closed and
 * sends nothing. link->dst is kept alive by src's pair pointer, which is
 * released only by l2tp_session_free(src) after this. */
static void l2tp_switch_link_peer_gone(struct l2tp_switch_link_t *link)
{
	uint16_t res, err;

	log_session(log_info2, link->src, "l2tp-switch: the other leg of this"
		    " call is already closing, disconnecting session\n");
	l2tp_switch_cdn_of(link->dst, &res, &err);
	l2tp_switch_link_teardown(link, res, err);
}

static int l2tp_switch_link_create(struct l2tp_sess_t *src,
				   struct l2tp_sess_t *dst,
				   struct l2tp_switch_target_t *target,
				   int from_upstream)
{
	struct l2tp_switch_link_t *link;
	int pfd[2], peek_pfd[2];

	if (pipe2(pfd, O_CLOEXEC | O_NONBLOCK) < 0)
		return -1;

	if (pipe2(peek_pfd, O_CLOEXEC | O_NONBLOCK) < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}

	link = _malloc(sizeof(*link));
	if (!link) {
		close(pfd[0]);
		close(pfd[1]);
		close(peek_pfd[0]);
		close(peek_pfd[1]);
		return -1;
	}
	memset(link, 0, sizeof(*link));
	link->pipe_rd = pfd[0];
	link->pipe_wr = pfd[1];
	link->peek_pipe_rd = peek_pfd[0];
	link->peek_pipe_wr = peek_pfd[1];
	link->src = src;
	link->dst = dst;
	link->target = target;
	link->from_upstream = from_upstream;
	link->downstream_sess = from_upstream ? dst : src;
	/* no session_hold(): the holds from l2tp_switch_place_call() keep
	 * src and dst alive */

	/* counted here so the unsigned counter stays balanced if the second
	 * link fails */
	if (from_upstream) {
		__atomic_add_fetch(&target->active, 1, __ATOMIC_RELAXED);
		l2tp_switch_starting_end(src);
	}

	link->hnd.fd = src->ppp.fd;
	link->hnd.read = l2tp_switch_link_read;

	triton_md_register_handler(&src->paren_conn->ctx, &link->hnd);
	if (triton_md_enable_handler(&link->hnd, MD_MODE_READ) < 0) {
		if (from_upstream)
			__atomic_sub_fetch(&target->active, 1, __ATOMIC_RELAXED);
		triton_md_unregister_handler(&link->hnd, 0);
		close(pfd[0]);
		close(pfd[1]);
		close(peek_pfd[0]);
		close(peek_pfd[1]);
		_free(link);
		return -1;
	}

	pthread_mutex_lock(&l2tp_switch_pair_lock);
	src->switch_link = link;
	pthread_mutex_unlock(&l2tp_switch_pair_lock);
	return 0;
}

static unsigned int l2tp_switch_active_total(void)
{
	struct l2tp_switch_target_t *t;
	unsigned int total = 0;

	list_for_each_entry(t, &l2tp_switch_targets, entry)
		total += __atomic_load_n(&t->active, __ATOMIC_RELAXED);

	return total;
}

struct l2tp_switch_finish_ctx {
	struct l2tp_sess_t *upstream;
	struct l2tp_sess_t *downstream;
};

static void l2tp_switch_finish_cancel(void *data)
{
	struct l2tp_switch_finish_ctx *ctx = data;
	struct l2tp_sess_t *upstream = ctx->upstream;
	struct l2tp_sess_t *downstream = ctx->downstream;

	_free(ctx);
	session_put(downstream);
	session_put(upstream);
}

/* creates the downstream->upstream link, freed on this context; consumes
 * the two holds in ctx */
static void l2tp_switch_finish_downstream(void *data)
{
	struct l2tp_switch_finish_ctx *ctx = data;
	struct l2tp_sess_t *upstream = ctx->upstream;
	struct l2tp_sess_t *downstream = ctx->downstream;

	_free(ctx);

	if (l2tp_sess_state(upstream) == STATE_CLOSE ||
	    l2tp_sess_state(downstream) == STATE_CLOSE)
		goto out;

	if (l2tp_switch_link_create(downstream, upstream,
				    upstream->switch_target, 0) < 0) {
		log_session(log_error, downstream,
			    "l2tp-switch: creating downstream->upstream"
			    " splice link failed\n");
		goto err;
	}
	goto out;

err:
	l2tp_switch_session_cancel(downstream, 2, 6);
out:
	session_put(downstream);
	session_put(upstream);
}

/* creates the upstream->downstream link, then hands over to
 * l2tp_switch_finish_downstream(); the two holds travel with ctx */
static void l2tp_switch_finish_upstream(void *data)
{
	struct l2tp_switch_finish_ctx *ctx = data;
	struct l2tp_sess_t *upstream = ctx->upstream;
	struct l2tp_sess_t *downstream = ctx->downstream;
	int res = -1;

	/* both sessions come from ctx, the cascade may have cleared
	 * upstream->switch_downstream */
	if (l2tp_sess_state(upstream) == STATE_CLOSE ||
	    l2tp_sess_state(downstream) == STATE_CLOSE)
		goto put_holds;


	if (l2tp_switch_link_create(upstream, downstream,
				    upstream->switch_target, 1) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: creating upstream->downstream"
			    " splice link failed\n");
		goto err;
	}


	res = l2tp_switch_hop(downstream->paren_conn,
			      l2tp_switch_finish_downstream,
			      l2tp_switch_finish_cancel, ctx);
	if (res < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: downstream context gone before the"
			    " splice could be finished\n");
		goto err;
	}

	return;

err:
	l2tp_switch_session_cancel(upstream, 2, 6);
put_holds:
	_free(ctx);
	session_put(downstream);
	session_put(upstream);
}

static int l2tp_recv_ICRP(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (l2tp_sess_state(sess) != STATE_WAIT_ICRP) {
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

	if (sess->switch_upstream)
		l2tp_switch_inflight_end(sess->switch_upstream);

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

	if (sess->switch_upstream) {
		struct l2tp_sess_t *upstream = sess->switch_upstream;

		if (l2tp_session_connect_socket(sess, 0) < 0) {
			log_session(log_error, sess,
				    "l2tp-switch: connecting downstream"
				    " kernel socket failed\n");
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}

		l2tp_stat_inc(&l2tp_stat.switch_downstream_connected);

		/* heap ctx: downstream->switch_upstream may be cleared by a
		 * teardown meanwhile */
		struct l2tp_switch_finish_ctx *ctx = _malloc(sizeof(*ctx));

		if (!ctx) {
			log_session(log_error, sess,
				    "l2tp-switch: allocating finish-upstream"
				    " context failed\n");
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}
		ctx->upstream = upstream;
		ctx->downstream = sess;

		session_hold(upstream);
		session_hold(sess);
		int res = l2tp_switch_hop(upstream->paren_conn,
					  l2tp_switch_finish_upstream,
					  l2tp_switch_finish_cancel, ctx);

		if (res < 0) {
			_free(ctx);
			session_put(sess);
			session_put(upstream);
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}

		return 0;
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

static struct l2tp_switch_avps *l2tp_switch_avps_get(struct l2tp_sess_t *sess)
{
	if (!sess->switch_avps) {
		sess->switch_avps = _malloc(sizeof(*sess->switch_avps));
		if (!sess->switch_avps)
			return NULL;
		memset(sess->switch_avps, 0, sizeof(*sess->switch_avps));
	}

	return sess->switch_avps;
}

/* TX-Speed and Framing-Type describe the upstream line; the downstream ICCN
 * repeats them */
static int l2tp_switch_capture_link(struct l2tp_sess_t *sess,
				    const struct l2tp_attr_t *attr)
{
	struct l2tp_switch_avps *avps = l2tp_switch_avps_get(sess);

	if (!avps)
		return -1;

	if (attr->attr->id == TX_Speed) {
		avps->tx_speed = attr->val.uint32;
		avps->have_tx_speed = 1;
	} else {
		avps->framing = attr->val.uint32;
		avps->have_framing = 1;
	}

	return 0;
}

static int l2tp_switch_capture_avp(struct l2tp_sess_t *sess,
				   const struct l2tp_attr_t *attr)
{
	struct l2tp_switch_avp_t *slot;

	if (!l2tp_switch_avps_get(sess))
		return -1;

	if (sess->switch_avps->count >=
	    (int)(sizeof(sess->switch_avps->avp) /
		  sizeof(sess->switch_avps->avp[0])))
		return -1;

	slot = &sess->switch_avps->avp[sess->switch_avps->count];
	slot->id = attr->attr->id;
	slot->M = attr->M;

	/* int16 and int32 AVPs keep their value in the union, so val.octets
	 * is not valid for them */
	switch (attr->attr->type) {
	case ATTR_TYPE_INT16: {
		uint16_t val = htons(attr->val.uint16);

		slot->len = sizeof(val);
		slot->val = _malloc(slot->len);
		if (!slot->val)
			return -1;
		memcpy(slot->val, &val, slot->len);
		slot->is_int16 = 1;
		break;
	}
	case ATTR_TYPE_INT32: {
		uint32_t val = htonl(attr->val.uint32);

		slot->len = sizeof(val);
		slot->val = _malloc(slot->len);
		if (!slot->val)
			return -1;
		memcpy(slot->val, &val, slot->len);
		slot->is_int32 = 1;
		break;
	}
	case ATTR_TYPE_OCTETS:
	case ATTR_TYPE_STRING:
	default:
		slot->len = attr->length;
		slot->val = _malloc(slot->len ? slot->len : 1);
		if (!slot->val)
			return -1;
		memcpy(slot->val, attr->val.octets, slot->len);
		break;
	}

	sess->switch_avps->count++;

	/* Name/Challenge/Response are credentials (RFC 2661 4.4.5), log
	 * only the capture */
	log_session(log_debug, sess,
		    "l2tp-switch: captured AVP %s (id=%d, len=%d)"
		    " from upstream ICCN\n",
		    attr->attr->name, attr->attr->id, slot->len);
	if (attr->attr->id == Proxy_Authen_Type)
		log_session(log_debug, sess,
			    "l2tp-switch: upstream ICCN proxy authen type = %d\n",
			    attr->val.uint16);

	return 0;
}

static void l2tp_switch_disconnect_upstream(void *data)
{
	struct l2tp_sess_t *upstream = data;

	if (l2tp_sess_state(upstream) != STATE_CLOSE)
		l2tp_switch_session_cancel(upstream, 2, 6);

	session_put(upstream);
}

static void l2tp_switch_disconnect_upstream_cancel(void *data)
{
	session_put(data);
}

static void l2tp_switch_shutdown_call(void *data)
{
	struct l2tp_sess_t *upstream = data;

	/* 3: call disconnected for administrative reasons; the other leg is
	 * told the same */
	if (l2tp_sess_state(upstream) != STATE_CLOSE) {
		upstream->switch_cdn_res = 3;
		upstream->switch_cdn_err = 0;
		l2tp_switch_session_cancel(upstream, 3, 0);
	}

	session_put(upstream);
}

/* ends all matched calls; the other leg follows when the upstream one is
 * gone. Each call then leaves the list in l2tp_session_free(), the last one
 * completes the shutdown. */
static void l2tp_switch_shutdown_terminate(void)
{
	struct l2tp_sess_t *sess;

	pthread_mutex_lock(&l2tp_switch_calls_lock);
	list_for_each_entry(sess, &l2tp_switch_calls, switch_call_entry) {
		if (l2tp_sess_state(sess) == STATE_CLOSE)
			continue;
		/* the entry is dropped before the final put, so the session
		 * is alive; the hop owns this hold */
		session_hold(sess);
		if (l2tp_switch_hop(sess->paren_conn, l2tp_switch_shutdown_call,
				    l2tp_switch_disconnect_upstream_cancel,
				    sess) < 0)
			session_put(sess);
	}
	pthread_mutex_unlock(&l2tp_switch_calls_lock);
}

static struct ap_shutdown_hook l2tp_switch_shutdown_hook = {
	.busy = l2tp_switch_shutdown_busy,
	.terminate = l2tp_switch_shutdown_terminate,
};

/* consumes the caller's hold on upstream on every path */
static void l2tp_switch_disconnect_upstream_async(struct l2tp_sess_t *upstream)
{
	if (l2tp_switch_hop(upstream->paren_conn,
			    l2tp_switch_disconnect_upstream,
			    l2tp_switch_disconnect_upstream_cancel,
			    upstream) < 0)
		session_put(upstream);
}

/* runs on the tunnel's own context, where conn->state is stable */
static void l2tp_switch_abort_stalled_tunnel(void *data)
{
	struct l2tp_conn_t *conn = data;
	struct l2tp_switch_target_t *target = conn->switch_target;
	int reclaimed;

	if (conn->state != STATE_ESTB) {
		if (conn->state != STATE_CLOSE)
			l2tp_tunnel_disconnect_push(conn, 2, 0);
		goto out;
	}

	/* it established between the timeout's state check and this call
	 * (md handlers run before queued calls), so the drain placed
	 * nothing */
	pthread_mutex_lock(&target->lock);
	/* take the slot back only if still free, a newer attempt may own it */
	reclaimed = !target->tunnel || target->tunnel == conn;
	if (reclaimed)
		target->tunnel = conn;
	pthread_mutex_unlock(&target->lock);

	if (reclaimed) {
		log_tunnel(log_info1, conn, "l2tp-switch: target \"%s\":"
			   " tunnel established just as its connect budget"
			   " expired, keeping it\n", target->name);
		l2tp_switch_drain_pending_calls(conn);
	} else {
		log_tunnel(log_info1, conn, "l2tp-switch: target \"%s\":"
			   " tunnel established too late, a newer attempt"
			   " already owns the target, closing it\n",
			   target->name);
		l2tp_tunnel_disconnect_push(conn, 1, 0);
	}

out:
	tunnel_put(conn);
}

static void l2tp_switch_abort_stalled_tunnel_cancel(void *data)
{
	tunnel_put(data);
}

/* runs on the default context; may fire with nothing to do, as triton can
 * dispatch a timer after it was closed or replaced, so check the budget
 * flag and deadline */
static void l2tp_switch_on_demand_timeout(struct triton_timer_t *t)
{
	struct l2tp_switch_target_t *target =
		container_of(t, typeof(*target), connect_timeout_timer);
	LIST_HEAD(drained);
	struct l2tp_sess_t *sess;
	struct l2tp_conn_t *stalled = NULL;

	pthread_mutex_lock(&target->lock);

	if (!target->connect_budget_open) {
		/* connect succeeded first, retire the timer on its owning
		 * context */
		if (target->connect_timeout_timer.tpd)
			triton_timer_del(&target->connect_timeout_timer);
		pthread_mutex_unlock(&target->lock);
		return;
	}

	if (l2tp_switch_monotonic_ms() < target->connect_deadline) {
		pthread_mutex_unlock(&target->lock);
		return;
	}

	if (target->connect_timeout_timer.tpd)
		triton_timer_del(&target->connect_timeout_timer);
	if (target->reconnect_timer.tpd)
		triton_timer_del(&target->reconnect_timer);
	target->connect_budget_open = 0;
	list_splice_init(&target->pending_calls, &drained);
	target->pending_count = 0;
	if (target->tunnel && target->tunnel->state != STATE_ESTB) {
		stalled = target->tunnel;
		tunnel_hold(stalled);
		/* release the connect slot in the same locked step;
		 * conn->switch_target stays set so l2tp_tunnel_free()
		 * accounts for it, its identity check protects a newer
		 * attempt */
		target->tunnel = NULL;
	}
	pthread_mutex_unlock(&target->lock);

	if (list_empty(&drained) && !stalled)
		return;

	log_error("l2tp-switch: target \"%s\": on-demand connect timed out,"
		  " disconnecting queued call(s)\n", target->name);

	while (!list_empty(&drained)) {
		sess = list_first_entry(&drained, typeof(*sess),
					switch_pending_entry);
		list_del(&sess->switch_pending_entry);
		l2tp_switch_disconnect_upstream_async(sess);
	}

	if (stalled &&
	    l2tp_switch_hop(stalled, l2tp_switch_abort_stalled_tunnel,
			    l2tp_switch_abort_stalled_tunnel_cancel,
			    stalled) < 0)
		tunnel_put(stalled);
}

static void l2tp_switch_close_idle_tunnel(void *data)
{
	struct l2tp_conn_t *conn = data;

	/* sess_count belongs to this context, so this is the authoritative
	 * idleness test */
	if (conn->state != STATE_ESTB || conn->sess_count)
		goto out;

	log_tunnel(log_info1, conn, "l2tp-switch: target \"%s\" idle for %ds,"
		   " closing on-demand tunnel\n",
		   conn->switch_target ? conn->switch_target->name : "?",
		   l2tp_switch_conf_idle_linger_ms() / 1000);

	l2tp_tunnel_disconnect_push(conn, 1, 0);
	/* free the connect slot now: the tunnel lingers until the StopCCN is
	 * acked and a call arriving meanwhile would wait for it */
	l2tp_switch_target_detach(conn);

out:
	tunnel_put(conn);
}

static void l2tp_switch_close_idle_tunnel_cancel(void *data)
{
	tunnel_put(data);
}

/* runs on the default context, the only place that deletes idle_timer;
 * idle_deadline tells a stale dispatch from a real expiry */
static void l2tp_switch_target_idle_timer(struct triton_timer_t *t)
{
	struct l2tp_switch_target_t *target =
		container_of(t, typeof(*target), idle_timer);
	struct l2tp_conn_t *conn = NULL;
	int res = -1;

	pthread_mutex_lock(&target->lock);

	if (target->idle_deadline &&
	    l2tp_switch_monotonic_ms() < target->idle_deadline) {
		pthread_mutex_unlock(&target->lock);
		return;
	}

	if (target->idle_timer.tpd)
		triton_timer_del(&target->idle_timer);

	if (target->idle_deadline && target->tunnel &&
	    __atomic_load_n(&target->active, __ATOMIC_RELAXED) == 0) {
		conn = target->tunnel;
		tunnel_hold(conn);
	}
	target->idle_deadline = 0;

	pthread_mutex_unlock(&target->lock);

	if (!conn)
		return;

	/* the re-arm stays outside ctx_lock: l2tp_tunnel_free() takes
	 * target->lock then ctx_lock */
	res = l2tp_switch_hop(conn, l2tp_switch_close_idle_tunnel,
			      l2tp_switch_close_idle_tunnel_cancel, conn);

	if (res < 0) {
		l2tp_switch_target_arm_idle_linger(target, conn);
		tunnel_put(conn);
	}
}

/* consumes one session hold on upstream on every path; conn is passed in as
 * upstream->switch_target->tunnel may have changed */
static void l2tp_switch_place_call_on(struct l2tp_sess_t *upstream,
				      struct l2tp_conn_t *conn)
{
	struct l2tp_switch_target_t *target = upstream->switch_target;
	struct l2tp_sess_t *downstream;


	/* upstream may already be STATE_CLOSE, no teardown hook would run
	 * again for a new pairing; nor would l2tp_session_free() release the
	 * slot the caller took for it, so release it here */
	if (l2tp_sess_state(upstream) == STATE_CLOSE) {
		l2tp_switch_inflight_end(upstream);
		session_put(upstream);
		goto out_idle;
	}

	if (conn->state != STATE_ESTB) {
		/* conn closed after the call was queued on it, e.g. the idle
		 * linger's close ran first on conn's context: the call is
		 * still unplaced, so it waits for the target's next tunnel */
		if (l2tp_switch_requeue_call(upstream) == 0) {
			log_session(log_info1, upstream,
				    "l2tp-switch: target tunnel closed under"
				    " the call, waiting for a new one\n");
			return;
		}
		log_session(log_error, upstream,
			    "l2tp-switch: target tunnel not available,"
			    " disconnecting upstream call\n");
		goto err_no_pairing;
	}

	downstream = l2tp_tunnel_alloc_session(conn);
	if (!downstream) {
		log_session(log_error, upstream,
			    "l2tp-switch: downstream session allocation"
			    " failed\n");
		goto err_no_pairing;
	}

	if (upstream->calling_num) {
		downstream->calling_num = _malloc(upstream->calling_num_len + 1);
		if (downstream->calling_num) {
			memcpy(downstream->calling_num, upstream->calling_num,
			      upstream->calling_num_len + 1);
			downstream->calling_num_len = upstream->calling_num_len;
		}
	}
	if (upstream->called_num) {
		downstream->called_num = _malloc(upstream->called_num_len + 1);
		if (downstream->called_num) {
			memcpy(downstream->called_num, upstream->called_num,
			      upstream->called_num_len + 1);
			downstream->called_num_len = upstream->called_num_len;
		}
	}

	/* sequencing must match on both legs */
	downstream->send_seq = upstream->send_seq;
	downstream->recv_seq = upstream->recv_seq;

	/* liveness check is atomic with the cross-links under the pair lock */
	pthread_mutex_lock(&l2tp_switch_pair_lock);
	if (l2tp_sess_state(upstream) == STATE_CLOSE) {
		pthread_mutex_unlock(&l2tp_switch_pair_lock);
		l2tp_session_free(downstream);
		l2tp_switch_inflight_end(upstream);
		session_put(upstream);
		goto out_idle;
	}
	downstream->switch_upstream = upstream;
	downstream->switch_avps = upstream->switch_avps;
	upstream->switch_avps = NULL;
	upstream->switch_downstream = downstream;
	session_hold(downstream);
	session_hold(upstream);
	pthread_mutex_unlock(&l2tp_switch_pair_lock);

	if (l2tp_session_place_call(downstream) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: placing downstream call failed\n");
		l2tp_session_free(downstream);
		goto err_pairing_done;
	}

	/* l2tp_session_place_call() only queues the ICRQ, push it as
	 * l2tp_tunnel_create_session() does */
	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: transmitting downstream ICRQ"
			    " failed\n");
		l2tp_session_free(downstream);
		goto err_pairing_done;
	}

	l2tp_stat_inc(&l2tp_stat.switch_placed);
	session_put(upstream);
	return;

err_no_pairing:
	l2tp_switch_disconnect_upstream_async(upstream);
	goto out_idle;

err_pairing_done:
	session_put(upstream);
	/* fall through */

out_idle:
	/* the fast path zeroed the linger window; restart it if the call
	 * fails before a session exists */
	if (conn->state == STATE_ESTB && conn->sess_count == 0)
		l2tp_switch_target_arm_idle_linger(target, conn);
}

struct l2tp_switch_place_ctx {
	struct l2tp_sess_t *upstream;
	struct l2tp_conn_t *conn;
};

static void l2tp_switch_place_call(void *data)
{
	struct l2tp_switch_place_ctx *ctx = data;
	struct l2tp_sess_t *upstream = ctx->upstream;
	struct l2tp_conn_t *conn = ctx->conn;

	_free(ctx);
	l2tp_switch_place_call_on(upstream, conn);
	tunnel_put(conn);
}

static void l2tp_switch_place_call_cancel(void *data)
{
	struct l2tp_switch_place_ctx *ctx = data;
	struct l2tp_sess_t *upstream = ctx->upstream;
	struct l2tp_conn_t *conn = ctx->conn;

	_free(ctx);
	l2tp_switch_disconnect_upstream_async(upstream);
	tunnel_put(conn);
}

/* caller holds target->lock; returns -1 if the timer could not be armed */
static int l2tp_switch_open_connect_budget_locked(struct l2tp_switch_target_t *target)
{
	uint64_t now = l2tp_switch_monotonic_ms();
	int res;

	target->connect_timeout_timer.expire = l2tp_switch_on_demand_timeout;
	target->connect_timeout_timer.period =
		l2tp_switch_conf_connect_timeout_ms();

	if (target->connect_timeout_timer.tpd)
		res = triton_timer_mod(&target->connect_timeout_timer, 0);
	else
		res = triton_timer_add(NULL, &target->connect_timeout_timer, 0);

	if (res < 0) {
		log_error("l2tp-switch: target \"%s\": failed to arm on-demand"
			  " connect timeout\n", target->name);
		return -1;
	}

	target->connect_deadline = now + l2tp_switch_conf_connect_timeout_ms();
	target->connect_budget_open = 1;

	return 0;
}

/* counts a call placed on the target's tunnel until the downstream answers
 * with an ICRP, so a target that never answers cannot make send_queue grow
 * without bound. Caller holds target->lock for the limit to be exact; force
 * skips the limit (calls that waited on the pending queue are already
 * bounded by it). Idempotent per call. */
static int l2tp_switch_inflight_begin(struct l2tp_sess_t *upstream, int force)
{
	struct l2tp_switch_target_t *target = upstream->switch_target;

	if (__atomic_load_n(&upstream->switch_inflight, __ATOMIC_RELAXED))
		return 0;

	if (!force &&
	    __atomic_load_n(&target->inflight_count, __ATOMIC_RELAXED) >=
	    L2TP_SWITCH_INFLIGHT_MAX) {
		l2tp_stat_inc(&l2tp_stat.switch_refused);
		log_session(log_error, upstream, "l2tp-switch: target \"%s\""
			    " has %u calls awaiting an answer, disconnecting"
			    " upstream call\n", target->name,
			    L2TP_SWITCH_INFLIGHT_MAX);
		return -1;
	}

	__atomic_store_n(&upstream->switch_inflight, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&target->inflight_count, 1, __ATOMIC_RELAXED);

	return 0;
}

/* caller holds target->lock so a tunnel coming up cannot drain the queue
 * first; *need_connect is set if the caller must start the connect */
static int l2tp_switch_enqueue_call_locked(struct l2tp_sess_t *upstream,
					   struct l2tp_switch_target_t *target,
					   int *need_connect)
{
	*need_connect = 0;

	if (target->pending_count >= L2TP_SWITCH_PENDING_MAX) {
		log_session(log_error, upstream, "l2tp-switch: target \"%s\""
			    " pending-call queue full, disconnecting"
			    " upstream call\n", target->name);
		return -1;
	}

	if (!target->connect_budget_open) {
		if (l2tp_switch_open_connect_budget_locked(target) < 0)
			return -1;
		*need_connect = 1;
	}

	session_hold(upstream); /* released by the drain or the connect timeout */
	list_add_tail(&upstream->switch_pending_entry, &target->pending_calls);
	target->pending_count++;

	return 0;
}

/* consumes the caller's tunnel_hold() on conn; -1 if not scheduled */
static int l2tp_switch_place_via_tunnel(struct l2tp_sess_t *upstream,
					struct l2tp_switch_target_t *target,
					struct l2tp_conn_t *conn)
{
	struct l2tp_switch_place_ctx *place;
	int res = -1;

	place = _malloc(sizeof(*place));
	if (!place) {
		log_session(log_error, upstream, "l2tp-switch: placing"
			    " downstream call failed: out of memory\n");
		goto fail;
	}
	place->upstream = upstream;
	place->conn = conn;

	session_hold(upstream);
	res = l2tp_switch_hop(conn, l2tp_switch_place_call,
			      l2tp_switch_place_call_cancel, place);
	if (res < 0) {
		session_put(upstream);
		_free(place);
		goto fail;
	}

	return 0;

fail:
	l2tp_switch_target_arm_idle_linger(target, conn);
	tunnel_put(conn);
	return -1;
}

static int l2tp_switch_place_downstream_call(struct l2tp_sess_t *upstream)
{
	struct l2tp_switch_target_t *target = upstream->switch_target;
	struct l2tp_conn_t *conn;
	int need_connect;
	int queued;

	pthread_mutex_lock(&target->lock);
	conn = target->tunnel;
	if (conn && conn->state == STATE_ESTB) {
		if (l2tp_switch_inflight_begin(upstream, 0) < 0) {
			pthread_mutex_unlock(&target->lock);
			return -1;
		}
		target->idle_deadline = 0;
		tunnel_hold(conn);
		pthread_mutex_unlock(&target->lock);

		return l2tp_switch_place_via_tunnel(upstream, target, conn);
	}

	if (target->mode == L2TP_SWITCH_MODE_PERSISTENT) {
		pthread_mutex_unlock(&target->lock);
		return -1;
	}

	queued = l2tp_switch_enqueue_call_locked(upstream, target, &need_connect);
	pthread_mutex_unlock(&target->lock);

	if (queued < 0)
		return -1;

	if (need_connect)
		l2tp_switch_target_connect(target); /* safe from any context */

	return 0;
}

/* gives an unplaced call back to its on-demand target: it takes a tunnel that
 * is up now or waits on the pending queue (pending limit and connect timeout
 * apply), so a tunnel that keeps closing cannot spin it. Returns 0 after
 * releasing the caller's session hold; -1 with the hold kept if the call is
 * to be disconnected (persistent target, queue full, ...) */
static int l2tp_switch_requeue_call(struct l2tp_sess_t *upstream)
{
	l2tp_switch_inflight_end(upstream);

	if (l2tp_switch_target_is_persistent(upstream->switch_target))
		return -1;

	if (l2tp_switch_place_downstream_call(upstream) < 0)
		return -1;

	/* the pending queue or the placement hop holds its own */
	session_put(upstream);

	return 0;
}

static int l2tp_recv_ICCN(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (l2tp_sess_state(sess) != STATE_WAIT_ICCN) {
		log_session(log_warn, sess, "discarding unexpected ICCN\n");
		return 0;
	}

	log_session(log_info2, sess, "handling ICCN\n");

	/* some AVPs worth routing on (Proxy-Authen-Name) only appear in ICCN */
	l2tp_switch_match_lock();
	if (!sess->switch_target) {
		sess->switch_target = l2tp_switch_match_attrs_locked(&pack->attrs);
		if (sess->switch_target) {
			/* refused when a shutdown is pending, the walk may
			 * have passed already */
			if (l2tp_switch_starting_begin(sess) < 0) {
				log_session(log_warn, sess,
					    "shutdown in progress,"
					    " disconnecting session\n");
				l2tp_switch_match_unlock();
				l2tp_session_disconnect_push(sess, 3, 0);
				return -1;
			}
			l2tp_stat_inc(&l2tp_stat.switch_matched);
			log_session(log_info1, sess,
				    "call matches l2tp-switch target \"%s\"\n",
				    sess->switch_target->name);
		}
	}
	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Random_Vector:
			break;
		case TX_Speed:
		case Framing_Type:
			if (sess->switch_target &&
			    l2tp_switch_capture_link(sess, attr) < 0) {
				log_session(log_error, sess,
					    "impossible to handle ICCN:"
					    " capturing speed failed\n");
				l2tp_switch_match_unlock();
				l2tp_session_disconnect(sess, 2, 6);
				return -1;
			}
			break;
		case Init_Recv_LCP:
		case Last_Sent_LCP:
		case Last_Recv_LCP:
		case Proxy_Authen_Type:
		case Proxy_Authen_Name:
		case Proxy_Authen_Challenge:
		case Proxy_Authen_ID:
		case Proxy_Authen_Response:
		/* the optional ones: repeated to the downstream LNS as they
		 * are, a new one is a case label here */
		case Private_Group_ID:
		case RX_Speed:
			/* the match above already looked at every AVP of this
			 * ICCN, so only a call that is going to be switched
			 * needs them (they include the cleartext PAP
			 * password) */
			if (!sess->switch_target)
				break;
			if (l2tp_switch_capture_avp(sess, attr) < 0) {
				log_session(log_error, sess,
					    "impossible to handle ICCN:"
					    " capturing proxy AVP failed\n");
				l2tp_switch_match_unlock();
				l2tp_session_disconnect(sess, 2, 6);
				return -1;
			}
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
	l2tp_switch_match_unlock();

	if (unknown_attr) {
		log_session(log_error, sess, "impossible to handle ICCN:"
			    " unknown mandatory attribute type %i,"
			    " disconnecting session\n",
			    unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);

		return -1;
	}

	if (sess->switch_target) {
		/* a call matched at the ICRQ may have waited for this ICCN
		 * through the start of a soft shutdown, which does not walk
		 * the calls; do not start a new downstream leg */
		if (ap_shutdown) {
			log_session(log_warn, sess, "shutdown in progress,"
				    " disconnecting session\n");
			l2tp_session_disconnect_push(sess, 3, 0);
			return -1;
		}

		/* connect the kernel socket now so peer data frames are
		 * queued during the downstream handshake */
		if (l2tp_session_connect_socket(sess, 0) < 0) {
			log_session(log_error, sess,
				    "impossible to switch call:"
				    " connecting upstream kernel socket"
				    " failed, disconnecting session\n");
			l2tp_session_disconnect(sess, 2, 6);

			return -1;
		}

		if (l2tp_switch_place_downstream_call(sess) < 0) {
			log_session(log_error, sess,
				    "impossible to switch call:"
				    " placing downstream call failed,"
				    " disconnecting session\n");
			l2tp_session_disconnect(sess, 2, 6);

			return -1;
		}

		return 0;
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

	if (l2tp_reject_on_target_tunnel(conn, pack, "OCRQ"))
		return 0;

	if (conn->state != STATE_ESTB && !conn->lns_mode) {
		log_tunnel(log_warn, conn, "discarding unexpected OCRQ\n");
		return 0;
	}

	if (ap_shutdown) {
		log_tunnel(log_warn, conn, "shutdown in progress,"
			   " discarding OCRQ\n");
		return 0;
	}

	if (conf_max_starting && l2tp_starting_in_use() >= conf_max_starting)
		return 0;

	if (conf_max_sessions && l2tp_sessions_in_use() >= conf_max_sessions)
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

	if (l2tp_sess_state(sess) != STATE_WAIT_OCRP) {
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

	l2tp_sess_set_state(sess, STATE_WAIT_OCCN);

	return 0;
}

static int l2tp_recv_OCCN(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (l2tp_sess_state(sess) != STATE_WAIT_OCCN) {
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

	if (l2tp_sess_state(sess) == STATE_CLOSE) {
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
		} else {
			sess->switch_cdn_res = res;
			sess->switch_cdn_err = err;
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
	if (l2tp_sess_state(sess) != STATE_ESTB || !sess->paren_conn->lns_mode) {
		log_session(log_warn, sess, "discarding unexpected WEN\n");

		return 0;
	}

	log_session(log_info2, sess, "handling WEN\n");

	return 0;
}

static int l2tp_recv_SLI(struct l2tp_sess_t *sess,
			 const struct l2tp_packet_t *pack)
{
	if (l2tp_sess_state(sess) != STATE_ESTB || sess->paren_conn->lns_mode) {
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

	l2tp_sess_set_state(sess, sess->lns_mode ? STATE_WAIT_OCRP :
					     STATE_WAIT_ICRP);

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

in_addr_t l2tp_conf_get_bind_addr(void)
{
	const char *opt = conf_get_opt("l2tp", "bind");

	return opt ? inet_addr(opt) : htonl(INADDR_ANY);
}

/* conf_port is filled only after l2tp_switch_conf_load() has run */
uint16_t l2tp_conf_get_bind_port(void)
{
	const char *opt = conf_get_opt("l2tp", "port");

	return (opt && atoi(opt) > 0) ? atoi(opt) : L2TP_PORT;
}

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
	struct l2tp_stat_t stat;

	l2tp_stat_get(&stat);

	cli_send(client, "l2tp:\r\n");
	cli_send(client, "  tunnels:\r\n");
	cli_sendv(client, "    starting: %u\r\n", stat.conn_starting);
	cli_sendv(client, "    active: %u\r\n", stat.conn_active);
	cli_sendv(client, "    finishing: %u\r\n", stat.conn_finishing);

	cli_send(client, "  sessions (control channels):\r\n");
	cli_sendv(client, "    starting: %u\r\n", stat.sess_starting);
	cli_sendv(client, "    active: %u\r\n", stat.sess_active);
	cli_sendv(client, "    finishing: %u\r\n", stat.sess_finishing);

	cli_send(client, "  sessions (data channels):\r\n");
	cli_sendv(client, "    starting: %u\r\n", stat.data_starting);
	cli_sendv(client, "    active: %u\r\n", stat.data_active);
	cli_sendv(client, "    finishing: %u\r\n", stat.data_finishing);

	cli_send(client, "  l2tp-switch:\r\n");
	cli_sendv(client, "    active: %u\r\n", l2tp_switch_active_total());
	cli_sendv(client, "    lns_rx_bytes: %llu\r\n",
		 (unsigned long long)stat.switch_lns_rx_bytes);
	cli_sendv(client, "    lns_tx_bytes: %llu\r\n",
		 (unsigned long long)stat.switch_lns_tx_bytes);

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

/* The proxied PAP password and the other Proxy-Authen AVPs of an ICCN are
 * repeated to the downstream LNS; they are hidden only if hide-avps is on. At
 * startup the targets are not loaded yet when load_config() runs, so this is
 * also called after l2tp_switch_conf_load(). */
static void l2tp_switch_warn_cleartext_avps(void)
{
	if (conf_hide_avps || list_empty(&l2tp_switch_targets))
		return;

	log_warn("l2tp-switch: hide-avps is not set, proxied authentication"
		 " AVPs (including a PAP password) cross the downstream leg"
		 " unhidden; set hide-avps=1 in [l2tp]\n");
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

	opt = conf_get_opt("l2tp", "session-timeout");
		if (opt)
			conf_session_timeout = atoi(opt);
		else
			conf_session_timeout = 0;

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

	l2tp_switch_warn_cleartext_avps();
}

/* twalk_r() is a GNU extension, twalk() takes no closure */
static __thread FILE *switch_show_out;

static void switch_show_walk(const void *nodep, VISIT which, int depth)
{
	struct l2tp_sess_t *sess = *(struct l2tp_sess_t **)nodep;
	FILE *out = switch_show_out;
	struct l2tp_sess_t *up;
	unsigned long long bytes_in = 0, bytes_out = 0;
	char calling[64];
	uint16_t up_tid, up_peer_tid;

	if (which != postorder && which != leaf)
		return;

	/* the pair lock is held while reading the pairing,
	 * l2tp_switch_unpair() and l2tp_switch_link_free() take it before
	 * freeing */
	pthread_mutex_lock(&l2tp_switch_pair_lock);
	up = sess->switch_upstream;
	if (!up) {
		pthread_mutex_unlock(&l2tp_switch_pair_lock);
		return;
	}
	/* up may be set for a finished call until
	 * l2tp_switch_teardown_peer() runs; STATE_CLOSE is set under the
	 * pair lock */
	if (l2tp_sess_state(up) == STATE_CLOSE) {
		pthread_mutex_unlock(&l2tp_switch_pair_lock);
		return;
	}
	snprintf(calling, sizeof(calling), "%s",
		 up->calling_num ? up->calling_num : "?");
	/* peer-controlled: no control characters into the CLI */
	for (char *c = calling; *c; c++)
		if ((unsigned char)*c < 0x20 || *c == 0x7f)
			*c = '?';
	up_tid = up->paren_conn->tid;
	up_peer_tid = up->paren_conn->peer_tid;
	if (sess->switch_link)
		bytes_in = __atomic_load_n(&sess->switch_link->bytes,
					   __ATOMIC_RELAXED);
	if (up->switch_link)
		bytes_out = __atomic_load_n(&up->switch_link->bytes,
					    __ATOMIC_RELAXED);
	pthread_mutex_unlock(&l2tp_switch_pair_lock);

	fprintf(out, "    call: %s tunnel %hu-%hu / %hu-%hu"
		     " bytes_in=%llu bytes_out=%llu\r\n",
		calling, up_tid, up_peer_tid,
		sess->paren_conn->tid, sess->paren_conn->peer_tid,
		bytes_in, bytes_out);
}

/* runs on the CLI thread under conn->sessions_lock; hopping to the tunnel's
 * context would deadlock with a single worker thread */
static void switch_show_calls(struct l2tp_conn_t *conn, void *client)
{
	char *text = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&text, &len);

	if (!f)
		return;

	switch_show_out = f;
	pthread_mutex_lock(&conn->sessions_lock);
	twalk(conn->sessions, switch_show_walk);
	pthread_mutex_unlock(&conn->sessions_lock);
	fclose(f);

	if (len)
		cli_send(client, text);
	free(text);
}

static int l2tp_switch_show_exec(const char *cmd, char * const *fields,
				 int fields_cnt, void *client)
{
	struct l2tp_switch_target_t *t;
	char *rules;

	cli_send(client, "targets:\r\n");
	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		struct l2tp_conn_t *conn;
		const char *status;
		unsigned int active;
		char peer_addr[17];

		/* snapshot under the target's lock, it changes on every
		 * connect cycle */
		pthread_mutex_lock(&t->lock);
		conn = t->tunnel;
		if (conn)
			tunnel_hold(conn);
		pthread_mutex_unlock(&t->lock);

		active = __atomic_load_n(&t->active, __ATOMIC_RELAXED);
		u_inet_ntoa(t->peer_addr.sin_addr.s_addr, peer_addr);

		if (t->mode == L2TP_SWITCH_MODE_PERSISTENT) {
			status = (conn && conn->state == STATE_ESTB) ?
				"up" : "down";
		} else {
			/* idle: ESTB with no calls (lingering); connecting
			 * uses conn's state, connect_budget_open stays set
			 * across failed attempts */
			if (active > 0)
				status = "up";
			else if (conn && conn->state != STATE_ESTB)
				status = "connecting";
			else
				status = "idle";
		}

		cli_sendv(client, "  %s -> %s:%hu [%s] active=%u"
				   " bytes_in=%llu bytes_out=%llu\r\n",
			 t->name, peer_addr,
			 ntohs(t->peer_addr.sin_port),
			 status, active,
			 (unsigned long long)__atomic_load_n(&t->rx_bytes, __ATOMIC_RELAXED),
			 (unsigned long long)__atomic_load_n(&t->tx_bytes, __ATOMIC_RELAXED));
		if (conn) {
			switch_show_calls(conn, client);
			tunnel_put(conn);
		}
	}

	rules = l2tp_switch_rules_format();
	cli_send(client, "rules:\r\n");
	if (rules) {
		cli_send(client, rules);
		_free(rules);
	}

	cli_send(client, "calls:\r\n");
	cli_sendv(client, "  matched: %u\r\n",
		  __atomic_load_n(&l2tp_stat.switch_matched, __ATOMIC_RELAXED));
	cli_sendv(client, "  placed: %u\r\n",
		  __atomic_load_n(&l2tp_stat.switch_placed, __ATOMIC_RELAXED));
	cli_sendv(client, "  connected: %u\r\n",
		  __atomic_load_n(&l2tp_stat.switch_downstream_connected, __ATOMIC_RELAXED));
	cli_sendv(client, "  refused: %u\r\n",
		  __atomic_load_n(&l2tp_stat.switch_refused, __ATOMIC_RELAXED));
	cli_sendv(client, "  active: %u\r\n", l2tp_switch_active_total());

	return CLI_CMD_OK;
}

static void l2tp_switch_show_help(char * const *fields, int fields_cnt,
				  void *client)
{
	cli_send(client,
		 "l2tp switch show - show switch targets, rules and calls\r\n");
}

static void l2tp_switch_add_help(char * const *fields, int fields_cnt,
				 void *client)
{
	cli_send(client,
		 "l2tp switch add <attr> <exact|prefix> <value> <target>"
		 " - add a match rule until the next restart\r\n"
		 "\tattr: Calling-Number, Called-Number, Sub-Address or"
		 " Proxy-Authen-Name\r\n");
}

static void l2tp_switch_del_help(char * const *fields, int fields_cnt,
				 void *client)
{
	cli_send(client,
		 "l2tp switch del <attr> <exact|prefix> <value>"
		 " - remove a match rule\r\n");
}

static int l2tp_switch_add_exec(const char *cmd, char * const *fields,
				int fields_cnt, void *client)
{
	if (fields_cnt != 7) {
		cli_send(client, "usage: l2tp switch add <attr> <exact|prefix>"
				 " <value> <target>\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (l2tp_switch_rule_add(fields[3], fields[4],
				 (const uint8_t *)fields[5], strlen(fields[5]),
				 fields[6]) < 0) {
		cli_send(client, "failed: unknown target, unknown/non-string"
				 " attr, invalid mode, or an overlapping rule"
				 " already exists\r\n");
		return CLI_CMD_FAILED;
	}

	return CLI_CMD_OK;
}

static int l2tp_switch_del_exec(const char *cmd, char * const *fields,
				int fields_cnt, void *client)
{
	if (fields_cnt != 6) {
		cli_send(client, "usage: l2tp switch del <attr> <exact|prefix>"
				 " <value>\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (l2tp_switch_rule_del(fields[3], fields[4],
				 (const uint8_t *)fields[5],
				 strlen(fields[5])) < 0) {
		cli_send(client, "failed: no such rule\r\n");
		return CLI_CMD_FAILED;
	}

	return CLI_CMD_OK;
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

	if (l2tp_switch_conf_load() < 0) {
		log_emerg("l2tp-switch: configuration is invalid,"
			  " terminating\n");
		_exit(EXIT_FAILURE);
	}
	l2tp_switch_warn_cleartext_avps();
	l2tp_switch_targets_connect();

	start_udp_server();

	cli_register_simple_cmd2(&show_stat_exec, NULL, 2, "show", "stat");
	cli_register_simple_cmd2(l2tp_create_tunnel_exec,
				 l2tp_create_tunnel_help, 3,
				 "l2tp", "create", "tunnel");
	cli_register_simple_cmd2(l2tp_create_session_exec,
				 l2tp_create_session_help, 3,
				 "l2tp", "create", "session");
	ap_shutdown_hook_register(&l2tp_switch_shutdown_hook);

	cli_register_simple_cmd2(l2tp_switch_show_exec,
				 l2tp_switch_show_help, 3,
				 "l2tp", "switch", "show");
	cli_register_simple_cmd2(l2tp_switch_add_exec,
				 l2tp_switch_add_help, 3,
				 "l2tp", "switch", "add");
	cli_register_simple_cmd2(l2tp_switch_del_exec,
				 l2tp_switch_del_help, 3,
				 "l2tp", "switch", "del");

	if (triton_event_register_handler(EV_CONFIG_RELOAD,
					  (triton_event_func)load_config) < 0)
		log_warn("l2tp: registration of CONFIG_RELOAD event failed,"
			 " configuration reloading deactivated\n");
}

DEFINE_INIT(22, l2tp_init);
