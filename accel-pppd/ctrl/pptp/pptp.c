#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "if_pppox.h"

#include "events.h"
#include "list.h"
#include "pptp_prot.h"
#include "triton.h"
#include "log.h"
#include "ppp.h"
#include "mempool.h"
#include "iprange.h"
#include "utils.h"
#include "cli.h"

#include "connlimit.h"

#include "memdebug.h"

#define STATE_IDLE 0
#define STATE_ESTB 1
#define STATE_PPP  2
#define STATE_FIN  3
#define STATE_CLOSE 4

struct pptp_conn_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct triton_timer_t timeout_timer;
	struct triton_timer_t echo_timer;
	int call_id;
	int peer_call_id;
	int state;
	int echo_sent;

	uint8_t *in_buf;
	int in_size;
	uint8_t *out_buf;
	int out_size;
	int out_pos;

	struct ap_ctrl ctrl;
	struct ppp_t ppp;
};

static int conf_ppp_max_mtu = PPTP_MAX_MTU;
static int conf_timeout = 5;
static int conf_echo_interval = 0;
static int conf_echo_failure = 3;
static int conf_verbose = 0;
static int conf_mppe = MPPE_UNSET;
static const char *conf_ip_pool;
static const char *conf_ipv6_pool;
static const char *conf_dpv6_pool;
static const char *conf_ifname;

static mempool_t conn_pool;

static unsigned int stat_starting;
static unsigned int stat_active;

static int pptp_read(struct triton_md_handler_t *h);
static int pptp_write(struct triton_md_handler_t *h);
static void pptp_timeout(struct triton_timer_t *);
static void ppp_started(struct ap_session *);
static void ppp_finished(struct ap_session *);

static void pptp_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	if (arg) {
		struct ap_session *s = arg;
		net = s->net;
	} else
		net = def_net;
	log_switch(ctx, arg);
}

static void disconnect(struct pptp_conn_t *conn)
{
	log_ppp_debug("pptp: disconnect\n");

	triton_md_unregister_handler(&conn->hnd, 1);

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);

	if (conn->echo_timer.tpd)
		triton_timer_del(&conn->echo_timer);

	if (conn->state == STATE_PPP) {
		__sync_sub_and_fetch(&stat_active, 1);
		conn->state = STATE_CLOSE;
		ap_session_terminate(&conn->ppp.ses, TERM_LOST_CARRIER, 1);
	} else if (conn->state != STATE_CLOSE)
		__sync_sub_and_fetch(&stat_starting, 1);

	triton_event_fire(EV_CTRL_FINISHED, &conn->ppp.ses);

	log_ppp_info1("disconnected\n");

	triton_context_unregister(&conn->ctx);

	if (conn->ppp.ses.chan_name)
		_free(conn->ppp.ses.chan_name);

	_free(conn->in_buf);
	_free(conn->out_buf);
	_free(conn->ctrl.calling_station_id);
	_free(conn->ctrl.called_station_id);
	mempool_free(conn);
}

static int post_msg(struct pptp_conn_t *conn, void *buf, int size)
{
	int n;
	if (conn->out_size) {
		log_error("pptp: buffer is not empty\n");
		return -1;
	}

again:
	n=write(conn->hnd.fd, buf, size);
	if (n < 0) {
		if (errno == EINTR)
			goto again;
		else if (errno == EAGAIN)
			n = 0;
		else {
			if (errno != EPIPE) {
				if (conf_verbose)
					log_ppp_info2("pptp: write: %s\n", strerror(errno));
				return -1;
			}
		}
	}

	if ( n<size ) {
		memcpy(conn->out_buf, (uint8_t *)buf + n, size - n);
		triton_md_enable_handler(&conn->hnd, MD_MODE_WRITE);
	}

	return 0;
}

static int send_pptp_stop_ctrl_conn_rqst(struct pptp_conn_t *conn, int reason)
{
	struct pptp_stop_ctrl_conn msg = {
		.header = PPTP_HEADER_CTRL(PPTP_STOP_CTRL_CONN_RQST),
		.reason_result = hton8(reason),
	};

	if (conf_verbose)
		log_ppp_info2("send [PPTP Stop-Ctrl-Conn-Request <Reason %i>]\n", reason);

	return post_msg(conn, &msg, sizeof(msg));
}

static int send_pptp_stop_ctrl_conn_rply(struct pptp_conn_t *conn, int reason, int err_code)
{
	struct pptp_stop_ctrl_conn msg = {
		.header = PPTP_HEADER_CTRL(PPTP_STOP_CTRL_CONN_RPLY),
		.reason_result = hton8(reason),
		.error_code = hton8(err_code),
	};

	if (conf_verbose)
		log_ppp_info2("send [PPTP Stop-Ctrl-Conn-Reply <Result %i> <Error %i>]\n", msg.reason_result, msg.error_code);

	return post_msg(conn, &msg, sizeof(msg));
}
static int pptp_stop_ctrl_conn_rqst(struct pptp_conn_t *conn)
{
	struct pptp_stop_ctrl_conn *msg = (struct pptp_stop_ctrl_conn *)conn->in_buf;
	if (conf_verbose)
		log_ppp_info2("recv [PPTP Stop-Ctrl-Conn-Request <Reason %i>]\n", msg->reason_result);

	send_pptp_stop_ctrl_conn_rply(conn, PPTP_CONN_STOP_OK, 0);

	return -1;
}

static int pptp_stop_ctrl_conn_rply(struct pptp_conn_t *conn)
{
	struct pptp_stop_ctrl_conn *msg = (struct pptp_stop_ctrl_conn*)conn->in_buf;
	if (conf_verbose)
		log_ppp_info2("recv [PPTP Stop-Ctrl-Conn-Reply <Result %i> <Error %i>]\n", msg->reason_result, msg->error_code);
	return -1;
}

static int send_pptp_start_ctrl_conn_rply(struct pptp_conn_t *conn, int res_code, int err_code)
{
	struct pptp_start_ctrl_conn msg = {
		.header = PPTP_HEADER_CTRL(PPTP_START_CTRL_CONN_RPLY),
		.version = htons(PPTP_VERSION),
		.result_code = res_code,
		.error_code = err_code,
		.framing_cap = htonl(PPTP_FRAME_ANY),
		.bearer_cap = htonl(PPTP_BEARER_ANY),
		.max_channels = htons(1),
		.firmware_rev = htons(PPTP_FIRMWARE_VERSION),
	};

	memset(msg.hostname, 0, sizeof(msg.hostname));
	strcpy((char*)msg.hostname, PPTP_HOSTNAME);

	memset(msg.vendor, 0, sizeof(msg.vendor));
	strcpy((char*)msg.vendor, PPTP_VENDOR);

	if (conf_verbose)
		log_ppp_info2("send [PPTP Start-Ctrl-Conn-Reply <Version %i> <Result %i> <Error %i> <Framing %x> <Bearer %x> <Max-Chan %i>]\n", msg.version, msg.result_code, msg.error_code, ntohl(msg.framing_cap), ntohl(msg.bearer_cap), ntohs(msg.max_channels));

	return post_msg(conn, &msg, sizeof(msg));
}

static int pptp_start_ctrl_conn_rqst(struct pptp_conn_t *conn)
{
	struct pptp_start_ctrl_conn *msg = (struct pptp_start_ctrl_conn *)conn->in_buf;

	if (conf_verbose)
		log_ppp_info2("recv [PPTP Start-Ctrl-Conn-Request <Version %i> <Framing %x> <Bearer %x> <Max-Chan %i>]\n", msg->version, ntohl(msg->framing_cap), ntohl(msg->bearer_cap), ntohs(msg->max_channels));

	if (conn->state != STATE_IDLE) {
		log_ppp_warn("unexpected PPTP_START_CTRL_CONN_RQST\n");
		if (send_pptp_start_ctrl_conn_rply(conn, PPTP_CONN_RES_EXISTS, 0))
			return -1;
		return 0;
	}

	if (msg->version != htons(PPTP_VERSION)) {
		log_ppp_warn("PPTP version mismatch: expecting %x, received %" PRIu32 "\n", PPTP_VERSION, msg->version);
		if (send_pptp_start_ctrl_conn_rply(conn, PPTP_CONN_RES_PROTOCOL, 0))
			return -1;
		return 0;
	}
	/*if (!(ntohl(msg->framing_cap) & PPTP_FRAME_SYNC)) {
		log_ppp_warn("connection does not supports sync mode\n");
		if (send_pptp_start_ctrl_conn_rply(conn, PPTP_CONN_RES_GE, 0))
			return -1;
		return 0;
	}*/
	if (send_pptp_start_ctrl_conn_rply(conn, PPTP_CONN_RES_SUCCESS, 0))
		return -1;

	if (conn->timeout_timer.tpd)
		triton_timer_mod(&conn->timeout_timer, 0);

	conn->state = STATE_ESTB;

	return 0;
}

static int send_pptp_out_call_rply(struct pptp_conn_t *conn, struct pptp_out_call_rqst *rqst, int call_id, int res_code, int err_code)
{
	struct pptp_out_call_rply msg = {
		.header = PPTP_HEADER_CTRL(PPTP_OUT_CALL_RPLY),
		.call_id = htons(call_id),
		.call_id_peer = rqst->call_id,
		.result_code = res_code,
		.error_code = err_code,
		.cause_code = 0,
		.speed = rqst->bps_max,
		.recv_size = rqst->recv_size,
		.delay = 0,
		.channel = 0,
	};

	if (conf_verbose)
		log_ppp_info2("send [PPTP Outgoing-Call-Reply <Call-ID %x> <Peer-Call-ID %x> <Result %i> <Error %i> <Cause %i> <Speed %i> <Window-Size %i> <Delay %i> <Channel %x>]\n", ntohs(msg.call_id), ntohs(msg.call_id_peer), msg.result_code, msg.error_code, ntohs(msg.cause_code), ntohl(msg.speed), ntohs(msg.recv_size), ntohs(msg.delay), ntohl(msg.channel));

	return post_msg(conn, &msg, sizeof(msg));
}

static int pptp_out_call_rqst(struct pptp_conn_t *conn)
{
	struct pptp_out_call_rqst *msg = (struct pptp_out_call_rqst *)conn->in_buf;
	struct sockaddr_pppox src_addr, dst_addr;
  struct sockaddr_in addr;
	socklen_t addrlen;
	int pptp_sock;

	if (conf_verbose)
		log_ppp_info2("recv [PPTP Outgoing-Call-Request <Call-ID %x> <Call-Serial %x> <Min-BPS %i> <Max-BPS %i> <Bearer %x> <Framing %x> <Window-Size %i> <Delay %i>]\n", ntohs(msg->call_id), ntohs(msg->call_sernum), ntohl(msg->bps_min), ntohl(msg->bps_max), ntohl(msg->bearer), ntohl(msg->framing), ntohs(msg->recv_size), ntohs(msg->delay));

	if (conn->state != STATE_ESTB) {
		log_ppp_warn("unexpected PPTP_OUT_CALL_RQST\n");
		if (send_pptp_out_call_rply(conn, msg, 0, PPTP_CALL_RES_GE, PPTP_GE_NOCONN))
			return -1;
		return 0;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.sa_family = AF_PPPOX;
	src_addr.sa_protocol = PX_PROTO_PPTP;
	src_addr.sa_addr.pptp.call_id = 0;
	addrlen = sizeof(addr);
	getsockname(conn->hnd.fd, (struct sockaddr*)&addr, &addrlen);
	src_addr.sa_addr.pptp.sin_addr = addr.sin_addr;

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.sa_family = AF_PPPOX;
	dst_addr.sa_protocol = PX_PROTO_PPTP;
	dst_addr.sa_addr.pptp.call_id = htons(msg->call_id);
	addrlen = sizeof(addr);
	getpeername(conn->hnd.fd, (struct sockaddr*)&addr, &addrlen);
	dst_addr.sa_addr.pptp.sin_addr = addr.sin_addr;

	pptp_sock = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_PPTP);
	if (pptp_sock < 0) {
		log_ppp_error("failed to create PPTP socket (%s)\n", strerror(errno));
		return -1;
	}

	fcntl(pptp_sock, F_SETFD, fcntl(pptp_sock, F_GETFD) | FD_CLOEXEC);

	if (bind(pptp_sock, (struct sockaddr*)&src_addr, sizeof(src_addr))) {
		log_ppp_error("failed to bind PPTP socket (%s)\n", strerror(errno));
		close(pptp_sock);
		return -1;
	}
	addrlen = sizeof(src_addr);
	getsockname(pptp_sock, (struct sockaddr*)&src_addr, &addrlen);

	if (connect(pptp_sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr))) {
		log_ppp_error("failed to connect PPTP socket (%s)\n", strerror(errno));
		close(pptp_sock);
		return -1;
	}

	if (send_pptp_out_call_rply(conn, msg, src_addr.sa_addr.pptp.call_id, PPTP_CALL_RES_OK, 0))
		return -1;

	conn->call_id = src_addr.sa_addr.pptp.call_id;
	conn->peer_call_id = msg->call_id;
	conn->ppp.fd = pptp_sock;
	conn->ppp.ses.chan_name = _strdup(inet_ntoa(dst_addr.sa_addr.pptp.sin_addr));

	triton_event_fire(EV_CTRL_STARTED, &conn->ppp.ses);

	if (establish_ppp(&conn->ppp)) {
		close(pptp_sock);
		//if (send_pptp_stop_ctrl_conn_rqst(conn, 0, 0))
		conn->state = STATE_FIN;
		return -1;
	}
	conn->state = STATE_PPP;
	__sync_sub_and_fetch(&stat_starting, 1);
	__sync_add_and_fetch(&stat_active, 1);

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);

	if (conf_echo_interval) {
		conn->echo_timer.period = conf_echo_interval * 1000;
		triton_timer_add(&conn->ctx, &conn->echo_timer, 0);
	}

	return 0;
}

static int send_pptp_call_disconnect_notify(struct pptp_conn_t *conn, int result)
{
	struct pptp_call_clear_ntfy msg = {
		.header = PPTP_HEADER_CTRL(PPTP_CALL_CLEAR_NTFY),
		.call_id = htons(conn->peer_call_id),
		.result_code = result,
		.error_code = 0,
		.cause_code = 0,
	};

	if (conf_verbose)
		log_ppp_info2("send [PPTP Call-Disconnect-Notify <Call-ID %x> <Result %i> <Error %i> <Cause %i>]\n", ntohs(msg.call_id), msg.result_code, msg.error_code, msg.cause_code);

	return post_msg(conn, &msg, sizeof(msg));
}

static int pptp_call_clear_rqst(struct pptp_conn_t *conn)
{
	struct pptp_call_clear_rqst *rqst = (struct pptp_call_clear_rqst *)conn->in_buf;

	if (conf_verbose)
		log_ppp_info2("recv [PPTP Call-Clear-Request <Call-ID %x>]\n", ntohs(rqst->call_id));

	if (conn->echo_timer.tpd)
		triton_timer_del(&conn->echo_timer);

	if (conn->state == STATE_PPP) {
		__sync_sub_and_fetch(&stat_active, 1);
		conn->state = STATE_CLOSE;
		ap_session_terminate(&conn->ppp.ses, TERM_USER_REQUEST, 1);
	}

	return send_pptp_call_disconnect_notify(conn, 4);
}

static int pptp_echo_rqst(struct pptp_conn_t *conn)
{
	struct pptp_echo_rqst *in_msg = (struct pptp_echo_rqst *)conn->in_buf;
	struct pptp_echo_rply out_msg = {
		.header = PPTP_HEADER_CTRL(PPTP_ECHO_RPLY),
		.identifier = in_msg->identifier,
		.result_code = 1,
	};

	if (conf_verbose) {
		log_ppp_debug("recv [PPTP Echo-Request <Identifier %x>]\n", in_msg->identifier);
		log_ppp_debug("send [PPTP Echo-Reply <Identifier %x>]\n", out_msg.identifier);
	}

	if (conn->echo_timer.tpd)
		triton_timer_mod(&conn->echo_timer, 0);

	return post_msg(conn, &out_msg, sizeof(out_msg));
}

static int pptp_echo_rply(struct pptp_conn_t *conn)
{
	struct pptp_echo_rply *msg = (struct pptp_echo_rply *)conn->in_buf;

	if (conf_verbose)
		log_ppp_debug("recv [PPTP Echo-Reply <Identifier %x>]\n", msg->identifier);

	conn->echo_sent = 0;
	return 0;
}

static void pptp_send_echo(struct triton_timer_t *t)
{
	struct pptp_conn_t *conn = container_of(t, typeof(*conn), echo_timer);
	struct pptp_echo_rqst msg = {
		.header = PPTP_HEADER_CTRL(PPTP_ECHO_RQST),
	};

	if (++conn->echo_sent == conf_echo_failure) {
		log_ppp_warn("pptp: no echo reply\n");
		disconnect(conn);
		return;
	}

	msg.identifier = random();

	if (conf_verbose)
		log_ppp_debug("send [PPTP Echo-Request <Identifier %x>]\n", msg.identifier);

	if (post_msg(conn, &msg, sizeof(msg)))
		disconnect(conn);
}

static int process_packet(struct pptp_conn_t *conn)
{
	struct pptp_header *hdr = (struct pptp_header *)conn->in_buf;
	switch(ntohs(hdr->ctrl_type))
	{
		case PPTP_START_CTRL_CONN_RQST:
			return pptp_start_ctrl_conn_rqst(conn);
		case PPTP_STOP_CTRL_CONN_RQST:
			return pptp_stop_ctrl_conn_rqst(conn);
		case PPTP_STOP_CTRL_CONN_RPLY:
			return pptp_stop_ctrl_conn_rply(conn);
		case PPTP_OUT_CALL_RQST:
			return pptp_out_call_rqst(conn);
		case PPTP_ECHO_RQST:
			return pptp_echo_rqst(conn);
		case PPTP_ECHO_RPLY:
			return pptp_echo_rply(conn);
		case PPTP_CALL_CLEAR_RQST:
			return pptp_call_clear_rqst(conn);
		case PPTP_SET_LINK_INFO:
			if (conf_verbose)
				log_ppp_info2("recv [PPTP Set-Link-Info]\n");
			return 0;
		default:
			log_ppp_warn("recv [PPTP Unknown (%x)]\n", ntohs(hdr->ctrl_type));
	}
	return 0;
}

static int pptp_read(struct triton_md_handler_t *h)
{
	struct pptp_conn_t *conn=container_of(h,typeof(*conn),hnd);
	struct pptp_header *hdr=(struct pptp_header *)conn->in_buf;
	int n;

	while(1) {
		n = read(h->fd, conn->in_buf + conn->in_size, PPTP_CTRL_SIZE_MAX - conn->in_size);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return 0;
			log_ppp_error("pptp: read: %s\n",strerror(errno));
			goto drop;
		}
		if (n == 0) {
			if (conf_verbose)
				log_ppp_info2("pptp: disconnect by peer\n");
			goto drop;
		}
		conn->in_size += n;
		if (conn->in_size >= sizeof(*hdr)) {
			if (hdr->magic != htonl(PPTP_MAGIC)) {
				log_ppp_error("pptp: invalid magic\n");
				goto drop;
			}
			if (ntohs(hdr->length) >= PPTP_CTRL_SIZE_MAX) {
				log_ppp_error("pptp: message is too long\n");
				goto drop;
			}
			if (ntohs(hdr->length) > conn->in_size)
				continue;
			if (ntohs(hdr->length) <= conn->in_size) {
				if (ntohs(hdr->length) != PPTP_CTRL_SIZE(ntohs(hdr->ctrl_type))) {
					log_ppp_error("pptp: invalid message length\n");
					goto drop;
				}
				if (process_packet(conn))
					goto drop;
				conn->in_size -= ntohs(hdr->length);
				if (conn->in_size)
					memmove(conn->in_buf, conn->in_buf + ntohs(hdr->length), conn->in_size);
			}
		}
	}
drop:
	disconnect(conn);
	return 1;
}
static int pptp_write(struct triton_md_handler_t *h)
{
	struct pptp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	int n;

	while (1) {
		n = write(h->fd, conn->out_buf+conn->out_pos, conn->out_size-conn->out_pos);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				n = 0;
			else {
				if (errno != EPIPE) {
					if (conf_verbose)
						log_ppp_info2("pptp: post_msg: %s\n", strerror(errno));
				}
				disconnect(conn);
				return 1;
			}
		}

		conn->out_pos += n;
		if (conn->out_pos == conn->out_size) {
			conn->out_pos = 0;
			conn->out_size = 0;
			triton_md_disable_handler(h, MD_MODE_WRITE);
			return 0;
		}
	}
}
static void pptp_timeout(struct triton_timer_t *t)
{
	struct pptp_conn_t *conn = container_of(t, typeof(*conn), timeout_timer);
	disconnect(conn);
}
static void pptp_close(struct triton_context_t *ctx)
{
	struct pptp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);
	if (conn->state == STATE_PPP) {
		__sync_sub_and_fetch(&stat_active, 1);
		conn->state = STATE_CLOSE;
		ap_session_terminate(&conn->ppp.ses, TERM_ADMIN_RESET, 1);
		if (send_pptp_call_disconnect_notify(conn, 3)) {
			triton_context_call(&conn->ctx, (void (*)(void*))disconnect, conn);
			return;
		}
	} else {
		if (send_pptp_stop_ctrl_conn_rqst(conn, 0)) {
			triton_context_call(&conn->ctx, (void (*)(void*))disconnect, conn);
			return;
		}
	}

	if (conn->timeout_timer.tpd)
		triton_timer_mod(&conn->timeout_timer, 0);
	else
		triton_timer_add(ctx, &conn->timeout_timer, 0);
}
static void ppp_started(struct ap_session *ses)
{
	log_ppp_debug("pptp: ppp started\n");
}
static void ppp_finished(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct pptp_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	if (conn->state != STATE_CLOSE) {
		log_ppp_debug("pptp: ppp finished\n");
		conn->state = STATE_CLOSE;
		__sync_sub_and_fetch(&stat_active, 1);

		if (send_pptp_call_disconnect_notify(conn, 3))
			triton_context_call(&conn->ctx, (void (*)(void*))disconnect, conn);
		else if (send_pptp_stop_ctrl_conn_rqst(conn, 0))
			triton_context_call(&conn->ctx, (void (*)(void*))disconnect, conn);
		else {
			if (conn->timeout_timer.tpd)
				triton_timer_mod(&conn->timeout_timer, 0);
			else
				triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);
		}
	}
}

//==================================

struct pptp_serv_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
};

static int pptp_connect(struct triton_md_handler_t *h)
{
  struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int sock;
	struct pptp_conn_t *conn;

	while(1) {
		sock = accept(h->fd, (struct sockaddr *)&addr, &size);
		if (sock < 0) {
			if (errno == EAGAIN)
				return 0;
			log_error("pptp: accept failed: %s\n", strerror(errno));
			continue;
		}

		if (ap_shutdown) {
			close(sock);
			continue;
		}

		if (conf_max_starting && ap_session_stat.starting >= conf_max_starting) {
			close(sock);
			continue;
		}

		if (conf_max_sessions && ap_session_stat.active + ap_session_stat.starting >= conf_max_sessions) {
			close(sock);
			continue;
		}

		if (triton_module_loaded("connlimit") && connlimit_check(cl_key_from_ipv4(addr.sin_addr.s_addr))) {
			close(sock);
			continue;
		}

		log_info2("pptp: new connection from %s\n", inet_ntoa(addr.sin_addr));

		if (iprange_client_check(addr.sin_addr.s_addr)) {
			log_warn("pptp: IP is out of client-ip-range, droping connection...\n");
			close(sock);
			continue;
		}

		if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
			log_error("pptp: failed to set nonblocking mode: %s, closing connection...\n", strerror(errno));
			close(sock);
			continue;
		}

		conn = mempool_alloc(conn_pool);
		memset(conn, 0, sizeof(*conn));
		conn->hnd.fd = sock;
		conn->hnd.read = pptp_read;
		conn->hnd.write = pptp_write;
		conn->ctx.close = pptp_close;
		conn->ctx.before_switch = pptp_ctx_switch;
		conn->in_buf = _malloc(PPTP_CTRL_SIZE_MAX);
		conn->out_buf = _malloc(PPTP_CTRL_SIZE_MAX);
		conn->timeout_timer.expire = pptp_timeout;
		conn->timeout_timer.period = conf_timeout * 1000;
		conn->echo_timer.expire = pptp_send_echo;
		conn->ctrl.ctx = &conn->ctx;
		conn->ctrl.started = ppp_started;
		conn->ctrl.finished = ppp_finished;
		conn->ctrl.terminate = ppp_terminate;
		conn->ctrl.max_mtu = conf_ppp_max_mtu;
		conn->ctrl.type = CTRL_TYPE_PPTP;
		conn->ctrl.ppp = 1;
		conn->ctrl.name = "pptp";
		conn->ctrl.ifname = "";
		conn->ctrl.mppe = conf_mppe;

		conn->ctrl.calling_station_id = _malloc(17);
		conn->ctrl.called_station_id = _malloc(17);
		u_inet_ntoa(addr.sin_addr.s_addr, conn->ctrl.calling_station_id);
		getsockname(sock, &addr, &size);
		u_inet_ntoa(addr.sin_addr.s_addr, conn->ctrl.called_station_id);

		ppp_init(&conn->ppp);
		conn->ppp.ses.ctrl = &conn->ctrl;

		if (conf_ip_pool)
			conn->ppp.ses.ipv4_pool_name = _strdup(conf_ip_pool);
		if (conf_ipv6_pool)
			conn->ppp.ses.ipv6_pool_name = _strdup(conf_ipv6_pool);
		if (conf_dpv6_pool)
			conn->ppp.ses.dpv6_pool_name = _strdup(conf_dpv6_pool);
		if (conf_ifname)
			conn->ppp.ses.ifname_rename = _strdup(conf_ifname);

		triton_context_register(&conn->ctx, &conn->ppp.ses);
		triton_md_register_handler(&conn->ctx, &conn->hnd);
		triton_md_enable_handler(&conn->hnd,MD_MODE_READ);
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);
		triton_context_wakeup(&conn->ctx);

		triton_event_fire(EV_CTRL_STARTING, &conn->ppp.ses);

		__sync_add_and_fetch(&stat_starting, 1);
	}
	return 0;
}
static void pptp_serv_close(struct triton_context_t *ctx)
{
	struct pptp_serv_t *s=container_of(ctx,typeof(*s),ctx);
	triton_md_unregister_handler(&s->hnd, 1);
	triton_context_unregister(ctx);
}

static struct pptp_serv_t serv=
{
	.hnd.read = pptp_connect,
	.ctx.close = pptp_serv_close,
	.ctx.before_switch = pptp_ctx_switch,
};

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "pptp:\r\n");
	cli_sendv(client,"  starting: %u\r\n", stat_starting);
	cli_sendv(client,"  active: %u\r\n", stat_active);

	return CLI_CMD_OK;
}

void __export pptp_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static void load_config(void)
{
	char *opt;

	opt = conf_get_opt("pptp", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("pptp", "echo-interval");
	if (opt && atoi(opt) >= 0)
		conf_echo_interval = atoi(opt);

	opt = conf_get_opt("pptp", "echo-failure");
	if (opt && atoi(opt) >= 0)
		conf_echo_failure = atoi(opt);

	opt = conf_get_opt("pptp", "verbose");
	if (opt && atoi(opt) >= 0)
		conf_verbose = atoi(opt) > 0;

	opt = conf_get_opt("pptp", "ppp-max-mtu");
	if (opt && atoi(opt) > 0)
		conf_ppp_max_mtu = atoi(opt);
	else
		conf_ppp_max_mtu = PPTP_MAX_MTU;

	conf_mppe = MPPE_UNSET;
	opt = conf_get_opt("pptp", "mppe");
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

	conf_ip_pool = conf_get_opt("pptp", "ip-pool");
	conf_ipv6_pool = conf_get_opt("pptp", "ipv6-pool");
	conf_dpv6_pool = conf_get_opt("pptp", "ipv6-pool-delegate");
	conf_ifname = conf_get_opt("pptp", "ifname");

	switch (iprange_check_activation()) {
	case IPRANGE_DISABLED:
		log_warn("pptp: iprange module disabled, improper IP configuration of PPP interfaces may cause kernel soft lockup\n");
		break;
	case IPRANGE_NO_RANGE:
		log_warn("pptp: no IP address range defined in section [%s], incoming PPTP connections will be rejected\n",
			 IPRANGE_CONF_SECTION);
		break;
	default:
		/* Makes compiler happy */
		break;
	}
}

static void pptp_init(void)
{
	struct sockaddr_in addr;
	char *opt;
	int fd;

	fd = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_PPTP);
	if (fd >= 0)
		close(fd);
	else if (system("modprobe -q pptp"))
		log_warn("failed to load pptp kernel module\n");

	serv.hnd.fd = socket(PF_INET, SOCK_STREAM, 0);
	if (serv.hnd.fd < 0) {
		log_emerg("pptp: failed to create server socket: %s\n", strerror(errno));
		return;
	}

	fcntl(serv.hnd.fd, F_SETFD, fcntl(serv.hnd.fd, F_GETFD) | FD_CLOEXEC);

	addr.sin_family = AF_INET;

	opt = conf_get_opt("pptp", "bind");
	if (opt)
		addr.sin_addr.s_addr = inet_addr(opt);
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

	opt = conf_get_opt("pptp", "port");
	if (opt && atoi(opt) > 0)
		addr.sin_port = htons(atoi(opt));
	else
		addr.sin_port = htons(PPTP_PORT);

  setsockopt(serv.hnd.fd, SOL_SOCKET, SO_REUSEADDR, &serv.hnd.fd, 4);
  if (bind (serv.hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    log_emerg("pptp: failed to bind socket: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
  }

  if (listen (serv.hnd.fd, 100) < 0) {
    log_emerg("pptp: failed to listen socket: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
  }

	if (fcntl(serv.hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_emerg("pptp: failed to set nonblocking mode: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
	}

	conn_pool = mempool_create(sizeof(struct pptp_conn_t));

	load_config();

	triton_context_register(&serv.ctx, NULL);
	triton_md_register_handler(&serv.ctx, &serv.hnd);
	triton_md_enable_handler(&serv.hnd, MD_MODE_READ);
	triton_context_wakeup(&serv.ctx);

	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(20, pptp_init);
