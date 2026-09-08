/*
 * Standalone MK-simulator L2TP LAC peer for integration testing.
 *
 * Not part of the cmake build. Compile and run with:
 *   gcc -O1 -g -Wall -fno-strict-aliasing -D_GNU_SOURCE \
 *       -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -I accel-pppd/include -I accel-pppd/ctrl/l2tp \
 *       -o /tmp/l2tp_switch_peer_test \
 *       accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c \
 *       accel-pppd/ctrl/l2tp/packet.c -lcrypto
 *
 * Performs one scripted LAC exchange: SCCRQ -> SCCRP -> SCCCN, then
 * ICRQ -> ICRP -> ICCN, using real packet.c encode/decode. Exits 0 on
 * success. See packet_test.c in this directory for the sibling harness
 * that exercises packet.c's parser directly rather than over a socket,
 * and whose stub-dictionary approach this file copies (real dict.c is
 * not linked here either -- see the note above this listing).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_pppox.h>
#include <time.h>

#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "l2tp.h"
#include "l2tp_prot.h"
#include "attr_defs.h"
#include <openssl/md5.h>

/* Mirrors l2tp.c's static inline comp_chap_md5() (~line 286) -- tunnel-auth
 * Challenge Response is MD5(msg-ident-octet || secret || challenge), per
 * RFC 2661 section 5.1.1 / 4.3. Needed because every test fixture in this
 * plan sets [l2tp] secret=, which makes the real daemon send a mandatory
 * Challenge AVP in its SCCRP and reject a SCCCN that doesn't answer it. */
static void comp_chap_md5(uint8_t *md5, uint8_t ident,
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

/* packet.c needs a working dictionary (attr_alloc() and l2tp_recv()'s AVP
 * loop both call l2tp_dict_find_attr_by_id(), and every l2tp_packet_add_*
 * call fails outright without a match), a mempool implementation, a
 * u_randbuf() (used internally by l2tp_packet_alloc() for the Random-Vector
 * AVP every control message carries), and log_emerg/log_error/log_warn/
 * log_ppp_debug. None of the real implementations are usable standalone --
 * see the note above this listing for why dict.c is out; mempool_*, the
 * log_* functions, and u_randbuf() all live in accel-pppd's core/utils,
 * which pulls in the whole triton runtime. packet_test.c stubs all of
 * these itself for the exact same reason; copy that approach verbatim
 * rather than diverging into a second convention. */
int conf_verbose = 1;
int conf_avp_permissive = 0;

#define DEFINE_LOG_STUB(name)						\
void name(const char *fmt, ...)					\
{									\
	va_list ap;							\
	va_start(ap, fmt);						\
	fprintf(stderr, "l2tp_switch_peer_test: " #name ": ");		\
	vfprintf(stderr, fmt, ap);					\
	va_end(ap);							\
}
DEFINE_LOG_STUB(log_emerg)
DEFINE_LOG_STUB(log_error)
DEFINE_LOG_STUB(log_warn)
DEFINE_LOG_STUB(log_ppp_debug)

mempool_t *mempool_create(int size)
{
	int *pool = malloc(sizeof(int));

	*pool = size;

	return (mempool_t *)pool;
}

void *mempool_alloc(mempool_t *pool)
{
	return malloc(*(int *)pool);
}

void mempool_free(void *ptr)
{
	free(ptr);
}

void triton_register_init(int order, void (*func)(void))
{
	func();
}

int u_randbuf(void *buf, size_t buf_len, int *err)
{
	FILE *f = fopen("/dev/urandom", "rb");

	if (!f) {
		if (err)
			*err = errno;
		return -1;
	}
	if (fread(buf, 1, buf_len, f) != buf_len) {
		if (err)
			*err = errno;
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/* Stub dictionary -- see the note above. Types and M values copied
 * verbatim from dict/dictionary.rfc2661. */
static struct l2tp_dict_attr_t dict[] = {
	{ .name = "Message-Type",           .id = Message_Type,           .type = ATTR_TYPE_INT16,  .M = -1, .H =  0 },
	{ .name = "Result-Code",            .id = Result_Code,            .type = ATTR_TYPE_OCTETS, .M =  1, .H =  0 },
	{ .name = "Protocol-Version",       .id = Protocol_Version,       .type = ATTR_TYPE_INT16,  .M =  1, .H =  0 },
	{ .name = "Framing-Capabilities",   .id = Framing_Capabilities,   .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Bearer-Capabilities",    .id = Bearer_Capabilities,    .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Recv-Window-Size",       .id = Recv_Window_Size,       .type = ATTR_TYPE_INT16,  .M =  1, .H =  0 },
	{ .name = "Challenge",              .id = Challenge,              .type = ATTR_TYPE_OCTETS, .M =  1, .H = -1 },
	{ .name = "Challenge-Response",     .id = Challenge_Response,     .type = ATTR_TYPE_OCTETS, .M =  1, .H = -1 },
	{ .name = "Cause-Code",             .id = Cause_Code,             .type = ATTR_TYPE_OCTETS, .M =  1, .H = -1 },
	{ .name = "Host-Name",              .id = Host_Name,              .type = ATTR_TYPE_STRING, .M =  1, .H =  0 },
	{ .name = "Vendor-Name",            .id = Vendor_Name,            .type = ATTR_TYPE_STRING, .M =  0, .H =  0 },
	{ .name = "Assigned-Tunnel-ID",     .id = Assigned_Tunnel_ID,     .type = ATTR_TYPE_INT16,  .M =  1, .H = -1 },
	{ .name = "Assigned-Session-ID",    .id = Assigned_Session_ID,    .type = ATTR_TYPE_INT16,  .M =  1, .H = -1 },
	{ .name = "Call-Serial-Number",     .id = Call_Serial_Number,     .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Framing-Type",           .id = Framing_Type,           .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Called-Number",          .id = Called_Number,          .type = ATTR_TYPE_STRING, .M =  1, .H = -1 },
	{ .name = "Calling-Number",         .id = Calling_Number,         .type = ATTR_TYPE_STRING, .M =  1, .H = -1 },
	{ .name = "TX-Speed",               .id = TX_Speed,               .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Init-Recv-LCP",          .id = Init_Recv_LCP,          .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Last-Sent-LCP",          .id = Last_Sent_LCP,          .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Last-Recv-LCP",          .id = Last_Recv_LCP,          .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Type",      .id = Proxy_Authen_Type,      .type = ATTR_TYPE_INT16,  .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Name",      .id = Proxy_Authen_Name,      .type = ATTR_TYPE_STRING, .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Challenge", .id = Proxy_Authen_Challenge, .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-ID",        .id = Proxy_Authen_ID,        .type = ATTR_TYPE_INT16,  .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Response",  .id = Proxy_Authen_Response,  .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
};

struct l2tp_dict_attr_t *l2tp_dict_find_attr_by_id(int id)
{
	size_t indx;

	for (indx = 0; indx < sizeof(dict) / sizeof(dict[0]); ++indx)
		if (dict[indx].id == id)
			return &dict[indx];

	return NULL;
}

const struct l2tp_dict_value_t *l2tp_dict_find_value(const struct l2tp_dict_attr_t *attr,
						     l2tp_value_t val)
{
	return NULL;
}

static struct sockaddr_in peer_addr;
static const char *secret = "";
static const char *calling_number = "472913";
static const char *called_number;
static const char *proxy_username;
static const char *proxy_password;
static const char *data_pattern;
static int send_stopccn;
static int wait_cdn;
static const char *second_call_number;
static uint16_t local_tid = 0x1234;
static uint16_t local_sid = 0x5678;

static int die(const char *msg)
{
	log_error("%s\n", msg);
	return 1;
}

static int send_and_recv(int fd, struct l2tp_packet_t *pack,
			 struct l2tp_packet_t **reply)
{
	if (l2tp_packet_send(fd, pack) < 0)
		return -1;
	l2tp_packet_free(pack);

	for (;;) {
		if (l2tp_recv(fd, reply, NULL, (const char *)secret,
			     strlen(secret)) != 0)
			return -1;
		/* l2tp_recv() always sets *reply to a valid, non-NULL packet
		 * -- even a ZLB (zero-AVP ack), which just has an empty
		 * attrs list. A NULL check can never catch that; check
		 * attrs emptiness instead (see the bug note above this
		 * listing). */
		if (*reply == NULL)
			continue;
		if (list_empty(&(*reply)->attrs)) {
			l2tp_packet_free(*reply);
			*reply = NULL;
			continue;
		}
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int fd, opt;
	struct l2tp_packet_t *pack, *reply;
	uint16_t peer_tid, peer_sid;
	/* RFC 2661 5.8: every control message carries a monotonically
	 * increasing Ns and acks the peer's last-received Ns via Nr.
	 * l2tp_packet_alloc() zero-initializes both, so this harness must
	 * track and set them itself on every message beyond the first. */
	uint16_t my_ns = 0, peer_next_nr = 0;

	static struct option opts[] = {
		{"peer-addr", required_argument, 0, 'a'},
		{"peer-port", required_argument, 0, 'p'},
		{"secret", required_argument, 0, 's'},
		{"calling-number", required_argument, 0, 'c'},
		{"called-number", required_argument, 0, 'n'},
		{"proxy-username", required_argument, 0, 'u'},
		{"proxy-password", required_argument, 0, 'w'},
		{"data-pattern", required_argument, 0, 'd'},
		{"send-stopccn", no_argument, 0, 'x'},
		{"wait-cdn", no_argument, 0, 'W'},
		{"second-call", required_argument, 0, 'S'},
		{0, 0, 0, 0},
	};

	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = htons(1701);

	while ((opt = getopt_long(argc, argv, "a:p:s:c:n:u:w:d:xWS:", opts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			if (inet_aton(optarg, &peer_addr.sin_addr) == 0)
				return die("invalid --peer-addr");
			break;
		case 'p':
			peer_addr.sin_port = htons(atoi(optarg));
			break;
		case 's':
			secret = optarg;
			break;
		case 'c':
			calling_number = optarg;
			break;
		case 'n':
			called_number = optarg;
			break;
		case 'u':
			proxy_username = optarg;
			break;
		case 'w':
			proxy_password = optarg;
			break;
		case 'd':
			data_pattern = optarg;
			break;
		case 'x':
			send_stopccn = 1;
			break;
		case 'W':
			wait_cdn = 1;
			break;
		case 'S':
			second_call_number = optarg;
			break;
		default:
			return die("usage: --peer-addr A --peer-port P"
				   " --secret S [--calling-number C]"
				   " [--called-number N]"
				   " [--proxy-username U] [--proxy-password W]"
				   " [--data-pattern D] [--send-stopccn]"
				   " [--wait-cdn] [--second-call C]");
		}
	}

	/* connect()ed to the peer, exactly like the real daemon's own
	 * l2tp_tunnel_alloc() (l2tp.c ~1776) connect()s its per-tunnel UDP
	 * socket. This is required for the pppol2tp data channel: the
	 * kernel's pppol2tp/l2tp_core xmit path routes via the underlying
	 * UDP socket's connected peer (inet_sk(sk)->inet_daddr); leaving fd
	 * unconnected made data-channel write()/splice() report success
	 * while emitting zero wire packets, because the kernel had no
	 * destination to route to. l2tp_packet_send()'s sendto() with an
	 * explicit destination still works fine afterwards -- Linux does
	 * not return EISCONN for a connected SOCK_DGRAM socket used with
	 * sendto() (that restriction is for connection-mode/TCP sockets);
	 * the real daemon relies on exactly this same combination for
	 * every control message it sends. */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return die("socket() failed");
	if (connect(fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0)
		return die("connect(fd) failed");

	/* --- SCCRQ --- */
	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Request,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("SCCRQ alloc failed");
	l2tp_packet_add_int16(pack, Protocol_Version, L2TP_V2_PROTOCOL_VERSION, 1);
	l2tp_packet_add_int32(pack, Framing_Capabilities, 3, 1);
	l2tp_packet_add_string(pack, Host_Name, "mk-simulator", 1);
	l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, local_tid, 1);
	pack->hdr.tid = 0;
	pack->hdr.sid = 0;
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (send_and_recv(fd, pack, &reply) < 0)
		return die("SCCRQ/SCCRP exchange failed");
	my_ns++;
	peer_next_nr = ntohs(reply->hdr.Ns) + 1;

	/* RFC 2661 3.1: the header's Tunnel ID just echoes back the tunnel ID
	 * *we* assigned (local_tid) -- the peer's own tunnel ID, which we
	 * must use as the header tid on every subsequent message we send,
	 * comes from the Assigned-Tunnel-ID AVP in the SCCRP payload. */
	peer_tid = 0;

	/* Tunnel-auth Challenge (RFC 2661 5.1.1): present in SCCRP whenever
	 * the peer has a [l2tp] secret= configured, which every fixture in
	 * this plan does. */
	{
		struct l2tp_attr_t *attr;
		uint8_t *chall = NULL;
		int chall_len = 0;
		uint8_t challresp[MD5_DIGEST_LENGTH];

		list_for_each_entry(attr, &reply->attrs, entry) {
			if (attr->attr && attr->attr->id == Assigned_Tunnel_ID)
				peer_tid = (uint16_t)attr->val.int16;
			if (attr->attr && attr->attr->id == Challenge) {
				chall = attr->val.octets;
				chall_len = attr->length;
			}
		}

		if (peer_tid == 0) {
			l2tp_packet_free(reply);
			return die("SCCRP carried no Assigned-Tunnel-ID");
		}

		if (chall && strlen(secret) > 0)
			comp_chap_md5(challresp,
				     Message_Type_Start_Ctrl_Conn_Connected,
				     secret, strlen(secret), chall, chall_len);
		l2tp_packet_free(reply);

		/* --- SCCCN --- */
		pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Connected,
					 &peer_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("SCCCN alloc failed");
		pack->hdr.tid = htons(peer_tid);
		pack->hdr.sid = 0;
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (chall && strlen(secret) > 0) {
			if (l2tp_packet_add_octets(pack, Challenge_Response,
						   challresp,
						   MD5_DIGEST_LENGTH, 1) < 0)
				return die("SCCCN Challenge-Response add failed");
		}
		if (l2tp_packet_send(fd, pack) < 0)
			return die("SCCCN send failed");
		l2tp_packet_free(pack);
		my_ns++;
	}

	/* --- ICRQ --- */
	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Request,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("ICRQ alloc failed");
	l2tp_packet_add_int16(pack, Assigned_Session_ID, local_sid, 1);
	l2tp_packet_add_int32(pack, Call_Serial_Number, 1, 1);
	l2tp_packet_add_string(pack, Calling_Number, calling_number, 1);
	if (called_number)
		l2tp_packet_add_string(pack, Called_Number, called_number, 1);
	pack->hdr.tid = htons(peer_tid);
	pack->hdr.sid = 0;
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (send_and_recv(fd, pack, &reply) < 0)
		return die("ICRQ/ICRP exchange failed");
	my_ns++;
	peer_next_nr = ntohs(reply->hdr.Ns) + 1;

	{
		struct l2tp_attr_t *a;
		peer_sid = 0;
		list_for_each_entry(a, &reply->attrs, entry)
			if (a->attr && a->attr->id == Assigned_Session_ID)
				peer_sid = a->val.uint16;
	}
	l2tp_packet_free(reply);

	if (!peer_sid)
		return die("ICRP carried no Assigned-Session-ID");

	/* --- ICCN --- */
	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("ICCN alloc failed");
	l2tp_packet_add_int32(pack, TX_Speed, 1000, 1);
	l2tp_packet_add_int32(pack, Framing_Type, 3, 1);
	if (proxy_username) {
		/* Proxy-Authen-Type is int16 per dict/dictionary.rfc2661 (id 29),
		 * not an octet string -- 2 = PPP_PAP is sufficient here since this
		 * harness only needs to prove the AVP survives the switch intact,
		 * not exercise real PAP semantics. */
		l2tp_packet_add_int16(pack, Proxy_Authen_Type, 2, 1);
		l2tp_packet_add_string(pack, Proxy_Authen_Name, proxy_username, 1);
		if (proxy_password)
			l2tp_packet_add_string(pack, Proxy_Authen_Response,
					       proxy_password, 1);
	}
	pack->hdr.tid = htons(peer_tid);
	pack->hdr.sid = htons(peer_sid);
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (l2tp_packet_send(fd, pack) < 0)
		return die("ICCN send failed");
	l2tp_packet_free(pack);
	my_ns++;

	if (data_pattern) {
		struct sockaddr_pppol2tp pppox_addr;
		int data_fd, reg_fd, lns_mode = 0;

		/* Sending our own ICCN only completes *our* (MK's) side of the
		 * handshake -- on a real switch, ICCN triggers placing the
		 * downstream call asynchronously (its own ICRQ/ICRP/ICCN round
		 * trip), and only once *that* finishes does the switch open
		 * its own kernel socket for this (upstream) session and the
		 * splice actually starts moving bytes. Writing immediately
		 * races that: this local connect() below still succeeds
		 * regardless (it only sets up local kernel state for
		 * encapsulating outgoing packets, independent of whether the
		 * peer has a matching session yet), but the switch's kernel
		 * has nowhere to route the resulting packet until pairing
		 * finishes, so it is silently dropped -- confirmed on a real
		 * VM: the write "succeeds" but the byte pattern never reaches
		 * the downstream leg. A real PPP client papers over this via
		 * LCP's own retransmission; this harness has no such retry,
		 * so give the switch a moment instead. */
		usleep(300000);

		/* The real accel-ppp daemon registers each tunnel with the
		 * kernel's L2TP subsystem via a throwaway pppol2tp connect
		 * with session IDs left at 0 (l2tp_tunnel_connect(), l2tp.c
		 * ~2071) as soon as its own SCCRQ/SCCRP/SCCCN handshake
		 * completes -- confirmed on real hardware (Step 0 above) to
		 * be a hard prerequisite for any *session*-level pppol2tp
		 * connect() on that tunnel, which otherwise fails ENOENT.
		 * This harness plays the MK/LAC side of the upstream tunnel,
		 * so it must do the same registration itself before the real
		 * session-level connect below -- nothing else on this
		 * process's side ever does it, unlike the daemon, which
		 * always goes through l2tp_tunnel_connect() for every tunnel
		 * it establishes. */
		reg_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
		if (reg_fd < 0)
			return die("tunnel registration socket() failed");

		memset(&pppox_addr, 0, sizeof(pppox_addr));
		pppox_addr.sa_family = AF_PPPOX;
		pppox_addr.sa_protocol = PX_PROTO_OL2TP;
		pppox_addr.pppol2tp.fd = fd;
		pppox_addr.pppol2tp.addr = peer_addr;
		pppox_addr.pppol2tp.s_tunnel = local_tid;
		pppox_addr.pppol2tp.d_tunnel = peer_tid;
		/* s_session/d_session left at 0: this is the tunnel-level
		 * registration, not a real session. */

		if (connect(reg_fd, (struct sockaddr *)&pppox_addr,
			   sizeof(pppox_addr)) < 0)
			return die("tunnel registration connect() failed");
		close(reg_fd);

		data_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
		if (data_fd < 0)
			return die("data socket() failed");

		memset(&pppox_addr, 0, sizeof(pppox_addr));
		pppox_addr.sa_family = AF_PPPOX;
		pppox_addr.sa_protocol = PX_PROTO_OL2TP;
		pppox_addr.pppol2tp.fd = fd; /* share the control-channel UDP socket */
		pppox_addr.pppol2tp.addr = peer_addr;
		pppox_addr.pppol2tp.s_tunnel = local_tid;
		pppox_addr.pppol2tp.d_tunnel = peer_tid;
		pppox_addr.pppol2tp.s_session = local_sid;
		pppox_addr.pppol2tp.d_session = peer_sid;

		if (connect(data_fd, (struct sockaddr *)&pppox_addr,
			   sizeof(pppox_addr)) < 0)
			return die("data socket connect() failed");

		if (setsockopt(data_fd, SOL_PPPOL2TP, PPPOL2TP_SO_LNSMODE,
			      &lns_mode, sizeof(lns_mode)) < 0)
			return die("data socket setsockopt(LNSMODE) failed");

		{
			ssize_t n = write(data_fd, data_pattern, strlen(data_pattern));

			if (n < 0)
				return die("data socket write() failed");
		}

		close(data_fd);

		/* Give the kernel a moment to finish encapsulating and
		 * emitting the queued datagram before the process (and so
		 * `fd`, the UDP socket the tunnel/session are keyed to)
		 * exits and tears down the underlying socket. */
		usleep(200000);
	}

	if (send_stopccn) {
		pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
					 &peer_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("StopCCN alloc failed");
		l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, local_tid, 1);
		pack->hdr.tid = htons(peer_tid);
		pack->hdr.sid = 0;
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (l2tp_packet_send(fd, pack) < 0)
			return die("StopCCN send failed");
		l2tp_packet_free(pack);
		my_ns++;
	}

	if (wait_cdn) {
		/* RFC 2661 5.1: a control message's header sid/tid is the ID
		 * *assigned by the recipient* -- a session-level CDN sent to
		 * us for our own call carries our own fixed local_sid (not
		 * peer_sid); a tunnel-level StopCCN carries sid 0 and our own
		 * local_tid. Accept either: l2tp_tunnel_disconnect() (l2tp.c
		 * ~1039) deliberately discards any already-queued CDN and
		 * sends only StopCCN when the tunnel itself is going down
		 * (the common case when the call being torn down is the
		 * tunnel's last session) -- "to minimise delay in case of
		 * congestion", per that function's own comment. Both signals
		 * unambiguously mean the same thing to a peer: this call is
		 * over. Requiring a CDN specifically would fail exactly the
		 * scenario this flag exists to test. Poll with a wall-clock
		 * deadline rather than a single SO_RCVTIMEO-bounded call,
		 * since SO_RCVTIMEO bounds each individual recv(), not the
		 * cumulative wait -- an intervening Hello/ZLB would
		 * otherwise reset the budget. */
		struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
		time_t deadline = time(NULL) + 5;
		int got_cdn = 0;

		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
			return die("setsockopt(SO_RCVTIMEO) failed");

		while (time(NULL) < deadline) {
			struct l2tp_packet_t *cdn = NULL;
			struct l2tp_attr_t *msg_type;
			int is_ours;

			if (l2tp_recv(fd, &cdn, NULL, secret, strlen(secret)) != 0) {
				if (errno == EAGAIN)
					break;
				continue;
			}
			if (!cdn)
				continue;
			is_ours = ntohs(cdn->hdr.sid) == local_sid ||
				  (ntohs(cdn->hdr.sid) == 0 &&
				   ntohs(cdn->hdr.tid) == local_tid);
			if (list_empty(&cdn->attrs) || !is_ours) {
				l2tp_packet_free(cdn);
				continue;
			}
			msg_type = list_first_entry(&cdn->attrs,
						    typeof(*msg_type), entry);
			if (msg_type->attr &&
			    msg_type->attr->id == Message_Type &&
			    (msg_type->val.uint16 ==
				     Message_Type_Call_Disconnect_Notify ||
			     msg_type->val.uint16 ==
				     Message_Type_Stop_Ctrl_Conn_Notify))
				got_cdn = 1;
			l2tp_packet_free(cdn);
			if (got_cdn)
				break;
		}

		if (!got_cdn)
			return die("timed out waiting for CDN");
	}

	if (second_call_number) {
		/* A second call on the *same* tunnel, with a calling number
		 * that (by test setup) doesn't match any [l2tp-switch] line=
		 * entry -- exercises the switch instance's own normal,
		 * locally-terminated call path side by side with a switched
		 * one, to confirm one has no effect on the other. Own session
		 * ID (local_sid + 1): the tunnel is shared, but session IDs
		 * are not. */
		uint16_t second_local_sid = local_sid + 1;
		uint16_t second_peer_sid;

		pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Request,
					 &peer_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("second ICRQ alloc failed");
		l2tp_packet_add_int16(pack, Assigned_Session_ID, second_local_sid, 1);
		l2tp_packet_add_int32(pack, Call_Serial_Number, 2, 1);
		l2tp_packet_add_string(pack, Calling_Number, second_call_number, 1);
		pack->hdr.tid = htons(peer_tid);
		pack->hdr.sid = 0;
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (send_and_recv(fd, pack, &reply) < 0)
			return die("second ICRQ/ICRP exchange failed");
		my_ns++;
		peer_next_nr = ntohs(reply->hdr.Ns) + 1;

		second_peer_sid = 0;
		{
			struct l2tp_attr_t *a;

			list_for_each_entry(a, &reply->attrs, entry)
				if (a->attr && a->attr->id == Assigned_Session_ID)
					second_peer_sid = a->val.uint16;
		}
		l2tp_packet_free(reply);

		if (!second_peer_sid)
			return die("second ICRP carried no Assigned-Session-ID");

		pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
					 &peer_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("second ICCN alloc failed");
		l2tp_packet_add_int32(pack, TX_Speed, 1000, 1);
		l2tp_packet_add_int32(pack, Framing_Type, 3, 1);
		pack->hdr.tid = htons(peer_tid);
		pack->hdr.sid = htons(second_peer_sid);
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (l2tp_packet_send(fd, pack) < 0)
			return die("second ICCN send failed");
		l2tp_packet_free(pack);
		my_ns++;

		printf("second_call sid=%hu\n", second_local_sid);
	}

	printf("ok tid=%hu sid=%hu\n", peer_tid, peer_sid);
	return 0;
}
