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
		{0, 0, 0, 0},
	};

	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = htons(1701);

	while ((opt = getopt_long(argc, argv, "a:p:s:c:n:u:w:", opts, NULL)) != -1) {
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
		default:
			return die("usage: --peer-addr A --peer-port P"
				   " --secret S [--calling-number C]"
				   " [--called-number N]"
				   " [--proxy-username U] [--proxy-password W]");
		}
	}

	/* Deliberately not connect()ed: l2tp_packet_send() always calls
	 * sendto() with an explicit destination (pack->addr) regardless of
	 * the socket's connection state, and POSIX leaves sendto() with an
	 * explicit address on an already-connect()ed DGRAM socket
	 * implementation-defined (EISCONN on some stacks -- confirmed
	 * hitting exactly this while verifying this harness by hand).
	 * accel-ppp's own l2tp.c never connect()s its UDP sockets either --
	 * match that instead of introducing a second convention. */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return die("socket() failed");

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

	printf("ok tid=%hu sid=%hu\n", peer_tid, peer_sid);
	return 0;
}
