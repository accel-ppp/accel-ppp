/*
 * Standalone L2TP peer simulator for the l2tp-switch tests; not in the cmake build.
 * The client role runs one LAC exchange (SCCRQ to ICCN) using packet.c, --listen plays
 * the downstream target. Helpers are in l2tp_switch_peer_{lcp,flood,listen}.c.
 * Build: gcc -O1 -g -D_GNU_SOURCE -I accel-pppd/include -I accel-pppd/ctrl/l2tp \
 *   -o /tmp/l2tp_switch_peer_test accel-pppd/ctrl/l2tp/l2tp_switch_peer_*.c \
 *   accel-pppd/ctrl/l2tp/packet.c -lcrypto
 */
#include "l2tp_switch_peer_test.h"

/* Stubs for what packet.c needs, instead of the triton runtime. */
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

/* Stub dictionary, types and M values from dict/dictionary.rfc2661. */
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

struct sockaddr_in peer_addr;
const char *secret = "";
const char *calling_number = "472913";
const char *called_number;
const char *proxy_username;
const char *proxy_password;
const char *data_pattern;
int send_stopccn;
int wait_cdn;
int real_ppp;
int minimal_lcp;
int lcp_auth;
int hold_seconds;
int listen_mode;
int listen_rounds = 1;
int sccrp_delay_ms;
/* l2tp_conn_read() drains its socket first, so the tunnel comes up only when the flood ends;
 * context calls such as the connect timeout are starved meanwhile. */
int sccrp_storm_ms;
/* Must exceed the daemon's 10s connect timeout to see the CDN that follows it. */
int cdn_timeout = 5;
int cdn_after_lcp_ms;
int cdn_after_iccn_ms;
const char *second_call_number;
/* Random per process: the kernel keys tunnels by id per netns, so fixed ids would collide. */
uint16_t local_tid;
uint16_t local_sid;

int die(const char *msg)
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
		/* *reply is non-NULL for a ZLB too. */
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

double now_monotonic(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	int fd, opt;
	struct l2tp_packet_t *pack, *reply;
	uint16_t peer_tid, peer_sid;
	/* RFC 2661 5.8: l2tp_packet_alloc() zeroes Ns and Nr. */
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
		{"real-ppp", no_argument, 0, 'R'},
		{"minimal-lcp", no_argument, 0, 'm'},
		{"lcp-auth", required_argument, 0, 'A'},
		{"hold-seconds", required_argument, 0, 'H'},
		{"listen", no_argument, 0, 'L'},
		{"rounds", required_argument, 0, 'N'},
		{"sccrp-delay-ms", required_argument, 0, 'D'},
		{"sccrp-storm-ms", required_argument, 0, 'M'},
		{"cdn-timeout", required_argument, 0, 'T'},
		{"cdn-after-lcp-ms", required_argument, 0, 'C'},
		{"cdn-after-iccn-ms", required_argument, 0, 'I'},
		{"fin-flood", required_argument, 0, 'F'},
		{"fin-flood-on", required_argument, 0, 'O'},
		{"busy-flood-ms", required_argument, 0, 'B'},
		{0, 0, 0, 0},
	};

	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = htons(1701);

	{
		unsigned seed = (unsigned)getpid() ^ (unsigned)time(NULL);

		srandom(seed);
		local_tid = 1024 + (uint16_t)(random() % 60000);
		local_sid = 1024 + (uint16_t)(random() % 60000);
	}

	while ((opt = getopt_long(argc, argv, "a:p:s:c:n:u:w:d:xWS:RmH:LN:D:M:T:C:I:A:F:O:B:", opts, NULL)) != -1) {
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
		case 'R':
			real_ppp = 1;
			break;
		case 'm':
			minimal_lcp = 1;
			break;
		case 'A':
			if (!strcmp(optarg, "pap"))
				lcp_auth = LCP_AUTH_PAP;
			else if (!strcmp(optarg, "chap"))
				lcp_auth = LCP_AUTH_CHAP;
			else if (!strcmp(optarg, "none"))
				lcp_auth = LCP_AUTH_NONE;
			else
				return die("invalid --lcp-auth (pap|chap|none)");
			break;
		case 'H':
			hold_seconds = atoi(optarg);
			break;
		case 'L':
			listen_mode = 1;
			break;
		case 'N':
			listen_rounds = atoi(optarg);
			break;
		case 'D':
			sccrp_delay_ms = atoi(optarg);
			if (sccrp_delay_ms < 0)
				return die("invalid --sccrp-delay-ms");
			break;
		case 'M':
			sccrp_storm_ms = atoi(optarg);
			if (sccrp_storm_ms < 0)
				return die("invalid --sccrp-storm-ms");
			break;
		case 'T':
			cdn_timeout = atoi(optarg);
			if (cdn_timeout <= 0)
				return die("invalid --cdn-timeout");
			break;
		case 'C':
			cdn_after_lcp_ms = atoi(optarg);
			if (cdn_after_lcp_ms < 0)
				return die("invalid --cdn-after-lcp-ms");
			break;
		case 'I':
			cdn_after_iccn_ms = atoi(optarg);
			if (cdn_after_iccn_ms < 0)
				return die("invalid --cdn-after-iccn-ms");
			break;
		case 'F':
			if (parse_fin_flood(optarg))
				return 1;
			break;
		case 'O':
			if (!strcmp(optarg, "sccrq"))
				fin_flood_on = FIN_FLOOD_ON_SCCRQ;
			else if (!strcmp(optarg, "cdn"))
				fin_flood_on = FIN_FLOOD_ON_CDN;
			else if (!strcmp(optarg, "iccn"))
				fin_flood_on = FIN_FLOOD_ON_ICCN;
			else
				return die("invalid --fin-flood-on (sccrq|cdn|iccn)");
			break;
		case 'B':
			busy_flood_ms = atoi(optarg);
			if (busy_flood_ms <= 0)
				return die("invalid --busy-flood-ms");
			break;
		default:
			return die("usage: --peer-addr A --peer-port P"
				   " --secret S [--calling-number C]"
				   " [--called-number N]"
				   " [--proxy-username U] [--proxy-password W]"
				   " [--data-pattern D] [--send-stopccn]"
				   " [--wait-cdn [--cdn-timeout S]]"
				   " [--second-call C]"
				   " [--real-ppp | --minimal-lcp [--lcp-auth pap|chap|none]]"
				   " [--hold-seconds N]"
				   " [--listen [--rounds N] [--sccrp-delay-ms M]"
				   " [--sccrp-storm-ms M] [--hold-seconds N]"
				   " [--minimal-lcp [--cdn-after-lcp-ms M]]"
				   " [--cdn-after-iccn-ms M]]"
				   " [--fin-flood A:S:W --fin-flood-on"
				   " sccrq|cdn (--listen) | iccn]"
				   " [--busy-flood-ms N]");
		}
	}

	if (cdn_after_lcp_ms > 0 && !(listen_mode && minimal_lcp))
		return die("--cdn-after-lcp-ms requires --listen and --minimal-lcp");

	if (cdn_after_iccn_ms > 0 && !listen_mode)
		return die("--cdn-after-iccn-ms requires --listen");

	if (busy_flood_ms > 0 && !listen_mode)
		return die("--busy-flood-ms requires --listen");

	if (lcp_auth != LCP_AUTH_NONE && !minimal_lcp)
		return die("--lcp-auth requires --minimal-lcp");

	if ((fin_flood_on == FIN_FLOOD_OFF) != (fin_flood_len_ms == 0))
		return die("--fin-flood and --fin-flood-on go together");
	if (fin_flood_on == FIN_FLOOD_ON_ICCN && listen_mode)
		return die("--fin-flood-on iccn is for the calling role");
	if (fin_flood_on != FIN_FLOOD_OFF &&
	    fin_flood_on != FIN_FLOOD_ON_ICCN && !listen_mode)
		return die("--fin-flood-on sccrq|cdn requires --listen");

	if (listen_mode)
		return run_listen_mode(listen_rounds);

	/* connect() so the kernel xmit path routes through the UDP socket. */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return die("socket() failed");
	if (connect(fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0)
		return die("connect(fd) failed");

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

	/* RFC 2661 3.1: the header tid is the Assigned-Tunnel-ID from the SCCRP. */
	peer_tid = 0;

	/* RFC 2661 5.1.1: the SCCRP carries a Challenge when the peer has a secret. */
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

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("ICCN alloc failed");
	l2tp_packet_add_int32(pack, TX_Speed, 1000, 1);
	l2tp_packet_add_int32(pack, Framing_Type, 3, 1);
	if (proxy_username) {
		/* Proxy-Authen-Type: 1 textual, 2 CHAP, 3 PAP. */
		l2tp_packet_add_int16(pack, Proxy_Authen_Type, 3, 1);
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

	/* Zero point for timing the switch's downstream disconnect; printed only under --wait-cdn. */
	if (wait_cdn) {
		printf("event=sent_iccn t=%.6f\n", now_monotonic());
		fflush(stdout);
	}

	if (fin_flood_on == FIN_FLOOD_ON_ICCN &&
	    run_fin_flood(fd, &peer_addr, peer_tid, local_tid, my_ns,
			  peer_next_nr))
		return 1;

	if (real_ppp && (!proxy_username || !proxy_password))
		return die("--real-ppp requires --proxy-username and --proxy-password");

	if (real_ppp && minimal_lcp)
		return die("--real-ppp and --minimal-lcp are mutually exclusive");

	if (data_pattern || real_ppp || minimal_lcp) {
		struct sockaddr_pppol2tp pppox_addr;
		int data_fd, reg_fd, lns_mode = 0;

		/* The switch opens its session socket only after the downstream call is up.
		 * There is no LCP retransmission here, so wait. */
		usleep(300000);

		/* A session 0 pppol2tp connect registers the tunnel; the session connect fails with ENOENT without it. */
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
		pppox_addr.pppol2tp.fd = fd;
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

		if (real_ppp) {
			if (run_real_ppp(data_fd) != 0)
				return 1;
		} else if (minimal_lcp) {
			if (run_minimal_lcp(data_fd, 5) != 0)
				return 1;
		} else {
			ssize_t n = write(data_fd, data_pattern, strlen(data_pattern));

			if (n < 0)
				return die("data socket write() failed");

			close(data_fd);

			/* Let the kernel emit the datagram before exit closes the socket. */
			usleep(200000);
		}
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
		/* The CDN carries our local_sid, a tunnel-level StopCCN has sid 0 and our local_tid; accept either.
		 * Wall-clock deadline: SO_RCVTIMEO bounds each recv(), not the total wait. */
		struct timeval tv = { .tv_sec = cdn_timeout, .tv_usec = 0 };
		time_t deadline = time(NULL) + cdn_timeout;
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

		printf("event=recv_cdn t=%.6f\n", now_monotonic());
		fflush(stdout);
	}

	if (second_call_number) {
		/* The calling number should not match any [l2tp-switch] line=; needs its own session ID. */
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

	/* Keep the tunnel socket alive so tests can watch the switch. --real-ppp holds on its own. */
	if (hold_seconds > 0 && !real_ppp)
		sleep((unsigned int)hold_seconds);

	printf("ok tid=%hu sid=%hu\n", peer_tid, peer_sid);
	return 0;
}
