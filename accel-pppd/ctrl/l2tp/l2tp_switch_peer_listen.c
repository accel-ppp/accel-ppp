/* l2tp-switch peer simulator: --listen role (downstream target) */
#include "l2tp_switch_peer_test.h"

/* Batching keeps the sender ahead of the switch draining its socket. */
#define STORM_BATCH 64

/* Junk is a bare header with a tunnel ID the switch never assigned, so l2tp_conn_read() drops it. */
static int send_sccrp_storm(int fd, const struct sockaddr_in *their_addr,
			    struct l2tp_packet_t *sccrp)
{
	static const int sccrp_every = 4;
	/* An early SCCRP would end the switch's read loop as soon as the socket runs dry. */
	double started = now_monotonic();
	double until = started + (double)sccrp_storm_ms / 1000.0;
	double offer_sccrp_from = started + (double)sccrp_storm_ms / 2000.0;
	/* Junk stops for the last tenth so the buffer drains and an SCCRP gets in. */
	double junk_until = started + (double)sccrp_storm_ms * 0.9 / 1000.0;
	struct mmsghdr msgs[STORM_BATCH];
	struct l2tp_packet_t *junk;
	struct l2tp_hdr_t wire;
	struct iovec iov;
	unsigned long batches = 0, sent = 0;
	int i;

	junk = l2tp_packet_alloc(2, 0, their_addr, 0, NULL, 0);
	if (!junk)
		return die("storm junk alloc failed");
	junk->hdr.tid = htons(0xffff);
	junk->hdr.sid = 0;
	/* Same wire form as l2tp_packet_send(): bare-header length, byte-swapped flags. */
	wire = junk->hdr;
	wire.length = htons(sizeof(wire));
	wire.flags = htons(junk->hdr.flags);
	l2tp_packet_free(junk);

	iov.iov_base = &wire;
	iov.iov_len = sizeof(wire);
	memset(msgs, 0, sizeof(msgs));
	for (i = 0; i < STORM_BATCH; i++) {
		msgs[i].msg_hdr.msg_name = (void *)their_addr;
		msgs[i].msg_hdr.msg_namelen = sizeof(*their_addr);
		msgs[i].msg_hdr.msg_iov = &iov;
		msgs[i].msg_hdr.msg_iovlen = 1;
	}

	printf("event=storm_start t=%.6f\n", now_monotonic());
	fflush(stdout);

	while (1) {
		double now = now_monotonic();
		int n;

		if (now >= until)
			break;
		if (now >= junk_until ||
		    (now >= offer_sccrp_from && (batches % sccrp_every) == 0)) {
			if (l2tp_packet_send(fd, sccrp) < 0)
				return die("SCCRP send failed");
			if (now >= junk_until) {
				batches++;
				continue;
			}
		}
		n = sendmmsg(fd, msgs, STORM_BATCH, 0);
		if (n < 0)
			n = 0;
		sent += (unsigned long)n;
		batches++;
	}

	for (i = 0; i < 8; i++) {
		if (l2tp_packet_send(fd, sccrp) < 0)
			return die("SCCRP send failed");
	}

	printf("event=storm_end t=%.6f junk=%lu\n", now_monotonic(), sent);
	fflush(stdout);

	return 0;
}

static int send_call_cdn(int fd, const struct sockaddr_in *their_addr,
			 uint16_t their_tid, uint16_t their_sid,
			 uint16_t our_sid, uint16_t *my_ns,
			 const uint16_t *peer_next_nr)
{
	struct l2tp_packet_t *pack;
	struct l2tp_avp_result_code res = { htons(1), htons(0) };

	pack = l2tp_packet_alloc(2, Message_Type_Call_Disconnect_Notify,
				 their_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("CDN alloc failed");
	/* Header sid is the recipient's, Assigned-Session-ID is ours. */
	l2tp_packet_add_int16(pack, Assigned_Session_ID, our_sid, 1);
	l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&res,
			       sizeof(res), 1);
	pack->hdr.tid = htons(their_tid);
	pack->hdr.sid = htons(their_sid);
	pack->hdr.Ns = htons((*my_ns)++);
	pack->hdr.Nr = htons(*peer_next_nr);
	if (l2tp_packet_send(fd, pack) < 0) {
		l2tp_packet_free(pack);
		return die("CDN send failed");
	}
	l2tp_packet_free(pack);

	return 0;
}

static int serve_minimal_lcp_and_cdn(int fd, const struct sockaddr_in *their_addr,
				     uint16_t my_tid, uint16_t their_tid,
				     uint16_t our_sid, uint16_t their_sid,
				     uint16_t *my_ns, uint16_t *peer_next_nr,
				     int round)
{
	struct sockaddr_pppol2tp pppox_addr;
	int data_fd, reg_fd, lns_mode = 1;

	/* The kernel xmit path needs the tunnel socket connect()ed to the peer. */
	if (connect(fd, (const struct sockaddr *)their_addr, sizeof(*their_addr)) < 0)
		return die("connect(fd) to the calling peer failed");

	reg_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (reg_fd < 0)
		return die("tunnel registration socket() failed");

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = fd;
	pppox_addr.pppol2tp.addr = *their_addr;
	pppox_addr.pppol2tp.s_tunnel = my_tid;
	pppox_addr.pppol2tp.d_tunnel = their_tid;

	if (connect(reg_fd, (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		close(reg_fd);
		return die("tunnel registration connect() failed");
	}
	close(reg_fd);

	data_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (data_fd < 0)
		return die("data socket() failed");

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = fd;
	pppox_addr.pppol2tp.addr = *their_addr;
	pppox_addr.pppol2tp.s_tunnel = my_tid;
	pppox_addr.pppol2tp.d_tunnel = their_tid;
	pppox_addr.pppol2tp.s_session = our_sid;
	pppox_addr.pppol2tp.d_session = their_sid;

	if (connect(data_fd, (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		close(data_fd);
		return die("data socket connect() failed");
	}

	if (setsockopt(data_fd, SOL_PPPOL2TP, PPPOL2TP_SO_LNSMODE,
		      &lns_mode, sizeof(lns_mode)) < 0) {
		close(data_fd);
		return die("data socket setsockopt(LNSMODE) failed");
	}

	if (run_minimal_lcp(data_fd, 5) != 0) {
		close(data_fd);
		return -1;
	}

	printf("event=downstream_lcp_settled round=%d t=%.6f\n",
	       round, now_monotonic());
	fflush(stdout);

	if (cdn_after_lcp_ms > 0) {
		usleep((useconds_t)cdn_after_lcp_ms * 1000);

		if (send_call_cdn(fd, their_addr, their_tid, their_sid, our_sid,
				  my_ns, peer_next_nr)) {
			close(data_fd);
			return 1;
		}

		printf("event=sent_cdn round=%d t=%.6f\n", round, now_monotonic());
		fflush(stdout);
	}

	close(data_fd);
	return 0;
}

static int serve_established_tunnel(int fd, const struct sockaddr_in *their_addr,
				    uint16_t my_tid, uint16_t their_tid,
				    uint16_t *my_ns, uint16_t *peer_next_nr,
				    int round)
{
	double until = now_monotonic() + hold_seconds;
	struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
	uint16_t next_sid = (uint16_t)(200 + round * 10);
	uint16_t call_our_sid = 0, call_their_sid = 0;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		return die("setsockopt(SO_RCVTIMEO) failed");

	while (now_monotonic() < until) {
		struct l2tp_packet_t *msg = NULL, *rsp;
		struct l2tp_attr_t *attr, *msg_type;
		uint16_t type = 0, their_sid = 0;
		int stop = 0, flood = 0;

		if (l2tp_recv(fd, &msg, NULL, secret, strlen(secret)) != 0)
			continue;
		if (!msg)
			continue;
		if (list_empty(&msg->attrs)) {
				/* ZLB: do not ack an ack. */
			l2tp_packet_free(msg);
			continue;
		}

		*peer_next_nr = ntohs(msg->hdr.Ns) + 1;
		msg_type = list_first_entry(&msg->attrs, typeof(*msg_type),
					    entry);
		if (msg_type->attr && msg_type->attr->id == Message_Type)
			type = msg_type->val.uint16;

		if (type == Message_Type_Incoming_Call_Request) {
			list_for_each_entry(attr, &msg->attrs, entry)
				if (attr->attr &&
				    attr->attr->id == Assigned_Session_ID)
					their_sid = (uint16_t)attr->val.int16;
			call_their_sid = their_sid;
			printf("event=recv_icrq round=%d t=%.6f\n",
			       round, now_monotonic());
		} else if (type == Message_Type_Incoming_Call_Connected) {
			/* Check the value, not just presence. */
			list_for_each_entry(attr, &msg->attrs, entry)
				if (attr->attr &&
				    attr->attr->id == Proxy_Authen_Type)
					printf("event=recv_proxy_authen_type"
					       " round=%d t=%.6f value=%u\n",
					       round, now_monotonic(),
					       (unsigned int)attr->val.uint16);
			printf("event=recv_iccn round=%d t=%.6f\n",
			       round, now_monotonic());
		} else if (type == Message_Type_Call_Disconnect_Notify) {
			printf("event=recv_cdn round=%d t=%.6f\n",
			       round, now_monotonic());
			flood = fin_flood_on == FIN_FLOOD_ON_CDN;
		} else if (type == Message_Type_Stop_Ctrl_Conn_Notify) {
			unsigned int res = 0;

			list_for_each_entry(attr, &msg->attrs, entry)
				if (attr->attr && attr->attr->id == Result_Code &&
				    attr->length >= 2)
					res = (unsigned int)
						((attr->val.octets[0] << 8) |
						 attr->val.octets[1]);
			printf("event=recv_stopccn round=%d t=%.6f res=%u\n",
			       round, now_monotonic(), res);
			stop = 1;
		}
		l2tp_packet_free(msg);
		fflush(stdout);

		if (type == Message_Type_Incoming_Call_Request && their_sid) {
			rsp = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Reply,
						their_addr, 0, secret,
						strlen(secret));
			if (!rsp)
				return die("ICRP alloc failed");
			if (l2tp_packet_add_int16(rsp, Assigned_Session_ID,
						  next_sid, 1) < 0)
				return die("ICRP Assigned-Session-ID add failed");
			rsp->hdr.tid = htons(their_tid);
			rsp->hdr.sid = htons(their_sid);
			rsp->hdr.Ns = htons((*my_ns)++);
			rsp->hdr.Nr = htons(*peer_next_nr);
			if (l2tp_packet_send(fd, rsp) < 0)
				return die("ICRP send failed");
			l2tp_packet_free(rsp);
			call_our_sid = next_sid;
			next_sid++;
		} else {
			/* A ZLB takes no Ns slot (RFC 2661 5.8). */
			rsp = l2tp_packet_alloc(2, 0, their_addr, 0, NULL, 0);
			if (!rsp)
				return die("ZLB alloc failed");
			rsp->hdr.tid = htons(their_tid);
			rsp->hdr.sid = 0;
			rsp->hdr.Ns = htons(*my_ns);
			rsp->hdr.Nr = htons(*peer_next_nr);
			if (l2tp_packet_send(fd, rsp) < 0)
				return die("ZLB send failed");
			l2tp_packet_free(rsp);
		}

		if (type == Message_Type_Incoming_Call_Connected && minimal_lcp) {
			if (serve_minimal_lcp_and_cdn(fd, their_addr, my_tid, their_tid,
						      call_our_sid, call_their_sid,
						      my_ns, peer_next_nr, round) < 0)
				return 1;
			if (cdn_after_lcp_ms > 0)
				break;
		}

		if (type == Message_Type_Incoming_Call_Connected &&
		    cdn_after_iccn_ms > 0) {
			usleep((useconds_t)cdn_after_iccn_ms * 1000);
			if (send_call_cdn(fd, their_addr, their_tid,
					  call_their_sid, call_our_sid,
					  my_ns, peer_next_nr))
				return 1;
			printf("event=sent_cdn round=%d t=%.6f\n", round,
			       now_monotonic());
			fflush(stdout);
		}

		if (type == Message_Type_Incoming_Call_Connected &&
		    busy_flood_ms > 0) {
			printf("event=busy_flood_start round=%d t=%.6f\n",
			       round, now_monotonic());
			fflush(stdout);
			if (run_busy_flood(fd, their_addr, busy_flood_ms))
				return 1;
			printf("event=busy_flood_end round=%d t=%.6f\n",
			       round, now_monotonic());
			fflush(stdout);
		}

		if (flood) {
			if (run_fin_flood(fd, their_addr, their_tid, my_tid,
					  *my_ns, *peer_next_nr))
				return 1;
			break;
		}

		if (stop)
			break;
	}

	return 0;
}

int run_listen_mode(int rounds)
{
	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_addr = { htonl(INADDR_ANY) },
		.sin_port = peer_addr.sin_port,
	};
	int fd, round;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return die("listen socket() failed");
	if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0)
		return die("listen bind() failed");

	for (round = 0; round < rounds; ++round) {
		struct l2tp_packet_t *pack, *req;
		struct l2tp_attr_t *attr;
		struct sockaddr_in their_addr;
		uint16_t their_tid = 0, my_tid;
		uint16_t my_ns = 0, peer_next_nr;
		uint8_t chall[16];
		/* Up to 143 bytes (0x7F + MD5_DIGEST_LENGTH) per l2tp_send_SCCRQ(). */
		uint8_t their_chall[160];
		int their_chall_len = 0;
		uint8_t challresp[MD5_DIGEST_LENGTH];
		int err;

		for (;;) {
			if (l2tp_recv(fd, &req, NULL, secret, strlen(secret)) != 0)
				return die("waiting for SCCRQ failed");
			if (!req)
				continue;
			if (list_empty(&req->attrs)) {
				l2tp_packet_free(req);
				continue;
			}
			break;
		}
		their_addr = req->addr;
		peer_next_nr = ntohs(req->hdr.Ns) + 1;
		list_for_each_entry(attr, &req->attrs, entry) {
			if (attr->attr && attr->attr->id == Assigned_Tunnel_ID)
				their_tid = (uint16_t)attr->val.int16;
			/* RFC 2661 5.1.1: the SCCRQ Challenge must be answered in the SCCRP. */
			if (attr->attr && attr->attr->id == Challenge &&
			    attr->length <= (int)sizeof(their_chall)) {
				memcpy(their_chall, attr->val.octets, attr->length);
				their_chall_len = attr->length;
			}
		}
		l2tp_packet_free(req);
		if (!their_tid)
			return die("SCCRQ carried no Assigned-Tunnel-ID");

		printf("event=recv_sccrq round=%d t=%.6f\n", round, now_monotonic());
		fflush(stdout);

		if (fin_flood_on == FIN_FLOOD_ON_SCCRQ) {
			if (run_fin_flood(fd, &their_addr, their_tid,
					  1024 + (uint16_t)(random() % 60000),
					  0, peer_next_nr))
				return 1;
			if (hold_seconds > 0)
				sleep((unsigned int)hold_seconds);
			continue;
		}

		if (sccrp_delay_ms > 0)
			usleep((useconds_t)sccrp_delay_ms * 1000);

		my_tid = 1024 + (uint16_t)(random() % 60000);

		if (strlen(secret) > 0 && u_randbuf(chall, sizeof(chall), &err) < 0)
			return die("u_randbuf(challenge) failed");
		if (their_chall_len > 0 && strlen(secret) > 0)
			comp_chap_md5(challresp, Message_Type_Start_Ctrl_Conn_Reply,
				     secret, strlen(secret), their_chall,
				     their_chall_len);

		pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Reply,
					 &their_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("SCCRP alloc failed");
		l2tp_packet_add_int16(pack, Protocol_Version, L2TP_V2_PROTOCOL_VERSION, 1);
		l2tp_packet_add_int32(pack, Framing_Capabilities, 3, 1);
		l2tp_packet_add_string(pack, Host_Name, "fake-downstream", 1);
		l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, my_tid, 1);
		if (strlen(secret) > 0)
			l2tp_packet_add_octets(pack, Challenge, chall, sizeof(chall), 1);
		if (their_chall_len > 0 && strlen(secret) > 0) {
			if (l2tp_packet_add_octets(pack, Challenge_Response,
						   challresp, MD5_DIGEST_LENGTH, 1) < 0)
				return die("SCCRP Challenge-Response add failed");
		}
		pack->hdr.tid = htons(their_tid);
		pack->hdr.sid = 0;
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (sccrp_storm_ms > 0) {
			if (send_sccrp_storm(fd, &their_addr, pack) != 0)
				return 1;
		} else if (l2tp_packet_send(fd, pack) < 0) {
			return die("SCCRP send failed");
		}
		l2tp_packet_free(pack);
		my_ns++;

		for (;;) {
			struct l2tp_packet_t *cn = NULL;
			struct l2tp_attr_t *msg_type;
			int is_scccn;

			if (l2tp_recv(fd, &cn, NULL, secret, strlen(secret)) != 0)
				return die("waiting for SCCCN failed");
			if (!cn)
				continue;
			if (list_empty(&cn->attrs)) {
				l2tp_packet_free(cn);
				continue;
			}
			/* Skip SCCRQ retransmissions queued during --sccrp-delay-ms. */
			msg_type = list_first_entry(&cn->attrs,
						    typeof(*msg_type), entry);
			is_scccn = msg_type->attr &&
				   msg_type->attr->id == Message_Type &&
				   msg_type->val.uint16 ==
					   Message_Type_Start_Ctrl_Conn_Connected;
			if (!is_scccn) {
				l2tp_packet_free(cn);
				continue;
			}
			peer_next_nr = ntohs(cn->hdr.Ns) + 1;
			l2tp_packet_free(cn);
			break;
		}

		printf("event=established round=%d t=%.6f\n", round, now_monotonic());
		fflush(stdout);

		if (send_stopccn) {
			struct l2tp_avp_result_code rc = { htons(1), htons(6) };

			pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
						 &their_addr, 0, secret, strlen(secret));
			if (!pack)
				return die("StopCCN alloc failed");
			l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, my_tid, 1);
			l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
					       sizeof(rc), 1);
			pack->hdr.tid = htons(their_tid);
			pack->hdr.sid = 0;
			pack->hdr.Ns = htons(my_ns);
			pack->hdr.Nr = htons(peer_next_nr);
			if (l2tp_packet_send(fd, pack) < 0)
				return die("StopCCN send failed");
			l2tp_packet_free(pack);
			my_ns++;

			printf("event=sent_stopccn round=%d t=%.6f\n", round, now_monotonic());
			fflush(stdout);
		}

		if (hold_seconds > 0 &&
		    serve_established_tunnel(fd, &their_addr, my_tid, their_tid,
					     &my_ns, &peer_next_nr, round) < 0)
			return 1;
	}

	return 0;
}
