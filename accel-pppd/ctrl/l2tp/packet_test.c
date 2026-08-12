/*
 * Standalone regression test for the L2TP control message parser.
 *
 * Not part of the cmake build. Compile and run with:
 *   gcc -O1 -g -Wall -fno-strict-aliasing -D_GNU_SOURCE \
 *       -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -I accel-pppd/include -I accel-pppd/ctrl/l2tp \
 *       -o /tmp/l2tp_packet_test \
 *       accel-pppd/ctrl/l2tp/packet_test.c accel-pppd/ctrl/l2tp/packet.c \
 *       -lcrypto && /tmp/l2tp_packet_test
 *
 * The interesting part is the hidden AVP subformat: the 2 bytes length prefix
 * of a hidden AVP is an *output of the cipher*, so a peer using a different
 * secret -- or an attacker injecting hidden AVPs blindly -- turns it into an
 * essentially random 16 bits value. It must never be trusted to bound a read
 * of the attribute value.
 *
 * The test drives the real parser through a real UDP socket:
 *   - hand-crafted packets exercise the hidden AVP length checks, including
 *     the single block (attribute <= 16 bytes) cipher path which the accel-ppp
 *     encoder itself never produces (it always pads by >= 16 bytes);
 *   - l2tp_packet_send()/l2tp_recv() round trips exercise the multi block
 *     cipher path and the unaligned AVP accessors.
 *
 * Everything packet.c needs besides libcrypto is stubbed below.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/md5.h>

#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "l2tp.h"
#include "attr_defs.h"

static int failures;
#define CHECK(cond) do { if (!(cond)) { \
	fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

/* ------------------------------------------------------------------ stubs */

int conf_verbose = 1;
int conf_avp_permissive = 0;

/* A dictionary just big enough for the attributes used here. Types are the
   ones accel-ppp's own dictionary uses, except Tie_Breaker which is turned
   into an INT64 to get coverage of the 64 bits accessor. */
static struct l2tp_dict_attr_t dict[] = {
	{ .name = "Message-Type",       .id = Message_Type,       .type = ATTR_TYPE_INT16,  .M =  1, .H =  0 },
	{ .name = "Tie-Breaker",        .id = Tie_Breaker,        .type = ATTR_TYPE_INT64,  .M =  0, .H = -1 },
	{ .name = "Host-Name",          .id = Host_Name,          .type = ATTR_TYPE_STRING, .M =  1, .H = -1 },
	{ .name = "Assigned-Tunnel-Id", .id = Assigned_Tunnel_ID, .type = ATTR_TYPE_INT16,  .M =  1, .H = -1 },
	{ .name = "Call-Serial-Number", .id = Call_Serial_Number, .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Random-Vector",      .id = Random_Vector,      .type = ATTR_TYPE_OCTETS, .M =  1, .H =  0 },
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

/* Size carrying mempool: allocations stay exactly as large as the pool's
   object size, so that ASan traps any read past the end of a packet buffer */
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
	uint8_t *u8_buf = buf;
	size_t indx;

	/* Deterministic on purpose: reproducible failures beat real entropy */
	for (indx = 0; indx < buf_len; ++indx)
		u8_buf[indx] = (uint8_t)(indx * 7 + 0x5a);

	return 0;
}

#define DEFINE_LOG_STUB(name)						\
	void name(const char *fmt, ...) {}
DEFINE_LOG_STUB(log_emerg)
DEFINE_LOG_STUB(log_error)
DEFINE_LOG_STUB(log_warn)
DEFINE_LOG_STUB(log_ppp_debug)

/* -------------------------------------------------------- packet building */

struct pktbuf {
	uint8_t data[2048];
	size_t len;
};

static void pkt_init(struct pktbuf *pkt)
{
	struct l2tp_hdr_t hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags = htons(L2TP_FLAG_T | L2TP_FLAG_L | L2TP_FLAG_S | 2);

	memset(pkt, 0, sizeof(*pkt));
	memcpy(pkt->data, &hdr, sizeof(hdr));
	pkt->len = sizeof(hdr);
}

/* Append an AVP and return a pointer to its value */
static uint8_t *pkt_add_avp(struct pktbuf *pkt, uint16_t extra_flags,
			    uint16_t type, const void *val, size_t val_len)
{
	struct l2tp_avp_t avp;
	uint8_t *ptr = pkt->data + pkt->len;

	memset(&avp, 0, sizeof(avp));
	avp.flags = htons(extra_flags | ((sizeof(avp) + val_len) & L2TP_AVP_LEN_MASK));
	avp.type = htons(type);

	memcpy(ptr, &avp, sizeof(avp));
	if (val_len)
		memcpy(ptr + sizeof(avp), val, val_len);
	pkt->len += sizeof(avp) + val_len;

	return ptr + sizeof(avp);
}

static void pkt_finish(struct pktbuf *pkt)
{
	uint16_t length = htons(pkt->len);

	memcpy(pkt->data + offsetof(struct l2tp_hdr_t, length),
	       &length, sizeof(length));
}

/*
 * Cipher a hidden AVP whose cleartext (length prefix included) is at most one
 * MD5 block long, i.e. the path that never validated the length prefix.
 */
static void hide_single_block(uint8_t *val, size_t val_len, uint16_t type,
			      const char *secret, size_t secret_len,
			      const uint8_t *rv, size_t rv_len)
{
	uint8_t md5[MD5_DIGEST_LENGTH];
	uint16_t attr_type = htons(type);
	MD5_CTX md5_ctx;
	size_t indx;

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, &attr_type, sizeof(attr_type));
	MD5_Update(&md5_ctx, secret, secret_len);
	MD5_Update(&md5_ctx, rv, rv_len);
	MD5_Final(md5, &md5_ctx);

	for (indx = 0; indx < val_len && indx < MD5_DIGEST_LENGTH; ++indx)
		val[indx] ^= md5[indx];
}

/* --------------------------------------------------------------- plumbing */

static const char secret[] = "s3cr3t";
static int sock = -1;
static struct sockaddr_in sock_addr;

static void loopback_socket(void)
{
	socklen_t addr_len = sizeof(sock_addr);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(1);
	}

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0
	    || getsockname(sock, (struct sockaddr *)&sock_addr, &addr_len) < 0) {
		perror("bind");
		exit(1);
	}
}

/* Feed raw bytes to the parser, NULL means "packet rejected" */
static struct l2tp_packet_t *parse(const struct pktbuf *pkt)
{
	struct l2tp_packet_t *pack = NULL;

	if (sendto(sock, pkt->data, pkt->len, 0,
		   (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
		perror("sendto");
		exit(1);
	}

	CHECK(l2tp_recv(sock, &pack, NULL, secret, sizeof(secret) - 1) == 0);

	return pack;
}

static const struct l2tp_attr_t *find_attr(const struct l2tp_packet_t *pack, int id)
{
	const struct l2tp_attr_t *attr;

	list_for_each_entry(attr, &pack->attrs, entry)
		if (attr->attr->id == id)
			return attr;

	return NULL;
}

/* ------------------------------------------------------------------ tests */

/*
 * A hidden AVP small enough to be ciphered in a single block: its deciphered
 * length prefix used to be taken at face value, so anything up to 65535 was
 * handed to the memcpy() feeding attr->val, reading way past the packet
 * buffer. The parser must accept a prefix only if the attribute value it
 * announces really fits in the received AVP.
 */
static void test_hidden_avp_length_prefix(void)
{
	static const struct {
		const char *name;
		size_t attr_len;	/* ciphered attribute length */
		uint16_t declared;	/* deciphered length prefix */
		int accept;
	} cases[] = {
		{ "lies about 64K",      16,      0xffff, 0 },
		{ "lies, minimal avp",    2,      0xffff, 0 },
		{ "off by one",          16,          15, 0 },
		{ "one byte too big",     4,           3, 0 },
		{ "fits exactly",        16,          14, 1 },
		{ "fits",                16,           4, 1 },
		{ "empty value",          2,           0, 1 },
		{ "no length prefix",     1,           0, 0 },
	};
	static const uint8_t rv[16] = {
		0xf3, 0x1a, 0x00, 0xff, 0x42, 0x7c, 0x91, 0x08,
		0x5d, 0xe6, 0x33, 0xb0, 0x14, 0xaa, 0x69, 0xc2,
	};
	uint8_t value[MD5_DIGEST_LENGTH];
	struct l2tp_packet_t *pack;
	const struct l2tp_attr_t *attr;
	struct pktbuf pkt;
	uint16_t declared;
	size_t indx, i;

	for (indx = 0; indx < sizeof(cases) / sizeof(cases[0]); ++indx) {
		pkt_init(&pkt);
		pkt_add_avp(&pkt, L2TP_AVP_FLAG_M, Random_Vector, rv, sizeof(rv));

		/* Cleartext: 2 bytes length prefix, then the value, then padding.
		   The value is a recognizable pattern so that a short read shows
		   up as wrong content rather than as a lucky pass. */
		memset(value, 0, sizeof(value));
		declared = htons(cases[indx].declared);
		memcpy(value, &declared, cases[indx].attr_len < sizeof(declared)
					 ? cases[indx].attr_len : sizeof(declared));
		for (i = sizeof(declared); i < cases[indx].attr_len; ++i)
			value[i] = 'a' + (i % 26);

		hide_single_block(value, cases[indx].attr_len, Host_Name,
				  secret, sizeof(secret) - 1, rv, sizeof(rv));
		pkt_add_avp(&pkt, L2TP_AVP_FLAG_M | L2TP_AVP_FLAG_H, Host_Name,
			    value, cases[indx].attr_len);
		pkt_finish(&pkt);

		pack = parse(&pkt);
		if (!cases[indx].accept) {
			if (pack) {
				fprintf(stderr, "FAIL %s:%d: hidden avp accepted"
					" (%s)\n", __FILE__, __LINE__,
					cases[indx].name);
				failures++;
				l2tp_packet_free(pack);
			}
			continue;
		}

		if (!pack) {
			fprintf(stderr, "FAIL %s:%d: hidden avp rejected (%s)\n",
				__FILE__, __LINE__, cases[indx].name);
			failures++;
			continue;
		}

		attr = find_attr(pack, Host_Name);
		CHECK(attr != NULL);
		if (attr) {
			CHECK(attr->length == cases[indx].declared);
			for (i = 0; i < cases[indx].declared; ++i)
				CHECK((uint8_t)attr->val.string[i] ==
				      'a' + ((i + sizeof(declared)) % 26));
			CHECK(attr->val.string[cases[indx].declared] == '\0');
		}
		l2tp_packet_free(pack);
	}
}

/*
 * A hidden AVP is rejected outright when no Random Vector was received, or
 * when its length cannot even hold the length prefix.
 */
static void test_hidden_avp_prerequisites(void)
{
	static const uint8_t value[16] = { 0 };
	struct l2tp_packet_t *pack;
	struct pktbuf pkt;

	pkt_init(&pkt);
	pkt_add_avp(&pkt, L2TP_AVP_FLAG_M | L2TP_AVP_FLAG_H, Host_Name,
		    value, sizeof(value));
	pkt_finish(&pkt);
	pack = parse(&pkt);
	CHECK(pack == NULL);
	if (pack)
		l2tp_packet_free(pack);

	/* Random Vector present, but the hidden AVP carries no value at all */
	pkt_init(&pkt);
	pkt_add_avp(&pkt, L2TP_AVP_FLAG_M, Random_Vector, value, sizeof(value));
	pkt_add_avp(&pkt, L2TP_AVP_FLAG_M | L2TP_AVP_FLAG_H, Host_Name, NULL, 0);
	pkt_finish(&pkt);
	pack = parse(&pkt);
	CHECK(pack == NULL);
	if (pack)
		l2tp_packet_free(pack);
}

/*
 * Round trip through the real encoder. With hide_avps set every attribute but
 * Message-Type and Random-Vector goes through the multi block cipher, since
 * encode_attr() always appends at least 16 bytes of padding.
 */
static void test_roundtrip(int hide_avps)
{
	static const char host_name[] = "accel-ppp regression test host name";
	struct l2tp_packet_t *pack;
	const struct l2tp_attr_t *attr;
	int ret;

	pack = l2tp_packet_alloc(2, Message_Type_Hello, &sock_addr, hide_avps,
				 secret, sizeof(secret) - 1);
	CHECK(pack != NULL);
	if (!pack)
		return;

	/* Odd length string first: everything after it sits on an odd offset,
	   so the integer accessors below run unaligned */
	CHECK(l2tp_packet_add_string(pack, Host_Name, host_name, 1) == 0);
	CHECK(l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, 0x1234, 1) == 0);
	CHECK(l2tp_packet_add_int32(pack, Call_Serial_Number, 0x89abcdef, 1) == 0);
	CHECK(l2tp_packet_add_int64(pack, Tie_Breaker, 0x0123456789abcdefULL, 0) == 0);

	ret = l2tp_packet_send(sock, pack);
	CHECK(ret == 0);
	l2tp_packet_free(pack);
	if (ret < 0)
		return;

	pack = NULL;
	CHECK(l2tp_recv(sock, &pack, NULL, secret, sizeof(secret) - 1) == 0);
	CHECK(pack != NULL);
	if (!pack)
		return;

	attr = find_attr(pack, Message_Type);
	CHECK(attr && attr->val.uint16 == Message_Type_Hello);
	attr = find_attr(pack, Host_Name);
	CHECK(attr && attr->length == (int)strlen(host_name));
	CHECK(attr && strcmp(attr->val.string, host_name) == 0);
	attr = find_attr(pack, Assigned_Tunnel_ID);
	CHECK(attr && attr->val.uint16 == 0x1234);
	attr = find_attr(pack, Call_Serial_Number);
	CHECK(attr && attr->val.uint32 == 0x89abcdef);
	attr = find_attr(pack, Tie_Breaker);
	CHECK(attr && attr->val.uint64 == 0x0123456789abcdefULL);

	l2tp_packet_free(pack);
}

/*
 * A hidden AVP deciphered with the wrong secret yields a random length
 * prefix. Whatever it is, the parser must not read outside the AVP.
 */
static void test_wrong_secret(void)
{
	struct l2tp_packet_t *pack;
	struct pktbuf pkt;
	uint8_t buf[1024];
	size_t len, indx;
	int ret;

	pack = l2tp_packet_alloc(2, Message_Type_Hello, &sock_addr, 1,
				 secret, sizeof(secret) - 1);
	CHECK(pack != NULL);
	if (!pack)
		return;

	CHECK(l2tp_packet_add_string(pack, Host_Name, "hidden", 1) == 0);
	CHECK(l2tp_packet_send(sock, pack) == 0);
	l2tp_packet_free(pack);

	len = recv(sock, buf, sizeof(buf), 0);
	CHECK(len > 0);

	/* Same bytes on the wire, every other secret at the receiving end */
	for (indx = 0; indx < 64; ++indx) {
		char wrong[8];

		snprintf(wrong, sizeof(wrong), "wrong%02zu", indx);
		memcpy(pkt.data, buf, len);
		pkt.len = len;

		if (sendto(sock, pkt.data, pkt.len, 0,
			   (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
			perror("sendto");
			exit(1);
		}
		pack = NULL;
		ret = l2tp_recv(sock, &pack, NULL, wrong, strlen(wrong));
		CHECK(ret == 0);
		if (pack) {
			/* Accepting is fine (the random prefix may happen to be
			   plausible), reading out of the AVP is not */
			const struct l2tp_attr_t *attr = find_attr(pack, Host_Name);

			CHECK(!attr || attr->length <= (int)len);
			l2tp_packet_free(pack);
		}
	}
}

int main(void)
{
	loopback_socket();

	test_hidden_avp_length_prefix();
	test_hidden_avp_prerequisites();
	test_roundtrip(0);
	test_roundtrip(1);
	test_wrong_secret();

	close(sock);

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}

	printf("all tests passed\n");

	return 0;
}
