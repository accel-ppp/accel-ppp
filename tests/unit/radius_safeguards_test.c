/* Exercise production response verification and accounting signing with real packets. */
#include <assert.h>
#include "triton.h"
#undef DEFINE_INIT
#define DEFINE_INIT(o, f)
#include "../../accel-pppd/radius/req.c"
#include "../../accel-pppd/radius/packet.c"

static const char *server_secret = "first-secret";
static int healthy, delivered;
int conf_verbose;
char *rad_server_secret_dup(struct rad_server_t *s) { return strdup(server_secret); }
void log_emerg(const char *fmt, ...) {}
void log_ppp_error(const char *fmt, ...) {}
void log_ppp_warn(const char *fmt, ...) {}
void log_switch(struct triton_context_t *ctx, void *arg) {}
struct triton_context_t *triton_context_self(void) { return NULL; }
void rad_server_reply(struct rad_server_t *s) { healthy++; }
void rad_server_req_exit(struct rad_req_t *r) { r->active = 0; }
int rad_server_req_cancel(struct rad_req_t *r, int full) { return 0; }
void *mempool_alloc(mempool_t *p) { return calloc(1, (size_t)p); }
void mempool_free(void *p) { free(p); }
struct rad_dict_attr_t *rad_dict_find_attr_id(struct rad_dict_vendor_t *v, int id) { return NULL; }
struct rad_dict_vendor_t *rad_dict_find_vendor_id(int id) { return NULL; }
struct rad_dict_value_t *rad_dict_find_val(struct rad_dict_attr_t *a, rad_value_t v) { return NULL; }

static void receive_reply(struct rad_req_t *req) { delivered++; }
static void sign_response(unsigned char *buf, int code, const unsigned char *ra, const char *secret)
{
	unsigned char input[256];
	size_t n = strlen(secret);
	memset(buf, 0, 20);
	buf[0] = code;
	buf[1] = 1;
	buf[3] = 20;
	memcpy(input, buf, 4);
	memcpy(input + 4, ra, 16);
	memcpy(input + 20, secret, n);
	MD5(input, 20 + n, buf + 4);
}

int main(void)
{
	struct rad_packet_t request = {.code = CODE_ACCOUNTING_REQUEST, .id = 1, .len = 20};
	struct rad_packet_t response_packet = {.len = 20};
	struct rad_server_t server = {0};
	struct rad_req_t req = {.pack = &request, .serv = &server, .recv = receive_reply};
	unsigned char response[20], expected[16], input[256], first_ra[16];
	int pair[2], code, i;

	packet_pool = (void *)sizeof(struct rad_packet_t);
	buf_pool = (void *)REQ_LENGTH_MAX;
	INIT_LIST_HEAD(&request.attrs);
	assert(!rad_req_set_RA(&req));
	memcpy(first_ra, req.RA, 16);
	memcpy(input, request.buf, 20);
	memset(input + 4, 0, 16);
	memcpy(input + 20, server_secret, strlen(server_secret));
	MD5(input, 20 + strlen(server_secret), expected);
	assert(!memcmp(expected, req.RA, 16));
	/* Rebuilding must zero the previous digest before hashing. */
	assert(!rad_req_set_RA(&req));
	assert(!memcmp(first_ra, req.RA, 16));
	response_packet.buf = response;
	for (i = 0; i < 4; i++) {
		const int codes[] = {CODE_ACCESS_ACCEPT, CODE_ACCESS_REJECT, CODE_ACCESS_CHALLENGE, CODE_ACCOUNTING_RESPONSE};
		code = codes[i];
		sign_response(response, code, request.buf + 4, server_secret);
		assert(!verify_response_authenticator(&req, &response_packet));
		response[4] ^= 1;
		assert(verify_response_authenticator(&req, &response_packet));
		sign_response(response, code, first_ra, "wrong-secret");
		assert(verify_response_authenticator(&req, &response_packet));
	}
	/* An in-flight response still verifies after the configuration changes. */
	sign_response(response, CODE_ACCOUNTING_RESPONSE, first_ra, server_secret);
	server_secret = "second-secret";
	assert(!verify_response_authenticator(&req, &response_packet));
	/* A new accounting send after failover/reload signs with the new secret. */
	assert(!rad_req_set_RA(&req));
	assert(memcmp(first_ra, req.RA, 16));
	assert(verify_response_authenticator(&req, &response_packet));
	sign_response(response, CODE_ACCOUNTING_RESPONSE, req.RA, server_secret);
	assert(!verify_response_authenticator(&req, &response_packet));

	assert(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, pair));
	req.hnd.fd = pair[1];
	response[4] ^= 1;
	assert(write(pair[0], response, 20) == 20);
	assert(!rad_req_read(&req.hnd));
	assert(!healthy && !delivered && !req.reply);
	response[4] ^= 1;
	assert(write(pair[0], response, 20) == 20);
	assert(rad_req_read(&req.hnd) == 1);
	assert(healthy == 1 && delivered == 1 && req.reply);
	rad_packet_free(req.reply);
	/* Outbound Message-Authenticator retransmits must hash a zeroed field. */
	{
		unsigned char wire[38] = {CODE_ACCESS_REQUEST, 1, 0, 38};
		unsigned char first[38], second[38];
		struct rad_packet_t access = {
			.buf = wire, .len = sizeof(wire), .message_authenticator = 1,
			.secret = (uint8_t *)"blast-secret"
		};
		wire[20] = 80;
		wire[21] = 18;
		assert(!rad_packet_send(&access, pair[0], NULL));
		assert(read(pair[1], first, sizeof(first)) == sizeof(first));
		assert(!rad_packet_send(&access, pair[0], NULL));
		assert(read(pair[1], second, sizeof(second)) == sizeof(second));
		assert(!memcmp(first, second, sizeof(first)));
	}
	close(pair[0]);
	close(pair[1]);
	free(request.secret);
	free(request.buf);
	puts("RADIUS safeguards: PASS");
	return 0;
}
