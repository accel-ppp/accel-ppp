#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <byteswap.h>
#include <arpa/inet.h>

#include "crypto.h"

#include "log.h"
#include "ppp.h"
#include "events.h"
#include "ppp_auth.h"
#include "ppp_lcp.h"
#include "pwdb.h"

#include "memdebug.h"

#define MSCHAP_V1 0x80

#define CHAP_CHALLENGE 1
#define CHAP_RESPONSE  2
#define CHAP_SUCCESS   3
#define CHAP_FAILURE   4

#define VALUE_SIZE 8
#define RESPONSE_VALUE_SIZE (24+24+1)

#define HDR_LEN (sizeof(struct chap_hdr)-2)

static int conf_timeout = 5;
static int conf_interval = 0;
static int conf_max_failure = 3;
static int conf_any_login = 0;
static char *conf_msg_failure = "E=691 R=0";
static char *conf_msg_success = "Authentication succeeded";

struct chap_hdr {
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

struct chap_challenge {
	struct chap_hdr hdr;
	uint8_t val_size;
	uint8_t val[VALUE_SIZE];
	char name[0];
} __attribute__((packed));

struct chap_response {
	struct chap_hdr hdr;
	uint8_t val_size;
	uint8_t lm_hash[24];
	uint8_t nt_hash[24];
	uint8_t flags;
	char name[0];
} __attribute__((packed));

struct chap_auth_data {
	struct auth_data_t auth;
	struct ppp_handler_t h;
	struct ppp_t *ppp;
	uint8_t id;
	uint8_t val[VALUE_SIZE];
	struct triton_timer_t timeout;
	struct triton_timer_t interval;
	int failure;
	char *name;
	char *mschap_error;
	unsigned int started:1;
};

static void chap_send_challenge(struct chap_auth_data *ad, int new);
static void chap_recv(struct ppp_handler_t *h);
static int chap_check_response(struct chap_auth_data *ad, struct chap_response *res, const char *name);
static void chap_timeout_timer(struct triton_timer_t *t);
static void chap_restart_timer(struct triton_timer_t *t);
static void set_mppe_keys(struct chap_auth_data *ad, uint8_t *z_hash);

static void print_buf(const uint8_t *buf,int size)
{
	int i;
	for (i = 0; i < size; i++)
		log_ppp_info2("%x", buf[i]);
}
static void print_str(const char *buf, int size)
{
	int i;
	for(i = 0; i < size; i++)
		log_ppp_info2("%c", buf[i]);
}

static struct auth_data_t* auth_data_init(struct ppp_t *ppp)
{
	struct chap_auth_data *d = _malloc(sizeof(*d));

	memset(d, 0, sizeof(*d));
	d->auth.proto = PPP_CHAP;
	d->auth.len = 1;
	d->ppp = ppp;

	return &d->auth;
}

static void auth_data_free(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data *d = container_of(auth, typeof(*d), auth);

	if (d->timeout.tpd)
		triton_timer_del(&d->timeout);

	if (d->interval.tpd)
		triton_timer_del(&d->interval);

	_free(d);
}

static int chap_start(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data *d = container_of(auth, typeof(*d), auth);

	d->h.proto = PPP_CHAP;
	d->h.recv = chap_recv;
	d->timeout.expire = chap_timeout_timer;
	d->timeout.period = conf_timeout * 1000;
	d->interval.expire = chap_restart_timer;
	d->interval.period = conf_interval * 1000;
	d->id = 1;
	d->name = NULL;

	ppp_register_chan_handler(ppp, &d->h);

	chap_send_challenge(d, 1);

	return 0;
}

static int chap_finish(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data *d = container_of(auth, typeof(*d), auth);

	if (d->timeout.tpd)
		triton_timer_del(&d->timeout);

	if (d->interval.tpd)
		triton_timer_del(&d->interval);

	if (d->name)
		_free(d->name);

	ppp_unregister_handler(ppp, &d->h);

	return 0;
}

static void chap_timeout_timer(struct triton_timer_t *t)
{
	struct chap_auth_data *d = container_of(t, typeof(*d), timeout);

	if (conf_ppp_verbose)
		log_ppp_warn("mschap-v1: timeout\n");

	if (++d->failure == conf_max_failure) {
		if (d->started)
			ap_session_terminate(&d->ppp->ses, TERM_USER_ERROR, 0);
		else
			ppp_auth_failed(d->ppp, NULL);
	} else
		chap_send_challenge(d, 0);
}

static void chap_restart_timer(struct triton_timer_t *t)
{
	struct chap_auth_data *d = container_of(t, typeof(*d), interval);

	chap_send_challenge(d, 1);
}

static int lcp_send_conf_req(struct ppp_t *ppp, struct auth_data_t *d, uint8_t *ptr)
{
	*ptr = MSCHAP_V1;
	return 1;
}

static void chap_send_failure(struct chap_auth_data *ad, char *mschap_error)
{
	struct chap_hdr *hdr = _malloc(sizeof(*hdr) + strlen(mschap_error) + 1);
	hdr->proto = htons(PPP_CHAP);
	hdr->code = CHAP_FAILURE;
	hdr->id = ad->id;
	hdr->len = htons(HDR_LEN + strlen(mschap_error));
	strcpy((char *)(hdr + 1), mschap_error);

	if (conf_ppp_verbose)
		log_ppp_info2("send [MSCHAP-v1 Failure id=%x \"%s\"]\n", hdr->id, mschap_error);

	ppp_chan_send(ad->ppp, hdr, ntohs(hdr->len) + 2);

	_free(hdr);
}

static void chap_send_success(struct chap_auth_data *ad, int id)
{
	struct chap_hdr *hdr = _malloc(sizeof(*hdr) + strlen(conf_msg_success) + 1);
	hdr->proto = htons(PPP_CHAP);
	hdr->code = CHAP_SUCCESS;
	hdr->id = id;
	hdr->len = htons(HDR_LEN + strlen(conf_msg_success));
	strcpy((char *)(hdr + 1), conf_msg_success);

	if (conf_ppp_verbose)
		log_ppp_info2("send [MSCHAP-v1 Success id=%x \"%s\"]\n", hdr->id, conf_msg_success);

	ppp_chan_send(ad->ppp, hdr, ntohs(hdr->len) + 2);

	_free(hdr);
}

static void chap_send_challenge(struct chap_auth_data *ad, int new)
{
	struct chap_challenge msg = {
		.hdr.proto = htons(PPP_CHAP),
		.hdr.code = CHAP_CHALLENGE,
		.hdr.id = ad->id,
		.hdr.len = htons(sizeof(msg) - 2),
		.val_size = VALUE_SIZE,
	};

	if (new)
		read(urandom_fd, ad->val, VALUE_SIZE);

	memcpy(msg.val, ad->val, VALUE_SIZE);

	if (conf_ppp_verbose) {
		log_ppp_info2("send [MSCHAP-v1 Challenge id=%x <", msg.hdr.id);
		print_buf(msg.val, VALUE_SIZE);
		log_ppp_info2(">]\n");
	}

	ppp_chan_send(ad->ppp, &msg, ntohs(msg.hdr.len) + 2);

	if (conf_timeout && !ad->timeout.tpd)
		triton_timer_add(ad->ppp->ses.ctrl->ctx, &ad->timeout, 0);
}

static void auth_result(struct chap_auth_data *ad, int res)
{
	char *name = ad->name;

	ad->name = NULL;

	if (res == PWDB_DENIED) {
		chap_send_failure(ad, ad->mschap_error);
		if (ad->started) {
			ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
			_free(name);
		} else
			ppp_auth_failed(ad->ppp, name);
	} else {
		if (!ad->started) {
			if (ppp_auth_succeeded(ad->ppp, name)) {
				chap_send_failure(ad, ad->mschap_error);
				ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
			} else {
				chap_send_success(ad, ad->id);
				ad->started = 1;
				if (conf_interval)
					triton_timer_add(ad->ppp->ses.ctrl->ctx, &ad->interval, 0);
			}
		} else {
			chap_send_success(ad, ad->id);
		}
	}

	ad->id++;

	if (ad->mschap_error != conf_msg_failure) {
		_free(ad->mschap_error);
		ad->mschap_error = conf_msg_failure;
	}
}

static void chap_recv_response(struct chap_auth_data *ad, struct chap_hdr *hdr)
{
	struct chap_response *msg = (struct chap_response*)hdr;
	char *name;
	int r;

	if (ad->timeout.tpd)
		triton_timer_del(&ad->timeout);

	if (conf_ppp_verbose) {
		log_ppp_info2("recv [MSCHAP-v1 Response id=%x <", msg->hdr.id);
		print_buf(msg->lm_hash, 24);
		log_ppp_info2(">, <");
		print_buf(msg->nt_hash, 24);
		log_ppp_info2(">, F=%i, name=\"", msg->flags);
		print_str(msg->name, ntohs(msg->hdr.len) - sizeof(*msg) + 2);
		log_ppp_info2("\"]\n");
	}

	if (ad->started && msg->hdr.id == ad->id - 1) {
		chap_send_success(ad, msg->hdr.id);
		return;
	}

	if (ad->name)
		return;

	if (msg->hdr.id != ad->id) {
		if (conf_ppp_verbose)
			log_ppp_warn("mschap-v1: id mismatch\n");
		return;
	}

	if (msg->val_size != RESPONSE_VALUE_SIZE)	{
		log_ppp_error("mschap-v1: incorrect value-size (%i)\n", msg->val_size);
		if (ad->started)
			ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
		else
			ppp_auth_failed(ad->ppp, NULL);
		return;
	}

	name = _strndup(msg->name, ntohs(msg->hdr.len) - sizeof(*msg) + 2);
	if (!name) {
		log_emerg("mschap-v1: out of memory\n");
		if (ad->started)
			ap_session_terminate(&ad->ppp->ses, TERM_NAS_ERROR, 0);
		else
			ppp_auth_failed(ad->ppp, NULL);
		return;
	}

	if (conf_any_login) {
		if (ppp_auth_succeeded(ad->ppp, name)) {
			chap_send_failure(ad, ad->mschap_error);
			ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
			return;
		}
		chap_send_success(ad, ad->id);
		ad->started = 1;
		ad->id++;
		return;
	}

	ad->mschap_error = conf_msg_failure;

	r = pwdb_check(&ad->ppp->ses, (pwdb_callback)auth_result, ad, name, PPP_CHAP, MSCHAP_V1, ad->id, ad->val, VALUE_SIZE, msg->lm_hash, msg->nt_hash, msg->flags, &ad->mschap_error);

	if (r == PWDB_WAIT) {
		ad->name = name;
		return;
	}

	if (r == PWDB_NO_IMPL)
		if (chap_check_response(ad, msg, name))
			r = PWDB_DENIED;

	if (r == PWDB_DENIED) {
		chap_send_failure(ad, ad->mschap_error);
		if (ad->started) {
			ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
			_free(name);
		} else
			ppp_auth_failed(ad->ppp, name);
		if (ad->mschap_error != conf_msg_failure) {
			_free(ad->mschap_error);
			ad->mschap_error = conf_msg_failure;
		}
	} else {
		if (!ad->started) {
			if (ppp_auth_succeeded(ad->ppp, name)) {
				chap_send_failure(ad, ad->mschap_error);
				ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
			} else {
				chap_send_success(ad, ad->id);
				ad->started = 1;
				if (conf_interval)
					triton_timer_add(ad->ppp->ses.ctrl->ctx, &ad->interval, 0);
			}
		} else {
			chap_send_success(ad, ad->id);
			_free(name);
		}

		ad->id++;
	}
}

static void des_encrypt(const uint8_t *input, const uint8_t *key, uint8_t *output)
{
	int i, j, parity;
	union
	{
		uint64_t u64;
		uint8_t buf[8];
	} p_key;
	DES_cblock cb;
	DES_cblock res;
	DES_key_schedule ks;

	memcpy(p_key.buf, key, 7);
	p_key.u64 = be64toh(p_key.u64);

	for (i = 0; i < 8; i++) {
		cb[i] = (((p_key.u64 << (7 * i)) >> 56) & 0xfe);
		for( j = 0, parity = 0; j < 7; j++)
			if ((cb[i] >> (j + 1)) & 1)
				parity++;
		cb[i] |= (~parity) & 1;
	}

	DES_set_key_checked(&cb, &ks);
	memcpy(cb, input, 8);
	DES_ecb_encrypt(&cb, &res, &ks, DES_ENCRYPT);
	memcpy(output, res, 8);
}

static int chap_check_response(struct chap_auth_data *ad, struct chap_response *msg, const char *name)
{
	MD4_CTX md4_ctx;
	uint8_t z_hash[21];
	uint8_t nt_hash[24];
	char *passwd;
	char *u_passwd;
	int i;

	passwd = pwdb_get_passwd(&ad->ppp->ses, name);
	if (!passwd) {
		if (conf_ppp_verbose)
			log_ppp_warn("mschap-v1: user not found\n");
		return PWDB_DENIED;
	}

	u_passwd = _malloc(strlen(passwd) * 2);
	for (i = 0; i< strlen(passwd); i++) {
		u_passwd[i * 2] = passwd[i];
		u_passwd[i * 2 + 1] = 0;
	}

	memset(z_hash, 0, sizeof(z_hash));
	MD4_Init(&md4_ctx);
	MD4_Update(&md4_ctx, u_passwd, strlen(passwd) * 2);
	MD4_Final(z_hash, &md4_ctx);

	des_encrypt(ad->val, z_hash, nt_hash);
	des_encrypt(ad->val, z_hash + 7, nt_hash + 8);
	des_encrypt(ad->val, z_hash + 14, nt_hash + 16);

	set_mppe_keys(ad, z_hash);

	_free(passwd);
	_free(u_passwd);

	return memcmp(nt_hash, msg->nt_hash, 24) ? PWDB_DENIED : PWDB_SUCCESS;
}

static int chap_check(uint8_t *ptr)
{
	return *ptr == MSCHAP_V1;
}

static void set_mppe_keys(struct chap_auth_data *ad, uint8_t *z_hash)
{
	MD4_CTX md4_ctx;
	SHA_CTX sha_ctx;
	uint8_t digest[20];

	struct ev_mppe_keys_t ev_mppe = {
		.ppp = ad->ppp,
		.policy = -1,
		.recv_key = digest,
		.send_key = digest,
	};

	//NtPasswordHashHash
	MD4_Init(&md4_ctx);
	MD4_Update(&md4_ctx, z_hash, 16);
	MD4_Final(digest, &md4_ctx);

	//Get_Start_Key
	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, digest, 16);
	SHA1_Update(&sha_ctx, digest, 16);
	SHA1_Update(&sha_ctx, ad->val, VALUE_SIZE);
	SHA1_Final(digest, &sha_ctx);

	triton_event_fire(EV_MPPE_KEYS, &ev_mppe);
}

static int chap_restart(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data *d = container_of(auth, typeof(*d), auth);

	chap_send_challenge(d, 1);

	return 0;
}

static struct ppp_auth_handler_t chap = {
	.name          = "MSCHAP-v1",
	.init          = auth_data_init,
	.free          = auth_data_free,
	.send_conf_req = lcp_send_conf_req,
	.start         = chap_start,
	.finish        = chap_finish,
	.check         = chap_check,
	.restart       = chap_restart,
};

static void chap_recv(struct ppp_handler_t *h)
{
	struct chap_auth_data *d = container_of(h, typeof(*d), h);
	struct chap_hdr *hdr = (struct chap_hdr *)d->ppp->buf;

	if (d->ppp->buf_size < sizeof(*hdr) || ntohs(hdr->len) < HDR_LEN || ntohs(hdr->len) > d->ppp->buf_size - 2) {
		log_ppp_warn("mschap-v1: short packet received\n");
		return;
	}

	if (hdr->code == CHAP_RESPONSE)
		chap_recv_response(d, hdr);
	else
		log_ppp_warn("mschap-v1: unknown code received %x\n", hdr->code);
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("auth", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("auth", "interval");
	if (opt && atoi(opt) > 0)
		conf_interval = atoi(opt);

	opt = conf_get_opt("auth", "max-failure");
	if (opt && atoi(opt) > 0)
		conf_max_failure = atoi(opt);

	opt = conf_get_opt("auth", "any-login");
	if (opt)
		conf_any_login = atoi(opt);
}

static void auth_mschap_v1_init()
{
	load_config();

	if (ppp_auth_register_handler(&chap))
		log_emerg("mschap-v1: failed to register handler\n");

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(4, auth_mschap_v1_init);
