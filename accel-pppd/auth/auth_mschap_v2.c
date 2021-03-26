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

#define MSCHAP_V2 0x81

#define CHAP_CHALLENGE 1
#define CHAP_RESPONSE  2
#define CHAP_SUCCESS   3
#define CHAP_FAILURE   4

#define VALUE_SIZE 16
#define RESPONSE_VALUE_SIZE (16+8+24+1)

#define HDR_LEN (sizeof(struct chap_hdr)-2)

static int conf_timeout = 5;
static int conf_interval = 0;
static int conf_max_failure = 3;
static char *conf_msg_failure = "E=691 R=0 V=3";
static char *conf_msg_failure2 = "Authentication failure";
static char *conf_msg_success = "Authentication succeeded";

struct chap_hdr {
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

struct chap_challenge_t {
	struct chap_hdr hdr;
	uint8_t val_size;
	uint8_t val[VALUE_SIZE];
	char name[0];
} __attribute__((packed));

struct chap_response {
	struct chap_hdr hdr;
	uint8_t val_size;
	uint8_t peer_challenge[16];
	uint8_t reserved[8];
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
	char authenticator[41];
	char *name;
	char *mschap_error;
	char *reply_msg;
	int failure;
	unsigned int started:1;
};

static void chap_send_challenge(struct chap_auth_data *ad, int new);
static void chap_recv(struct ppp_handler_t *h);
static int chap_check_response(struct chap_auth_data *ad, struct chap_response *msg, const char *name);
static void chap_timeout_timer(struct triton_timer_t *t);
static void chap_restart_timer(struct triton_timer_t *t);
static void set_mppe_keys(struct chap_auth_data *ad, uint8_t *z_hash, uint8_t *nt_hash);

static void print_buf(const uint8_t *buf, int size)
{
	int i;
	for (i = 0; i < size; i++)
		log_ppp_info2("%x", buf[i]);
}

static void print_str(const char *buf, int size)
{
	int i;
	for (i = 0; i < size; i++)
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

	ppp_unregister_handler(ppp,&d->h);

	return 0;
}

static void chap_timeout_timer(struct triton_timer_t *t)
{
	struct chap_auth_data *d = container_of(t, typeof(*d), timeout);

	if (conf_ppp_verbose)
		log_ppp_warn("mschap-v2: timeout\n");

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
	*ptr = MSCHAP_V2;
	return 1;
}

static void chap_send_failure(struct chap_auth_data *ad, char *mschap_error, char *reply_msg)
{
	struct chap_hdr *hdr = _malloc(sizeof(*hdr) + strlen(mschap_error) + strlen(reply_msg) + 4);
	hdr->proto = htons(PPP_CHAP);
	hdr->code = CHAP_FAILURE;
	hdr->id = ad->id;
	hdr->len = htons(HDR_LEN + strlen(mschap_error) + strlen(reply_msg) + 3);

	sprintf((char *)(hdr + 1), "%s M=%s", mschap_error, reply_msg);

	if (conf_ppp_verbose)
		log_ppp_info2("send [MSCHAP-v2 Failure id=%x \"%s\"]\n", hdr->id, (char *)(hdr + 1));

	ppp_chan_send(ad->ppp, hdr, ntohs(hdr->len) + 2);

	_free(hdr);
}

static void chap_send_success(struct chap_auth_data *ad, int id, const char *authenticator)
{
	struct chap_hdr *hdr = _malloc(sizeof(*hdr) + strlen(conf_msg_success) + 1 +	45);
	hdr->proto = htons(PPP_CHAP),
	hdr->code = CHAP_SUCCESS,
	hdr->id = id,
	hdr->len = htons(HDR_LEN + strlen(conf_msg_success) + 45),

	sprintf((char *)(hdr + 1), "S=%s M=%s", authenticator, conf_msg_success);

	if (conf_ppp_verbose)
		log_ppp_info2("send [MSCHAP-v2 Success id=%x \"%s\"]\n", hdr->id, (char *)(hdr + 1));

	ppp_chan_send(ad->ppp, hdr, ntohs(hdr->len) + 2);

	_free(hdr);
}

static int generate_response(struct chap_auth_data *ad, struct chap_response *msg, const char *name, char *authenticator)
{
	MD4_CTX md4_ctx;
	SHA_CTX sha_ctx;
	char *passwd;
	char *u_passwd;
	uint8_t pw_hash[MD4_DIGEST_LENGTH];
	uint8_t c_hash[SHA_DIGEST_LENGTH];
	uint8_t response[SHA_DIGEST_LENGTH];
	int i;

	uint8_t magic1[39] =
         {0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
          0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
          0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
          0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};
	uint8_t magic2[41] =
         {0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
          0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
          0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
          0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
          0x6E};


	passwd = pwdb_get_passwd(&ad->ppp->ses, name);
	if (!passwd)
		return -1;

	u_passwd=_malloc(strlen(passwd)*2);
	for(i=0; i<strlen(passwd); i++)
	{
		u_passwd[i*2]=passwd[i];
		u_passwd[i*2+1]=0;
	}

	MD4_Init(&md4_ctx);
	MD4_Update(&md4_ctx,u_passwd,strlen(passwd)*2);
	MD4_Final(pw_hash,&md4_ctx);

	MD4_Init(&md4_ctx);
	MD4_Update(&md4_ctx,pw_hash,16);
	MD4_Final(pw_hash,&md4_ctx);

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx,pw_hash,16);
	SHA1_Update(&sha_ctx,msg->nt_hash,24);
	SHA1_Update(&sha_ctx,magic1,39);
	SHA1_Final(response,&sha_ctx);

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx,msg->peer_challenge,16);
	SHA1_Update(&sha_ctx,ad->val,16);
	SHA1_Update(&sha_ctx,name,strlen(name));
	SHA1_Final(c_hash,&sha_ctx);

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx,response,20);
	SHA1_Update(&sha_ctx,c_hash,8);
	SHA1_Update(&sha_ctx,magic2,41);
	SHA1_Final(response,&sha_ctx);

	for(i=0; i<20; i++)
		sprintf(authenticator+i*2,"%02X",response[i]);

	_free(passwd);
	_free(u_passwd);

	return 0;
}

static void chap_send_challenge(struct chap_auth_data *ad, int new)
{
	struct chap_challenge_t msg =	{
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
		log_ppp_info2("send [MSCHAP-v2 Challenge id=%x <", msg.hdr.id);
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
		chap_send_failure(ad, ad->mschap_error, ad->reply_msg);
		if (ad->started) {
			ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
			_free(name);
		} else
			ppp_auth_failed(ad->ppp, name);
	} else {
		if (!ad->started) {
			if (ppp_auth_succeeded(ad->ppp, name)) {
				chap_send_failure(ad, ad->mschap_error, ad->reply_msg);
				ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
			} else {
				chap_send_success(ad, ad->id, ad->authenticator);
				ad->started = 1;
				if (conf_interval)
					triton_timer_add(ad->ppp->ses.ctrl->ctx, &ad->interval, 0);
			}
		} else {
			chap_send_success(ad, ad->id, ad->authenticator);
		}
	}

	ad->id++;

	if (ad->mschap_error != conf_msg_failure) {
		_free(ad->mschap_error);
		ad->mschap_error = conf_msg_failure;
	}

	if (ad->reply_msg != conf_msg_failure2) {
		_free(ad->reply_msg);
		ad->reply_msg = conf_msg_failure2;
	}
}


static void chap_recv_response(struct chap_auth_data *ad, struct chap_hdr *hdr)
{
	struct chap_response *msg = (struct chap_response*)hdr;
	char *name;
	char *authenticator = ad->authenticator;
	int r;

	authenticator[40] = 0;

	if (ad->timeout.tpd)
		triton_timer_del(&ad->timeout);

	if (conf_ppp_verbose) {
		log_ppp_info2("recv [MSCHAP-v2 Response id=%x <", msg->hdr.id);
		print_buf(msg->peer_challenge,16);
		log_ppp_info2(">, <");
		print_buf(msg->nt_hash, 24);
		log_ppp_info2(">, F=%i, name=\"", msg->flags);
		print_str(msg->name, ntohs(msg->hdr.len) - sizeof(*msg) + 2);
		log_ppp_info2("\"]\n");
	}

	if (ad->started && msg->hdr.id == ad->id - 1) {
		chap_send_success(ad, msg->hdr.id, ad->authenticator);
		return;
	}

	if (ad->name)
		return;

	ad->mschap_error = conf_msg_failure;
	ad->reply_msg = conf_msg_failure2;

	if (msg->hdr.id != ad->id) {
		if (conf_ppp_verbose)
			log_ppp_warn("mschap-v2: id mismatch\n");
		return;
	}

	if (msg->val_size != RESPONSE_VALUE_SIZE) {
		log_ppp_error("mschap-v2: incorrect value-size (%i)\n", msg->val_size);
		chap_send_failure(ad, ad->mschap_error, ad->reply_msg);
		if (ad->started)
			ap_session_terminate(&ad->ppp->ses, TERM_USER_ERROR, 0);
		else
			ppp_auth_failed(ad->ppp, NULL);
		return;
	}

	name = _strndup(msg->name, ntohs(msg->hdr.len) - sizeof(*msg) + 2);
	if (!name) {
		log_emerg("mschap-v2: out of memory\n");
		if (ad->started)
			ap_session_terminate(&ad->ppp->ses, TERM_NAS_ERROR, 0);
		else
			ppp_auth_failed(ad->ppp, NULL);
		return;
	}

	r = pwdb_check(&ad->ppp->ses, (pwdb_callback)auth_result, ad, name, PPP_CHAP, MSCHAP_V2, ad->id, ad->val, msg->peer_challenge, msg->reserved, msg->nt_hash, msg->flags, authenticator, &ad->mschap_error, &ad->reply_msg);

	if (r == PWDB_WAIT) {
		ad->name = name;
		return;
	}

	if (r == PWDB_NO_IMPL) {
		r = chap_check_response(ad, msg, name);
		if (r)
			r = PWDB_DENIED;
		else if (generate_response(ad, msg, name, authenticator))
			r = PWDB_DENIED;
	}

	if (r == PWDB_DENIED) {
		chap_send_failure(ad, ad->mschap_error, ad->reply_msg);
		if (ad->started) {
			_free(name);
			ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
		} else
			ppp_auth_failed(ad->ppp, name);

		if (ad->mschap_error != conf_msg_failure) {
			_free(ad->mschap_error);
			ad->mschap_error = conf_msg_failure;
		}

		if (ad->reply_msg != conf_msg_failure2) {
			_free(ad->reply_msg);
			ad->reply_msg = conf_msg_failure2;
		}
	} else {
		if (!ad->started) {
			if (ppp_auth_succeeded(ad->ppp, name)) {
				chap_send_failure(ad, ad->mschap_error, ad->reply_msg);
				ap_session_terminate(&ad->ppp->ses, TERM_AUTH_ERROR, 0);
			} else {
				chap_send_success(ad, ad->id, authenticator);
				ad->started = 1;
				if (conf_interval)
					triton_timer_add(ad->ppp->ses.ctrl->ctx, &ad->interval, 0);
			}
		} else {
			chap_send_success(ad, ad->id, authenticator);
			_free(name);
		}

		ad->id++;
	}
}

static void des_encrypt(const uint8_t *input, const uint8_t *key, uint8_t *output)
{
	int i,j,parity;
	union
	{
		uint64_t u64;
		uint8_t buf[8];
	} p_key;
	DES_cblock cb;
	DES_cblock res;
	DES_key_schedule ks;

	memcpy(p_key.buf,key,7);
	p_key.u64 = be64toh(p_key.u64);

	for(i=0;i<8;i++)
	{
		cb[i]=(((p_key.u64<<(7*i))>>56)&0xfe);
		for(j=0, parity=0; j<7; j++)
			if ((cb[i]>>(j+1))&1) parity++;
		cb[i]|=(~parity)&1;
	}

	DES_set_key_checked(&cb, &ks);
	memcpy(cb,input,8);
	DES_ecb_encrypt(&cb,&res,&ks,DES_ENCRYPT);
	memcpy(output,res,8);
}

static int chap_check_response(struct chap_auth_data *ad, struct chap_response *msg, const char *name)
{
	MD4_CTX md4_ctx;
	SHA_CTX sha_ctx;
	uint8_t z_hash[21];
	uint8_t c_hash[SHA_DIGEST_LENGTH];
	uint8_t nt_hash[24];
	char *passwd;
	char *u_passwd;
	int i;

	passwd = pwdb_get_passwd(&ad->ppp->ses, name);
	if (!passwd) {
		if (conf_ppp_verbose)
			log_ppp_warn("mschap-v2: user not found\n");
		return -1;
	}

	u_passwd = _malloc(strlen(passwd) * 2);
	for (i = 0; i < strlen(passwd); i++) {
		u_passwd[i*2]=passwd[i];
		u_passwd[i*2+1]=0;
	}

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, msg->peer_challenge, 16);
	SHA1_Update(&sha_ctx, ad->val, 16);
	SHA1_Update(&sha_ctx, name, strlen(name));
	SHA1_Final(c_hash, &sha_ctx);

	memset(z_hash, 0, sizeof(z_hash));
	MD4_Init(&md4_ctx);
	MD4_Update(&md4_ctx, u_passwd, strlen(passwd) * 2);
	MD4_Final(z_hash, &md4_ctx);

	des_encrypt(c_hash, z_hash, nt_hash);
	des_encrypt(c_hash, z_hash + 7, nt_hash + 8);
	des_encrypt(c_hash, z_hash + 14, nt_hash + 16);

	set_mppe_keys(ad, z_hash, msg->nt_hash);

	_free(passwd);
	_free(u_passwd);

	return memcmp(nt_hash, msg->nt_hash, 24);
}

static void set_mppe_keys(struct chap_auth_data *ad, uint8_t *z_hash, uint8_t *nt_hash)
{
	MD4_CTX md4_ctx;
	SHA_CTX sha_ctx;
	uint8_t digest[20];
	uint8_t send_key[20];
	uint8_t recv_key[20];

	uint8_t pad1[40] =
   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	uint8_t pad2[40] =
   {0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
    0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
    0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
    0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2};

	uint8_t magic1[27] =
   {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
    0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79};

	uint8_t magic2[84] =
   {0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
    0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
    0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
    0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
    0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
    0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
    0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
    0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
    0x6b, 0x65, 0x79, 0x2e};

	uint8_t magic3[84] =
   {0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
    0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
    0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
    0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
    0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
    0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
    0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
    0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
    0x6b, 0x65, 0x79, 0x2e};

	struct ev_mppe_keys_t ev_mppe = {
		.ppp = ad->ppp,
		.policy = -1,
		.recv_key = recv_key,
		.send_key = send_key,
	};

	//NtPasswordHashHash
	MD4_Init(&md4_ctx);
	MD4_Update(&md4_ctx, z_hash, 16);
	MD4_Final(digest, &md4_ctx);

	//GetMasterKey
	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, digest, 16);
	SHA1_Update(&sha_ctx, nt_hash, 24);
	SHA1_Update(&sha_ctx, magic1, sizeof(magic1));
	SHA1_Final(digest, &sha_ctx);

	//send key
	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, digest, 16);
	SHA1_Update(&sha_ctx, pad1, sizeof(pad1));
	SHA1_Update(&sha_ctx, magic3, sizeof(magic2));
	SHA1_Update(&sha_ctx, pad2, sizeof(pad2));
	SHA1_Final(send_key, &sha_ctx);

	//recv key
	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, digest, 16);
	SHA1_Update(&sha_ctx, pad1, sizeof(pad1));
	SHA1_Update(&sha_ctx, magic2, sizeof(magic3));
	SHA1_Update(&sha_ctx, pad2, sizeof(pad2));
	SHA1_Final(recv_key, &sha_ctx);

	triton_event_fire(EV_MPPE_KEYS, &ev_mppe);
}

static int chap_check(uint8_t *ptr)
{
	return *ptr == MSCHAP_V2;
}

static int chap_restart(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data *d = container_of(auth, typeof(*d), auth);

	chap_send_challenge(d, 1);

	return 0;
}

static struct ppp_auth_handler_t chap=
{
	.name          = "MSCHAP-v2",
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
		log_ppp_warn("mschap-v2: short packet received\n");
		return;
	}

	if (hdr->code == CHAP_RESPONSE)
		chap_recv_response(d, hdr);
	else
		log_ppp_warn("mschap-v2: unknown code received %x\n",hdr->code);
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
}

static void reload_config(void)
{
        config_lock();
        load_config();
        config_unlock();
}

static void auth_mschap_v2_init()
{
	load_config();

	if (ppp_auth_register_handler(&chap))
		log_emerg("mschap-v2: failed to register handler\n");

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_config);
}

DEFINE_INIT(4, auth_mschap_v2_init);
