#include <stdlib.h>
#include <string.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include "triton.h"
#include "mempool.h"
#include "events.h"
#include "log.h"
#include "pwdb.h"

#include "radius_p.h"
#include "attr_defs.h"

#include "memdebug.h"

static int decrypt_chap_mppe_keys(struct rad_req_t *req, struct rad_attr_t *attr, const uint8_t *challenge, uint8_t *key)
{
	MD5_CTX md5_ctx;
	SHA_CTX sha1_ctx;
	uint8_t md5[MD5_DIGEST_LENGTH];
	uint8_t sha1[SHA_DIGEST_LENGTH];
	uint8_t plain[32];
	int i;

	if (attr->len != 32) {
		log_ppp_warn("radius: %s: incorrect attribute length (%i)\n", attr->attr->name, attr->len);
		return -1;
	}

	memcpy(plain, attr->val.octets, 32);

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, req->serv->secret, strlen(req->serv->secret));
	MD5_Update(&md5_ctx, req->pack->buf + 4, 16);
	MD5_Final(md5, &md5_ctx);

	for (i = 0; i < 16; i++)
		plain[i] ^= md5[i];

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, req->serv->secret, strlen(req->serv->secret));
	MD5_Update(&md5_ctx, attr->val.octets, 16);
	MD5_Final(md5, &md5_ctx);

	for (i = 0; i < 16; i++)
		plain[i + 16] ^= md5[i];

	SHA1_Init(&sha1_ctx);
	SHA1_Update(&sha1_ctx, plain + 8, 16);
	SHA1_Update(&sha1_ctx, plain + 8, 16);
	SHA1_Update(&sha1_ctx, challenge, 8);
	SHA1_Final(sha1, &sha1_ctx);

	memcpy(key, sha1, 16);

	return 0;
}

static int decrypt_mppe_key(struct rad_req_t *req, struct rad_attr_t *attr, uint8_t *key)
{
	MD5_CTX md5_ctx;
	uint8_t md5[16];
	uint8_t plain[32];
	int i;

	if (attr->len != 34) {
		log_ppp_warn("radius: %s: incorrect attribute length (%i)\n", attr->attr->name, attr->len);
		return -1;
	}

	if ((attr->val.octets[0] & 0x80) == 0) {
		log_ppp_warn("radius: %s: incorrect salt value (%x)\n", attr->attr->name, attr->len);
		return -1;
	}

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, req->serv->secret, strlen(req->serv->secret));
	MD5_Update(&md5_ctx, req->pack->buf + 4, 16);
	MD5_Update(&md5_ctx, attr->val.octets, 2);
	MD5_Final(md5, &md5_ctx);

	memcpy(plain, attr->val.octets + 2, 32);

	for (i = 0; i < 16; i++)
		plain[i] ^= md5[i];

	if (plain[0] != 16) {
		log_ppp_warn("radius: %s: incorrect key length (%i)\n", attr->attr->name, plain[0]);
		return -1;
	}

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, req->serv->secret, strlen(req->serv->secret));
	MD5_Update(&md5_ctx, attr->val.octets + 2, 16);
	MD5_Final(md5, &md5_ctx);

	plain[16] ^= md5[0];

	memcpy(key, plain + 1, 16);

	return 0;
}


static uint8_t* encrypt_password(const char *passwd, const char *secret, const uint8_t *RA, int *epasswd_len)
{
	uint8_t *epasswd;
	int i, j, chunk_cnt;
	uint8_t b[16], c[16];
	MD5_CTX ctx;

	if (strlen(passwd))
		chunk_cnt = (strlen(passwd) - 1) / 16 + 1;
	else {
		*epasswd_len = 0;
		return (uint8_t *)1;
	}

	epasswd = _malloc(chunk_cnt * 16);
	if (!epasswd) {
		log_emerg("radius: out of memory\n");
		return NULL;
	}

	memset(epasswd, 0, chunk_cnt * 16);
	memcpy(epasswd, passwd, strlen(passwd));
	memcpy(c, RA, 16);

	for (i = 0; i < chunk_cnt; i++) {
		MD5_Init(&ctx);
		MD5_Update(&ctx, secret, strlen(secret));
		MD5_Update(&ctx, c, 16);
		MD5_Final(b, &ctx);

		for(j = 0; j < 16; j++)
			epasswd[i * 16 + j] ^= b[j];

		memcpy(c, epasswd + i * 16, 16);
	}

	*epasswd_len = chunk_cnt * 16;
	return epasswd;
}

static void rad_auth_finalize(struct radius_pd_t *rpd, int r)
{
	hold_pd(rpd);

	if (rpd->auth_ctx)
		rpd->auth_ctx->cb(rpd->auth_ctx->cb_arg, r);

	if (rpd->auth_ctx) {
		if (r == PWDB_SUCCESS) {
			rpd->auth_reply = rpd->auth_ctx->req->reply;
			rpd->auth_ctx->req->reply = NULL;
		}
		rad_req_free(rpd->auth_ctx->req);
		mempool_free(rpd->auth_ctx);
		rpd->auth_ctx = NULL;
	}

	release_pd(rpd);
}

static void rad_auth_recv(struct rad_req_t *req)
{
	struct rad_packet_t *pack = req->reply;
	unsigned int dt;

	triton_timer_del(&req->timeout);

	dt = (req->reply->tv.tv_sec - req->pack->tv.tv_sec) * 1000 + (req->reply->tv.tv_nsec - req->pack->tv.tv_nsec) / 1000000;
	stat_accm_add(req->serv->stat_auth_query_1m, dt);
	stat_accm_add(req->serv->stat_auth_query_5m, dt);

	if (pack->code == CODE_ACCESS_ACCEPT) {
		if (rad_proc_attrs(req)) {
			rad_auth_finalize(req->rpd, PWDB_DENIED);
			return;
		}

		struct ev_radius_t ev = {
			.ses = req->rpd->ses,
			.request = req->pack,
			.reply = pack,
		};
		triton_event_fire(EV_RADIUS_ACCESS_ACCEPT, &ev);
	} else {
		rad_auth_finalize(req->rpd, PWDB_DENIED);
		return;
	}

	if (req->rpd->auth_ctx->recv && req->rpd->auth_ctx->recv(req)) {
		rad_auth_finalize(req->rpd, PWDB_DENIED);
		return;
	}

	req->rpd->authenticated = 1;

	rad_auth_finalize(req->rpd, PWDB_SUCCESS);
}

static void rad_auth_timeout(struct triton_timer_t *t)
{
	struct rad_req_t *req = container_of(t, typeof(*req), timeout);

	rad_server_timeout(req->serv);

	__sync_add_and_fetch(&req->serv->stat_auth_lost, 1);
	stat_accm_add(req->serv->stat_auth_lost_1m, 1);
	stat_accm_add(req->serv->stat_auth_lost_5m, 1);

	if (rad_req_send(req))
		rad_auth_finalize(req->rpd, PWDB_DENIED);
}

static void rad_auth_sent(struct rad_req_t *req, int res)
{
	if (res) {
		rad_auth_finalize(req->rpd, PWDB_DENIED);
		return;
	}

	__sync_add_and_fetch(&req->serv->stat_auth_sent, 1);

	if (!req->hnd.tpd)
		triton_md_register_handler(req->rpd->ses->ctrl->ctx, &req->hnd);

	triton_md_enable_handler(&req->hnd, MD_MODE_READ);

	if (req->timeout.tpd)
		triton_timer_mod(&req->timeout, 0);
	else
		triton_timer_add(req->rpd->ses->ctrl->ctx, &req->timeout, 0);
}

static struct rad_req_t *rad_auth_req_alloc(struct radius_pd_t *rpd, const char *username, int (*recv)(struct rad_req_t *))
{
	struct rad_req_t *req = rad_req_alloc(rpd, CODE_ACCESS_REQUEST, username, 0);

	if (!req)
		return NULL;

	if (conf_sid_in_auth) {
		if (rad_packet_add_str(req->pack, NULL, "Acct-Session-Id", rpd->ses->sessionid))
			goto out;
	}

	if (rpd->attr_state) {
		if (rad_packet_add_octets(req->pack, NULL, "State", rpd->attr_state, rpd->attr_state_len))
			goto out;
	}

	req->hnd.read = rad_req_read;
	req->timeout.expire = rad_auth_timeout;
	req->timeout.expire_tv.tv_sec = conf_timeout;
	req->recv = rad_auth_recv;
	req->sent = rad_auth_sent;
	if (conf_verbose)
		req->log = log_ppp_info1;

	rpd->auth_ctx->recv = recv;
	rpd->auth_ctx->req = req;

	return req;

out:
	rad_req_free(req);
	return NULL;
}

int rad_auth_pap(struct radius_pd_t *rpd, const char *username, va_list args)
{
	struct rad_req_t *req = rad_auth_req_alloc(rpd, username, NULL);
	int r;
	const char *passwd = va_arg(args, const char *);
	uint8_t *epasswd;
	int epasswd_len;

	if (!req)
		return PWDB_DENIED;

	epasswd = encrypt_password(passwd, req->serv->secret, req->RA, &epasswd_len);
	if (!epasswd)
		return PWDB_DENIED;

	r = rad_packet_add_octets(req->pack, NULL, "User-Password", epasswd, epasswd_len);
	if (epasswd_len)
		_free(epasswd);

	if (r)
		return PWDB_DENIED;

	if (rad_req_send(req))
		return PWDB_DENIED;

	return PWDB_WAIT;
}

int rad_auth_chap_md5(struct radius_pd_t *rpd, const char *username, va_list args)
{
	struct rad_req_t *req = rad_auth_req_alloc(rpd, username, NULL);
	uint8_t chap_password[17];
	int id = va_arg(args, int);
	uint8_t *challenge = va_arg(args, uint8_t *);
	int challenge_len = va_arg(args, int);
	uint8_t *response = va_arg(args, uint8_t *);

	if (!req)
		return PWDB_DENIED;

	chap_password[0] = id;
	memcpy(chap_password + 1, response, 16);

	if (challenge_len == 16)
		memcpy(req->RA, challenge, 16);

	if (rad_packet_add_octets(req->pack, NULL, "CHAP-Challenge", challenge, challenge_len))
		return PWDB_DENIED;

	if (rad_packet_add_octets(req->pack, NULL, "CHAP-Password", chap_password, 17))
		return PWDB_DENIED;

	if (rad_req_send(req))
		return PWDB_DENIED;

	return PWDB_WAIT;
}

static void setup_mppe(struct rad_req_t *req, const uint8_t *challenge)
{
	struct rad_attr_t *attr;
	uint8_t mppe_recv_key[16];
	uint8_t mppe_send_key[16];
	struct ev_mppe_keys_t ev_mppe = {
		.ppp = container_of(req->rpd->ses, typeof(struct ppp_t), ses),
	};

	if (!req->rpd->ses->ctrl->ppp)
		return;

	list_for_each_entry(attr, &req->reply->attrs, entry) {
		if (attr->vendor && attr->vendor->id == VENDOR_Microsoft) {
			switch (attr->attr->id) {
				case MS_CHAP_MPPE_Keys:
					if (decrypt_chap_mppe_keys(req, attr, challenge, mppe_recv_key))
						continue;
					ev_mppe.recv_key = mppe_recv_key;
					ev_mppe.send_key = mppe_recv_key;
					break;
				case MS_MPPE_Recv_Key:
					if (decrypt_mppe_key(req, attr, mppe_recv_key))
						continue;
					ev_mppe.recv_key = mppe_recv_key;
					break;
				case MS_MPPE_Send_Key:
					if (decrypt_mppe_key(req, attr, mppe_send_key))
						continue;
					ev_mppe.send_key = mppe_send_key;
					break;
				case MS_MPPE_Encryption_Policy:
					ev_mppe.policy = attr->val.integer;
					break;
				case MS_MPPE_Encryption_Type:
					ev_mppe.type = attr->val.integer;
					break;
			}
		}
	}

	if (ev_mppe.recv_key && ev_mppe.send_key)
		triton_event_fire(EV_MPPE_KEYS, &ev_mppe);
}

static int rad_auth_mschap_v1_recv(struct rad_req_t *req)
{
	if (req->reply->code == CODE_ACCESS_ACCEPT)
		setup_mppe(req, req->rpd->auth_ctx->challenge);
	else {
		struct rad_attr_t *ra = rad_packet_find_attr(req->reply, "Microsoft", "MS-CHAP-Error");
		if (ra) {
			char **mschap_error = req->rpd->auth_ctx->mschap_error;
			*mschap_error = _malloc(ra->len + 1);
			memcpy(*mschap_error, ra->val.string, ra->len);
			(*mschap_error)[ra->len] = 0;
		}
	}

	return 0;
}

int rad_auth_mschap_v1(struct radius_pd_t *rpd, const char *username, va_list args)
{
	uint8_t response[50];

	int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	int challenge_len = va_arg(args, int);
	const uint8_t *lm_response = va_arg(args, const uint8_t *);
	const uint8_t *nt_response = va_arg(args, const uint8_t *);
	int flags = va_arg(args, int);
	rpd->auth_ctx->mschap_error = va_arg(args, char  **);
	struct rad_req_t *req = rad_auth_req_alloc(rpd, username, rad_auth_mschap_v1_recv);

	if (!req)
		return PWDB_DENIED;

	rpd->auth_ctx->challenge = challenge;

	response[0] = id;
	response[1] = flags;
	memcpy(response + 2, lm_response, 24);
	memcpy(response + 2 + 24, nt_response, 24);

	if (rad_packet_add_octets(req->pack, "Microsoft", "MS-CHAP-Challenge", challenge, challenge_len))
		return PWDB_DENIED;

	if (rad_packet_add_octets(req->pack, "Microsoft", "MS-CHAP-Response", response, sizeof(response)))
		return PWDB_DENIED;

	if (rad_req_send(req))
		return PWDB_DENIED;

	return PWDB_WAIT;
}

static int rad_auth_mschap_v2_recv(struct rad_req_t *req)
{
	struct radius_pd_t *rpd = req->rpd;
	struct rad_attr_t *ra;

	if (req->reply->code == CODE_ACCESS_ACCEPT) {
		ra = rad_packet_find_attr(req->reply, "Microsoft", "MS-CHAP2-Success");
		if (!ra) {
			log_error("radius:auth:mschap-v2: 'MS-CHAP2-Success' not found in radius response\n");
			return -1;
		} else if (ra->len < 43) {
			log_error("radius:auth:mschap-v2: 'MS-CHAP2-Success' too short (%i)\n", ra->len);
			return -1;
		} else
			memcpy(rpd->auth_ctx->authenticator, ra->val.octets + 3, 40);

		setup_mppe(rpd->auth_ctx->req, NULL);
	} else {
		ra = rad_packet_find_attr(req->reply, "Microsoft", "MS-CHAP-Error");
		if (ra) {
			char **mschap_error = req->rpd->auth_ctx->mschap_error;
			*mschap_error = _malloc(ra->len + 1);
			memcpy(*mschap_error, ra->val.string, ra->len);
			(*mschap_error)[ra->len] = 0;
		}

		ra = rad_packet_find_attr(req->reply, NULL, "Reply-Message");
		if (ra) {
			char **reply_msg = req->rpd->auth_ctx->reply_msg;
			*reply_msg = _malloc(ra->len + 1);
			memcpy(*reply_msg, ra->val.string, ra->len);
			(*reply_msg)[ra->len] = 0;
		}
	}

	return 0;
}

int rad_auth_mschap_v2(struct radius_pd_t *rpd, const char *username, va_list args)
{
	uint8_t mschap_response[50];
	struct rad_req_t *req = rad_auth_req_alloc(rpd, username, rad_auth_mschap_v2_recv);

	int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	const uint8_t *peer_challenge = va_arg(args, const uint8_t *);
	const uint8_t *reserved = va_arg(args, const uint8_t *);
	const uint8_t *response = va_arg(args, const uint8_t *);
	int flags = va_arg(args, int);
	rpd->auth_ctx->authenticator = va_arg(args, uint8_t *);
	rpd->auth_ctx->mschap_error = va_arg(args, char **);
	rpd->auth_ctx->reply_msg = va_arg(args, char **);

	if (!req)
		return PWDB_DENIED;

	mschap_response[0] = id;
	mschap_response[1] = flags;
	memcpy(mschap_response + 2, peer_challenge, 16);
	memcpy(mschap_response + 2 + 16, reserved, 8);
	memcpy(mschap_response + 2 + 16 + 8, response, 24);

	if (rad_packet_add_octets(req->pack, "Microsoft", "MS-CHAP-Challenge", challenge, 16))
		return PWDB_DENIED;

	if (rad_packet_add_octets(req->pack, "Microsoft", "MS-CHAP2-Response", mschap_response, sizeof(mschap_response)))
		return PWDB_DENIED;

	if (rad_req_send(req))
		return PWDB_DENIED;

	return PWDB_WAIT;
}

int rad_auth_null(struct radius_pd_t *rpd, const char *username, va_list args)
{
	struct rad_req_t *req = rad_auth_req_alloc(rpd, username, NULL);

	if (!req)
		return PWDB_DENIED;

	if (rad_req_send(req))
		return PWDB_DENIED;

	return PWDB_WAIT;
}

