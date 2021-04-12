#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <byteswap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef CRYPTO_OPENSSL
#include "crypto.h"
#endif

#include "pwdb.h"
#include "ipdb.h"
#include "ppp.h"
#include "ppp_auth.h"
#include "events.h"
#include "triton.h"
#include "log.h"

#include "memdebug.h"

static char *def_chap_secrets = "/etc/ppp/chap-secrets";
static char *conf_chap_secrets;
static int conf_encrypted;
static in_addr_t conf_gw_ip_address = 0;
static int conf_netmask = 0;

static void *pd_key;
static struct ipdb_t ipdb;

#ifdef CRYPTO_OPENSSL
struct hash_chain
{
	struct list_head entry;
	const EVP_MD *md;
};
#endif

struct cs_pd_t
{
	struct ap_private pd;
	struct ipv4db_item_t ip;
	char *passwd;
	char *rate;
	char *pool;
};

#ifdef CRYPTO_OPENSSL
static LIST_HEAD(hash_chain);
#endif

static char *skip_word(char *ptr)
{
	char quote = 0;

	if (*ptr == '\'' || *ptr == '"') {
		quote = *ptr;
		ptr++;
	}

	for(; *ptr; ptr++) {
		if (quote) {
			if (*ptr == '\n')
				break;
			if (*ptr == '\\' && ptr[1] && ptr[1] != '\n') {
				memmove(ptr, ptr + 1, strlen(ptr));
				continue;
			}
			if (*ptr == quote) {
				*ptr = ' ';
				break;
			}
		} else if (*ptr == ' ' || *ptr == '\t' || *ptr == '\n')
			break;
	}

	return ptr;
}

static char *skip_space(char *ptr)
{
	for(; *ptr; ptr++)
		if (*ptr != ' ' && *ptr != '\t')
			break;

	return ptr;
}

static int split(char *buf, char **ptr)
{
	int i;

	for (i = 0; i < 4; i++) {
		buf = skip_word(buf);
		if (!*buf)
			return i;

		*buf = 0;

		buf = skip_space(buf + 1);
		if (!*buf)
			return i;

		if (*buf == '"' || *buf == '\'')
			ptr[i] = buf + 1;
		else
			ptr[i] = buf;
	}

	buf = skip_word(buf);
	//if (*buf == '\n')
		*buf = 0;
	//else if (*buf)
	//	return -1;

	return i;
}


static struct cs_pd_t *create_pd(struct ap_session *ses, const char *username)
{
	FILE *f;
	char *buf;
	char *ptr[5];
	int n;
	struct cs_pd_t *pd;
	struct in_addr in;
#ifdef CRYPTO_OPENSSL
	char username_hash[EVP_MAX_MD_SIZE * 2 + 1];
	uint8_t hash[EVP_MAX_MD_SIZE];
	struct hash_chain *hc;
	EVP_MD_CTX *md_ctx = NULL;
	char c;
	int i;
#endif

	if (!conf_chap_secrets)
		return NULL;

#ifdef CRYPTO_OPENSSL
	if (conf_encrypted && !list_empty(&hash_chain)) {
		unsigned int size = 0;
		list_for_each_entry(hc, &hash_chain, entry) {
			md_ctx = EVP_MD_CTX_new();
			EVP_MD_CTX_init(md_ctx);
			EVP_DigestInit_ex(md_ctx, hc->md, NULL);
			EVP_DigestUpdate(md_ctx, size == 0 ? (void *)username : (void *)hash, size == 0 ? strlen(username) : size);
			EVP_DigestFinal_ex(md_ctx, hash, &size);
			EVP_MD_CTX_free(md_ctx);
			md_ctx = NULL;
		}

		for (n = 0; n < size; n++)
			sprintf(username_hash + n*2, "%02x", hash[n]);

		username = username_hash;
	}
#endif

	f = fopen(conf_chap_secrets, "r");
	if (!f) {
		log_error("chap-secrets: open '%s': %s\n", conf_chap_secrets, strerror(errno));
		return NULL;
	}

	buf = _malloc(4096);
	if (!buf) {
		log_emerg("chap-secrets: out of memory\n");
		fclose(f);
		return NULL;
	}

	while (fgets(buf, 4096, f)) {
		if (buf[0] == '#')
			continue;
		n = split(buf, ptr);
		if (n < 3)
			continue;
		if (*buf == '\'' || *buf == '"') {
			if (!strcmp(buf + 1, username))
				goto found;
		} else {
			if (!strcmp(buf, username))
				goto found;
		}
	}

out:
	fclose(f);
	_free(buf);
	return NULL;

found:
#ifdef CRYPTO_OPENSSL
	if (conf_encrypted && strlen(ptr[1]) != 32)
		goto out;
#endif

	pd = _malloc(sizeof(*pd));
	if (!pd) {
		log_emerg("chap-secrets: out of memory\n");
		goto out;
	}

	memset(pd, 0, sizeof(*pd));
	pd->pd.key = &pd_key;
#ifdef CRYPTO_OPENSSL
	if (conf_encrypted) {
		pd->passwd = _malloc(16);
		if (!pd->passwd) {
			log_emerg("chap-secrets: out of memory\n");
			_free(pd);
			goto out;
		}

		for (i = 0; i < 16; i++) {
			c = ptr[1][i*2 + 2];
			ptr[1][i*2 + 2] = 0;
			pd->passwd[i] = strtol(ptr[1] + i*2, NULL, 16);
			ptr[1][i*2 + 2] = c;
		}
	} else
#endif
	{
		pd->passwd = _strdup(ptr[1]);
		if (!pd->passwd) {
			log_emerg("chap-secrets: out of memory\n");
			_free(pd);
			goto out;
		}
	}

	pd->ip.addr = conf_gw_ip_address;
	if (n >= 3 && !strchr("*-!", ptr[2][0])) {
		if (inet_aton(ptr[2], &in))
			pd->ip.peer_addr = in.s_addr;
		else
			pd->pool = _strdup(ptr[2]);
	}
	pd->ip.mask = conf_netmask;
	pd->ip.owner = &ipdb;

	if (n >= 4)
		pd->rate = _strdup(ptr[3]);

	list_add_tail(&pd->pd.entry, &ses->pd_list);

	fclose(f);
	_free(buf);

	return pd;
}

static struct cs_pd_t *find_pd(struct ap_session *ses)
{
	struct ap_private *pd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key) {
			return container_of(pd, typeof(struct cs_pd_t), pd);
		}
	}

	return NULL;
}

static void ev_ses_finished(struct ap_session *ses)
{
	struct cs_pd_t *pd = find_pd(ses);

	if (!pd)
		return;

	list_del(&pd->pd.entry);
	_free(pd->passwd);
	if (pd->rate)
		_free(pd->rate);
	if (pd->pool)
		_free(pd->pool);
	_free(pd);
}

static void ev_ses_pre_up(struct ap_session *ses)
{
	struct cs_pd_t *pd = find_pd(ses);
	struct ev_shaper_t ev = {
		.ses = ses,
	};

	if (!pd)
		return;

	if (pd->rate) {
		ev.val = pd->rate;
		triton_event_fire(EV_SHAPER, &ev);
	}
}

static struct ipv4db_item_t *get_ip(struct ap_session *ses)
{
	struct cs_pd_t *pd;

	if (!conf_gw_ip_address && ses->ctrl->ppp)
		return NULL;

	pd = find_pd(ses);

	if (!pd)
		return NULL;

	if (pd->pool) {
		if (ses->ipv4_pool_name)
			_free(ses->ipv4_pool_name);
		ses->ipv4_pool_name = _strdup(pd->pool);
/* TODO: wrong to use same pool name, but there's no other syntax
		if (ses->ipv6_pool_name)
			_free(ses->ipv6_pool_name);
		ses->ipv6_pool_name = _strdup(pd->pool);
		if (ses->dpv6_pool_name)
			_free(ses->dpv6_pool_name);
		ses->dpv6_pool_name = _strdup(pd->pool);
*/
		return NULL;
	} else if (!pd->ip.peer_addr)
		return NULL;

	if (!ses->ctrl->ppp)
		pd->ip.addr = 0;

	return &pd->ip;
}

static char* get_passwd(struct pwdb_t *pwdb, struct ap_session *ses, const char *username)
{
	struct cs_pd_t *pd = find_pd(ses);

#ifdef CRYPTO_OPENSSL
	if (conf_encrypted)
		return NULL;
#endif

	if (!pd)
		pd = create_pd(ses, username);

	if (!pd)
		return NULL;

	return _strdup(pd->passwd);
}

#ifdef CRYPTO_OPENSSL
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

static int auth_pap(struct cs_pd_t *pd, const char *username, va_list args)
{
	const char *passwd = va_arg(args, const char *);
	MD4_CTX md4_ctx;
	unsigned char z_hash[21];
	char *u_passwd;
	int i, len = strlen(passwd);

	u_passwd = _malloc(len * 2);
	for (i = 0; i< len; i++) {
		u_passwd[i * 2] = passwd[i];
		u_passwd[i * 2 + 1] = 0;
	}

	memset(z_hash, 0, sizeof(z_hash));
	MD4_Init(&md4_ctx);
	MD4_Update(&md4_ctx, u_passwd, len * 2);
	MD4_Final(z_hash, &md4_ctx);

	_free(u_passwd);

	/*des_encrypt(ad->val, z_hash, nt_hash);
	des_encrypt(ad->val, z_hash + 7, nt_hash + 8);
	des_encrypt(ad->val, z_hash + 14, nt_hash + 16);*/

	if (memcmp(z_hash, pd->passwd, 16))
		return PWDB_DENIED;

	return PWDB_SUCCESS;
}

static int auth_chap_md5(struct cs_pd_t *pd, const char *username, va_list args)
{
	/*int id = va_arg(args, int);
	uint8_t *challenge = va_arg(args, uint8_t *);
	int challenge_len = va_arg(args, int);
	uint8_t *response = va_arg(args, uint8_t *);*/

	return PWDB_NO_IMPL;
}

static void derive_mppe_keys_mschap_v1(struct ap_session *ses, const uint8_t *z_hash, const uint8_t *challenge, int challenge_len)
{
	MD4_CTX md4_ctx;
	SHA_CTX sha_ctx;
	uint8_t digest[20];
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);

	struct ev_mppe_keys_t ev_mppe = {
		.ppp = ppp,
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
	SHA1_Update(&sha_ctx, challenge, challenge_len);
	SHA1_Final(digest, &sha_ctx);

	triton_event_fire(EV_MPPE_KEYS, &ev_mppe);
}

int auth_mschap_v1(struct ap_session *ses, struct cs_pd_t *pd, const char *username, va_list args)
{
	int id __unused = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	int challenge_len = va_arg(args, int);
	const uint8_t *lm_response __unused = va_arg(args, const uint8_t *);
	const uint8_t *nt_response = va_arg(args, const uint8_t *);
	int flags __unused = va_arg(args, int);
	uint8_t z_hash[21];
	uint8_t nt_hash[24];

	memcpy(z_hash, pd->passwd, 16);
	memset(z_hash + 16, 0, sizeof(z_hash) - 16);

	des_encrypt(challenge, z_hash, nt_hash);
	des_encrypt(challenge, z_hash + 7, nt_hash + 8);
	des_encrypt(challenge, z_hash + 14, nt_hash + 16);

	if (memcmp(nt_hash, nt_response, 24))
		return PWDB_DENIED;

	if (ses->ctrl->ppp)
		derive_mppe_keys_mschap_v1(ses, z_hash, challenge, challenge_len);

	return PWDB_SUCCESS;
}

static void generate_mschap_response(const uint8_t *nt_response, const uint8_t *c_hash, const uint8_t *z_hash, char *authenticator)
{
	MD4_CTX md4_ctx;
	SHA_CTX sha_ctx;
	uint8_t pw_hash[MD4_DIGEST_LENGTH];
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


	MD4_Init(&md4_ctx);
	MD4_Update(&md4_ctx, z_hash, 16);
	MD4_Final(pw_hash, &md4_ctx);

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, pw_hash, 16);
	SHA1_Update(&sha_ctx, nt_response, 24);
	SHA1_Update(&sha_ctx, magic1, 39);
	SHA1_Final(response, &sha_ctx);

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, response, 20);
	SHA1_Update(&sha_ctx, c_hash, 8);
	SHA1_Update(&sha_ctx, magic2, 41);
	SHA1_Final(response, &sha_ctx);

	for (i = 0; i < 20; i++)
		sprintf(authenticator + i*2, "%02X", response[i]);
}

static void derive_mppe_keys_mschap_v2(struct ap_session *ses, const uint8_t *z_hash, const uint8_t *nt_hash)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
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
		.ppp = ppp,
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

int auth_mschap_v2(struct ap_session *ses, struct cs_pd_t *pd, const char *username, va_list args)
{
	int id __unused = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	const uint8_t *peer_challenge = va_arg(args, const uint8_t *);
	const uint8_t *reserved __unused = va_arg(args, const uint8_t *);
	const uint8_t *response = va_arg(args, const uint8_t *);
	int flags __unused = va_arg(args, int);
	char *authenticator = va_arg(args, char *);
	uint8_t z_hash[21];
	uint8_t nt_hash[24];
	uint8_t c_hash[SHA_DIGEST_LENGTH];
	SHA_CTX sha_ctx;

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, peer_challenge, 16);
	SHA1_Update(&sha_ctx, challenge, 16);
	SHA1_Update(&sha_ctx, username, strlen(username));
	SHA1_Final(c_hash, &sha_ctx);

	memcpy(z_hash, pd->passwd, 16);
	memset(z_hash + 16, 0, sizeof(z_hash) - 16);

	des_encrypt(c_hash, z_hash, nt_hash);
	des_encrypt(c_hash, z_hash + 7, nt_hash + 8);
	des_encrypt(c_hash, z_hash + 14, nt_hash + 16);

	if (memcmp(nt_hash, response, 24))
		return PWDB_DENIED;

	if (ses->ctrl->ppp)
		derive_mppe_keys_mschap_v2(ses, z_hash, response);

	generate_mschap_response(response, c_hash, z_hash, authenticator);

	return PWDB_SUCCESS;
}

static int check_passwd(struct pwdb_t *pwdb, struct ap_session *ses, pwdb_callback cb, void *cb_arg, const char *username, int type, va_list _args)
{
	va_list args;
	int r = PWDB_NO_IMPL;
	struct cs_pd_t *pd;

	if (!conf_encrypted)
		return PWDB_NO_IMPL;

	pd = find_pd(ses);

	if (!pd)
		pd = create_pd(ses, username);

	if (!pd)
		return PWDB_NO_IMPL;

	va_copy(args, _args);

	switch (type) {
		case PPP_PAP:
			r = auth_pap(pd, username, args);
			break;
		case PPP_CHAP:
			type = va_arg(args, int);
			switch (type) {
				case CHAP_MD5:
					r = auth_chap_md5(pd, username, args);
					break;
				case MSCHAP_V1:
					r = auth_mschap_v1(ses, pd, username, args);
					break;
				case MSCHAP_V2:
					r = auth_mschap_v2(ses, pd, username, args);
					break;
			}
			break;
	}

	va_end(args);

	return r;
}
#endif

static struct ipdb_t ipdb = {
	.get_ipv4 = get_ip,
};

static struct pwdb_t pwdb = {
	.get_passwd = get_passwd,
#ifdef CRYPTO_OPENSSL
	.check = check_passwd,
#endif
};

#ifdef CRYPTO_OPENSSL
static void clear_hash_chain(void)
{
	struct hash_chain *hc;

	while (!list_empty(&hash_chain)) {
		hc = list_entry(hash_chain.next, typeof(*hc), entry);
		list_del(&hc->entry);
		_free(hc);
	}
}

static void parse_hash_chain(const char *opt)
{
	char *str = _strdup(opt);
	char *ptr1 = str, *ptr2;
	struct hash_chain *hc;
	int f = 0;

	while (!f) {
		for (ptr2 = ptr1 + 1; *ptr2 && *ptr2 != ','; ptr2++);
		f = *ptr2 == 0;
		*ptr2 = 0;
		hc = _malloc(sizeof(*hc));
		hc->md = EVP_get_digestbyname(ptr1);
		if (!hc->md) {
			log_error("chap-secrets: digest '%s' is unavailable\n", ptr1);
			_free(hc);
			return;
		}
		list_add_tail(&hc->entry, &hash_chain);
		ptr1 = ptr2 + 1;
	}
}
#endif

static void parse_gw_ip_address(const char *opt)
{
	char addr[17];
	const char *ptr = strchr(opt, '/');

	if (ptr) {
		memcpy(addr, opt, ptr - opt);
		addr[ptr - opt] = 0;
		conf_gw_ip_address = inet_addr(addr);
		conf_netmask = atoi(ptr + 1);
		if (conf_netmask < 0 || conf_netmask > 32) {
			log_error("chap-secrets: invalid netmask %i\n", conf_netmask);
			conf_netmask = 32;
		}
	} else {
		conf_gw_ip_address = inet_addr(opt);
		conf_netmask = 32;
	}
}

static void load_config(void)
{
	const char *opt;

	if (conf_chap_secrets && conf_chap_secrets != def_chap_secrets)
		_free(conf_chap_secrets);
	opt = conf_get_opt("chap-secrets", "chap-secrets");
	if (opt)
		conf_chap_secrets = _strdup(opt);
	else
		conf_chap_secrets = def_chap_secrets;

	opt = conf_get_opt("chap-secrets", "gw-ip-address");
	if (opt)
		parse_gw_ip_address(opt);
	else {
		conf_gw_ip_address = 0;
		conf_netmask = 0;
	}

	opt = conf_get_opt("chap-secrets", "encrypted");
	if (opt)
		conf_encrypted = atoi(opt);
	else
		conf_encrypted = 0;

#ifdef CRYPTO_OPENSSL
	clear_hash_chain();
	opt = conf_get_opt("chap-secrets", "username-hash");
	if (opt)
		parse_hash_chain(opt);
#endif
}

static void init(void)
{
	load_config();

	pwdb_register(&pwdb);
	ipdb_register(&ipdb);

	triton_event_register_handler(EV_SES_FINISHED, (triton_event_func)ev_ses_finished);
	triton_event_register_handler(EV_SES_PRE_UP, (triton_event_func)ev_ses_pre_up);
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(51, init);
