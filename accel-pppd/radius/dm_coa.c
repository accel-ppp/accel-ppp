#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/md5.h>

#include "triton.h"
#include "events.h"
#include "log.h"

#include "radius_p.h"
#include "attr_defs.h"

#include "memdebug.h"

#define PD_COA_PORT 3799

struct dm_coa_serv_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
};

static struct dm_coa_serv_t serv;

static int dm_coa_check_RA(struct rad_packet_t *pack, const char *secret)
{
	uint8_t RA[16];
	MD5_CTX ctx;

	memset(RA, 0, 16);

	MD5_Init(&ctx);
	MD5_Update(&ctx, pack->buf, 4);
	MD5_Update(&ctx, RA, 16);
	MD5_Update(&ctx, pack->buf + 20, pack->len - 20);
	MD5_Update(&ctx, secret, strlen(secret));
	MD5_Final(RA, &ctx);

	return memcmp(RA, pack->buf + 4, 16);
}

static void dm_coa_set_RA(struct rad_packet_t *pack, const char *secret)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, pack->buf, pack->len);
	MD5_Update(&ctx, secret, strlen(secret));
	MD5_Final(pack->buf + 4, &ctx);
}

static int dm_coa_send_ack(int fd, struct rad_packet_t *req, struct sockaddr_in *addr)
{
	struct rad_packet_t *reply;
	uint8_t RA[16];

	memcpy(RA, req->buf + 4, sizeof(RA));

	reply = rad_packet_alloc(req->code == CODE_COA_REQUEST ? CODE_COA_ACK : CODE_DISCONNECT_ACK);
	if (!reply)
		return -1;

	reply->id = req->id;

	if (rad_packet_build(reply, RA)) {
		rad_packet_free(reply);
		return -1;
	}

	dm_coa_set_RA(reply, conf_dm_coa_secret);

	if (conf_verbose) {
		log_ppp_info2("send ");
		rad_packet_print(reply, NULL, log_ppp_info2);
	}

	rad_packet_send(reply, fd, addr);

	rad_packet_free(reply);

	return 0;
}

static int dm_coa_send_nak(int fd, struct rad_packet_t *req, struct sockaddr_in *addr, int err_code)
{
	struct rad_packet_t *reply;
	uint8_t RA[16];

	memcpy(RA, req->buf + 4, sizeof(RA));

	reply = rad_packet_alloc(req->code == CODE_COA_REQUEST ? CODE_COA_NAK : CODE_DISCONNECT_NAK);
	if (!reply)
		return -1;

	reply->id = req->id;

	if (err_code)
		rad_packet_add_int(reply, NULL, "Error-Cause", err_code);

	// TODO: We need to add Message-Authenticator attribute here
	if (rad_packet_build(reply, RA)) {
		rad_packet_free(reply);
		return -1;
	}

	dm_coa_set_RA(reply, conf_dm_coa_secret);

	if (conf_verbose) {
		log_ppp_info2("send ");
		rad_packet_print(reply, NULL, log_ppp_info2);
	}

	rad_packet_send(reply, fd, addr);

	rad_packet_free(reply);

	return 0;
}


static void disconnect_request(struct radius_pd_t *rpd)
{
	if (conf_verbose) {
		log_ppp_info2("recv ");
		rad_packet_print(rpd->dm_coa_req, NULL, log_ppp_info2);
	}

	dm_coa_send_ack(serv.hnd.fd, rpd->dm_coa_req, &rpd->dm_coa_addr);

	rad_packet_free(rpd->dm_coa_req);

	pthread_mutex_lock(&rpd->lock);
	rpd->dm_coa_req = NULL;
	pthread_mutex_unlock(&rpd->lock);

	ap_session_terminate(rpd->ses, TERM_ADMIN_RESET, 0);
}

#ifdef HAVE_VRF
int rad_update_vrf(struct radius_pd_t *rpd, const char *vrf_name)
{
	if (*vrf_name == '0') {
		// Delete interface from VRF
		if (!ap_session_vrf(rpd->ses, NULL, 0))
			return 1;
	}
	else {
		// Add interface to VRF
		if(!ap_session_vrf(rpd->ses, vrf_name, -1))
			return 1;
	}

	return 0;
}
#endif

static void coa_request(struct radius_pd_t *rpd)
{
	struct rad_attr_t *class;
	struct rad_attr_t *attr;
	void *prev_class = rpd->attr_class;
	struct ev_radius_t ev = {
		.ses = rpd->ses,
		.request = rpd->dm_coa_req,
	};

	int send_ack = 0;

	if (conf_verbose) {
		log_ppp_info2("recv ");
		rad_packet_print(rpd->dm_coa_req, NULL, log_ppp_info2);
	}

	triton_event_fire(EV_RADIUS_COA, &ev);

	if (ev.res)
		goto out;
	else {
		class = rad_packet_find_attr(rpd->dm_coa_req, NULL, "Class");
		if (class) {
			if (rpd->attr_class_len < class->len) {
				if (rpd->attr_class)
					_free(rpd->attr_class);
				rpd->attr_class = _malloc(class->len);
			}

			memcpy(rpd->attr_class, class->val.octets, class->len);
			rpd->attr_class_len = class->len;

			if (rpd->acct_req && rpd->acct_req->pack) {
				if (prev_class)
					rad_packet_change_octets(rpd->acct_req->pack, NULL, "Class", rpd->attr_class, rpd->attr_class_len);
				else
					rad_packet_add_octets(rpd->acct_req->pack, NULL, "Class", rpd->attr_class, rpd->attr_class_len);
			}
			send_ack = 1;
			goto out;
		}

		attr = rad_packet_find_attr(rpd->dm_coa_req, NULL, "Session-Timeout");
		if (attr){
			rad_update_session_timeout(rpd, attr->val.integer);
			send_ack = 1;
			goto out;
		}
#ifdef HAVE_VRF
		attr = rad_packet_find_attr(rpd->dm_coa_req, "Accel-PPP", "Accel-VRF-Name");
		if (attr){
			if(!rad_update_vrf(rpd, attr->val.string)){
				goto out;
			}
		}
#endif
		send_ack = 1;
	}

out:
	if (send_ack)
		dm_coa_send_ack(serv.hnd.fd, rpd->dm_coa_req, &rpd->dm_coa_addr);
	else
		dm_coa_send_nak(serv.hnd.fd, rpd->dm_coa_req, &rpd->dm_coa_addr, 0);

	rad_packet_free(rpd->dm_coa_req);

	pthread_mutex_lock(&rpd->lock);
	rpd->dm_coa_req = NULL;
	pthread_mutex_unlock(&rpd->lock);
}

void dm_coa_cancel(struct radius_pd_t *rpd)
{
	triton_cancel_call(rpd->ses->ctrl->ctx, (triton_event_func)disconnect_request);
	triton_cancel_call(rpd->ses->ctrl->ctx, (triton_event_func)coa_request);
	rad_packet_free(rpd->dm_coa_req);
}

static int dm_coa_read(struct triton_md_handler_t *h)
{
	struct rad_packet_t *pack;
	struct radius_pd_t *rpd;
	int err_code;
	struct sockaddr_in addr;

	while (1) {
		if (rad_packet_recv(h->fd, &pack, &addr))
			return 0;

		if (!pack)
			continue;

		if (pack->code != CODE_DISCONNECT_REQUEST && pack->code != CODE_COA_REQUEST) {
			log_warn("radius:dm_coa: unexpected code (%i) received\n", pack->code);
			goto out_err_no_reply;
		}

		if (conf_verbose) {
			log_debug("recv ");
			rad_packet_print(pack, NULL, log_debug);
		}

		if (dm_coa_check_RA(pack, conf_dm_coa_secret)) {
			log_warn("radius:dm_coa: RA validation failed\n");
			goto out_err_no_reply;
		}

		if (rad_check_nas_pack(pack)) {
			log_warn("radius:dm_coa: NAS identification failed\n");
			err_code = 403;
			goto out_err;
		}

		rpd = rad_find_session_pack(pack);
		if (!rpd) {
			log_warn("radius:dm_coa: session not found\n");
			err_code = 503;
			goto out_err;
		}

		if (rpd->dm_coa_req) {
			pthread_mutex_unlock(&rpd->lock);
			goto out_err_no_reply;
		}

		rpd->dm_coa_req = pack;
		memcpy(&rpd->dm_coa_addr, &addr, sizeof(addr));

		if (pack->code == CODE_DISCONNECT_REQUEST)
			triton_context_call(rpd->ses->ctrl->ctx, (triton_event_func)disconnect_request, rpd);
		else
			triton_context_call(rpd->ses->ctrl->ctx, (triton_event_func)coa_request, rpd);

		pthread_mutex_unlock(&rpd->lock);

		continue;

	out_err:
		dm_coa_send_nak(h->fd, pack, &addr, err_code);

	out_err_no_reply:
		rad_packet_free(pack);
	}
}

static void dm_coa_close(struct triton_context_t *ctx)
{
	struct dm_coa_serv_t *serv = container_of(ctx, typeof(*serv), ctx);
	triton_md_unregister_handler(&serv->hnd, 1);
	triton_context_unregister(ctx);
}

static struct dm_coa_serv_t serv = {
	.ctx.close = dm_coa_close,
	.ctx.before_switch = log_switch,
	.hnd.read = dm_coa_read,
};

static void init(void)
{
	struct sockaddr_in addr;

	if (!conf_dm_coa_secret) {
		log_emerg("radius: no dm_coa_secret specified, DM/CoA disabled...\n");
		return;
	}

	serv.hnd.fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (serv.hnd.fd < 0) {
		log_emerg("radius:dm_coa: socket: %s\n", strerror(errno));
		return;
	}

	if ( !conf_dm_coa_bind_default && ( 0 > setsockopt(serv.hnd.fd, SOL_SOCKET, SO_BINDTODEVICE, conf_dm_coa_bind_device, strlen(conf_dm_coa_bind_device)) ) )
        {
		log_emerg("radius:dm_coa: failed set bind device '%s' in setsockopt: %s\n", conf_dm_coa_bind_device, strerror(errno));
		close(serv.hnd.fd);
		return;
	}

	fcntl(serv.hnd.fd, F_SETFD, fcntl(serv.hnd.fd, F_GETFD) | FD_CLOEXEC);

	addr.sin_family = AF_INET;
	addr.sin_port = htons (conf_dm_coa_port);
	if (conf_dm_coa_server)
		addr.sin_addr.s_addr = conf_dm_coa_server;
	else
		addr.sin_addr.s_addr = htonl (INADDR_ANY);
	if (bind (serv.hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		log_emerg("radius:dm_coa: bind: %s\n", strerror(errno));
		close(serv.hnd.fd);
		return;
	}

	if (fcntl(serv.hnd.fd, F_SETFL, O_NONBLOCK)) {
		log_emerg("radius:dm_coa: failed to set nonblocking mode: %s\n", strerror(errno));
		close(serv.hnd.fd);
		return;
	}

	triton_context_register(&serv.ctx, NULL);
	triton_md_register_handler(&serv.ctx, &serv.hnd);
	triton_md_enable_handler(&serv.hnd, MD_MODE_READ);
	triton_context_wakeup(&serv.ctx);
}

DEFINE_INIT(52, init);
