#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "radius_p.h"
#include "mempool.h"

#include "memdebug.h"

#define HMAC_MD5_LEN 16

static int make_socket(struct rad_req_t *req);
static mempool_t req_pool;

static struct rad_req_t *__rad_req_alloc(struct radius_pd_t *rpd, int code, const char *username, in_addr_t addr, int port, int prio)
{
	struct rad_plugin_t *plugin;
	struct ppp_t *ppp = NULL;
	struct rad_req_t *req = mempool_alloc(req_pool);
	struct timespec ts;

	if (!req) {
		log_emerg("radius: out of memory\n");
		return NULL;
	}

	if (rpd->ses->ctrl->ppp)
		ppp = container_of(rpd->ses, typeof(*ppp), ses);

	clock_gettime(CLOCK_MONOTONIC, &ts);

	memset(req, 0, sizeof(*req));
	req->rpd = rpd;
	req->hnd.fd = -1;
	req->hnd.read = rad_req_read;
	req->ts = ts.tv_sec;

	req->type = code == CODE_ACCESS_REQUEST ? RAD_SERV_AUTH : RAD_SERV_ACCT;
	req->prio = prio;

	if (addr)
		req->serv = rad_server_get2(req->type, addr, port);
	else
		req->serv = rad_server_get(req->type);

	if (!req->serv)
		goto out_err;

	req->server_addr = req->serv->addr;
	req->server_ipv6_addr = req->serv->addr6;
	req->server_port = req->serv->auth_port;

	while (1) {
		if (read(urandom_fd, req->RA, 16) != 16) {
			if (errno == EINTR)
				continue;
			log_ppp_error("radius:req:read urandom: %s\n", strerror(errno));
			goto out_err;
		}
		break;
	}

	if (conf_verbose)
		req->log = log_ppp_info1;

	req->pack = rad_packet_alloc(code);
	if (!req->pack)
		goto out_err;

	if (code == CODE_ACCESS_REQUEST && conf_blast_protection) {
		uint8_t buf[HMAC_MD5_LEN] = {0};
		req->pack->message_authenticator = 1;
		req->pack->secret = strdup(req->serv->secret);
		if (rad_packet_add_octets(req->pack, NULL, "Message-Authenticator", buf, HMAC_MD5_LEN)) {
                        free(req->pack->secret);
                        req->pack->secret == NULL;
			goto out_err;
                }
	}

	if (code == CODE_ACCOUNTING_REQUEST && rpd->acct_username)
		username = rpd->acct_username;

	if (rad_packet_add_str(req->pack, NULL, "User-Name", username))
		goto out_err;

	if (conf_nas_identifier)
		if (rad_packet_add_str(req->pack, NULL, "NAS-Identifier", conf_nas_identifier))
			goto out_err;

	if (conf_nas_ip_address)
		if (rad_packet_add_ipaddr(req->pack, NULL, "NAS-IP-Address", conf_nas_ip_address))
			goto out_err;

	if (rpd->ses->unit_idx != -1 && rad_packet_add_int(req->pack, NULL, "NAS-Port", rpd->ses->unit_idx))
		goto out_err;

	if (conf_nas_port_id_in_req) {
		if (*rpd->ses->ifname && rad_packet_add_str(req->pack, NULL, "NAS-Port-Id", rpd->ses->ifname))
			goto out_err;
	}

	if (req->rpd->ses->ctrl->type == CTRL_TYPE_IPOE) {
		if (rad_packet_add_val(req->pack, NULL, "NAS-Port-Type", "Ethernet"))
			goto out_err;
	} else {
		if (rad_packet_add_val(req->pack, NULL, "NAS-Port-Type", "Virtual"))
			goto out_err;

		if (rad_packet_add_val(req->pack, NULL, "Service-Type", "Framed-User"))
			goto out_err;

		if (rad_packet_add_val(req->pack, NULL, "Framed-Protocol", "PPP"))
			goto out_err;
	}

	if (rpd->ses->ctrl->calling_station_id)
		if (rad_packet_add_str(req->pack, NULL, "Calling-Station-Id", rpd->ses->ctrl->calling_station_id))
			goto out_err;

	if (rpd->ses->ctrl->called_station_id)
		if (rad_packet_add_str(req->pack, NULL, "Called-Station-Id", rpd->ses->ctrl->called_station_id))
			goto out_err;

	if (rpd->attr_class)
		if (rad_packet_add_octets(req->pack, NULL, "Class", rpd->attr_class, rpd->attr_class_len))
			goto out_err;

	if (conf_attr_tunnel_type)
		if (rad_packet_add_str(req->pack, NULL, conf_attr_tunnel_type, rpd->ses->ctrl->name))
			goto out_err;

	list_for_each_entry(plugin, &req->rpd->plugin_list, entry) {
		switch (code) {
			case CODE_ACCESS_REQUEST:
				if (plugin->send_access_request && plugin->send_access_request(plugin, req->pack))
					goto out_err;
				break;
			case CODE_ACCOUNTING_REQUEST:
				if (plugin->send_accounting_request && plugin->send_accounting_request(plugin, req->pack))
					goto out_err;
				break;
		}
	}

	return req;

out_err:
	if (!req->serv)
		log_ppp_error("radius: no servers available\n");
	else
		log_emerg("radius: out of memory\n");
	rad_req_free(req);
	return NULL;
}

struct rad_req_t *rad_req_alloc(struct radius_pd_t *rpd, int code, const char *username, int prio)
{
	return __rad_req_alloc(rpd, code, username, 0, 0, prio);
}

struct rad_req_t *rad_req_alloc2(struct radius_pd_t *rpd, int code, const char *username, in_addr_t addr, int port)
{
	struct rad_req_t *req = __rad_req_alloc(rpd, code, username, addr, port, 0);

	if (!req)
		return NULL;

	if (code == CODE_ACCOUNTING_REQUEST)
		req->server_port = req->serv->acct_port;

	if (make_socket(req)) {
		rad_req_free(req);
		req = NULL;
	}

	return req;
}

struct rad_req_t *rad_req_alloc_empty()
{
	struct rad_req_t *req = mempool_alloc(req_pool);

	if (!req) {
		log_emerg("radius: out of memory\n");
		return NULL;
	}

	memset(req, 0, sizeof(*req));
	req->hnd.fd = -1;

	return req;
}

int rad_req_acct_fill(struct rad_req_t *req)
{
	struct ipv6db_addr_t *a;

	req->server_port = req->serv->acct_port;

	memset(req->RA, 0, sizeof(req->RA));

	if (rad_packet_add_val(req->pack, NULL, "Acct-Status-Type", "Start"))
		return -1;
	if (rad_packet_add_val(req->pack, NULL, "Acct-Authentic", "RADIUS"))
		return -1;
	if (rad_packet_add_str(req->pack, NULL, "Acct-Session-Id", req->rpd->ses->sessionid))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Session-Time", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Input-Octets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Output-Octets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Input-Packets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Output-Packets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Input-Gigawords", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Output-Gigawords", 0))
		return -1;
	if (conf_acct_delay_time) {
		if (rad_packet_add_int(req->pack, NULL, "Acct-Delay-Time", 0))
			return -1;
	}
	if (req->rpd->ses->ipv4) {
		if (rad_packet_add_ipaddr(req->pack, NULL, "Framed-IP-Address", req->rpd->ses->ipv4->peer_addr))
			return -1;
	}
	if (req->rpd->ses->ipv6) {
		if (rad_packet_add_ifid(req->pack, NULL, "Framed-Interface-Id", req->rpd->ses->ipv6->peer_intf_id))
			return -1;
		list_for_each_entry(a, &req->rpd->ses->ipv6->addr_list, entry) {
			if (rad_packet_add_ipv6prefix(req->pack, NULL, "Framed-IPv6-Prefix", &a->addr, a->prefix_len))
				return -1;
		}
	}
	if (req->rpd->ses->ipv6_dp) {
		list_for_each_entry(a, &req->rpd->ses->ipv6_dp->prefix_list, entry) {
		    if (rad_packet_add_ipv6prefix(req->pack, NULL, "Delegated-IPv6-Prefix", &a->addr, a->prefix_len))
			return -1;
		}
		req->rpd->ipv6_dp_sent = 1;
	}

	return 0;
}

void rad_req_free(struct rad_req_t *req)
{
	assert(!req->active);
	assert(!req->entry.next);

	if (req->serv)
		rad_server_put(req->serv, req->type);

	if (req->hnd.tpd)
		triton_md_unregister_handler(&req->hnd, 1);
	else if (req->hnd.fd != -1)
		close(req->hnd.fd);

	if (req->timeout.tpd)
		triton_timer_del(&req->timeout);

	if (req->pack)
		rad_packet_free(req->pack);

	if (req->reply)
		rad_packet_free(req->reply);

	mempool_free(req);
}

static int make_socket(struct rad_req_t *req)
{
    if (req->serv->ipv4) {
		struct sockaddr_in addr;

		req->hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
		if (req->hnd.fd < 0) {
			log_ppp_error("radius:socket: %s\n", strerror(errno));
			return -1;
		}

		fcntl(req->hnd.fd, F_SETFD, fcntl(req->hnd.fd, F_GETFD) | FD_CLOEXEC);

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;

		if (conf_bind) {
			addr.sin_addr.s_addr = conf_bind;
			if (bind(req->hnd.fd, (struct sockaddr *) &addr, sizeof(addr))) {
				log_ppp_error("radius:bind: %s\n", strerror(errno));
				goto out_err;
			}
		}

		addr.sin_addr.s_addr = req->server_addr;
		addr.sin_port = htons(req->server_port);

		if ( req->serv && !req->serv->bind_default && ( 0 > setsockopt(req->hnd.fd, SOL_SOCKET, SO_BINDTODEVICE, req->serv->bind_device, strlen(req->serv->bind_device)) ) )
		{
			log_ppp_error("radius:setsockopt: %s\n", strerror(errno));
			goto out_err;
		}

		if (connect(req->hnd.fd, (struct sockaddr *) &addr, sizeof(addr))) {
			log_ppp_error("radius:connect: %s\n", strerror(errno));
			goto out_err;
		}

		if (fcntl(req->hnd.fd, F_SETFL, O_NONBLOCK)) {
			log_ppp_error("radius: failed to set nonblocking mode: %s\n", strerror(errno));
			goto out_err;
		}

		return 0;

	}else {//ipv6 address
		struct sockaddr_in6 addr6;

		req->hnd.fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if (req->hnd.fd < 0) {
			log_ppp_error("radius:socket: %s\n", strerror(errno));
			return -1;
		}

		fcntl(req->hnd.fd, F_SETFD, fcntl(req->hnd.fd, F_GETFD) | FD_CLOEXEC);

		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_addr = req->server_ipv6_addr;
		addr6.sin6_port = htons(req->server_port);

		if (connect(req->hnd.fd, (struct sockaddr *) &addr6, sizeof(addr6))) {
			log_ppp_error("radius:connect: %s\n", strerror(errno));
			goto out_err;
		}
		return 0;
	}

out_err:
	if (req->hnd.tpd)
		triton_md_unregister_handler(&req->hnd, 1);
	else {
		close(req->hnd.fd);
		req->hnd.fd = -1;
	}
	return -1;
}

int __rad_req_send(struct rad_req_t *req, int async)
{
	if (async == -1) {
		if (req->active)
			req->try = conf_max_try;
		if (rad_req_send(req))
			req->sent(req, -1);
		return 0;
	}

	if (req->hnd.fd == -1 && make_socket(req))
		return -2;

	if (req->before_send && req->before_send(req))
		goto out_err;

	if (!req->pack->buf && rad_packet_build(req->pack, req->RA))
		goto out_err;

	if (req->log) {
		req->log("send ");
		rad_packet_print(req->pack, req->serv, req->log);
	}

	if (req->sent)
		req->sent(req, 0);

	rad_packet_send(req->pack, req->hnd.fd, NULL);

	return 0;

out_err:
	if (req->hnd.tpd)
		triton_md_unregister_handler(&req->hnd, 1);
	else {
		close(req->hnd.fd);
		req->hnd.fd = -1;
	}

	if (async && req->sent)
		req->sent(req, -1);

	return -1;
}

int rad_req_send(struct rad_req_t *req)
{
	int r;

	req->send = __rad_req_send;

	if (req->try++ == conf_max_try) {
		if (req->active)
			rad_server_req_exit(req);

		log_ppp_warn("radius: server(%i) not responding\n", req->serv->id);

		if (rad_server_realloc(req)) {
			if (req->rpd)
				log_ppp_warn("radius: no available servers\n");
			return -1;
		}

		req->try = 1;
	}

	if (!req->active) {
		while (1) {
			r = rad_server_req_enter(req);

			if (r >= 0)
				break;

			if (rad_server_realloc(req)) {
				if (req->rpd)
					log_ppp_warn("radius: no available servers\n");
				return -1;
			}
		}
	} else
		r = __rad_req_send(req, 0);

	return r;
}

int rad_req_read(struct triton_md_handler_t *h)
{
	struct rad_req_t *req = container_of(h, typeof(*req), hnd);
	struct rad_packet_t *pack;

	if (!req->rpd)
	    log_switch(triton_context_self(), NULL);

	while (1) {
		if (rad_packet_recv(h->fd, &pack, NULL))
			return 0;

		rad_server_reply(req->serv);

		if (pack->id == req->pack->id)
			break;

		rad_packet_free(pack);
	}

	req->reply = pack;

	if (req->active)
		rad_server_req_exit(req);
	else
		rad_server_req_cancel(req, 0);

	if (req->log) {
		req->log("recv ");
		rad_packet_print(req->reply, req->serv, req->log);
	}

	if (req->recv)
		req->recv(req);

	return 1;
}

static void req_init(void)
{
	req_pool = mempool_create(sizeof(struct rad_req_t));
}

DEFINE_INIT(50, req_init);
