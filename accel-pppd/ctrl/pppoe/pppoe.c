#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <printf.h>

#include "crypto.h"

#include "events.h"
#include "triton.h"
#include "log.h"
#include "ppp.h"
#include "mempool.h"
#include "cli.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "iputils.h"
#include "connlimit.h"
#include "vlan_mon.h"

#include "pppoe.h"

#include "memdebug.h"

#define SID_MAX 65536

#ifndef min
#define min(x,y) ((x)<(y)?(x):(y))
#endif

struct pppoe_conn_t {
	struct list_head entry;
	struct triton_context_t ctx;
	struct pppoe_serv_t *serv;
	uint16_t sid;
	uint8_t addr[ETH_ALEN];
	unsigned int ppp_started:1;

	struct pppoe_tag *relay_sid;
	struct pppoe_tag *host_uniq;
	struct pppoe_tag *service_name;
	struct pppoe_tag *tr101;
	uint8_t cookie[COOKIE_LENGTH - 4];

	struct ap_ctrl ctrl;
	struct ppp_t ppp;
#ifdef RADIUS
	struct rad_plugin_t radius;
#endif
};

struct delayed_pado_t
{
	struct list_head entry;
	struct triton_timer_t timer;
	struct pppoe_serv_t *serv;
	uint8_t addr[ETH_ALEN];
	struct pppoe_tag *host_uniq;
	struct pppoe_tag *relay_sid;
	struct pppoe_tag *service_name;
	uint16_t ppp_max_payload;
};

struct padi_t
{
	struct list_head entry;
	struct timespec ts;
	uint8_t addr[ETH_ALEN];
};

struct iplink_arg {
	pcre *re;
	const char *opt;
	void *cli;
	long *arg1;
};

int conf_verbose;
char *conf_service_name[255];
int conf_accept_any_service;
int conf_accept_blank_service;
char *conf_ac_name;
char *conf_pado_delay;
int conf_tr101 = 1;
int conf_padi_limit = 0;
int conf_mppe = MPPE_UNSET;
int conf_sid_uppercase = 0;
static const char *conf_ip_pool;
static const char *conf_ipv6_pool;
static const char *conf_dpv6_pool;
static const char *conf_ifname;
enum {CSID_MAC, CSID_IFNAME, CSID_IFNAME_MAC};
static int conf_called_sid;
static int conf_calling_sid;
static int conf_cookie_timeout;
static const char *conf_vlan_name;
static int conf_vlan_timeout = 60;

static mempool_t conn_pool;
static mempool_t pado_pool;
static mempool_t padi_pool;

unsigned int stat_starting;
unsigned int stat_active;
unsigned int stat_delayed_pado;
unsigned long stat_PADI_recv;
unsigned long stat_PADI_drop;
unsigned long stat_PADO_sent;
unsigned long stat_PADR_recv;
unsigned long stat_PADR_dup_recv;
unsigned long stat_PADS_sent;
unsigned int total_padi_cnt;
unsigned long stat_filtered;

pthread_rwlock_t serv_lock = PTHREAD_RWLOCK_INITIALIZER;
LIST_HEAD(serv_list);
static int connlimit_loaded;
static int conf_session_timeout;

static pthread_mutex_t sid_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long *sid_map;
static unsigned long *sid_ptr;
static int sid_idx;

static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void pppoe_send_PADT(struct pppoe_conn_t *conn);
void pppoe_server_free(struct pppoe_serv_t *serv);
static int init_secret(struct pppoe_serv_t *serv);
static void __pppoe_server_start(const char *ifname, const char *opt, void *cli, int parent_ifindex, int vid, int vlan_mon);
static void pppoe_serv_timeout(struct triton_timer_t *t);
static void set_vlan_timeout(struct pppoe_serv_t *serv);

static void pppoe_serv_start_timer(struct pppoe_serv_t *serv)
{
	pthread_mutex_lock(&serv->lock);
	if (serv->conn_cnt) {
		pthread_mutex_unlock(&serv->lock);
		return;
	}

	if (conf_vlan_timeout) {
		serv->timer.expire = pppoe_serv_timeout;
		serv->timer.expire_tv.tv_sec = conf_vlan_timeout;
		if (serv->timer.tpd)
			triton_timer_mod(&serv->timer, 0);
		else
			triton_timer_add(&serv->ctx, &serv->timer, 0);
		pthread_mutex_unlock(&serv->lock);
	} else {
		pthread_mutex_unlock(&serv->lock);
		pppoe_disc_stop(serv);
		pppoe_server_free(serv);
	}
}

static void disconnect(struct pppoe_conn_t *conn)
{
	struct pppoe_serv_t *serv = conn->serv;

	if (conn->ppp_started) {
		dpado_check_prev(__sync_fetch_and_sub(&stat_active, 1));
		conn->ppp_started = 0;
		ap_session_terminate(&conn->ppp.ses, TERM_USER_REQUEST, 1);
	}

	pppoe_send_PADT(conn);

	triton_event_fire(EV_CTRL_FINISHED, &conn->ppp.ses);

	log_ppp_info1("disconnected\n");

	pthread_mutex_lock(&serv->lock);
	list_del(&conn->entry);
	serv->conn_cnt--;
	if (serv->conn_cnt == 0) {
		if (serv->stopping) {
			triton_context_call(&serv->ctx, (triton_event_func)pppoe_server_free, serv);
			pthread_mutex_unlock(&serv->lock);
		} else if (serv->vlan_mon) {
			triton_context_call(&serv->ctx, (triton_event_func)pppoe_serv_start_timer, serv);
			pthread_mutex_unlock(&conn->serv->lock);
		} else
			pthread_mutex_unlock(&serv->lock);
	} else
		pthread_mutex_unlock(&serv->lock);

	pthread_mutex_lock(&sid_lock);
	sid_map[conn->sid/(8*sizeof(long))] |= 1 << (conn->sid % (8*sizeof(long)));
	pthread_mutex_unlock(&sid_lock);

	_free(conn->ctrl.service_name);
	_free(conn->ctrl.calling_station_id);
	_free(conn->ctrl.called_station_id);
	_free(conn->service_name);
	if (conn->host_uniq)
		_free(conn->host_uniq);
	if (conn->relay_sid)
		_free(conn->relay_sid);
	if (conn->tr101)
		_free(conn->tr101);

	triton_context_unregister(&conn->ctx);

	mempool_free(conn);
}

static void ppp_started(struct ap_session *ses)
{
	log_ppp_debug("pppoe: ppp started\n");
}

static void ppp_finished(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct pppoe_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	log_ppp_debug("pppoe: ppp finished\n");

	if (conn->ppp_started) {
		dpado_check_prev(__sync_fetch_and_sub(&stat_active, 1));
		conn->ppp_started = 0;
		triton_context_call(&conn->ctx, (triton_event_func)disconnect, conn);
	}
}

static void pppoe_conn_close(struct triton_context_t *ctx)
{
	struct pppoe_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	if (conn->ppp_started)
		ap_session_terminate(&conn->ppp.ses, TERM_ADMIN_RESET, 0);
	else
		disconnect(conn);
}

#ifdef RADIUS
static int pppoe_rad_send_access_request(struct rad_plugin_t *rad, struct rad_packet_t *pack)
{
	struct pppoe_conn_t *conn = container_of(rad, typeof(*conn), radius);

	if (conn->tr101)
		return tr101_send_access_request(conn->tr101, pack);

	return 0;
}

static int pppoe_rad_send_accounting_request(struct rad_plugin_t *rad, struct rad_packet_t *pack)
{
	struct pppoe_conn_t *conn = container_of(rad, typeof(*conn), radius);

	if (conn->tr101)
		return tr101_send_accounting_request(conn->tr101, pack);

	return 0;
}
#endif

static void pppoe_conn_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	struct pppoe_conn_t *conn = arg;
	net = conn->ppp.ses.net;
	log_switch(ctx, &conn->ppp.ses);
}

static char* create_callid(uint8_t *hwaddr, char *ifname, int uppercase) {
	char mac[19] = {0};
	int offset = 0;
	char *callid = _malloc(IFNAMSIZ + 19);
	memset(callid, 0, IFNAMSIZ + 19);

	if (ifname) {
		if (hwaddr)
			offset = sprintf(callid, "%s:", ifname);
		else
			offset = sprintf(callid, "%s", ifname);
	}
	if (hwaddr) {
		uppercase == 1 ? sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]) : \
			sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
		sprintf(callid + offset, "%s", mac);
	}
	return callid;
}

static struct pppoe_conn_t *allocate_channel(struct pppoe_serv_t *serv, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name, const struct pppoe_tag *tr101, const uint8_t *cookie, uint16_t ppp_max_payload)
{
	struct pppoe_conn_t *conn;
	unsigned long *old_sid_ptr;

	conn = mempool_alloc(conn_pool);
	if (!conn) {
		log_error("pppoe: out of memory\n");
		return NULL;
	}

	memset(conn, 0, sizeof(*conn));

	pthread_mutex_lock(&sid_lock);
	old_sid_ptr = sid_ptr;
	while (1) {
		int bit = ffsl(*sid_ptr) - 1;

		if (bit != -1) {
			conn->sid = sid_idx*8*sizeof(long) + bit;
			*sid_ptr &= ~(1lu << bit);
		}

		if (++sid_idx == SID_MAX/8/sizeof(long)) {
			sid_ptr = sid_map;
			sid_idx = 0;
		} else
			sid_ptr++;

		if (bit != -1)
			break;

		if (sid_ptr == old_sid_ptr)
			break;
	}
	pthread_mutex_unlock(&sid_lock);

	if (!conn->sid) {
		log_warn("pppoe: no free sid available\n");
		mempool_free(conn);
		return NULL;
	}

	conn->serv = serv;
	memcpy(conn->addr, addr, ETH_ALEN);

	if (host_uniq) {
		conn->host_uniq = _malloc(sizeof(*host_uniq) + ntohs(host_uniq->tag_len));
		memcpy(conn->host_uniq, host_uniq, sizeof(*host_uniq) + ntohs(host_uniq->tag_len));
	}

	if (relay_sid) {
		conn->relay_sid = _malloc(sizeof(*relay_sid) + ntohs(relay_sid->tag_len));
		memcpy(conn->relay_sid, relay_sid, sizeof(*relay_sid) + ntohs(relay_sid->tag_len));
	}

	if (tr101) {
		conn->tr101 = _malloc(sizeof(*tr101) + ntohs(tr101->tag_len));
		memcpy(conn->tr101, tr101, sizeof(*tr101) + ntohs(tr101->tag_len));
	}

	conn->service_name = _malloc(sizeof(*service_name) + ntohs(service_name->tag_len));
	memcpy(conn->service_name, service_name, sizeof(*service_name) + ntohs(service_name->tag_len));

	memcpy(conn->cookie, cookie, COOKIE_LENGTH - 4);

	conn->ctx.before_switch = pppoe_conn_ctx_switch;
	conn->ctx.close = pppoe_conn_close;
	conn->ctrl.ctx = &conn->ctx;
	conn->ctrl.started = ppp_started;
	conn->ctrl.finished = ppp_finished;
	conn->ctrl.terminate = ppp_terminate;
	conn->ctrl.max_mtu = min(ETH_DATA_LEN, serv->mtu) - 8;
	conn->ctrl.type = CTRL_TYPE_PPPOE;
	conn->ctrl.ppp = 1;
	conn->ctrl.name = "pppoe";
	conn->ctrl.ifname = serv->ifname;
	conn->ctrl.mppe = conf_mppe;

	if (ppp_max_payload > ETH_DATA_LEN - 8)
		conn->ctrl.max_mtu = min(ppp_max_payload, serv->mtu - 8);

	conn->ctrl.called_station_id = create_callid((conf_called_sid == CSID_MAC || conf_called_sid == CSID_IFNAME_MAC) ? serv->hwaddr : NULL,
				  (conf_called_sid == CSID_IFNAME || conf_called_sid == CSID_IFNAME_MAC) ? serv->ifname : NULL, conf_sid_uppercase);
	conn->ctrl.calling_station_id = create_callid((conf_calling_sid == CSID_MAC || conf_calling_sid == CSID_IFNAME_MAC) ? addr : NULL,
				  (conf_calling_sid == CSID_IFNAME || conf_calling_sid == CSID_IFNAME_MAC) ? serv->ifname : NULL, conf_sid_uppercase);

	ppp_init(&conn->ppp);

	conn->ppp.ses.net = serv->net;
	conn->ppp.ses.ctrl = &conn->ctrl;
	conn->ppp.ses.chan_name = conn->ctrl.calling_station_id;

	if (conf_ip_pool)
		conn->ppp.ses.ipv4_pool_name = _strdup(conf_ip_pool);
	if (conf_ipv6_pool)
		conn->ppp.ses.ipv6_pool_name = _strdup(conf_ipv6_pool);
	if (conf_dpv6_pool)
		conn->ppp.ses.dpv6_pool_name = _strdup(conf_dpv6_pool);
	if (conf_ifname)
		conn->ppp.ses.ifname_rename = _strdup(conf_ifname);
	if (conf_session_timeout)
		conn->ppp.ses.session_timeout = conf_session_timeout;

	triton_context_register(&conn->ctx, conn);

	pthread_mutex_lock(&serv->lock);
	list_add_tail(&conn->entry, &serv->conn_list);
	if (serv->timer.tpd)
		triton_timer_del(&serv->timer);
	serv->conn_cnt++;
	pthread_mutex_unlock(&serv->lock);

	return conn;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
static void connect_channel(struct pppoe_conn_t *conn)
{
	int sock;
	struct sockaddr_pppox sp;

	triton_event_fire(EV_CTRL_STARTING, &conn->ppp.ses);
	triton_event_fire(EV_CTRL_STARTED, &conn->ppp.ses);

	sock = net->socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OE);
	if (sock < 0) {
		log_error("pppoe: socket(PPPOX): %s\n", strerror(errno));
		goto out_err;
	}

	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

	memset(&sp, 0, sizeof(sp));

	sp.sa_family = AF_PPPOX;
	sp.sa_protocol = PX_PROTO_OE;
	sp.sa_addr.pppoe.sid = htons(conn->sid);
	strcpy(sp.sa_addr.pppoe.dev, conn->serv->ifname);
	memcpy(sp.sa_addr.pppoe.remote, conn->addr, ETH_ALEN);

	if (net->connect(sock, (struct sockaddr *)&sp, sizeof(sp))) {
		log_error("pppoe: connect: %s\n", strerror(errno));
		goto out_err_close;
	}

	conn->ppp.fd = sock;

	if (establish_ppp(&conn->ppp))
		goto out_err_close;

#ifdef RADIUS
	if (conn->tr101 && triton_module_loaded("radius")) {
		conn->radius.send_access_request = pppoe_rad_send_access_request;
		conn->radius.send_accounting_request = pppoe_rad_send_accounting_request;
		rad_register_plugin(&conn->ppp.ses, &conn->radius);
	}
#endif

	conn->ppp_started = 1;

	dpado_check_next(__sync_add_and_fetch(&stat_active, 1));

	return;

out_err_close:
	close(sock);
out_err:
	disconnect(conn);
}
#pragma GCC diagnostic pop

static struct pppoe_conn_t *find_channel(struct pppoe_serv_t *serv, const uint8_t *cookie)
{
	struct pppoe_conn_t *conn;

	list_for_each_entry(conn, &serv->conn_list, entry) {
		if (!memcmp(conn->cookie, cookie, COOKIE_LENGTH - 4))
			return conn;
	}

	return NULL;
}

static void print_tag_string(struct pppoe_tag *tag)
{
	int i;

	for (i = 0; i < ntohs(tag->tag_len); i++)
		log_info2("%c", tag->tag_data[i]);
}

static void print_tag_octets(struct pppoe_tag *tag)
{
	int i;

	for (i = 0; i < ntohs(tag->tag_len); i++)
		log_info2("%02x", (uint8_t)tag->tag_data[i]);
}

static void print_tag_u16(struct pppoe_tag *tag)
{
	log_info2("%i", (uint16_t)ntohs(*(uint16_t *)tag->tag_data));
}

static void print_packet(const char *ifname, const char *op, uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	int n;

	log_info2("%s: %s [PPPoE ", ifname, op);

	switch (hdr->code) {
		case CODE_PADI:
			log_info2("PADI");
			break;
		case CODE_PADO:
			log_info2("PADO");
			break;
		case CODE_PADR:
			log_info2("PADR");
			break;
		case CODE_PADS:
			log_info2("PADS");
			break;
		case CODE_PADT:
			log_info2("PADT");
			break;
	}

	log_info2(" %02x:%02x:%02x:%02x:%02x:%02x => %02x:%02x:%02x:%02x:%02x:%02x",
		ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2], ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5],
		ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2], ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5]);

	log_info2(" sid=%04x", ntohs(hdr->sid));

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len)) {
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);

		if (n + sizeof(*tag) > ntohs(hdr->length)) {
			log_info2(" ...");
			break;
		}

		if (n + sizeof(*tag) + ntohs(tag->tag_len) > ntohs(hdr->length)) {
			log_info2(" ...");
			break;
		}

		switch (ntohs(tag->tag_type)) {
			case TAG_END_OF_LIST:
				log_info2(" <End-Of-List>");
				break;
			case TAG_SERVICE_NAME:
				log_info2(" <Service-Name ");
				print_tag_string(tag);
				log_info2(">");
				break;
			case TAG_AC_NAME:
				log_info2(" <AC-Name ");
				print_tag_string(tag);
				log_info2(">");
				break;
			case TAG_HOST_UNIQ:
				log_info2(" <Host-Uniq ");
				print_tag_octets(tag);
				log_info2(">");
				break;
			case TAG_AC_COOKIE:
				log_info2(" <AC-Cookie ");
				print_tag_octets(tag);
				log_info2(">");
				break;
			case TAG_VENDOR_SPECIFIC:
				if (ntohs(tag->tag_len) < 4)
					log_info2(" <Vendor-Specific invalid>");
				else
					log_info2(" <Vendor-Specific %x>", ntohl(*(uint32_t *)tag->tag_data));
				break;
			case TAG_RELAY_SESSION_ID:
				log_info2(" <Relay-Session-Id ");
				print_tag_octets(tag);
				log_info2(">");
				break;
			case TAG_PPP_MAX_PAYLOAD:
				log_info2(" <PPP-Max-Payload ");
				print_tag_u16(tag);
				log_info2(">");
				break;
			case TAG_SERVICE_NAME_ERROR:
				log_info2(" <Service-Name-Error>");
				break;
			case TAG_AC_SYSTEM_ERROR:
				log_info2(" <AC-System-Error>");
				break;
			case TAG_GENERIC_ERROR:
				log_info2(" <Generic-Error>");
				break;
			default:
				log_info2(" <Unknown (%x)>", ntohs(tag->tag_type));
				break;
		}
	}

	log_info2("]\n");
}

static void generate_cookie(struct pppoe_serv_t *serv, const uint8_t *src, uint8_t *cookie, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid)
{
	MD5_CTX ctx;
	DES_cblock key;
	DES_key_schedule ks;
	int i;
	union {
		DES_cblock b[3];
		uint8_t raw[24];
	} u1, u2;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	memcpy(key, serv->hwaddr, 6);
	key[6] = src[4];
	key[7] = src[5];
	DES_set_key(&key, &ks);

	MD5_Init(&ctx);
	MD5_Update(&ctx, serv->secret, SECRET_LENGTH);
	MD5_Update(&ctx, serv->hwaddr, ETH_ALEN);
	MD5_Update(&ctx, src, ETH_ALEN);
	if (relay_sid)
		MD5_Update(&ctx, relay_sid->tag_data, ntohs(relay_sid->tag_len));
	MD5_Final(u1.raw, &ctx);

	if (host_uniq) {
		uint8_t buf[16];
		MD5_Init(&ctx);
		MD5_Update(&ctx, serv->secret, SECRET_LENGTH);
		MD5_Update(&ctx, host_uniq->tag_data, ntohs(host_uniq->tag_len));
		MD5_Final(buf, &ctx);
		for (i = 0; i < 4; i++)
			u1.raw[16 + i] = buf[i] ^ buf[i + 4] ^ buf[i + 8] ^ buf[i + 12];
	} else
		memset(u1.raw + 16, 0, 4);

	*(uint32_t *)(u1.raw + 20) = ts.tv_sec + conf_cookie_timeout;

	for (i = 0; i < 3; i++)
		DES_ecb_encrypt(&u1.b[i], &u2.b[i], &ks, DES_ENCRYPT);

	for (i = 0; i < 3; i++)
		DES_ecb_encrypt(&u2.b[i], &u1.b[i], &serv->des_ks, DES_ENCRYPT);

	memcpy(cookie, u1.raw, 24);
}

static int check_cookie(struct pppoe_serv_t *serv, const uint8_t *src, const uint8_t *cookie, const struct pppoe_tag *relay_sid)
{
	MD5_CTX ctx;
	DES_cblock key;
	DES_key_schedule ks;
	int i;
	union {
		DES_cblock b[3];
		uint8_t raw[24];
	} u1, u2;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	memcpy(key, serv->hwaddr, 6);
	key[6] = src[4];
	key[7] = src[5];
	DES_set_key(&key, &ks);

	memcpy(u1.raw, cookie, 24);

	for (i = 0; i < 3; i++)
		DES_ecb_encrypt(&u1.b[i], &u2.b[i], &serv->des_ks, DES_DECRYPT);

	for (i = 0; i < 3; i++)
		DES_ecb_encrypt(&u2.b[i], &u1.b[i], &ks, DES_DECRYPT);

	if (*(uint32_t *)(u1.raw + 20) < ts.tv_sec)
		return 1;

	MD5_Init(&ctx);
	MD5_Update(&ctx, serv->secret, SECRET_LENGTH);
	MD5_Update(&ctx, serv->hwaddr, ETH_ALEN);
	MD5_Update(&ctx, src, ETH_ALEN);
	if (relay_sid)
		MD5_Update(&ctx, relay_sid->tag_data, ntohs(relay_sid->tag_len));
	MD5_Final(u2.raw, &ctx);

	return memcmp(u1.raw, u2.raw, 16);
}

static void setup_header(uint8_t *pack, const uint8_t *src, const uint8_t *dst, int code, uint16_t sid)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

	memcpy(ethhdr->h_source, src, ETH_ALEN);
	memcpy(ethhdr->h_dest, dst, ETH_ALEN);
	ethhdr->h_proto = htons(ETH_P_PPP_DISC);

	hdr->ver = 1;
	hdr->type = 1;
	hdr->code = code;
	hdr->sid = htons(sid);
	hdr->length = 0;
}

static int add_tag(uint8_t *pack, size_t pack_size, int type, const void *data, int len)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length));
	if (pack_size <= ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length) + sizeof(struct pppoe_tag) + len || len < 0)
		return -1;

	tag->tag_type = htons(type);
	tag->tag_len = htons(len);
	if (data && len)
		memcpy(tag->tag_data, data, len);

	hdr->length = htons(ntohs(hdr->length) + sizeof(*tag) + len);
	return 0;
}

static int add_tag2(uint8_t *pack, size_t pack_size, const struct pppoe_tag *t)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length));
	if (pack_size <= ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length) + ntohs(t->tag_len) || ntohs(t->tag_len) < 0)
		return -1;

	memcpy(tag, t, sizeof(*t) + ntohs(t->tag_len));

	hdr->length = htons(ntohs(hdr->length) + sizeof(*tag) + ntohs(t->tag_len));
	return 0;
}

static void pppoe_send(struct pppoe_serv_t *serv, const uint8_t *pack)
{
	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_PPP_DISC),
		.sll_ifindex = serv->ifindex,
		.sll_halen = ETH_ALEN,
	};

	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	int len = ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length);
	net->sendto(serv->disc_sock, pack, len, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
}

static void pppoe_send_PADO(struct pppoe_serv_t *serv, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name, uint16_t ppp_max_payload)
{
	uint8_t pack[ETHER_MAX_LEN];
	uint8_t cookie[COOKIE_LENGTH];

	setup_header(pack, serv->hwaddr, addr, CODE_PADO, 0);

	add_tag(pack, sizeof(pack), TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));
	if (conf_service_name[0]) {
		int i = 0;
		do {
		    add_tag(pack, sizeof(pack), TAG_SERVICE_NAME, (uint8_t *)conf_service_name[i], strlen(conf_service_name[i]));
		    i++;
		} while(conf_service_name[i]);
	}

	if (service_name)
		add_tag2(pack, sizeof(pack), service_name);

	generate_cookie(serv, addr, cookie, host_uniq, relay_sid);

	add_tag(pack, sizeof(pack), TAG_AC_COOKIE, cookie, COOKIE_LENGTH);

	if (host_uniq)
		add_tag2(pack, sizeof(pack), host_uniq);

	if (relay_sid)
		add_tag2(pack, sizeof(pack), relay_sid);

	if (ppp_max_payload) {
		ppp_max_payload = htons(ppp_max_payload);
		add_tag(pack, sizeof(pack), TAG_PPP_MAX_PAYLOAD, &ppp_max_payload, 2);
	}

	if (conf_verbose)
		print_packet(serv->ifname, "send", pack);

	__sync_add_and_fetch(&stat_PADO_sent, 1);
	pppoe_send(serv, pack);
}

static void pppoe_send_err(struct pppoe_serv_t *serv, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, int code, int tag_type)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, serv->hwaddr, addr, code, 0);

	add_tag(pack, sizeof(pack), TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));
	add_tag(pack, sizeof(pack), tag_type, NULL, 0);

	if (host_uniq)
		add_tag2(pack, sizeof(pack), host_uniq);

	if (relay_sid)
		add_tag2(pack, sizeof(pack), relay_sid);

	if (conf_verbose)
		print_packet(serv->ifname, "send", pack);

	pppoe_send(serv, pack);
}

static void pppoe_send_PADS(struct pppoe_conn_t *conn)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, conn->serv->hwaddr, conn->addr, CODE_PADS, conn->sid);

	add_tag(pack, sizeof(pack), TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));

	add_tag2(pack, sizeof(pack), conn->service_name);

	if (conn->host_uniq)
		add_tag2(pack, sizeof(pack), conn->host_uniq);

	if (conn->relay_sid)
		add_tag2(pack, sizeof(pack), conn->relay_sid);

	if (conn->ctrl.max_mtu > ETH_DATA_LEN - 8) {
		uint16_t ppp_max_payload = htons(conn->ctrl.max_mtu);
		add_tag(pack, sizeof(pack), TAG_PPP_MAX_PAYLOAD, &ppp_max_payload, 2);
	}

	if (conf_verbose)
		print_packet(conn->serv->ifname, "send", pack);

	__sync_add_and_fetch(&stat_PADS_sent, 1);
	pppoe_send(conn->serv, pack);
}

static void pppoe_send_PADT(struct pppoe_conn_t *conn)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, conn->serv->hwaddr, conn->addr, CODE_PADT, conn->sid);

	add_tag(pack, sizeof(pack), TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));

	add_tag2(pack, sizeof(pack), conn->service_name);

	if (conn->relay_sid)
		add_tag2(pack, sizeof(pack), conn->relay_sid);

	if (conf_verbose)
		print_packet(conn->serv->ifname, "send", pack);

	pppoe_send(conn->serv, pack);
}

static void free_delayed_pado(struct delayed_pado_t *pado)
{
	triton_timer_del(&pado->timer);

	__sync_sub_and_fetch(&stat_delayed_pado, 1);
	list_del(&pado->entry);

	if (pado->host_uniq)
		_free(pado->host_uniq);
	if (pado->relay_sid)
		_free(pado->relay_sid);
	if (pado->service_name)
		_free(pado->service_name);

	mempool_free(pado);
}

static void pado_timer(struct triton_timer_t *t)
{
	struct delayed_pado_t *pado = container_of(t, typeof(*pado), timer);

	if (!ap_shutdown)
		pppoe_send_PADO(pado->serv, pado->addr, pado->host_uniq, pado->relay_sid, pado->service_name, pado->ppp_max_payload);

	free_delayed_pado(pado);
}

static int check_padi_limit(struct pppoe_serv_t *serv, uint8_t *addr)
{
	struct padi_t *padi;
	struct timespec ts;

	if (serv->padi_limit == 0)
		goto connlimit_check;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	while (!list_empty(&serv->padi_list)) {
		padi = list_entry(serv->padi_list.next, typeof(*padi), entry);
		if ((ts.tv_sec - padi->ts.tv_sec) * 1000 + (ts.tv_nsec - padi->ts.tv_nsec) / 1000000 > 1000) {
			list_del(&padi->entry);
			mempool_free(padi);
			serv->padi_cnt--;
			__sync_sub_and_fetch(&total_padi_cnt, 1);
		} else
			break;
	}

	if (serv->padi_cnt == serv->padi_limit)
		return -1;

	if (conf_padi_limit && total_padi_cnt >= conf_padi_limit)
		return -1;

	list_for_each_entry(padi, &serv->padi_list, entry) {
		if (memcmp(padi->addr, addr, ETH_ALEN) == 0)
			return -1;
	}

	padi = mempool_alloc(padi_pool);
	if (!padi)
		return -1;

	padi->ts = ts;
	memcpy(padi->addr, addr, ETH_ALEN);
	list_add_tail(&padi->entry, &serv->padi_list);
	serv->padi_cnt++;

	__sync_add_and_fetch(&total_padi_cnt, 1);

connlimit_check:
	if (connlimit_loaded && connlimit_check(cl_key_from_mac(addr)))
		return -1;

	return 0;
}

static void pppoe_recv_PADI(struct pppoe_serv_t *serv, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	int len, n, service_match = conf_service_name[0] == NULL;
	struct delayed_pado_t *pado;
	struct timespec ts;
	uint16_t ppp_max_payload = 0;

	__sync_add_and_fetch(&stat_PADI_recv, 1);

	if (ap_shutdown || pado_delay == -1)
		return;

	if (conf_max_starting && ap_session_stat.starting >= conf_max_starting)
		return;

	if (conf_max_sessions && ap_session_stat.active + ap_session_stat.starting >= conf_max_sessions)
		return;

	if (check_padi_limit(serv, ethhdr->h_source)) {
		__sync_add_and_fetch(&stat_PADI_drop, 1);
		if (conf_verbose) {
			clock_gettime(CLOCK_MONOTONIC, &ts);
			if (ts.tv_sec - 60 >= serv->last_padi_limit_warn) {
				log_warn("pppoe: discarding overlimit PADI packets on interface %s\n", serv->ifname);
				serv->last_padi_limit_warn = ts.tv_sec;
			}
		}
		return;
	}

	if (hdr->sid)
		return;

	len = ntohs(hdr->length);
	for (n = 0; n < len; n += sizeof(*tag) + ntohs(tag->tag_len)) {
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		if (n + sizeof(*tag) + ntohs(tag->tag_len) > len)
			return;
		switch (ntohs(tag->tag_type)) {
			case TAG_END_OF_LIST:
				break;
			case TAG_SERVICE_NAME:
				if (tag->tag_len == 0 && conf_accept_blank_service) {
					service_match = 1;
					break;
				}
				else if (conf_service_name[0]) {
					int svc_index = 0;
					do {
					    if (ntohs(tag->tag_len) == strlen(conf_service_name[svc_index]) &&
						memcmp(tag->tag_data, conf_service_name[svc_index], ntohs(tag->tag_len)) == 0) {
						    service_match = 1;
						    break;
					    }
					    svc_index++;
					} while(conf_service_name[svc_index]);
				} else
					service_name_tag = tag;
				break;
			case TAG_HOST_UNIQ:
				host_uniq_tag = tag;
				break;
			case TAG_RELAY_SESSION_ID:
				relay_sid_tag = tag;
				break;
			case TAG_PPP_MAX_PAYLOAD:
				if (ntohs(tag->tag_len) == 2)
					ppp_max_payload = ntohs(*(uint16_t *)tag->tag_data);
				break;
		}
	}

	if (conf_verbose)
		print_packet(serv->ifname, "recv", pack);

	if (!service_match && !conf_accept_any_service) {
		if (conf_verbose)
			log_warn("pppoe: discarding PADI packet (Service-Name mismatch)\n");
		return;
	}

	if (ppp_max_payload > serv->mtu - 8)
		ppp_max_payload = serv->mtu - 8;

	if (pado_delay) {
		list_for_each_entry(pado, &serv->pado_list, entry) {
			if (memcmp(pado->addr, ethhdr->h_source, ETH_ALEN))
				continue;
			if (conf_verbose)
				log_warn("pppoe: discarding PADI packet (already queued)\n");
			return;
		}
		pado = mempool_alloc(pado_pool);
		memset(pado, 0, sizeof(*pado));
		pado->serv = serv;
		memcpy(pado->addr, ethhdr->h_source, ETH_ALEN);

		if (host_uniq_tag) {
			pado->host_uniq = _malloc(sizeof(*host_uniq_tag) + ntohs(host_uniq_tag->tag_len));
			memcpy(pado->host_uniq, host_uniq_tag, sizeof(*host_uniq_tag) + ntohs(host_uniq_tag->tag_len));
		}

		if (relay_sid_tag) {
			pado->relay_sid = _malloc(sizeof(*relay_sid_tag) + ntohs(relay_sid_tag->tag_len));
			memcpy(pado->relay_sid, relay_sid_tag, sizeof(*relay_sid_tag) + ntohs(relay_sid_tag->tag_len));
		}

		if (service_name_tag) {
			pado->service_name = _malloc(sizeof(*service_name_tag) + ntohs(service_name_tag->tag_len));
			memcpy(pado->service_name, service_name_tag, sizeof(*service_name_tag) + ntohs(service_name_tag->tag_len));
		}

		pado->ppp_max_payload = ppp_max_payload;

		pado->timer.expire = pado_timer;
		pado->timer.expire_tv.tv_sec = pado_delay / 1000;
		pado->timer.expire_tv.tv_usec = (pado_delay % 1000) * 1000;

		triton_timer_add(&serv->ctx, &pado->timer, 0);

		list_add_tail(&pado->entry, &serv->pado_list);
		__sync_add_and_fetch(&stat_delayed_pado, 1);
	} else
		pppoe_send_PADO(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag, ppp_max_payload);
}

static void pppoe_recv_PADR(struct pppoe_serv_t *serv, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *ac_cookie_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	struct pppoe_tag *tr101_tag = NULL;
	int n, service_match = 0;
	struct pppoe_conn_t *conn;
	int vendor_id;
	uint16_t ppp_max_payload = 0;

	__sync_add_and_fetch(&stat_PADR_recv, 1);

	if (ap_shutdown)
		return;

	if (conf_max_starting && ap_session_stat.starting >= conf_max_starting)
		return;

	if (conf_max_sessions && ap_session_stat.active + ap_session_stat.starting >= conf_max_sessions)
		return;

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN)) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR (destination address is broadcast)\n");
		return;
	}

	if (hdr->sid) {
		if (conf_verbose)
			log_warn("pppoe: discarding PADR packet (sid is not zero)\n");
		return;
	}

	if (conf_verbose)
		print_packet(serv->ifname, "recv", pack);

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len)) {
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);

		if (n + sizeof(*tag) > ntohs(hdr->length)) {
			if (conf_verbose)
				log_warn("pppoe: discard PADR packet (truncated tag)\n");
			return;
		}
		if (n + sizeof(*tag) + ntohs(tag->tag_len) > ntohs(hdr->length)) {
			if (conf_verbose)
				log_warn("pppoe: discard PADR packet (invalid tag length)\n");
			return;
		}
		switch (ntohs(tag->tag_type)) {
			case TAG_END_OF_LIST:
				break;
			case TAG_SERVICE_NAME:
				service_name_tag = tag;
				if (tag->tag_len == 0)
					service_match = 1;
				else if (conf_service_name[0]) {
					int svc_index = 0;
					do {
					    if (ntohs(tag->tag_len) == strlen(conf_service_name[svc_index]) &&
						memcmp(tag->tag_data, conf_service_name[svc_index], ntohs(tag->tag_len)) == 0) {
						    service_match = 1;
						    break;
					    }
					    svc_index++;
					} while(conf_service_name[svc_index]);
				} else {
					service_match = 1;
				}
				break;
			case TAG_HOST_UNIQ:
				host_uniq_tag = tag;
				break;
			case TAG_AC_COOKIE:
				ac_cookie_tag = tag;
				break;
			case TAG_RELAY_SESSION_ID:
				relay_sid_tag = tag;
				break;
			case TAG_VENDOR_SPECIFIC:
				if (ntohs(tag->tag_len) < 4)
					continue;
				vendor_id = ntohl(*(uint32_t *)tag->tag_data);
				if (vendor_id == VENDOR_ADSL_FORUM)
					if (conf_tr101)
						tr101_tag = tag;
			case TAG_PPP_MAX_PAYLOAD:
				if (ntohs(tag->tag_len) == 2)
					ppp_max_payload = ntohs(*(uint16_t *)tag->tag_data);
				break;
		}
	}

	if (!ac_cookie_tag) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR packet (no AC-Cookie tag present)\n");
		return;
	}

	if (ntohs(ac_cookie_tag->tag_len) != COOKIE_LENGTH) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR packet (incorrect AC-Cookie tag length)\n");
		return;
	}

	if (check_cookie(serv, ethhdr->h_source, (uint8_t *)ac_cookie_tag->tag_data, relay_sid_tag)) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR packet (incorrect AC-Cookie)\n");
		return;
	}

	if (!service_match && !conf_accept_any_service) {
		if (conf_verbose)
			log_warn("pppoe: Service-Name mismatch\n");
		pppoe_send_err(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, CODE_PADS, TAG_SERVICE_NAME_ERROR);
		return;
	}

	pthread_mutex_lock(&serv->lock);
	conn = find_channel(serv, (uint8_t *)ac_cookie_tag->tag_data);
	if (conn && !conn->ppp.ses.username) {
		__sync_add_and_fetch(&stat_PADR_dup_recv, 1);
		pppoe_send_PADS(conn);
	}
	pthread_mutex_unlock(&serv->lock);

	if (conn)
		return;

	conn = allocate_channel(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag, tr101_tag, (uint8_t *)ac_cookie_tag->tag_data, ppp_max_payload);
	if (!conn)
		pppoe_send_err(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, CODE_PADS, TAG_AC_SYSTEM_ERROR);
	else {
		pppoe_send_PADS(conn);
		triton_context_call(&conn->ctx, (triton_event_func)connect_channel, conn);
		triton_context_wakeup(&conn->ctx);
	}
}

static void pppoe_recv_PADT(struct pppoe_serv_t *serv, uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_conn_t *conn;
	uint16_t sid = ntohs(hdr->sid);

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN)) {
		if (conf_verbose)
			log_warn("pppoe: discard PADT (destination address is broadcast)\n");
		return;
	}

	if (conf_verbose)
		print_packet(serv->ifname, "recv", pack);

	pthread_mutex_lock(&serv->lock);
	list_for_each_entry(conn, &serv->conn_list, entry) {
		if (conn->sid == sid) {
			if (!memcmp(conn->addr, ethhdr->h_source, ETH_ALEN))
				triton_context_call(&conn->ctx, (void (*)(void *))disconnect, conn);
			break;
		}
	}
	pthread_mutex_unlock(&serv->lock);
}

void pppoe_serv_read(uint8_t *data)
{
	struct pppoe_serv_t *serv = container_of(triton_context_self(), typeof(*serv), ctx);
	uint8_t *pack = data + 4;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	int n = *(int *)data;

	switch (hdr->code) {
		case CODE_PADI:
			pppoe_recv_PADI(serv, pack, n);
			break;
		case CODE_PADR:
			pppoe_recv_PADR(serv, pack, n);
			break;
		case CODE_PADT:
			pppoe_recv_PADT(serv, pack);
			break;
	}

	mempool_free(data);
}

static void pppoe_serv_close(struct triton_context_t *ctx)
{
	struct pppoe_serv_t *serv = container_of(ctx, typeof(*serv), ctx);

	if (serv->stopping)
		return;

	serv->stopping = 1;
	pppoe_disc_stop(serv);

	pthread_mutex_lock(&serv->lock);
	if (!serv->conn_cnt) {
		pthread_mutex_unlock(&serv->lock);
		pppoe_server_free(serv);
		return;
	}
	pthread_mutex_unlock(&serv->lock);
}

static void pppoe_serv_timeout(struct triton_timer_t *t)
{
	struct pppoe_serv_t *serv = container_of(t, typeof(*serv), timer);

	pthread_mutex_lock(&serv->lock);
	if (serv->conn_cnt) {
		pthread_mutex_unlock(&serv->lock);
		return;
	}
	pthread_mutex_unlock(&serv->lock);

	pppoe_disc_stop(serv);

	pppoe_server_free(serv);
}

static int parse_server(const char *opt, int *padi_limit, struct ap_net **net)
{
	char *ptr, *endptr;
	char name[64];

	while (*opt == ',') {
		opt++;
		ptr = strchr(opt, '=');
		if (!ptr)
			goto out_err;
		if (!strncmp(opt, "padi-limit=", sizeof("padi-limit=") - 1)) {
			*padi_limit = strtol(ptr + 1, &endptr, 10);
			if (*endptr != 0 && *endptr != ',')
				goto out_err;
			opt = endptr;
		} else if (!strncmp(opt, "net=", sizeof("net=") - 1)) {
			ptr++;
			for (endptr = ptr + 1; *endptr && *endptr != ','; endptr++);
			if (endptr - ptr >= sizeof(name))
				goto out_err;
			memcpy(name, ptr, endptr - ptr);
			name[endptr - ptr] = 0;
			*net = ap_net_find(name);
			if (!*net)
				goto out_err;
		} else
			goto out_err;
	}

	return 0;

out_err:
	return -1;
}

static int __pppoe_add_interface_re(int index, int flags, const char *name, int iflink, int vid, struct iplink_arg *arg)
{
	if (pcre_exec(arg->re, NULL, name, strlen(name), 0, 0, NULL, 0) < 0)
		return 0;

	__pppoe_server_start(name, arg->opt, arg->cli, iflink, vid, 0);

	return 0;
}

static void pppoe_add_interface_re(const char *opt, void *cli)
{
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	const char *ptr;
	int pcre_offset;
	struct iplink_arg arg;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	pattern = _malloc(ptr - (opt + 3) + 1);
	memcpy(pattern, opt + 3, ptr - (opt + 3));
	pattern[ptr - (opt + 3)] = 0;

	re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

	if (!re) {
		log_error("pppoe: %s at %i\r\n", pcre_err, pcre_offset);
		return;
	}

	arg.re = re;
	arg.opt = ptr;
	arg.cli = cli;

	iplink_list((iplink_list_func)__pppoe_add_interface_re, &arg);

	pcre_free(re);
	_free(pattern);
}

void pppoe_server_start(const char *opt, void *cli)
{
	char name[IFNAMSIZ];
	const char *ptr;

	if (strlen(opt) > 3 && memcmp(opt, "re:", 3) == 0) {
		pppoe_add_interface_re(opt, cli);
		return;
	}

	ptr = strchr(opt, ',');
	if (ptr) {
		memcpy(name, opt, ptr - opt);
		name[ptr - opt] = 0;
		__pppoe_server_start(name, ptr, cli, -1, 0, 0);
	} else
		__pppoe_server_start(opt, opt, cli, -1, 0, 0);
}

static void pppoe_serv_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	struct pppoe_serv_t *serv = arg;
	net = serv->net;
	log_switch(ctx, NULL);
}

static void __pppoe_server_start(const char *ifname, const char *opt, void *cli, int parent_ifindex, int vid, int vlan_mon)
{
	struct pppoe_serv_t *serv;
	struct ifreq ifr;
	int padi_limit = conf_padi_limit;
	net = def_net;

	if (parse_server(opt, &padi_limit, &net)) {
		if (cli)
			cli_sendv(cli, "failed to parse '%s'\r\n", opt);
		else
			log_error("pppoe: failed to parse '%s'\r\n", opt);

		return;
	}

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->net == net && !strcmp(serv->ifname, ifname)) {
			if (cli)
				cli_send(cli, "error: already exists\r\n");
			pthread_rwlock_unlock(&serv_lock);
			return;
		}
	}
	pthread_rwlock_unlock(&serv_lock);

	if (vid && !vlan_mon && vlan_mon_check_busy(parent_ifindex, vid))
		return;

	serv = _malloc(sizeof(*serv));
	memset(serv, 0, sizeof(*serv));

	if (init_secret(serv)) {
		if (cli)
			cli_sendv(cli, "init secret failed\r\n");
		_free(serv);
		return;
	}

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (net->sock_ioctl(SIOCGIFFLAGS, &ifr)) {
		if (cli)
			cli_sendv(cli, "%s: %s\r\n", ifname, strerror(errno));
		log_error("pppoe: %s: %s\n", ifname, strerror(errno));
		goto out_err;
	}

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		net->sock_ioctl(SIOCSIFFLAGS, &ifr);
	}

	if (net->sock_ioctl(SIOCGIFHWADDR, &ifr)) {
		if (cli)
			cli_sendv(cli, "ioctl(SIOCGIFHWADDR): %s\r\n", strerror(errno));
		log_error("pppoe: ioctl(SIOCGIFHWADDR): %s\n", strerror(errno));
		goto out_err;
	}

#ifdef ARPHDR_ETHER
	if (ifr.ifr_hwaddr.sa_family != ARPHDR_ETHER) {
		log_error("pppoe: interface %s is not ethernet\n", ifname);
		goto out_err;
	}
#endif

	if ((ifr.ifr_hwaddr.sa_data[0] & 1) != 0) {
		if (cli)
			cli_sendv(cli, "interface %s has not unicast address\r\n", ifname);
		log_error("pppoe: interface %s has not unicast address\n", ifname);
		goto out_err;
	}

	memcpy(serv->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (net->sock_ioctl(SIOCGIFMTU, &ifr)) {
		if (cli)
			cli_sendv(cli, "ioctl(SIOCGIFMTU): %s\r\n", strerror(errno));
		log_error("pppoe: ioctl(SIOCGIFMTU): %s\n", strerror(errno));
		goto out_err;
	}

	serv->mtu = ifr.ifr_mtu;

	if (net->sock_ioctl(SIOCGIFINDEX, &ifr)) {
		if (cli)
			cli_sendv(cli, "ioctl(SIOCGIFINDEX): %s\r\n", strerror(errno));
		log_error("pppoe: ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
		goto out_err;
	}

	if (parent_ifindex == -1 && net == def_net)
		vid = iplink_vlan_get_vid(ifr.ifr_ifindex, &parent_ifindex);

	serv->ctx.close = pppoe_serv_close;
	serv->ctx.before_switch = pppoe_serv_ctx_switch;
	serv->ifname = _strdup(ifname);
	serv->ifindex = ifr.ifr_ifindex;
	serv->parent_ifindex = parent_ifindex;
	serv->vid = vid;
	serv->net = net;
	pthread_mutex_init(&serv->lock, NULL);

	INIT_LIST_HEAD(&serv->conn_list);
	INIT_LIST_HEAD(&serv->pado_list);
	INIT_LIST_HEAD(&serv->padi_list);
	serv->padi_limit = padi_limit;

	triton_context_register(&serv->ctx, serv);

	serv->disc_sock = pppoe_disc_start(serv);
	if (serv->disc_sock < 0) {
		log_error("pppoe: %s: failed to create discovery socket\n", ifname);
		triton_context_unregister(&serv->ctx);
		goto out_err;
	}

	if (vlan_mon) {
		serv->vlan_mon = 1;
		set_vlan_timeout(serv);
	}

	pthread_rwlock_wrlock(&serv_lock);
	list_add_tail(&serv->entry, &serv_list);
	pthread_rwlock_unlock(&serv_lock);

	triton_context_wakeup(&serv->ctx);

	return;

out_err:
	_free(serv);
}

static void _conn_stop(struct pppoe_conn_t *conn)
{
	ap_session_terminate(&conn->ppp.ses, TERM_ADMIN_RESET, 0);
}

void _server_stop(struct pppoe_serv_t *serv)
{
	struct pppoe_conn_t *conn;

	if (serv->stopping)
		return;

	serv->stopping = 1;
	pppoe_disc_stop(serv);

	pthread_mutex_lock(&serv->lock);
	if (!serv->conn_cnt) {
		pthread_mutex_unlock(&serv->lock);
		pppoe_server_free(serv);
		return;
	}
	list_for_each_entry(conn, &serv->conn_list, entry)
		triton_context_call(&conn->ctx, (triton_event_func)_conn_stop, conn);
	pthread_mutex_unlock(&serv->lock);
}

void pppoe_server_free(struct pppoe_serv_t *serv)
{
	struct delayed_pado_t *pado = NULL;

	pthread_rwlock_wrlock(&serv_lock);
	list_del(&serv->entry);
	pthread_rwlock_unlock(&serv_lock);

	while (!list_empty(&serv->pado_list)) {
		pado = list_entry(serv->pado_list.next, typeof(*pado), entry);
		free_delayed_pado(pado);
	}

	if (serv->timer.tpd)
		triton_timer_del(&serv->timer);

	if (serv->vlan_mon && conf_vlan_timeout) {
		log_info2("pppoe: remove vlan %s\n", serv->ifname);
		iplink_vlan_del(serv->ifindex);
		vlan_mon_add_vid(serv->parent_ifindex, ETH_P_PPP_DISC, serv->vid);
	}

	triton_context_unregister(&serv->ctx);
	_free(serv->ifname);
	_free(serv);
}

void pppoe_server_stop(const char *ifname)
{
	struct pppoe_serv_t *serv;

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		if (strcmp(serv->ifname, ifname))
			continue;
		triton_context_call(&serv->ctx, (triton_event_func)_server_stop, serv);
		break;
	}
	pthread_rwlock_unlock(&serv_lock);
}

void __export pppoe_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static int init_secret(struct pppoe_serv_t *serv)
{
	DES_cblock key;

	if (read(urandom_fd, serv->secret, SECRET_LENGTH) < 0) {
		log_error("pppoe: failed to read /dev/urandom: %s\n", strerror(errno));
		return -1;
	}

	memset(key, 0, sizeof(key));
	DES_random_key(&key);
	DES_set_key(&key, &serv->des_ks);

	return 0;
}

static void set_vlan_timeout(struct pppoe_serv_t *serv)
{
	if (conf_vlan_timeout) {
		serv->timer.expire = pppoe_serv_timeout;
		serv->timer.expire_tv.tv_sec = conf_vlan_timeout;
		if (!serv->conn_cnt)
			triton_timer_add(&serv->ctx, &serv->timer, 0);
	}
}

void pppoe_vlan_mon_notify(int ifindex, int vid, int vlan_ifindex)
{
	struct conf_sect_t *sect = conf_get_section("pppoe");
	struct conf_option_t *opt;
	struct ifreq ifr;
	char *ptr;
	int len, r, svid;
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	int pcre_offset;
	char ifname[IFNAMSIZ];

	if (!sect)
		return;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;
	if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
		log_error("pppoe: vlan-mon: failed to get interface name, ifindex=%i\n", ifindex);
		return;
	}

	svid = iplink_vlan_get_vid(ifindex, NULL);

#ifdef USE_LUA
	if (!memcmp(conf_vlan_name, "lua:", 4))
		r = ipoe_lua_make_vlan_name(conf_vlan_name + 4, ifr.ifr_name, svid, vid, ifname);
	else
#endif
	r = make_vlan_name(conf_vlan_name, ifr.ifr_name, svid, vid, ifname);
	if (r) {
		log_error("pppoe: vlan-mon: %s.%i: interface name is too long\n", ifr.ifr_name, vid);
		return;
	}

	if (vlan_ifindex) {
		struct pppoe_serv_t *serv;

		pthread_rwlock_rdlock(&serv_lock);
		list_for_each_entry(serv, &serv_list, entry) {
			if (serv->ifindex == vlan_ifindex) {
				if (!serv->vlan_mon) {
					serv->vlan_mon = 1;
					set_vlan_timeout(serv);
				}
				pthread_rwlock_unlock(&serv_lock);
				return;
			}
		}
		pthread_rwlock_unlock(&serv_lock);

		log_info2("pppoe: create vlan %s parent %s\n", ifname, ifr.ifr_name);

		ifr.ifr_ifindex = vlan_ifindex;
		if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
			log_error("pppoe: vlan-mon: failed to get interface name, ifindex=%i\n", ifindex);
			return;
		}

		if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr, sizeof(ifr)))
			return;

		if (ifr.ifr_flags & IFF_UP) {
			ifr.ifr_flags &= ~IFF_UP;

			if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr, sizeof(ifr)))
				return;
		}

		if (strcmp(ifr.ifr_name, ifname)) {
			strcpy(ifr.ifr_newname, ifname);
			if (ioctl(sock_fd, SIOCSIFNAME, &ifr, sizeof(ifr))) {
				log_error("pppoe: vlan-mon: failed to rename interface %s to %s\n", ifr.ifr_name, ifr.ifr_newname);
				return;
			}
			strcpy(ifr.ifr_name, ifname);
		}
	} else {
		log_info2("pppoe: create vlan %s parent %s\n", ifname, ifr.ifr_name);

		if (iplink_vlan_add(ifname, ifindex, vid))
			return;
	}

	len = strlen(ifname);
	memcpy(ifr.ifr_name, ifname, len + 1);

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr, sizeof(ifr))) {
		log_error("pppoe: vlan-mon: %s: failed to get interface index\n", ifr.ifr_name);
		return;
	}

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "interface"))
			continue;
		if (!opt->val)
			continue;

		ptr = strchr(opt->val, ',');
		if (!ptr)
			ptr = strchr(opt->val, 0);

		if (ptr - opt->val > 3 && memcmp(opt->val, "re:", 3) == 0) {
			pattern = _malloc(ptr - (opt->val + 3) + 1);
			memcpy(pattern, opt->val + 3, ptr - (opt->val + 3));
			pattern[ptr - (opt->val + 3)] = 0;

			re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

			_free(pattern);

			if (!re)
				continue;

			r = pcre_exec(re, NULL, ifr.ifr_name, len, 0, 0, NULL, 0);
			pcre_free(re);

			if (r < 0)
				continue;

			__pppoe_server_start(ifr.ifr_name, opt->val, NULL, ifindex, vid, 1);
			return;
		} else if (ptr - opt->val == len && memcmp(opt->val, ifr.ifr_name, len) == 0) {
			__pppoe_server_start(ifr.ifr_name, opt->val, NULL, ifindex, vid, 1);
			return;
		}
	}

	log_warn("pppoe: vlan %s not started\n", ifname);
	iplink_vlan_del(ifr.ifr_ifindex);
	vlan_mon_del_vid(ifindex, ETH_P_PPP_DISC, vid);
}

static void add_vlan_mon(const char *opt, long *mask)
{
	const char *ptr;
	struct ifreq ifr;
	int ifindex;
	long mask1[4096/8/sizeof(long)];
	struct pppoe_serv_t *serv;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	if (ptr - opt >= IFNAMSIZ) {
		log_error("pppoe: vlan-mon=%s: interface name is too long\n", opt);
		return;
	}

	memset(&ifr, 0, sizeof(ifr));

	memcpy(ifr.ifr_name, opt, ptr - opt);
	ifr.ifr_name[ptr - opt] = 0;

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_error("pppoe: '%s': ioctl(SIOCGIFINDEX): %s\n", ifr.ifr_name, strerror(errno));
		return;
	}

	ifindex = ifr.ifr_ifindex;

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr);

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	memcpy(mask1, mask, sizeof(mask1));
	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->parent_ifindex == ifindex &&
		    !(mask1[serv->vid / (8*sizeof(long))] & 1lu << (serv->vid % (8*sizeof(long))))) {
			mask1[serv->vid / (8*sizeof(long))] |= 1lu << (serv->vid % (8*sizeof(long)));

			if (!serv->vlan_mon) {
				serv->vlan_mon = 1;
				set_vlan_timeout(serv);
			}
		}
	}

	vlan_mon_add(ifindex, ETH_P_PPP_DISC, mask1, sizeof(mask1));
}

static int __load_vlan_mon_re(int index, int flags, const char *name, int iflink, int vid, struct iplink_arg *arg)
{
	struct ifreq ifr;
	long mask1[4096/8/sizeof(long)];
	struct pppoe_serv_t *serv;

	if (pcre_exec(arg->re, NULL, name, strlen(name), 0, 0, NULL, 0) < 0)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, name);

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr);

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	memcpy(mask1, arg->arg1, sizeof(mask1));
	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->parent_ifindex == index &&
		    !(mask1[serv->vid / (8*sizeof(long))] & (1lu << (serv->vid % (8*sizeof(long)))))) {
			mask1[serv->vid / (8*sizeof(long))] |= 1lu << (serv->vid % (8*sizeof(long)));

			if (!serv->vlan_mon) {
				serv->vlan_mon = 1;
				set_vlan_timeout(serv);
			}
		}
	}

	vlan_mon_add(index, ETH_P_PPP_DISC,  mask1, sizeof(mask1));

	return 0;
}

static void load_vlan_mon_re(const char *opt, long *mask, int len)
{
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	const char *ptr;
	int pcre_offset;
	struct iplink_arg arg;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	pattern = _malloc(ptr - (opt + 3) + 1);
	memcpy(pattern, opt + 3, ptr - (opt + 3));
	pattern[ptr - (opt + 3)] = 0;

	re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

	if (!re) {
		log_error("pppoe: '%s': %s at %i\r\n", pattern, pcre_err, pcre_offset);
		return;
	}

	arg.re = re;
	arg.opt = opt;
	arg.arg1 = mask;

	iplink_list((iplink_list_func)__load_vlan_mon_re, &arg);

	pcre_free(re);
	_free(pattern);

}

static void load_vlan_mon(struct conf_sect_t *sect)
{
	struct conf_option_t *opt;
	long mask[4096/8/sizeof(long)];
	static int registered = 0;

	if (!registered) {
		vlan_mon_register_proto(ETH_P_PPP_DISC, pppoe_vlan_mon_notify);
		registered = 1;
	}

	vlan_mon_del(-1, ETH_P_PPP_DISC);

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "vlan-mon"))
			continue;

		if (!opt->val)
			continue;

		if (parse_vlan_mon(opt->val, mask))
			continue;

		if (strlen(opt->val) > 3 && !memcmp(opt->val, "re:", 3))
			load_vlan_mon_re(opt->val, mask, sizeof(mask));
		else
			add_vlan_mon(opt->val, mask);
	}
}

static int parse_sid(char *opt) {
		// no option, default
		if (!opt)
			return CSID_MAC;

		if (!strcmp(opt, "mac"))
			return(CSID_MAC);
		else if (!strcmp(opt, "ifname"))
			return(CSID_IFNAME);
		else if (!strcmp(opt, "ifname:mac"))
			return(CSID_IFNAME_MAC);
		else
			return -1;
}

static void load_config(void)
{
	char *opt;
	struct conf_sect_t *s = conf_get_section("pppoe");

	opt = conf_get_opt("pppoe", "verbose");
	if (opt)
		conf_verbose = atoi(opt);

	opt = conf_get_opt("pppoe", "accept-any-service");
	if (opt)
	    conf_accept_any_service = atoi(opt);

	opt = conf_get_opt("pppoe", "accept-blank-service");
	if (opt)
	    conf_accept_blank_service = atoi(opt);

	opt = conf_get_opt("pppoe", "ac-name");
	if (!opt)
		opt = conf_get_opt("pppoe", "AC-Name");
	if (opt) {
		if (conf_ac_name)
			_free(conf_ac_name);
		conf_ac_name = _strdup(opt);
	} else
		conf_ac_name = _strdup("accel-ppp");

	opt = conf_get_opt("pppoe", "service-name");
	if (!opt)
		opt = conf_get_opt("pppoe", "Service-Name");
	if (opt) {
		if (conf_service_name[0]) {
			int i = 0;
			do {
			    _free(conf_service_name[i]);
			    i++;
			} while(conf_service_name[i]);
			conf_service_name[0] = NULL;
		}
		char *conf_service_name_string = _strdup(opt);
		char *p = strtok (conf_service_name_string, ",");
		int i = 0;
		while (p != NULL && i<255) {
		    conf_service_name[i++] = _strdup(p);
		    p = strtok(NULL, ",");
		}
		conf_service_name[i] = NULL;
		_free(conf_service_name_string);
	}

	opt = conf_get_opt("pppoe", "pado-delay");
	if (!opt)
		opt = conf_get_opt("pppoe", "PADO-Delay");
	if (opt)
		dpado_parse(opt);

	opt = conf_get_opt("pppoe", "tr101");
	if (opt)
		conf_tr101 = atoi(opt);

	opt = conf_get_opt("pppoe", "padi-limit");
	if (opt)
		conf_padi_limit = atoi(opt);

	opt = conf_get_opt("pppoe", "sid-uppercase");
	if (opt)
		conf_sid_uppercase = atoi(opt);

	opt = conf_get_opt("pppoe", "cookie-timeout");
	if (opt)
		conf_cookie_timeout = atoi(opt);
	else
		conf_cookie_timeout = 5;

	opt = conf_get_opt("pppoe", "session-timeout");
	if (opt)
		conf_session_timeout = atoi(opt);
	else
		conf_session_timeout = 0;

	conf_mppe = MPPE_UNSET;
	opt = conf_get_opt("pppoe", "mppe");
	if (opt) {
		if (strcmp(opt, "deny") == 0)
			conf_mppe = MPPE_DENY;
		else if (strcmp(opt, "allow") == 0)
			conf_mppe = MPPE_ALLOW;
		else if (strcmp(opt, "prefer") == 0)
			conf_mppe = MPPE_PREFER;
		else if (strcmp(opt, "require") == 0)
			conf_mppe = MPPE_REQUIRE;
	}

	conf_ip_pool = conf_get_opt("pppoe", "ip-pool");
	conf_ipv6_pool = conf_get_opt("pppoe", "ipv6-pool");
	conf_dpv6_pool = conf_get_opt("pppoe", "ipv6-pool-delegate");
	conf_ifname = conf_get_opt("pppoe", "ifname");

	opt = conf_get_opt("pppoe", "called-sid");
	conf_called_sid = parse_sid(opt);
	if (conf_called_sid == -1) {
			log_error("pppoe: unknown called-sid type\n");
			conf_called_sid = CSID_MAC;
	}

	opt = conf_get_opt("pppoe", "calling-sid");
	conf_calling_sid = parse_sid(opt);
	if (conf_calling_sid == -1) {
			log_error("pppoe: unknown calling-sid type\n");
			conf_calling_sid = CSID_MAC;
	}

	// If this option requests interface to be present and we have just MAC,
	// add interface name
	opt = conf_get_opt("pppoe", "ifname-in-sid");
	if (opt) {
		if (strcmp(opt, "called-sid") == 0 && conf_called_sid == CSID_MAC)
			conf_called_sid = CSID_IFNAME_MAC;
		else if (strcmp(opt, "calling-sid") == 0 && conf_calling_sid == CSID_MAC)
			conf_calling_sid = CSID_IFNAME_MAC;
		else if (strcmp(opt, "both") == 0) {
			if (conf_called_sid == CSID_MAC)
				conf_called_sid = CSID_IFNAME_MAC;
			if (conf_calling_sid == CSID_MAC)
				conf_calling_sid = CSID_IFNAME_MAC;
		}
		if (conf_verbose)
			log_info2("pppoe: config(): ifname-in-sid, conf_called_sid: %d, conf_calling_sid: %d\n", conf_called_sid, conf_calling_sid);
	}

	opt = conf_get_opt("pppoe", "vlan-name");
	if (opt)
		conf_vlan_name = opt;
	else
		conf_vlan_name = "%I.%N";

	opt = conf_get_opt("pppoe", "vlan-timeout");
	if (opt && atoi(opt) >= 0)
		conf_vlan_timeout = atoi(opt);

	load_vlan_mon(s);
}

static void load_interfaces()
{
	struct conf_sect_t *s = conf_get_section("pppoe");
	struct conf_option_t *opt;

	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "interface")) {
			if (opt->val)
				pppoe_server_start(opt->val, NULL);
		}
	}
}

static void pppoe_init(void)
{
	int fd;
	uint8_t *ptr;

	ptr = malloc(SID_MAX/8);
	memset(ptr, 0xff, SID_MAX/8);
	ptr[0] = 0xfe;
	ptr[SID_MAX/8-1] = 0x7f;
	sid_ptr = sid_map = (unsigned long *)ptr;

	fd = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
	if (fd >= 0)
		close(fd);
	else if (system("modprobe -q pppoe"))
		log_warn("failed to load pppoe kernel module\n");

	conn_pool = mempool_create(sizeof(struct pppoe_conn_t));
	pado_pool = mempool_create(sizeof(struct delayed_pado_t));
	padi_pool = mempool_create(sizeof(struct padi_t));
	conf_service_name[0] = NULL;

	if (!conf_get_section("pppoe")) {
		log_error("pppoe: no configuration, disabled...\n");
		return;
	}

	load_interfaces();
	load_config();

	connlimit_loaded = triton_module_loaded("connlimit");

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(21, pppoe_init);
