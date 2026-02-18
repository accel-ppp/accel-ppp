#ifndef __RADIUS_P_H
#define __RADIUS_P_H

#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>

#include "triton.h"
#include "radius.h"
#include "ppp.h"
#include "ipdb.h"
#include "pwdb.h"

struct rad_server_t;

struct radius_auth_ctx {
	struct rad_req_t *req;
	pwdb_callback cb;
	void *cb_arg;
	int (*recv)(struct rad_req_t *);

	const uint8_t *challenge;
	uint8_t *authenticator;
	char **mschap_error;
	char **reply_msg;
};

struct framed_route {
	in_addr_t dst;
	int mask;
	in_addr_t gw;
	uint32_t prio;
	struct framed_route *next;
};

struct framed_ip6_route {
	struct in6_addr prefix;
	struct in6_addr gw;
	uint32_t prio;
	uint8_t plen;
	struct framed_ip6_route *next;
};

struct radius_pd_t {
	struct list_head entry;
	struct ap_private pd;
	struct ap_session *ses;
	pthread_mutex_t lock;
	unsigned int refs:8;
	unsigned int authenticated:1;
	unsigned int acct_started:1;
	unsigned int ipv6_dp_assigned:1;
	unsigned int ipv6_dp_sent:1;

	struct rad_packet_t *auth_reply;

	struct rad_req_t *acct_req;
	struct triton_timer_t acct_interim_timer;

	struct triton_timer_t session_timeout;

	struct rad_packet_t *dm_coa_req;
	struct sockaddr_in dm_coa_addr;

	struct ipv4db_item_t ipv4_addr;
	struct ipv6db_item_t ipv6_addr;
	struct ipv6db_prefix_t ipv6_dp;
	int acct_interim_interval;
	int acct_interim_jitter;

	char *acct_username;
	uint8_t *attr_class;
	int attr_class_len;
	uint8_t *attr_state;
	int attr_state_len;
	int termination_action;

	struct framed_route *fr;
	struct framed_ip6_route *fr6;

	struct radius_auth_ctx *auth_ctx;

	struct list_head plugin_list;
};

struct rad_req_t {
	struct list_head entry;
	struct triton_md_handler_t hnd;
	struct triton_timer_t timeout;
	uint8_t RA[16];
	struct rad_packet_t *pack;
	struct rad_packet_t *reply;

	struct radius_pd_t *rpd;
	struct rad_server_t *serv;

	in_addr_t server_addr;
	struct in6_addr server_ipv6_addr;

	int server_port;
	int type;
	int prio;
	int try;

	unsigned int active:1;
	unsigned int async:1;

	time_t ts;

	void (*recv)(struct rad_req_t *);
	int (*before_send)(struct rad_req_t *);
	int (*send)(struct rad_req_t *, int async);
	void (*sent)(struct rad_req_t *, int res);

	void (*log)(const char *fmt, ...);
};

struct rad_server_t {
	struct list_head entry;
	struct triton_context_t ctx;
	struct triton_timer_t timer;
	int id;
	in_addr_t addr;
	struct in6_addr addr6;
	char *secret;
	int auth_port;
	int acct_port;
	int req_limit;
	int req_cnt;
	int queue_cnt;
	int fail_timeout;
	int max_fail;
	char bind_device[IFNAMSIZ];
	unsigned int bind_default:1;
	struct list_head req_queue[2];
	int client_cnt[2];
	time_t fail_time;
	int timeout_cnt;
	int weight;
	pthread_mutex_t lock;

	unsigned long stat_auth_sent;
	unsigned long stat_auth_lost;
	unsigned long stat_acct_sent;
	unsigned long stat_acct_lost;
	unsigned long stat_interim_sent;
	unsigned long stat_interim_lost;
	unsigned long stat_fail_cnt;

	struct stat_accm_t *stat_auth_lost_1m;
	struct stat_accm_t *stat_auth_lost_5m;
	struct stat_accm_t *stat_auth_query_1m;
	struct stat_accm_t *stat_auth_query_5m;

	struct stat_accm_t *stat_acct_lost_1m;
	struct stat_accm_t *stat_acct_lost_5m;
	struct stat_accm_t *stat_acct_query_1m;
	struct stat_accm_t *stat_acct_query_5m;

	struct stat_accm_t *stat_interim_lost_1m;
	struct stat_accm_t *stat_interim_lost_5m;
	struct stat_accm_t *stat_interim_query_1m;
	struct stat_accm_t *stat_interim_query_5m;

	unsigned int backup:1;
	unsigned int starting:1;
	unsigned int acct_on:1;
	unsigned int need_free:1;
	unsigned int need_close:1;
	//Flag to set radius ip version
	unsigned int ipv4:1;
};

#define RAD_SERV_AUTH 0
#define RAD_SERV_ACCT 1

extern int conf_max_try;
extern int conf_timeout;
extern int conf_acct_timeout;
extern int conf_acct_delay_time;
extern int conf_verbose;
extern int conf_interim_verbose;
extern char *conf_nas_identifier;
extern in_addr_t conf_nas_ip_address;
extern in_addr_t conf_bind;
extern in_addr_t conf_gw_ip_address;
extern in_addr_t conf_auth_server;
extern char *conf_dm_coa_secret;
extern char conf_dm_coa_bind_device[IFNAMSIZ];
extern unsigned int conf_dm_coa_bind_default;
extern int conf_sid_in_auth;
extern int conf_nas_port_id_in_req;
extern int conf_require_nas_ident;
extern in_addr_t conf_dm_coa_server;
extern int conf_dm_coa_port;
extern int conf_acct_interim_interval;
extern int conf_acct_interim_jitter;
extern int conf_accounting;
extern const char *conf_attr_tunnel_type;
extern int conf_acct_delay_start;
extern int conf_blast_protection;

int rad_check_nas_pack(struct rad_packet_t *pack);
struct radius_pd_t *rad_find_session(const char *sessionid, const char *username, const char *port_id, int port, in_addr_t ipaddr, const char *csid);
struct radius_pd_t *rad_find_session_pack(struct rad_packet_t *pack);

int rad_dict_load(const char *fname);
void rad_dict_free(struct rad_dict_t *dict);

struct rad_req_t *rad_req_alloc(struct radius_pd_t *rpd, int code, const char *username, int prio);
struct rad_req_t *rad_req_alloc2(struct radius_pd_t *rpd, int code, const char *username, in_addr_t addr, int port);
struct rad_req_t *rad_req_alloc_empty();
int rad_req_acct_fill(struct rad_req_t *);
struct rad_server_t *rad_req_free(struct rad_req_t *);
int rad_req_send(struct rad_req_t *req);
int __rad_req_send(struct rad_req_t *req, int async);
int rad_req_read(struct triton_md_handler_t *h);

struct radius_pd_t *find_pd(struct ap_session *ses);
int rad_proc_attrs(struct rad_req_t *req);
void hold_pd(struct radius_pd_t *rpd);
void release_pd(struct radius_pd_t *rpd);

int rad_auth_pap(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_chap_md5(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_mschap_v1(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_mschap_v2(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_null(struct radius_pd_t *rpd, const char *username, va_list args);

int rad_acct_start(struct radius_pd_t *rpd);
int rad_acct_stop(struct radius_pd_t *rpd);
void rad_acct_stop_defer(struct radius_pd_t *rpd);
void rad_acct_force_interim_update(struct radius_pd_t *rpd);

struct rad_packet_t *rad_packet_alloc(int code);
int rad_packet_build(struct rad_packet_t *pack, uint8_t *RA);
int rad_packet_recv(int fd, struct rad_packet_t **, struct sockaddr_in *addr);
void rad_packet_free(struct rad_packet_t *);
void rad_packet_print(struct rad_packet_t *pack, struct rad_server_t *s, void (*print)(const char *fmt, ...));
int rad_packet_send(struct rad_packet_t *pck, int fd, struct sockaddr_in *addr);

void dm_coa_cancel(struct radius_pd_t *pd);
int rad_dae_src_check(in_addr_t ipaddr);

struct rad_server_t *rad_server_get(int);
struct rad_server_t *rad_server_get2(int, in_addr_t, int);
struct rad_server_t *rad_server_put(struct rad_server_t *, int);
int rad_server_req_enter(struct rad_req_t *);
void rad_server_req_exit(struct rad_req_t *);
int rad_server_req_cancel(struct rad_req_t *, int full);
int rad_server_realloc(struct rad_req_t *);
void rad_server_fail(struct rad_server_t *);
void rad_server_timeout(struct rad_server_t *);
void rad_server_reply(struct rad_server_t *);

void rad_update_session_timeout(struct radius_pd_t *rpd, int timeout);

void radius_restore_session(struct ap_session *ses, struct radius_pd_t *rpd);

struct rtnl_link_stats;
int rad_read_stats(struct radius_pd_t *rpd, struct rtnl_link_stats *stats);

struct stat_accm_t;
struct stat_accm_t *stat_accm_create(unsigned int time);
void stat_accm_free(struct stat_accm_t *);
void stat_accm_add(struct stat_accm_t *, unsigned int);
unsigned long stat_accm_get_cnt(struct stat_accm_t *);
unsigned long stat_accm_get_avg(struct stat_accm_t *);

#endif
