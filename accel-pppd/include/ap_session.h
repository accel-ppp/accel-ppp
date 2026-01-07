#ifndef __AP_SESSION_H__
#define __AP_SESSION_H__

#include <sys/socket.h>

#include "triton.h"
#include "ap_net.h"

//#define AP_SESSIONID_LEN 16
#define AP_IFNAME_LEN 16

#define AP_STATE_STARTING  1
#define AP_STATE_ACTIVE    2
#define AP_STATE_FINISHING 3
#define AP_STATE_RESTORE   4

#define TERM_USER_REQUEST 1
#define TERM_SESSION_TIMEOUT 2
#define TERM_ADMIN_RESET 3
#define TERM_USER_ERROR 4
#define TERM_NAS_ERROR 5
#define TERM_NAS_REQUEST 6
#define TERM_NAS_REBOOT 7
#define TERM_AUTH_ERROR 8
#define TERM_LOST_CARRIER 9
#define TERM_IDLE_TIMEOUT 10

#define CTRL_TYPE_PPTP     1
#define CTRL_TYPE_L2TP     2
#define CTRL_TYPE_PPPOE    3
#define CTRL_TYPE_IPOE     4
#define CTRL_TYPE_OPENVPN  5
#define CTRL_TYPE_SSTP     6

#define MPPE_UNSET   -2
#define MPPE_ALLOW   -1
#define MPPE_DENY    0
#define MPPE_PREFER  1
#define MPPE_REQUIRE 2

struct ap_session;
struct backup_data;
struct rtnl_link_stats;

struct ap_ctrl {
	struct triton_context_t *ctx;
	int type;
	const char *name;
	const char *ifname;
	int max_mtu;
	int mppe;
	char *calling_station_id;
	char *called_station_id;
	char *service_name;
	unsigned int dont_ifcfg:1;
	unsigned int ppp:1;
	unsigned int ppp_npmode:2;
	void (*started)(struct ap_session*);
	void (*finished)(struct ap_session *);
	int (*terminate)(struct ap_session *, int hard);
};

struct ap_private
{
	struct list_head entry;
	void *key;
};

struct ap_session
{
	struct list_head entry;

	int state;
	char *chan_name;
	char ifname[AP_IFNAME_LEN];
	char *ifname_rename;
	char *vrf_name;
	int unit_idx;
	int ifindex;
	char sessionid[AP_SESSIONID_LEN+1];
	time_t start_time;
	time_t stop_time;
	time_t idle_time;
	char *username;
	struct ipv4db_item_t *ipv4;
	struct ipv6db_item_t *ipv6;
	struct ipv6db_prefix_t *ipv6_dp;
	char *ipv4_pool_name;
	char *ipv6_pool_name;
	char *dpv6_pool_name;
	struct ap_net *net;

	const struct ap_ctrl *ctrl;

	const char *comp;

#ifdef USE_BACKUP
	struct backup_data *backup;
#endif

	struct triton_context_t *wakeup;

	unsigned int terminating:1;
	unsigned int terminated:1;
	unsigned int down:1;
	int terminate_cause;

	struct list_head pd_list;

	int idle_timeout;
	int session_timeout;
	struct triton_timer_t timer;

	uint64_t acct_rx_packets;
	uint64_t acct_tx_packets;
	uint64_t acct_rx_bytes;
	uint64_t acct_tx_bytes;
	uint64_t acct_rx_packets_i;
	uint64_t acct_tx_packets_i;
	uint64_t acct_rx_bytes_i;
	uint64_t acct_tx_bytes_i;
	int acct_start;
#ifdef HAVE_SESSION_HOOKS
	struct ap_session_hooks_t *hooks;
#endif /* HAVE_SESSION_HOOKS */
};

struct ap_session_stat
{
	unsigned int active;
	unsigned int starting;
	unsigned int finishing;
};


extern pthread_rwlock_t ses_lock;
extern struct list_head ses_list;
extern int ap_shutdown;
extern int sock_fd;
extern int sock6_fd;
extern int urandom_fd;
extern struct ap_session_stat ap_session_stat;
extern int conf_max_sessions;
extern int conf_max_starting;

void ap_session_init(struct ap_session *ses);
void ap_session_set_ifindex(struct ap_session *ses);
int ap_session_starting(struct ap_session *ses);
void ap_session_finished(struct ap_session *ses);
void ap_session_terminate(struct ap_session *ses, int cause, int hard);
void ap_session_activate(struct ap_session *ses);
void ap_session_accounting_started(struct ap_session *ses);
int ap_session_set_username(struct ap_session *ses, char *username);
int ap_check_username(const char *username);

void ap_session_ifup(struct ap_session *ses);
void ap_session_ifdown(struct ap_session *ses);
int ap_session_rename(struct ap_session *ses, const char *ifname, int len);
#ifdef HAVE_VRF
int ap_session_vrf(struct ap_session *ses, const char *vrf_name, int len);
#endif

int ap_session_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats);

int ap_shutdown_soft(void (*cb)(void), int term);

#endif
