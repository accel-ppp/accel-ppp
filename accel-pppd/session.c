#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <features.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if.h>

#include "triton.h"
#include "log.h"
#include "events.h"
#include "ap_session.h"
#include "ipdb.h"
#include "backup.h"
#include "iputils.h"
#include "spinlock.h"
#include "mempool.h"
#include "memdebug.h"

#define SID_SOURCE_SEQ 0
#define SID_SOURCE_URANDOM 1

static int conf_sid_ucase;
static int conf_single_session = -1;
static int conf_single_session_ignore_case;
static int conf_sid_source;
static int conf_seq_save_timeout = 10;
static const char *conf_seq_file;
int __export conf_max_sessions;
int __export conf_max_starting;

pthread_rwlock_t __export ses_lock = PTHREAD_RWLOCK_INITIALIZER;
__export LIST_HEAD(ses_list);

int __export sock_fd;
int __export sock6_fd;
int __export urandom_fd;
int __export ap_shutdown;

#if __WORDSIZE == 32
static spinlock_t seq_lock;
#endif
static long long unsigned seq;
static struct timespec seq_ts;

struct ap_session_stat __export ap_session_stat;

static void (*shutdown_cb)(void);

static void generate_sessionid(struct ap_session *ses);
static void save_seq(void);

static pthread_rwlock_t config_modify = PTHREAD_RWLOCK_INITIALIZER;

void __export ap_session_init(struct ap_session *ses)
{
	memset(ses, 0, sizeof(*ses));
	INIT_LIST_HEAD(&ses->pd_list);
	ses->ifindex = -1;
	ses->unit_idx = -1;
	ses->net = net;
}

void __export ap_session_set_ifindex(struct ap_session *ses)
{
	struct rtnl_link_stats stats;

	if (iplink_get_stats(ses->ifindex, &stats))
		log_ppp_warn("failed to get interface statistics\n");
	else {
		ses->acct_rx_packets_i = stats.rx_packets;
		ses->acct_tx_packets_i = stats.tx_packets;
		ses->acct_rx_bytes_i = stats.rx_bytes;
		ses->acct_tx_bytes_i = stats.tx_bytes;
		ses->acct_rx_bytes = 0;
		ses->acct_tx_bytes = 0;
		ses->acct_input_gigawords = 0;
		ses->acct_output_gigawords = 0;
	}
}

int __export ap_session_starting(struct ap_session *ses)
{
	if (ap_shutdown)
		return -1;

	if (ses->ifindex == -1 && ses->ifname[0])
		ses->ifindex = net->get_ifindex(ses->ifname);

	if (ses->ifindex != -1)
		ap_session_set_ifindex(ses);

	if (ses->state != AP_STATE_RESTORE) {
		ses->start_time = _time();
		ses->idle_time = ses->start_time;
		generate_sessionid(ses);

		ses->state = AP_STATE_STARTING;
	}

	__sync_add_and_fetch(&ap_session_stat.starting, 1);

	pthread_rwlock_wrlock(&ses_lock);
	list_add_tail(&ses->entry, &ses_list);
	pthread_rwlock_unlock(&ses_lock);

	triton_event_fire(EV_SES_STARTING, ses);

	return 0;
}

static void ap_session_timer(struct triton_timer_t *t)
{
	struct timespec ts;
	struct ap_session *ses = container_of(t, typeof(*ses), timer);

	if (ap_session_read_stats(ses, NULL))
		ap_session_terminate(ses, TERM_NAS_ERROR, 0);

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ses->idle_timeout && ts.tv_sec - ses->idle_time >= ses->idle_timeout) {
		log_ppp_msg("idle timeout\n");
		ap_session_terminate(ses, TERM_SESSION_TIMEOUT, 0);
	} else if (ses->session_timeout) {
		if (ts.tv_sec - ses->start_time >= ses->session_timeout) {
			log_ppp_msg("session timeout\n");
			ap_session_terminate(ses, TERM_SESSION_TIMEOUT, 0);
		}
	}
}

void __export ap_session_activate(struct ap_session *ses)
{
	if (ap_shutdown)
		return;

	ap_session_ifup(ses);

	if (ses->stop_time)
		return;

	ses->state = AP_STATE_ACTIVE;
	__sync_sub_and_fetch(&ap_session_stat.starting, 1);
	__sync_add_and_fetch(&ap_session_stat.active, 1);

	if (ses->idle_timeout) {
		ses->timer.expire = ap_session_timer;
		ses->timer.period = 60000;
		triton_timer_add(ses->ctrl->ctx, &ses->timer, 0);
	} else if (ses->session_timeout) {
		ses->timer.expire = ap_session_timer;
		ses->timer.expire_tv.tv_sec = ses->session_timeout;
		triton_timer_add(ses->ctrl->ctx, &ses->timer, 0);
	}

	triton_context_set_priority(ses->ctrl->ctx, 2);

#ifdef USE_BACKUP
	if (!ses->backup)
		backup_save_session(ses);
#endif
}

void __export ap_session_finished(struct ap_session *ses)
{
	ses->terminated = 1;

	if (!ses->down) {
		ap_session_ifdown(ses);
		ap_session_read_stats(ses, NULL);

		triton_event_fire(EV_SES_FINISHING, ses);
	}

	triton_event_fire(EV_SES_PRE_FINISHED, ses);

	pthread_rwlock_wrlock(&ses_lock);
	list_del(&ses->entry);
	pthread_rwlock_unlock(&ses_lock);

	switch (ses->state) {
		case AP_STATE_ACTIVE:
			__sync_sub_and_fetch(&ap_session_stat.active, 1);
			break;
		case AP_STATE_RESTORE:
		case AP_STATE_STARTING:
			__sync_sub_and_fetch(&ap_session_stat.starting, 1);
			break;
		case AP_STATE_FINISHING:
			__sync_sub_and_fetch(&ap_session_stat.finishing, 1);
			break;
	}

	if (ses->ipv4 && ses->ipv4->owner) {
		ipdb_put_ipv4(ses, ses->ipv4);
		ses->ipv4 = NULL;
	}

	if (ses->ipv6 && ses->ipv6->owner) {
		ipdb_put_ipv6(ses, ses->ipv6);
		ses->ipv6 = NULL;
	}

	triton_event_fire(EV_SES_FINISHED, ses);
	ses->ctrl->finished(ses);

	if (ses->wakeup)
		triton_context_wakeup(ses->wakeup);

	if (ses->username) {
		_free(ses->username);
		ses->username = NULL;
	}

	if (ses->ipv4_pool_name) {
		_free(ses->ipv4_pool_name);
		ses->ipv4_pool_name = NULL;
	}

	if (ses->ipv6_pool_name) {
		_free(ses->ipv6_pool_name);
		ses->ipv6_pool_name = NULL;
	}

	if (ses->dpv6_pool_name) {
		_free(ses->dpv6_pool_name);
		ses->dpv6_pool_name = NULL;
	}

	if (ses->ifname_rename) {
		_free(ses->ifname_rename);
		ses->ifname_rename = NULL;
	}

	if (ses->net)
		ses->net->release(ses->net);

	if (ses->timer.tpd)
		triton_timer_del(&ses->timer);

#ifdef USE_BACKUP
	if (ses->backup)
		ses->backup->storage->free(ses->backup);
#endif

	if (ap_shutdown && !ap_session_stat.starting && !ap_session_stat.active && !ap_session_stat.finishing) {
		if (shutdown_cb)
			shutdown_cb();
		else
			kill(getpid(), SIGTERM);
	}
}

void __export ap_session_terminate(struct ap_session *ses, int cause, int hard)
{
	if (ses->terminated)
		return;

	triton_context_set_priority(ses->ctrl->ctx, 3);

	if (!ses->stop_time)
		ses->stop_time = _time();

	if (!ses->terminate_cause)
		ses->terminate_cause = cause;

	if (ses->timer.tpd)
		triton_timer_del(&ses->timer);

	if (ses->terminating) {
		if (hard)
			ses->ctrl->terminate(ses, hard);
		return;
	}

	if (ses->state == AP_STATE_ACTIVE)
		__sync_sub_and_fetch(&ap_session_stat.active, 1);
	else
		__sync_sub_and_fetch(&ap_session_stat.starting, 1);

	__sync_add_and_fetch(&ap_session_stat.finishing, 1);
	ses->terminating = 1;
	ses->state = AP_STATE_FINISHING;

	log_ppp_debug("terminate\n");

	if (ses->ctrl->terminate(ses, hard)) {
		ap_session_ifdown(ses);
		ap_session_read_stats(ses, NULL);

		triton_event_fire(EV_SES_FINISHING, ses);

		ses->down = 1;
	}
}

static void __terminate_soft_reboot(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_NAS_REBOOT, 0);
}

int ap_shutdown_soft(void (*cb)(void), int term)
{
	struct ap_session *ses;

	ap_shutdown = 1;
	shutdown_cb = cb;

	pthread_rwlock_rdlock(&ses_lock);

	if (!ap_session_stat.starting && !ap_session_stat.active && !ap_session_stat.finishing) {
		pthread_rwlock_unlock(&ses_lock);
		if (shutdown_cb)
			shutdown_cb();
		else
			kill(getpid(), SIGTERM);
		return 1;
	} else if (term) {
		list_for_each_entry(ses, &ses_list, entry)
			triton_context_call(ses->ctrl->ctx, (triton_event_func)__terminate_soft_reboot, ses);
	}

	pthread_rwlock_unlock(&ses_lock);

	return 0;
}

static void generate_sessionid(struct ap_session *ses)
{
	if (conf_sid_source == SID_SOURCE_SEQ) {
		unsigned long long sid;
		struct timespec ts;

#if __WORDSIZE == 32
		spin_lock(&seq_lock);
		sid = ++seq;
		spin_unlock(&seq_lock);
#else
		sid = __sync_add_and_fetch(&seq, 1);
#endif

		clock_gettime(CLOCK_MONOTONIC, &ts);
		if (ts.tv_sec - seq_ts.tv_sec > conf_seq_save_timeout)
			save_seq();

		if (conf_sid_ucase)
			sprintf(ses->sessionid, "%016llX", sid);
		else
			sprintf(ses->sessionid, "%016llx", sid);
	} else {
		uint8_t sid[AP_SESSIONID_LEN/2];
		int i;
		read(urandom_fd, sid, AP_SESSIONID_LEN/2);
		for (i = 0; i < AP_SESSIONID_LEN/2; i++) {
			if (conf_sid_ucase)
				sprintf(ses->sessionid + i*2, "%02X", sid[i]);
			else
				sprintf(ses->sessionid + i*2, "%02x", sid[i]);
		}
	}
}

int __export ap_session_read_stats(struct ap_session *ses, struct rtnl_link_stats *stats)
{
	struct rtnl_link_stats lstats;

	if (ses->ifindex == -1)
		return -1;

	if (!stats)
		stats = &lstats;

	if (iplink_get_stats(ses->ifindex, stats)) {
		log_ppp_warn("failed to get interface statistics\n");
		return -1;
	}

	stats->rx_packets -= ses->acct_rx_packets_i;
	stats->tx_packets -= ses->acct_tx_packets_i;
	stats->rx_bytes -= ses->acct_rx_bytes_i;
	stats->tx_bytes -= ses->acct_tx_bytes_i;

	if (stats->rx_bytes != ses->acct_rx_bytes)
		ses->idle_time = _time();

	if (stats->rx_bytes < ses->acct_rx_bytes)
		ses->acct_input_gigawords++;
	ses->acct_rx_bytes = stats->rx_bytes;

	if (stats->tx_bytes < ses->acct_tx_bytes)
		ses->acct_output_gigawords++;
	ses->acct_tx_bytes = stats->tx_bytes;

	return 0;
}

static void __terminate_sec(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_NAS_REQUEST, 0);
}

int __export ap_session_set_username(struct ap_session *s, char *username)
{
	struct ap_session *ses;
	int wait = 0;

	pthread_rwlock_wrlock(&ses_lock);
	if (conf_single_session >= 0) {
		list_for_each_entry(ses, &ses_list, entry) {
			if (ses->username && ses->terminate_cause != TERM_AUTH_ERROR && !(conf_single_session_ignore_case == 1 ? strcasecmp(ses->username, username) : strcmp(ses->username, username))) {
				if (conf_single_session == 0) {
					pthread_rwlock_unlock(&ses_lock);
					log_ppp_info1("%s: second session denied\n", username);
					_free(username);
					return -1;
				} else {
					if (!ses->wakeup) {
						ses->wakeup = s->ctrl->ctx;
						wait = 1;
					}
					ap_session_ifdown(ses);
					triton_context_call(ses->ctrl->ctx, (triton_event_func)__terminate_sec, ses);
					continue;
				}
			}
		}
	}
	s->username = username;
	pthread_rwlock_unlock(&ses_lock);

	if (wait)
		triton_context_schedule();

	return 0;
}

int __export ap_check_username(const char *username)
{
	struct ap_session *ses;
	int r = 0;

	if (conf_single_session)
		return 0;

	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		if (ses->username && !(conf_single_session_ignore_case == 1 ? strcasecmp(ses->username, username) : strcmp(ses->username, username))) {
			r = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&ses_lock);

	return r;
}

static void save_seq(void)
{
	FILE *f;
	char path[PATH_MAX];
	const char *ptr;

	if (conf_sid_source != SID_SOURCE_SEQ)
		return;

	for (ptr = conf_seq_file + 1; *ptr; ptr++) {
		if (*ptr == '/') {
			memcpy(path, conf_seq_file, ptr - conf_seq_file);
			path[ptr - conf_seq_file] = 0;
			mkdir(path, 0755);
		}
	}

	f = fopen(conf_seq_file, "w");
	if (f) {
		fprintf(f, "%llu", seq);
		fclose(f);
	}
}

static void load_config(void)
{
	const char *opt;

        config_lock();
	pthread_rwlock_wrlock(&config_modify);

	opt = conf_get_opt("common", "sid-case");
	if (opt) {
		if (!strcmp(opt, "upper"))
			conf_sid_ucase = 1;
		else if (strcmp(opt, "lower"))
			log_emerg("sid-case: invalid format\n");
	}

	opt = conf_get_opt("common", "single-session");
	if (opt) {
		if (!strcmp(opt, "deny"))
			conf_single_session = 0;
		else if (!strcmp(opt, "replace"))
			conf_single_session = 1;
	} else
		conf_single_session = -1;

	opt = conf_get_opt("common", "single-session-ignore-case");
	if (opt)
		conf_single_session_ignore_case = atoi(opt);
	else
		conf_single_session_ignore_case = 0;

	opt = conf_get_opt("common", "sid-source");
	if (opt) {
		if (strcmp(opt, "seq") == 0)
			conf_sid_source = SID_SOURCE_SEQ;
		else if (strcmp(opt, "urandom") == 0)
			conf_sid_source = SID_SOURCE_URANDOM;
		else
			log_error("unknown sid-source\n");
	} else
		conf_sid_source = SID_SOURCE_SEQ;

	conf_seq_file = conf_get_opt("common", "seq-file");
	if (!conf_seq_file)
		conf_seq_file = "/var/lib/accel-ppp/seq";

	opt = conf_get_opt("common", "max-sessions");
	if (opt)
		conf_max_sessions = atoi(opt);
	else
		conf_max_sessions = 0;

	opt = conf_get_opt("common", "max-starting");
	if (opt)
		conf_max_starting = atoi(opt);
	else
		conf_max_starting = 0;

	pthread_rwlock_unlock(&config_modify);
        config_unlock();
}

static void init(void)
{
	FILE *f;

#if __WORDSIZE == 32
	spinlock_init(&seq_lock);
#endif

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		perror("socket");
		_exit(EXIT_FAILURE);
	}

	fcntl(sock_fd, F_SETFD, fcntl(sock_fd, F_GETFD) | FD_CLOEXEC);

	sock6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock6_fd < 0)
		log_warn("ppp: kernel doesn't support ipv6\n");
	else
		fcntl(sock6_fd, F_SETFD, fcntl(sock6_fd, F_GETFD) | FD_CLOEXEC);

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0) {
		log_emerg("failed to open /dev/urandom: %s\n", strerror(errno));
		return;
	}

	fcntl(urandom_fd, F_SETFD, fcntl(urandom_fd, F_GETFD) | FD_CLOEXEC);

	load_config();

	f = fopen(conf_seq_file, "r");
	if (f) {
		fscanf(f, "%llu", &seq);
		seq += 1000;
		fclose(f);
	} else
		read(urandom_fd, &seq, sizeof(seq));

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	atexit(save_seq);
}

DEFINE_INIT(2, init);

