#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "linux_ppp.h"

#include "triton.h"

#include "events.h"
#include "ppp.h"
#include "ipdb.h"
#include "log.h"
#include "utils.h"
#include "sigchld.h"
#include "iputils.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "memdebug.h"

#define ENV_MEM 1024
#define ENV_MAX 16

static char *conf_ip_up;
static char *conf_ip_pre_up;
static char *conf_ip_down;
static char *conf_ip_change;
static char *conf_radattr_prefix;
static int conf_verbose = 0;
static int conf_fork_limit;

static void *pd_key;

static pthread_mutex_t queue_lock;
static int fork_cnt;
static LIST_HEAD(queue0);
static LIST_HEAD(queue1);

struct pppd_compat_pd
{
	struct ap_private pd;
	struct ap_session *ses;
	struct list_head entry;
	struct sigchld_handler_t hnd;
	struct sigchld_handler_t ip_up_hnd;
#ifdef RADIUS
	char *tmp_fname;
	unsigned int radattr_saved:1;
#endif
	unsigned int started:1;
	int res;
	in_addr_t ipv4_addr;
	in_addr_t ipv4_peer_addr;
};

static struct pppd_compat_pd *find_pd(struct ap_session *ses);
static void fill_argv(char **argv, struct pppd_compat_pd *pd, char *path);
static void fill_env(char **env, char *mem, struct pppd_compat_pd *pd);
#ifdef RADIUS
static void remove_radattr(struct pppd_compat_pd *);
static void write_radattr(struct pppd_compat_pd *, struct rad_packet_t *pack);
#endif

static void fork_queue_wakeup()
{
	struct pppd_compat_pd *pd;

	if (!conf_fork_limit)
		return;

	pthread_mutex_lock(&queue_lock);

	if (!list_empty(&queue0)) {
		pd = list_entry(queue0.next, typeof(*pd), entry);
		list_del(&pd->entry);
		pthread_mutex_unlock(&queue_lock);
		triton_context_wakeup(pd->ses->ctrl->ctx);
		return;
	}

	if (!list_empty(&queue1)) {
		pd = list_entry(queue1.next, typeof(*pd), entry);
		list_del(&pd->entry);
		pthread_mutex_unlock(&queue_lock);
		triton_context_wakeup(pd->ses->ctrl->ctx);
		return;
	}

	--fork_cnt;

	pthread_mutex_unlock(&queue_lock);
}

static void check_fork_limit(struct pppd_compat_pd *pd, struct list_head *queue)
{
	if (!conf_fork_limit)
		return;

	pthread_mutex_lock(&queue_lock);
	if (fork_cnt >= conf_fork_limit) {
		log_ppp_debug("pppd_compat: sleep\n");
		list_add_tail(&pd->entry, queue);
		pthread_mutex_unlock(&queue_lock);
		triton_context_schedule();
		log_ppp_debug("pppd_compat: wakeup\n");
	} else {
		++fork_cnt;
		pthread_mutex_unlock(&queue_lock);
	}
}


static void ip_pre_up_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd *pd = container_of(h, typeof(*pd), hnd);

	fork_queue_wakeup();

	if (conf_verbose) {
		log_switch(NULL, pd->ses);
		log_ppp_info2("pppd_compat: ip-pre-up finished (%i)\n", status);
	}

	pd->res = status;

	triton_context_wakeup(pd->ses->ctrl->ctx);
}

static void ses_ip_up_handler(long status)
{
	log_ppp_info2("pppd_compat: ip-up finished (%li)\n", status);
}

static void ip_up_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd *pd = container_of(h, typeof(*pd), ip_up_hnd);

	fork_queue_wakeup();

	if (conf_verbose)
		triton_context_call(pd->ses->ctrl->ctx, (triton_event_func)ses_ip_up_handler, (void *)(long)status);
}

static void ip_down_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd *pd = container_of(h, typeof(*pd), hnd);

	fork_queue_wakeup();

	if (conf_verbose) {
		log_switch(NULL, pd->ses);
		log_ppp_info2("pppd_compat: ip-down finished (%i)\n", status);
	}

	triton_context_wakeup(pd->ses->ctrl->ctx);
}

static void ip_change_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd *pd = container_of(h, typeof(*pd), hnd);

	fork_queue_wakeup();

	if (conf_verbose) {
		log_switch(NULL, pd->ses);
		log_ppp_info2("pppd_compat: ip-change finished (%i)\n", status);
	}

	pd->res = status;

	triton_context_wakeup(pd->ses->ctrl->ctx);
}

static void ev_ses_starting(struct ap_session *ses)
{
	struct pppd_compat_pd *pd;

	pd = _malloc(sizeof(*pd));
	if (!pd) {
		log_emerg("pppd_compat: out of memory\n");
		return;
	}

	memset(pd, 0, sizeof(*pd));
	pd->pd.key = &pd_key;
	pd->ses = ses;
	pd->ip_up_hnd.handler = ip_up_handler;
	list_add_tail(&pd->pd.entry, &ses->pd_list);
}

static void ev_ses_pre_up(struct ap_session *ses)
{
	pid_t pid;
	char *argv[8];
	char *env[ENV_MAX];
	char env_mem[ENV_MEM];
	char ipaddr[17];
	char peer_ipaddr[17];
	struct pppd_compat_pd *pd;

	pd = find_pd(ses);
	if (!pd)
		return;

#ifdef RADIUS
	if (pd->tmp_fname) {
		char fname[PATH_MAX];

		if (conf_radattr_prefix) {
			sprintf(fname, "%s.%s", conf_radattr_prefix, ses->ifname);
			rename(pd->tmp_fname, fname);
		} else
			unlink(pd->tmp_fname);

		_free(pd->tmp_fname);
		pd->tmp_fname = NULL;
	}
#endif

	if (ses->ipv4) {
		pd->ipv4_addr = ses->ipv4->addr;
		pd->ipv4_peer_addr = ses->ipv4->peer_addr;
	}

	if (!conf_ip_pre_up)
		return;

	argv[4] = ipaddr;
	argv[5] = peer_ipaddr;
	fill_argv(argv, pd, conf_ip_pre_up);

	fill_env(env, env_mem, pd);

	check_fork_limit(pd, &queue0);

	sigchld_lock();
	pid = fork();
	if (pid > 0) {
		pd->hnd.pid = pid;
		pd->hnd.handler = ip_pre_up_handler;
		sigchld_register_handler(&pd->hnd);
		if (conf_verbose)
			log_ppp_info2("pppd_compat: ip-pre-up started (pid %i)\n", pid);
		sigchld_unlock();

		triton_context_schedule();

		pthread_mutex_lock(&pd->hnd.lock);
		pthread_mutex_unlock(&pd->hnd.lock);
		if (pd->res != 0) {
			ap_session_terminate(ses, pd->res > 127 ? TERM_NAS_ERROR : TERM_ADMIN_RESET, 0);
			return;
		}

		pd->started = 1;
	} else if (pid == 0) {
		sigset_t set;
		sigfillset(&set);
		pthread_sigmask(SIG_UNBLOCK, &set, NULL);

		net->enter_ns();
		execve(conf_ip_pre_up, argv, env);
		net->exit_ns();

		log_emerg("pppd_compat: exec '%s': %s\n", conf_ip_pre_up, strerror(errno));
		_exit(EXIT_FAILURE);
	} else {
		sigchld_unlock();
		fork_queue_wakeup();
		log_error("pppd_compat: fork: %s\n", strerror(errno));
		ap_session_terminate(ses, TERM_NAS_ERROR, 0);
	}
}

static void ev_ses_started(struct ap_session *ses)
{
	pid_t pid;
	char *argv[8];
	char *env[ENV_MAX];
	char env_mem[ENV_MEM];
	char ipaddr[17];
	char peer_ipaddr[17];
	struct pppd_compat_pd *pd;

	pd = find_pd(ses);
	if (!pd)
		return;

	pd->started = 1;

	if (!conf_ip_up)
		return;

	argv[4] = ipaddr;
	argv[5] = peer_ipaddr;
	fill_argv(argv, pd, conf_ip_up);

	fill_env(env, env_mem, pd);

	check_fork_limit(pd, &queue1);

	sigchld_lock();
	pid = fork();
	if (pid > 0) {
		pd->ip_up_hnd.pid = pid;
		sigchld_register_handler(&pd->ip_up_hnd);
		if (conf_verbose)
			log_ppp_info2("pppd_compat: ip-up started (pid %i)\n", pid);
		sigchld_unlock();
	} else if (pid == 0) {
		sigset_t set;
		sigfillset(&set);
		pthread_sigmask(SIG_UNBLOCK, &set, NULL);

		net->enter_ns();
		execve(conf_ip_up, argv, env);
		net->exit_ns();

		log_emerg("pppd_compat: exec '%s': %s\n", conf_ip_up, strerror(errno));
		_exit(EXIT_FAILURE);
	} else {
		sigchld_unlock();
		fork_queue_wakeup();
		log_error("pppd_compat: fork: %s\n", strerror(errno));
	}
}

static void ev_ses_finished(struct ap_session *ses)
{
	pid_t pid;
	char *argv[8];
	char *env[ENV_MAX];
	char env_mem[ENV_MEM];
	char ipaddr[17];
	char peer_ipaddr[17];
	struct pppd_compat_pd *pd = find_pd(ses);

	if (!pd)
		return;

	if (pd->ip_up_hnd.pid) {
		pthread_mutex_lock(&pd->ip_up_hnd.lock);
		if (pd->ip_up_hnd.pid) {
			log_ppp_warn("pppd_compat: ip-up is not yet finished, terminating it ...\n");
			kill(pd->ip_up_hnd.pid, SIGTERM);
		}
		pthread_mutex_unlock(&pd->ip_up_hnd.lock);
	}

	if (pd->started && conf_ip_down) {
		argv[4] = ipaddr;
		argv[5] = peer_ipaddr;
		fill_argv(argv, pd, conf_ip_down);

		fill_env(env, env_mem, pd);

		check_fork_limit(pd, &queue1);

		sigchld_lock();
		pid = fork();
		if (pid > 0) {
			pd->hnd.pid = pid;
			pd->hnd.handler = ip_down_handler;
			sigchld_register_handler(&pd->hnd);
			if (conf_verbose)
				log_ppp_info2("pppd_compat: ip-down started (pid %i)\n", pid);
			sigchld_unlock();

			triton_context_schedule();

			pthread_mutex_lock(&pd->hnd.lock);
			pthread_mutex_unlock(&pd->hnd.lock);
		} else if (pid == 0) {
			sigset_t set;
			sigfillset(&set);
			pthread_sigmask(SIG_UNBLOCK, &set, NULL);

			net->enter_ns();
			execve(conf_ip_down, argv, env);
			net->exit_ns();

			log_emerg("pppd_compat: exec '%s': %s\n", conf_ip_down, strerror(errno));
			_exit(EXIT_FAILURE);
		} else {
			sigchld_unlock();
			fork_queue_wakeup();
			log_error("pppd_compat: fork: %s\n", strerror(errno));
		}
	}

	if (pd->ip_up_hnd.pid) {
		pthread_mutex_lock(&pd->ip_up_hnd.lock);
		if (pd->ip_up_hnd.pid) {
			log_ppp_warn("pppd_compat: ip-up is not yet finished, killing it ...\n");
			kill(pd->ip_up_hnd.pid, SIGKILL);
			pthread_mutex_unlock(&pd->ip_up_hnd.lock);
			if (sigchld_unregister_handler(&pd->ip_up_hnd))
				fork_queue_wakeup();
		} else
			pthread_mutex_unlock(&pd->ip_up_hnd.lock);
	}

#ifdef RADIUS
	if (pd->radattr_saved)
		remove_radattr(pd);
#endif

	list_del(&pd->pd.entry);
	_free(pd);
}

#ifdef RADIUS
static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct pppd_compat_pd *pd = find_pd(ev->ses);

	if (!pd)
		return;

	if (!conf_radattr_prefix)
		return;

	write_radattr(pd, ev->reply);

	pd->radattr_saved = 1;
}

static void ev_radius_coa(struct ev_radius_t *ev)
{
	pid_t pid;
	char *argv[8];
	char *env[ENV_MAX];
	char env_mem[ENV_MEM];
	char ipaddr[17];
	char peer_ipaddr[17];
	struct pppd_compat_pd *pd = find_pd(ev->ses);

	if (!pd)
		return;

	if (!pd->radattr_saved)
		return;

	write_radattr(pd, ev->request);

	if (conf_ip_change) {
		argv[4] = ipaddr;
		argv[5] = peer_ipaddr;
		fill_argv(argv, pd, conf_ip_change);

		fill_env(env, env_mem, pd);

		check_fork_limit(pd, &queue1);

		sigchld_lock();
		pid = fork();
		if (pid > 0) {
			pd->hnd.pid = pid;
			pd->hnd.handler = ip_change_handler;
			sigchld_register_handler(&pd->hnd);
			sigchld_unlock();
			if (conf_verbose)
				log_ppp_info2("pppd_compat: ip-change started (pid %i)\n", pid);

			triton_context_schedule();

			if (!ev->res)
				ev->res = pd->res;
		} else if (pid == 0) {
			net->enter_ns();
			execve(conf_ip_change, argv, env);
			net->exit_ns();

			log_emerg("pppd_compat: exec '%s': %s\n", conf_ip_change, strerror(errno));
			_exit(EXIT_FAILURE);
		} else {
			sigchld_unlock();
			fork_queue_wakeup();
			log_error("pppd_compat: fork: %s\n", strerror(errno));
		}
	}
}

static void remove_radattr(struct pppd_compat_pd *pd)
{
	char fname[PATH_MAX];

	if (pd->tmp_fname) {
		unlink(pd->tmp_fname);
		_free(pd->tmp_fname);
	} else {
		sprintf(fname, "%s.%s", conf_radattr_prefix, pd->ses->ifname);
		unlink(fname);

		sprintf(fname, "%s_old.%s", conf_radattr_prefix, pd->ses->ifname);
		unlink(fname);
	}
}

static void write_radattr(struct pppd_compat_pd *pd, struct rad_packet_t *pack)
{
	struct ap_session *ses = pd->ses;
	struct rad_attr_t *attr;
	struct rad_dict_value_t *val;
	FILE *f = NULL;
	char fname1[PATH_MAX], fname2[PATH_MAX];
	int fd, i;
	in_addr_t addr;
	char ip_str[50];

	if (ses->state == AP_STATE_ACTIVE) {
		sprintf(fname1, "%s.%s", conf_radattr_prefix, ses->ifname);
		sprintf(fname2, "%s_old.%s", conf_radattr_prefix, ses->ifname);
		if (rename(fname1, fname2))
			log_ppp_warn("pppd_compat: rename: %s\n", strerror(errno));

		f = fopen(fname1, "w");
	} else {
		sprintf(fname1, "%s.XXXXXX", conf_radattr_prefix);

		fd = mkstemp(fname1);
		if (fd < 0)
			log_ppp_warn("pppd_compat: mkstemp: %s\n", strerror(errno));
		else {
			fchmod(fd, 0644);
			f = fdopen(fd, "w");
		}
	}

	if (f) {
		list_for_each_entry(attr, &pack->attrs, entry) {
			fprintf(f, "%s ", attr->attr->name);
			switch (attr->attr->type) {
				case ATTR_TYPE_INTEGER:
					val = rad_dict_find_val(attr->attr, attr->val);
					if (val)
						fprintf(f, "%s\n", val->name);
					else
						fprintf(f, "%i\n", attr->val.integer);
					break;
				case ATTR_TYPE_STRING:
					fprintf(f, "%s\n", attr->val.string);
					break;
				case ATTR_TYPE_OCTETS:
					for (i = 0; i < attr->len; i++)
						fprintf(f, "%02X", attr->val.octets[i]);
					fprintf(f, "\n");
					break;
				case ATTR_TYPE_IPADDR:
					addr = ntohl(attr->val.ipaddr);
					fprintf(f, "%i.%i.%i.%i\n", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
					break;
				case ATTR_TYPE_DATE:
					fprintf(f, "%lu\n", (unsigned long) attr->val.date);
					break;
				case ATTR_TYPE_IPV6PREFIX:
					inet_ntop(AF_INET6, &attr->val.ipv6prefix.prefix, ip_str, sizeof(ip_str));
					fprintf(f, "%s/%i\n", ip_str, attr->val.ipv6prefix.len);
					break;
				case ATTR_TYPE_IPV6ADDR:
					inet_ntop(AF_INET6, &attr->val.ipv6addr, ip_str, sizeof(ip_str));
					fprintf(f, "%s\n", ip_str);
					break;
			}
		}
		fclose(f);

		if (ses->state == AP_STATE_STARTING)
			pd->tmp_fname = _strdup(fname1);
	} else
		log_ppp_warn("pppd_compat: failed to create '%s': %s\n", fname1, strerror(errno));
}
#endif

static struct pppd_compat_pd *find_pd(struct ap_session *ses)
{
	struct ap_private *pd;
	struct pppd_compat_pd *cpd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key) {
			cpd = container_of(pd, typeof(*cpd), pd);
			return cpd;
		}
	}

	//log_ppp_warn("pppd_compat: pd not found\n");
	return NULL;
}

static void fill_argv(char **argv, struct pppd_compat_pd *pd, char *path)
{
	argv[0] = path;
	argv[1] = pd->ses->ifname;
	argv[2] = "none";
	argv[3] = "0";
	u_inet_ntoa(pd->ipv4_addr, argv[4]);
	u_inet_ntoa(pd->ipv4_peer_addr, argv[5]);
	argv[6] = pd->ses->ctrl->calling_station_id;
	argv[7] = NULL;
}

static void fill_env(char **env, char *mem, struct pppd_compat_pd *pd)
{
	struct ap_session *ses = pd->ses;
	size_t mem_sz = ENV_MEM;
	int write_sz;
	int n = 0;

	env[n] = mem;
	write_sz = snprintf(mem, mem_sz, "PEERNAME=%s", pd->ses->username);
	if (write_sz < 0 || write_sz >= mem_sz)
		goto out;
	mem_sz -= write_sz + 1;
	mem += write_sz + 1;
	++n;

	env[n] = mem;
	write_sz = snprintf(mem, mem_sz, "CALLING_SID=%s",
			    pd->ses->ctrl->calling_station_id);
	if (write_sz < 0 || write_sz >= mem_sz)
		goto out;
	mem_sz -= write_sz + 1;
	mem += write_sz + 1;
	++n;

	env[n] = mem;
	write_sz = snprintf(mem, mem_sz, "CALLED_SID=%s",
			    pd->ses->ctrl->called_station_id);
	if (write_sz < 0 || write_sz >= mem_sz)
		goto out;
	mem_sz -= write_sz + 1;
	mem += write_sz + 1;
	++n;

	if (ses->ipv6 && !list_empty(&ses->ipv6->addr_list)) {
		///FIXME only first address is passed to env
		struct ipv6db_addr_t *a = list_first_entry(&ses->ipv6->addr_list,
							   typeof(*a), entry);
		char ip6_buf[INET6_ADDRSTRLEN];
		struct in6_addr addr;

		build_ip6_addr(a, ses->ipv6->peer_intf_id, &addr);

		env[n] = mem;
		write_sz = snprintf(mem, mem_sz, "IPV6_PREFIX=%s/%i",
				    inet_ntop(AF_INET6, &addr, ip6_buf,
					      sizeof(ip6_buf)),
				    a->prefix_len);
		if (write_sz < 0 || write_sz >= mem_sz)
			goto out;
		mem_sz -= write_sz + 1;
		mem += write_sz + 1;
		++n;
	}

	if (ses->ipv6_dp) {
		///FIXME only first prefix is passed to env
		struct ipv6db_addr_t *a = list_first_entry(&ses->ipv6_dp->prefix_list,
							   typeof(*a), entry);
		char ip6_buf[INET6_ADDRSTRLEN];

		env[n] = mem;
		write_sz = snprintf(mem, mem_sz, "IPV6_DELEGATED_PREFIX=%s/%i",
				    inet_ntop(AF_INET6, &a->addr, ip6_buf,
					      sizeof(ip6_buf)),
				    a->prefix_len);
		if (write_sz < 0 || write_sz >= mem_sz)
			goto out;
		mem_sz -= write_sz + 1;
		mem += write_sz + 1;
		++n;
	}

	if (pd->ses->stop_time) {
		uint64_t gword_sz = (uint64_t)UINT32_MAX + 1;
		uint64_t tx_bytes;
		uint64_t rx_bytes;

		tx_bytes = ses->acct_tx_bytes + gword_sz * ses->acct_output_gigawords;
		rx_bytes = ses->acct_rx_bytes + gword_sz * ses->acct_input_gigawords;

		env[n] = mem;
		write_sz = snprintf(mem, mem_sz, "CONNECT_TIME=%lu",
				    (unsigned long)(pd->ses->stop_time -
						    pd->ses->start_time));
		if (write_sz < 0 || write_sz >= mem_sz)
			goto out;
		mem_sz -= write_sz + 1;
		mem += write_sz + 1;
		++n;

		env[n] = mem;
		write_sz = snprintf(mem, mem_sz, "BYTES_SENT=%" PRIu64,
				    tx_bytes);
		if (write_sz < 0 || write_sz >= mem_sz)
			goto out;
		mem_sz -= write_sz + 1;
		mem += write_sz + 1;
		++n;

		env[n] = mem;
		write_sz = snprintf(mem, mem_sz, "BYTES_RCVD=%" PRIu64,
				    rx_bytes);
		if (write_sz < 0 || write_sz >= mem_sz)
			goto out;
		++n;
	}

out:
	env[n] = NULL;
}

static void load_config()
{
	const char *opt;

	conf_ip_pre_up = conf_get_opt("pppd-compat", "ip-pre-up");
	if (conf_ip_pre_up && access(conf_ip_pre_up, R_OK | X_OK)) {
		log_error("pppd_compat: %s: %s\n", conf_ip_pre_up, strerror(errno));
		conf_ip_pre_up = NULL;
	}

	conf_ip_up = conf_get_opt("pppd-compat", "ip-up");
	if (conf_ip_up && access(conf_ip_up, R_OK | X_OK)) {
		log_error("pppd_compat: %s: %s\n", conf_ip_up, strerror(errno));
		conf_ip_up = NULL;
	}

	conf_ip_down = conf_get_opt("pppd-compat", "ip-down");
	if (conf_ip_down && access(conf_ip_down, R_OK | X_OK)) {
		log_error("pppd_compat: %s: %s\n", conf_ip_down, strerror(errno));
		conf_ip_down = NULL;
	}

	conf_ip_change = conf_get_opt("pppd-compat", "ip-change");
	if (conf_ip_change && access(conf_ip_change, R_OK | X_OK)) {
		log_error("pppd_compat: %s: %s\n", conf_ip_change, strerror(errno));
		conf_ip_change = NULL;
	}

	conf_radattr_prefix = conf_get_opt("pppd-compat", "radattr-prefix");

	opt = conf_get_opt("pppd-compat", "verbose");
	if (opt)
		conf_verbose = atoi(opt);
	else
		conf_verbose = 0;

	opt = conf_get_opt("pppd-compat", "fork-limit");
	if (opt)
		conf_fork_limit = atoi(opt);
	else
		conf_fork_limit = sysconf(_SC_NPROCESSORS_ONLN)*2;
}

static void reload_config(void)
{
        config_lock();
        load_config();
        config_unlock();
}

static void init(void)
{
	load_config();

	triton_event_register_handler(EV_SES_STARTING, (triton_event_func)ev_ses_starting);
	triton_event_register_handler(EV_SES_PRE_UP, (triton_event_func)ev_ses_pre_up);
	triton_event_register_handler(EV_SES_STARTED, (triton_event_func)ev_ses_started);
	triton_event_register_handler(EV_SES_PRE_FINISHED, (triton_event_func)ev_ses_finished);
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_config);
#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	}
#endif
}

DEFINE_INIT(100, init);
