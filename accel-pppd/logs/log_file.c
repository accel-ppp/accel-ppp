#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <aio.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "log.h"
#include "events.h"
#include "ppp.h"
#include "spinlock.h"
#include "mempool.h"

#include "memdebug.h"

#define LOG_BUF_SIZE 16*1024

#define RED_COLOR     "\033[1;31m"
#define GREEN_COLOR   "\033[1;32m"
#define YELLOW_COLOR  "\033[1;33m"
#define BLUE_COLOR  	"\033[1;34m"
#define NORMAL_COLOR  "\033[0;39m"

struct log_file_t {
	struct list_head entry;
	struct list_head msgs;
	spinlock_t lock;
	unsigned int need_free:1;
	unsigned int queued:1;
	struct log_file_pd_t *lpd;

	int fd;
	int new_fd;
};

struct log_file_pd_t {
	struct ap_private pd;
	struct log_file_t lf;
	unsigned long tmp;
};

struct fail_log_pd_t {
	struct ap_private pd;
	struct list_head msgs;
};

static int conf_color;
static int conf_per_session;
static char *conf_per_user_dir;
static char *conf_per_session_dir;
static int conf_copy;
static int conf_fail_log;
static pthread_t log_thr;

static const char* level_name[]={"  msg", "error", " warn", " info", " info", "debug"};
static const char* level_color[]={NORMAL_COLOR, RED_COLOR, YELLOW_COLOR, GREEN_COLOR, GREEN_COLOR, BLUE_COLOR};

static void *pd_key1;
static void *pd_key2;
static void *pd_key3;

static struct log_file_t *log_file;
static struct log_file_t *fail_log_file;

static mempool_t lpd_pool;
static mempool_t fpd_pool;

static LIST_HEAD(lf_queue);
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long temp_seq;

static void log_file_init(struct log_file_t *lf)
{
	spinlock_init(&lf->lock);
	INIT_LIST_HEAD(&lf->msgs);
	lf->fd = -1;
	lf->new_fd = -1;
}

static int log_file_open(struct log_file_t *lf, const char *fname)
{
	lf->fd = open(fname, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (lf->fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return -1;
	}

	return 0;
}

static void purge(struct list_head *list)
{
	struct log_msg_t *msg;

	while (!list_empty(list)) {
		msg = list_first_entry(list, typeof(*msg), entry);
		list_del(&msg->entry);
		log_free_msg(msg);
	}
}

static void *log_thread(void *unused)
{
	struct log_file_t *lf;
	struct iovec iov[IOV_MAX];
	struct log_chunk_t *chunk;
	struct log_msg_t *msg;
	int iov_cnt;
	LIST_HEAD(msg_list);
	LIST_HEAD(free_list);
	sigset_t set;

	sigfillset(&set);
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	while (1) {
		pthread_mutex_lock(&lock);
		if (list_empty(&lf_queue))
			pthread_cond_wait(&cond, &lock);
		lf = list_first_entry(&lf_queue, typeof(*lf), entry);
		list_del(&lf->entry);
		pthread_mutex_unlock(&lock);

		iov_cnt = 0;

		while (1) {
			if (lf->new_fd != -1) {
				close(lf->fd);
				lf->fd = lf->new_fd;
				lf->new_fd = -1;
			}

			spin_lock(&lf->lock);
			if (list_empty(&lf->msgs)) {
				if (iov_cnt) {
					writev(lf->fd, iov, iov_cnt);
					purge(&free_list);
				}

				lf->queued = 0;
				if (lf->need_free) {
					spin_unlock(&lf->lock);
					close(lf->fd);
					if (lf->new_fd != -1)
						close(lf->new_fd);
					mempool_free(lf->lpd);
				} else
					spin_unlock(&lf->lock);

				break;
			}

			list_splice_init(&lf->msgs, &msg_list);
			spin_unlock(&lf->lock);

			while (!list_empty(&msg_list)) {
				msg = list_first_entry(&msg_list, typeof(*msg), entry);

				iov[iov_cnt].iov_base = msg->hdr->msg;
				iov[iov_cnt].iov_len = msg->hdr->len;
				if (++iov_cnt == IOV_MAX) {
					writev(lf->fd, iov, iov_cnt);
					purge(&free_list);
					iov_cnt = 0;
				}

				list_for_each_entry(chunk, msg->chunks, entry) {
					iov[iov_cnt].iov_base = chunk->msg;
					iov[iov_cnt].iov_len = chunk->len;
					if (++iov_cnt == IOV_MAX) {
						writev(lf->fd, iov, iov_cnt);
						iov_cnt = 0;
						purge(&free_list);
					}
				}

				list_move_tail(&msg->entry, &free_list);
			}
		}
	}

	return NULL;
}

static void queue_lf(struct log_file_t *lf)
{
	pthread_mutex_lock(&lock);
	list_add_tail(&lf->entry, &lf_queue);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);
}

static void queue_log(struct log_file_t *lf, struct log_msg_t *msg)
{
	int r;

	spin_lock(&lf->lock);
	list_add_tail(&msg->entry, &lf->msgs);
	if (lf->fd != -1) {
		r = lf->queued;
		lf->queued = 1;
	} else
		r = 1;
	spin_unlock(&lf->lock);

	if (!r)
		queue_lf(lf);
}

static void queue_log_list(struct log_file_t *lf, struct list_head *l)
{
	int r;

	spin_lock(&lf->lock);
	list_splice_init(l, &lf->msgs);
	if (lf->fd != -1) {
		r = lf->queued;
		lf->queued = 1;
	} else
		r = 1;
	spin_unlock(&lf->lock);

	if (!r)
		queue_lf(lf);
}


static void set_hdr(struct log_msg_t *msg, struct ap_session *ses)
{
	struct tm tm;
	char timestamp[32];

	localtime_r(&msg->timestamp.tv_sec, &tm);

	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);
	sprintf(msg->hdr->msg, "%s[%s]: %s: %s%s%s", conf_color ? level_color[msg->level] : "",
		timestamp, level_name[msg->level],
		ses ? (ses->ifname[0] ? ses->ifname : ses->ctrl->ifname) : "",
		ses ? ": " : "",
		conf_color ? NORMAL_COLOR : "");
	msg->hdr->len = strlen(msg->hdr->msg);
}

static void general_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	if (ses && !conf_copy) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ses);
	queue_log(log_file, msg);
}

static struct ap_private *find_pd(struct ap_session *ses, void *pd_key)
{
	struct ap_private *pd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == pd_key) {
			return pd;
		}
	}

	return NULL;
}

static struct log_file_pd_t *find_lpd(struct ap_session *ses, void *pd_key)
{
	struct ap_private *pd = find_pd(ses, pd_key);

	if (!pd)
		return NULL;

	return container_of(pd, struct log_file_pd_t, pd);
}

static struct fail_log_pd_t *find_fpd(struct ap_session *ses, void *pd_key)
{
	struct ap_private *pd = find_pd(ses, pd_key);

	if (!pd)
		return NULL;

	return container_of(pd, struct fail_log_pd_t, pd);
}


static void per_user_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	struct log_file_pd_t *lpd;

	if (!ses) {
		log_free_msg(msg);
		return;
	}

	lpd = find_lpd(ses, &pd_key1);

	if (!lpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ses);
	queue_log(&lpd->lf, msg);
}

static void per_session_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	struct log_file_pd_t *lpd;

	if (!ses) {
		log_free_msg(msg);
		return;
	}

	lpd = find_lpd(ses, &pd_key2);

	if (!lpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ses);
	queue_log(&lpd->lf, msg);
}

static void fail_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	struct fail_log_pd_t *fpd;

	if (!ses || !conf_fail_log) {
		log_free_msg(msg);
		return;
	}

	fpd = find_fpd(ses, &pd_key3);

	if (!fpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ses);
	list_add_tail(&msg->entry, &fpd->msgs);
}

static void fail_reopen(void)
{
	const char *fname = conf_get_opt("log", "log-fail-file");
	int old_fd = -1;
 	int fd = open(fname, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return;
	}

	spin_lock(&fail_log_file->lock);
	if (fail_log_file->queued)
		fail_log_file->new_fd = fd;
	else {
		old_fd = fail_log_file->fd;
		fail_log_file->fd = fd;
	}
	spin_unlock(&fail_log_file->lock);

	if (old_fd != -1)
		close(old_fd);
}

static void general_reopen(void)
{
	const char *fname = conf_get_opt("log", "log-file");
	int old_fd = -1;
 	int fd = open(fname, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return;
	}

	spin_lock(&log_file->lock);
	if (log_file->queued)
		log_file->new_fd = fd;
	else {
		old_fd = log_file->fd;
		log_file->fd = fd;
	}
	spin_unlock(&log_file->lock);

	if (old_fd != -1)
		close(old_fd);
}

static void free_lpd(struct log_file_pd_t *lpd)
{
	struct log_msg_t *msg;

	spin_lock(&lpd->lf.lock);
	list_del(&lpd->pd.entry);
	lpd->lf.need_free = 1;
	if (lpd->lf.queued)
		spin_unlock(&lpd->lf.lock);
	else {
		while (!list_empty(&lpd->lf.msgs)) {
			msg = list_entry(lpd->lf.msgs.next, typeof(*msg), entry);
			list_del(&msg->entry);
			log_free_msg(msg);
		}
		if (lpd->lf.fd != -1)
			close(lpd->lf.fd);
		if (lpd->lf.new_fd != -1)
			close(lpd->lf.fd);
		spin_unlock(&lpd->lf.lock);
		mempool_free(lpd);
	}
}

static void ev_ses_authorized2(struct ap_session *ses)
{
	struct fail_log_pd_t *fpd;
	struct log_msg_t *msg;

	fpd = find_fpd(ses, &pd_key3);
	if (!fpd)
		return;

	while (!list_empty(&fpd->msgs)) {
		msg = list_entry(fpd->msgs.next, typeof(*msg), entry);
		list_del(&msg->entry);
		log_free_msg(msg);
	}

	list_del(&fpd->pd.entry);
	mempool_free(fpd);
}

static void ev_ses_authorized1(struct ap_session *ses)
{
	struct log_file_pd_t *lpd;
	char *fname;

	lpd = find_lpd(ses, &pd_key1);
	if (!lpd)
		return;

	fname = _malloc(PATH_MAX);
	if (!fname) {
		log_emerg("log_file: out of memory\n");
		return;
	}

	strcpy(fname, conf_per_user_dir);
	strcat(fname, "/");
	strcat(fname, ses->username);
	if (conf_per_session) {
		if (mkdir(fname, S_IRWXU) && errno != EEXIST) {
			log_emerg("log_file: mkdir '%s': %s'\n", fname, strerror(errno));
			goto out_err;
		}
		strcat(fname, "/");
		strcat(fname, ses->sessionid);
	}
	strcat(fname, ".log");

	if (log_file_open(&lpd->lf, fname))
		goto out_err;

	_free(fname);

	if (!list_empty(&lpd->lf.msgs)) {
		lpd->lf.queued = 1;
		queue_lf(&lpd->lf);
	}

	return;

out_err:
	_free(fname);
	free_lpd(lpd);
}

static void ev_ctrl_started(struct ap_session *ses)
{
	struct log_file_pd_t *lpd;
	struct fail_log_pd_t *fpd;
	char *fname;

	if (conf_per_user_dir) {
		lpd = mempool_alloc(lpd_pool);
		if (!lpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(lpd, 0, sizeof(*lpd));
		lpd->pd.key = &pd_key1;
		log_file_init(&lpd->lf);
		lpd->lf.lpd = lpd;
		list_add_tail(&lpd->pd.entry, &ses->pd_list);
	}

	if (conf_per_session_dir) {
		lpd = mempool_alloc(lpd_pool);
		if (!lpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(lpd, 0, sizeof(*lpd));
		lpd->pd.key = &pd_key2;
		log_file_init(&lpd->lf);
		lpd->lf.lpd = lpd;

		fname = _malloc(PATH_MAX);
		if (!fname) {
			mempool_free(lpd);
			log_emerg("log_file: out of memory\n");
			return;
		}

		lpd->tmp = temp_seq++;
		strcpy(fname, conf_per_session_dir);
		strcat(fname, "/tmp");
		sprintf(fname + strlen(fname), "%lu", lpd->tmp);

		if (log_file_open(&lpd->lf, fname)) {
			mempool_free(lpd);
			_free(fname);
			return;
		}

		_free(fname);

		list_add_tail(&lpd->pd.entry, &ses->pd_list);
	}

	if (conf_fail_log) {
		fpd = mempool_alloc(fpd_pool);
		if (!fpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(fpd, 0, sizeof(*fpd));
		fpd->pd.key = &pd_key3;
		list_add_tail(&fpd->pd.entry, &ses->pd_list);
		INIT_LIST_HEAD(&fpd->msgs);
	}
}

static void ev_ctrl_finished(struct ap_session *ses)
{
	struct log_file_pd_t *lpd;
	struct fail_log_pd_t *fpd;
	char *fname;

	fpd = find_fpd(ses, &pd_key3);
	if (fpd) {
		queue_log_list(fail_log_file, &fpd->msgs);
		list_del(&fpd->pd.entry);
		mempool_free(fpd);
	}

	lpd = find_lpd(ses, &pd_key1);
	if (lpd)
		free_lpd(lpd);

	lpd = find_lpd(ses, &pd_key2);
	if (lpd) {
		if (lpd->tmp) {
			fname = _malloc(PATH_MAX);
			if (fname) {
				strcpy(fname, conf_per_session_dir);
				strcat(fname, "/tmp");
				sprintf(fname + strlen(fname), "%lu", lpd->tmp);
				if (unlink(fname))
					log_emerg("log_file: unlink '%s': %s\n", fname, strerror(errno));
				_free(fname);
			} else
				log_emerg("log_file: out of memory\n");
		}
		free_lpd(lpd);
	}
}

static void ev_ses_starting(struct ap_session *ses)
{
	struct log_file_pd_t *lpd;
	char *fname1, *fname2;

	lpd = find_lpd(ses, &pd_key2);
	if (!lpd)
		return;

	fname1 = _malloc(PATH_MAX);
	if (!fname1) {
		log_emerg("log_file: out of memory\n");
		return;
	}

	fname2 = _malloc(PATH_MAX);
	if (!fname2) {
		log_emerg("log_file: out of memory\n");
		_free(fname1);
		return;
	}

	strcpy(fname1, conf_per_session_dir);
	strcat(fname1, "/tmp");
	sprintf(fname1 + strlen(fname1), "%lu", lpd->tmp);

	strcpy(fname2, conf_per_session_dir);
	strcat(fname2, "/");
	strcat(fname2, ses->sessionid);
	strcat(fname2, ".log");

	if (rename(fname1, fname2))
		log_emerg("log_file: rename '%s' to '%s': %s\n", fname1, fname2, strerror(errno));

	lpd->tmp = 0;

	_free(fname1);
	_free(fname2);
}

static struct log_target_t general_target =
{
	.log = general_log,
	.reopen = general_reopen,
};

static struct log_target_t per_user_target =
{
	.log = per_user_log,
};

static struct log_target_t per_session_target =
{
	.log = per_session_log,
};

static struct log_target_t fail_log_target =
{
	.log = fail_log,
	.reopen = fail_reopen,
};


static void init(void)
{
	const char *opt;

	pthread_create(&log_thr, NULL, log_thread, NULL);

	lpd_pool = mempool_create(sizeof(struct log_file_pd_t));
	fpd_pool = mempool_create(sizeof(struct fail_log_pd_t));

	opt = conf_get_opt("log", "log-file");
	if (opt) {
		log_file = malloc(sizeof(*log_file));
		memset(log_file, 0, sizeof(*log_file));
		log_file_init(log_file);
		if (log_file_open(log_file, opt)) {
			log_emerg("log_file:init:log_file_open: failed\n");
			free(log_file);
			_exit(EXIT_FAILURE);
		}
	}

	opt = conf_get_opt("log", "log-fail-file");
	if (opt) {
		fail_log_file = malloc(sizeof(*fail_log_file));
		memset(fail_log_file, 0, sizeof(*fail_log_file));
		log_file_init(fail_log_file);
		if (log_file_open(fail_log_file, opt)) {
			log_emerg("log_file:init:log_file_open: failed\n");
			free(fail_log_file);
			_exit(EXIT_FAILURE);
		}
		conf_fail_log = 1;
	}

	opt = conf_get_opt("log","color");
	if (opt && atoi(opt) > 0)
		conf_color = 1;

	opt = conf_get_opt("log", "per-user-dir");
	if (opt)
		conf_per_user_dir = _strdup(opt);

	opt = conf_get_opt("log", "per-session-dir");
	if (opt)
		conf_per_session_dir = _strdup(opt);

	opt = conf_get_opt("log", "per-session");
	if (opt && atoi(opt) > 0)
		conf_per_session = 1;

	opt = conf_get_opt("log", "copy");
	if (opt && atoi(opt) > 0)
		conf_copy = 1;

	log_register_target(&general_target);

	if (conf_per_user_dir) {
		log_register_target(&per_user_target);
		triton_event_register_handler(EV_SES_AUTHORIZED, (triton_event_func)ev_ses_authorized1);
	}

	if (conf_per_session_dir) {
		log_register_target(&per_session_target);
		triton_event_register_handler(EV_SES_STARTING, (triton_event_func)ev_ses_starting);
	}

	if (conf_fail_log) {
		log_register_target(&fail_log_target);
		triton_event_register_handler(EV_SES_AUTHORIZED, (triton_event_func)ev_ses_authorized2);
	}

	triton_event_register_handler(EV_CTRL_STARTED, (triton_event_func)ev_ctrl_started);
	triton_event_register_handler(EV_CTRL_FINISHED, (triton_event_func)ev_ctrl_finished);
}

DEFINE_INIT(1, init);
