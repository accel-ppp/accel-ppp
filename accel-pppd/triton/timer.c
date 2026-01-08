#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#ifdef HAVE_TIMERFD
#include <sys/timerfd.h>
#else
#include "timerfd.h"
#endif

#include "triton_p.h"

#include "memdebug.h"

extern int max_events;
static int epoll_fd;
static struct epoll_event *epoll_events;

static pthread_t timer_thr;
static void *timer_thread(void *arg);

static mempool_t *timer_pool;

static pthread_mutex_t freed_list_lock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(freed_list);
static LIST_HEAD(freed_list2);

int timer_init(void)
{
	epoll_fd = epoll_create(1);
	if (epoll_fd < 0) {
		perror("timer:epoll_create");
		return -1;
	}

	fcntl(epoll_fd, F_SETFD, O_CLOEXEC);

	epoll_events = _malloc(max_events * sizeof(struct epoll_event));
	if (!epoll_events) {
		fprintf(stderr,"timer: cannot allocate memory\n");
		return -1;
	}

	timer_pool = mempool_create(sizeof(struct _triton_timer_t));

	return 0;
}

void timer_run(void)
{
	if (pthread_create(&timer_thr, NULL, timer_thread, NULL)) {
		triton_log_error("timer:pthread_create: %s",strerror(errno));
		_exit(-1);
	}
}

void timer_terminate(void)
{
	pthread_cancel(timer_thr);
	pthread_join(timer_thr, NULL);
}

void *timer_thread(void *arg)
{
	int i,n,r;
	struct _triton_timer_t *t;
	sigset_t set;

	sigfillset(&set);
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	while(1) {
		n = epoll_wait(epoll_fd, epoll_events, max_events, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			triton_log_error("timer:epoll_wait: %s", strerror(errno));
			_exit(-1);
		}

		for(i = 0; i < n; i++) {
			t = (struct _triton_timer_t *)epoll_events[i].data.ptr;
			if (!t->ud)
				continue;
			spin_lock(&t->ctx->lock);
			if (t->ud) {
				if (!t->pending) {
					list_add_tail(&t->entry2, &t->ctx->pending_timers);
					t->pending = 1;
					__sync_add_and_fetch(&triton_stat.timer_pending, 1);
					r = triton_queue_ctx(t->ctx);
				} else
					r = 0;
			} else
				r = 0;
			spin_unlock(&t->ctx->lock);
			if (r)
				triton_thread_wakeup(t->ctx->thread);
		}

		while (!list_empty(&freed_list2)) {
			t = list_entry(freed_list2.next, typeof(*t), entry);
			epoll_ctl(epoll_fd,EPOLL_CTL_DEL, t->fd, &t->epoll_event);
			close(t->fd);
			list_del(&t->entry);
			triton_context_release(t->ctx);
			mempool_free(t);
		}

		pthread_mutex_lock(&freed_list_lock);
		list_splice_init(&freed_list, &freed_list2);
		pthread_mutex_unlock(&freed_list_lock);
	}

	return NULL;
}


int __export triton_timer_add(struct triton_context_t *ctx, struct triton_timer_t *ud, int abs_time)
{
	struct _triton_timer_t *t = mempool_alloc(timer_pool);

	memset(t, 0, sizeof(*t));
	t->ud = ud;
	t->epoll_event.data.ptr = t;
	t->epoll_event.events = EPOLLIN | EPOLLET;
	if (ctx)
		t->ctx = (struct _triton_context_t *)ctx->tpd;
	else
		t->ctx = (struct _triton_context_t *)default_ctx.tpd;
	t->fd = timerfd_create(abs_time ? CLOCK_REALTIME : CLOCK_MONOTONIC, 0);
	if (t->fd < 0) {
		triton_log_error("timer:timerfd_create: %s", strerror(errno));
		mempool_free(t);
		return -1;
	}

	if (fcntl(t->fd, F_SETFL, O_NONBLOCK)) {
		triton_log_error("timer: failed to set nonblocking mode: %s", strerror(errno));
		goto out_err;
	}

	__sync_add_and_fetch(&t->ctx->refs, 1);
	ud->tpd = t;

	if (triton_timer_mod(ud, abs_time))
		goto out_err;

	spin_lock(&t->ctx->lock);
	list_add_tail(&t->entry, &t->ctx->timers);
	spin_unlock(&t->ctx->lock);

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, t->fd, &t->epoll_event)) {
		triton_log_error("timer:epoll_ctl: %s", strerror(errno));
		spin_lock(&t->ctx->lock);
		t->ud = NULL;
		list_del(&t->entry);
		spin_unlock(&t->ctx->lock);
		goto out_err;
	}

	__sync_add_and_fetch(&triton_stat.timer_count, 1);

	return 0;

out_err:
	ud->tpd = NULL;
	close(t->fd);
	mempool_free(t);
	return -1;
}
int __export triton_timer_mod(struct triton_timer_t *ud,int abs_time)
{
	struct _triton_timer_t *t = (struct _triton_timer_t *)ud->tpd;
	struct itimerspec ts =	{
		.it_value.tv_sec = ud->expire_tv.tv_sec,
		.it_value.tv_nsec = ud->expire_tv.tv_usec * 1000,
		.it_interval.tv_sec = ud->period / 1000,
		.it_interval.tv_nsec = (ud->period % 1000) * 1000,
	};

	if (ud->expire_tv.tv_sec == 0 && ud->expire_tv.tv_usec == 0)
		ts.it_value = ts.it_interval;

	if (timerfd_settime(t->fd, abs_time ? TFD_TIMER_ABSTIME : 0, &ts, NULL)) {
		triton_log_error("timer:timerfd_settime: %s", strerror(errno));
		return -1;
	}

	return 0;
}
void __export triton_timer_del(struct triton_timer_t *ud)
{
	struct _triton_timer_t *t = (struct _triton_timer_t *)ud->tpd;

	if (ud == NULL || t == NULL) {
		/* double time del? */
		return;
	}

	spin_lock(&t->ctx->lock);
	t->ud = NULL;
	list_del(&t->entry);
	if (t->pending) {
		list_del(&t->entry2);
		__sync_sub_and_fetch(&triton_stat.timer_pending, 1);
	}
	spin_unlock(&t->ctx->lock);

	pthread_mutex_lock(&freed_list_lock);
	list_add_tail(&t->entry, &freed_list);
	pthread_mutex_unlock(&freed_list_lock);

	ud->tpd = NULL;

	__sync_sub_and_fetch(&triton_stat.timer_count, 1);
}

