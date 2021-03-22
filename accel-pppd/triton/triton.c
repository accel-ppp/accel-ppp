#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <ucontext.h>
#include <setjmp.h>
#include <sys/resource.h>

#include "triton_p.h"
#include "memdebug.h"

#define WORKER_STACK_SIZE 1024*1024

int thread_count = 2;
int max_events = 64;

static spinlock_t threads_lock;
static LIST_HEAD(threads);
static LIST_HEAD(sleep_threads);

static struct list_head ctx_queue[CTX_PRIO_MAX];

static spinlock_t ctx_list_lock;
static LIST_HEAD(ctx_list);

static LIST_HEAD(init_list);

static int terminate;
static int need_terminate;

static int need_config_reload;
static void (*config_reload_notify)(int);

static mempool_t *ctx_pool;
static mempool_t *call_pool;

struct triton_stat_t __export triton_stat;

static struct timeval ru_utime;
static struct timeval ru_stime;
static struct timespec ru_timestamp;
static int ru_refs;
static void ru_update(struct triton_timer_t *);
static struct triton_timer_t ru_timer = {
	.period = 1000,
	.expire = ru_update,
};
struct triton_context_t default_ctx;

static __thread struct triton_context_t *this_ctx;
static __thread jmp_buf jmp_env;
static __thread void *thread_frame;

#define log_debug2(fmt, ...)

void triton_thread_wakeup(struct _triton_thread_t *thread)
{
	log_debug2("wake up thread %p\n", thread);
	pthread_kill(thread->thread, SIGUSR1);
}

static void __config_reload(void (*notify)(int))
{
	struct _triton_thread_t *t;
	int r;

	log_debug2("config_reload: enter\n");
	r = conf_reload(NULL);
	notify(r);

	spin_lock(&threads_lock);
	need_config_reload = 0;
	list_for_each_entry(t, &threads, entry)
		triton_thread_wakeup(t);
	spin_unlock(&threads_lock);
	log_debug2("config_reload: exit\n");
}

static void ctx_thread(struct _triton_context_t *ctx);

static int check_ctx_queue_empty(struct _triton_thread_t *t)
{
	int i;

	for (i = 0; i < CTX_PRIO_MAX; i++) {
		if (!list_empty(&t->wakeup_list[i])) {
			t->ctx = list_entry(t->wakeup_list[i].next, struct _triton_context_t, entry2);
			return 1;
		}

		if (!list_empty(&ctx_queue[i])) {
			t->ctx = list_entry(ctx_queue[i].next, struct _triton_context_t, entry2);
			return 1;
		}
	}

	return 0;
}

static void* triton_thread(struct _triton_thread_t *thread)
{
	sigset_t set;
	int sig, need_free;
	void *stack;

	sigfillset(&set);
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	sigdelset(&set, SIGSEGV);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGQUIT);

	thread_frame = __builtin_frame_address(0);

	pthread_mutex_lock(&thread->sleep_lock);
	pthread_mutex_unlock(&thread->sleep_lock);

	while (1) {
		spin_lock(&threads_lock);
		if (!need_config_reload && check_ctx_queue_empty(thread)) {
			if (thread->ctx->asleep && thread->ctx->wakeup) {
				log_debug2("thread: %p: wakeup ctx %p\n", thread, thread->ctx);
				list_del(&thread->ctx->entry2);
				spin_unlock(&threads_lock);

				this_ctx = thread->ctx->ud;
				if (this_ctx->before_switch)
					this_ctx->before_switch(this_ctx, thread->ctx->bf_arg);

				stack = alloca(thread->ctx->uc->uc_stack.ss_size + 64);
				asm volatile("" :: "m" (stack));

				memcpy(thread_frame - thread->ctx->uc->uc_stack.ss_size, thread->ctx->uc->uc_stack.ss_sp, thread->ctx->uc->uc_stack.ss_size);
				setcontext(thread->ctx->uc);
				abort();
			} else {
				log_debug2("thread: %p: dequeued ctx %p\n", thread, thread->ctx);
				list_del(&thread->ctx->entry2);
				thread->ctx->thread = thread;
				thread->ctx->queued = 0;
				spin_unlock(&threads_lock);
				__sync_sub_and_fetch(&triton_stat.context_pending, 1);
			}
		} else {
			log_debug2("thread: %p: sleeping\n", thread);

			if (!terminate)
				list_add(&thread->entry2, &sleep_threads);

			if (__sync_sub_and_fetch(&triton_stat.thread_active, 1) == 0 && need_config_reload) {
				spin_unlock(&threads_lock);
				__config_reload(config_reload_notify);
			} else
				spin_unlock(&threads_lock);

			spin_lock(&ctx_list_lock);
			if (terminate) {
				spin_unlock(&ctx_list_lock);
				spin_lock(&threads_lock);
				list_del(&thread->entry);
				spin_unlock(&threads_lock);
				return NULL;
			}
			spin_unlock(&ctx_list_lock);

			//printf("thread %p: enter sigwait\n", thread);
			sigwait(&set, &sig);
			//printf("thread %p: exit sigwait\n", thread);

			spin_lock(&threads_lock);
			__sync_add_and_fetch(&triton_stat.thread_active, 1);
			if (!thread->ctx) {
				list_del(&thread->entry2);
				spin_unlock(&threads_lock);
				continue;
			}
			spin_unlock(&threads_lock);
		}

		if (setjmp(jmp_env) == 0) {
			log_debug2("thread %p: ctx=%p %p\n", thread, thread->ctx, thread->ctx ? thread->ctx->thread : NULL);
			this_ctx = thread->ctx->ud;
			if (this_ctx->before_switch)
				this_ctx->before_switch(this_ctx, thread->ctx->bf_arg);

			while (1) {
				log_debug2("thread %p: switch to %p\n", thread, thread->ctx);
				ctx_thread(thread->ctx);
				log_debug2("thread %p: switch from %p %p\n", thread, thread->ctx, thread->ctx->thread);

				spin_lock(&threads_lock);
				if (!thread->ctx->pending || thread->ctx->need_free)
					break;
				spin_unlock(&threads_lock);
			}

			thread->ctx->thread = NULL;
			need_free = thread->ctx->need_free;
			spin_unlock(&threads_lock);

			if (need_free) {
				log_debug2("- context %p removed\n", thread->ctx);
				triton_context_release(thread->ctx);
			}
			thread->ctx = NULL;
		}
	}
}

static void ctx_thread(struct _triton_context_t *ctx)
{
	struct _triton_md_handler_t *h;
	struct _triton_timer_t *t;
	struct _triton_ctx_call_t *call;
	uint64_t tt;
	int events;

	log_debug2("ctx %p %p: enter\n", ctx, ctx->thread);

	while (1) {
		spin_lock(&ctx->lock);
		if (!list_empty(&ctx->pending_timers)) {
			t = list_entry(ctx->pending_timers.next, typeof(*t), entry2);
			list_del(&t->entry2);
			t->pending = 0;
			spin_unlock(&ctx->lock);
			__sync_sub_and_fetch(&triton_stat.timer_pending, 1);
			read(t->fd, &tt, sizeof(tt));
			if (t->ud)
				t->ud->expire(t->ud);
			continue;
		}

		if (!list_empty(&ctx->pending_handlers)) {
			h = list_entry(ctx->pending_handlers.next, typeof(*h), entry2);
			list_del(&h->entry2);
			h->pending = 0;
			events = h->trig_epoll_events;
			h->trig_epoll_events = 0;
			spin_unlock(&ctx->lock);

			__sync_sub_and_fetch(&triton_stat.md_handler_pending, 1);

			h->armed = 0;

			if ((events & (EPOLLIN | EPOLLERR | EPOLLHUP)) && (h->epoll_event.events & EPOLLIN)) {
				if (h->ud && h->ud->read) {
					if (h->ud->read(h->ud))
						continue;
				}
			}

			if ((events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) && (h->epoll_event.events & EPOLLOUT)) {
				if (h->ud && h->ud->write) {
					if (h->ud->write(h->ud))
						continue;
				}
			}

			md_rearm(h);

			continue;
		}

		if (!list_empty(&ctx->pending_calls)) {
			call = list_entry(ctx->pending_calls.next, typeof(*call), entry);
			list_del(&call->entry);
			spin_unlock(&ctx->lock);
			call->func(call->arg);
			mempool_free(call);
			continue;
		}

		ctx->pending = 0;
		spin_unlock(&ctx->lock);
		break;
	}

	spin_lock(&ctx->lock);
	if (ctx->need_close && !ctx->need_free) {
		spin_unlock(&ctx->lock);
		if (ctx->ud->close) {
			ctx->ud->close(ctx->ud);
		}
		spin_lock(&ctx->lock);
		ctx->need_close = 0;
	}
	spin_unlock(&ctx->lock);

	log_debug2("ctx %p %p: exit\n", ctx, ctx->thread);
}

struct _triton_thread_t *create_thread()
{
	int i;

	pthread_attr_t attr;
	struct _triton_thread_t *thread = _malloc(sizeof(*thread));
	if (!thread) {
		triton_log_error("out of memory");
		return NULL;
	}


	memset(thread, 0, sizeof(*thread));

	for (i = 0; i < CTX_PRIO_MAX; i++)
		INIT_LIST_HEAD(&thread->wakeup_list[i]);

	pthread_mutex_init(&thread->sleep_lock, NULL);
	pthread_mutex_lock(&thread->sleep_lock);

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, WORKER_STACK_SIZE);

	while (pthread_create(&thread->thread, &attr, (void*(*)(void*))triton_thread, thread))
		sleep(1);

	__sync_add_and_fetch(&triton_stat.thread_count, 1);
	__sync_add_and_fetch(&triton_stat.thread_active, 1);

	return thread;
}

int triton_queue_ctx(struct _triton_context_t *ctx)
{
	spin_lock(&threads_lock);
	ctx->pending = 1;
	if (ctx->thread || ctx->entry2.next || ctx->need_free) {
		spin_unlock(&threads_lock);
		return 0;
	}

	if (list_empty(&sleep_threads) || ctx->init || need_config_reload) {
		list_add_tail(&ctx->entry2, &ctx_queue[ctx->priority]);
		spin_unlock(&threads_lock);
		ctx->queued = 1;
		log_debug2("ctx %p: queued\n", ctx);
		__sync_add_and_fetch(&triton_stat.context_pending, 1);
		return 0;
	}

	ctx->thread = list_entry(sleep_threads.next, typeof(*ctx->thread), entry2);
	ctx->thread->ctx = ctx;
	log_debug2("ctx %p: assigned to thread %p\n", ctx, ctx->thread);
	list_del(&ctx->thread->entry2);
	spin_unlock(&threads_lock);

	return 1;
}

void triton_context_release(struct _triton_context_t *ctx)
{
	if (__sync_sub_and_fetch(&ctx->refs, 1) == 0)
		mempool_free(ctx);
}

int __export triton_context_register(struct triton_context_t *ud, void *bf_arg)
{
	struct _triton_context_t *ctx = mempool_alloc(ctx_pool);

	log_debug2("ctx %p: register\n", ctx);
	if (!ctx)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ud = ud;
	ctx->bf_arg = bf_arg;
	ctx->init = 1;
	ctx->refs = 1;
	ctx->priority = 1;
	spinlock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->handlers);
	INIT_LIST_HEAD(&ctx->timers);
	INIT_LIST_HEAD(&ctx->pending_handlers);
	INIT_LIST_HEAD(&ctx->pending_timers);
	INIT_LIST_HEAD(&ctx->pending_calls);

	ud->tpd = ctx;

	spin_lock(&ctx_list_lock);
	list_add_tail(&ctx->entry, &ctx_list);
	spin_unlock(&ctx_list_lock);

	__sync_add_and_fetch(&triton_stat.context_sleeping, 1);
	__sync_add_and_fetch(&triton_stat.context_count, 1);

	return 0;
}

void __export triton_context_unregister(struct triton_context_t *ud)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	struct _triton_ctx_call_t *call;
	struct _triton_thread_t *t;

	log_debug2("ctx %p: unregister\n", ctx);

	while (!list_empty(&ctx->pending_calls)) {
		call = list_entry(ctx->pending_calls.next, typeof(*call), entry);
		list_del(&call->entry);
		mempool_free(call);
	}

	if (!list_empty(&ctx->handlers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: handlers is not empty");
		{
			struct _triton_md_handler_t *h;
			list_for_each_entry(h, &ctx->handlers, entry)
				if (h->ud)
					printf("%p\n", h->ud);
		}
		abort();
	}

	if (!list_empty(&ctx->pending_handlers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: pending_handlers is not empty");
		abort();
	}

	if (!list_empty(&ctx->timers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: timers is not empty");
		abort();
	}

	if (!list_empty(&ctx->pending_timers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: pending_timers is not empty");
		abort();
	}

	ctx->need_free = 1;
	ud->tpd = NULL;

	spin_lock(&ctx_list_lock);
	list_del(&ctx->entry);
	if (__sync_sub_and_fetch(&triton_stat.context_count, 1) == 1) {
		if (need_terminate)
			terminate = 1;
	}
	spin_unlock(&ctx_list_lock);

	if (terminate) {
		spin_lock(&threads_lock);
		list_for_each_entry(t, &threads, entry)
			triton_thread_wakeup(t);
		spin_unlock(&threads_lock);
	}
}

void __export triton_context_set_priority(struct triton_context_t *ud, int prio)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;

	assert(prio >= 0 && prio < CTX_PRIO_MAX);

	ctx->priority = prio;
}

struct triton_context_t __export *triton_context_self(void)
{
	return this_ctx;
}

void triton_context_print(void)
{
	struct _triton_context_t *ctx;

	list_for_each_entry(ctx, &ctx_list, entry)
		printf("%p\n", ctx);
}

static ucontext_t * __attribute__((noinline)) alloc_context()
{
	ucontext_t *uc;
	void *frame = __builtin_frame_address(0);
	size_t stack_size = thread_frame - frame;

	uc = _malloc(sizeof(*uc) + stack_size);
	uc->uc_stack.ss_sp = (void *)(uc + 1);
	uc->uc_stack.ss_size = stack_size;
	memcpy(uc->uc_stack.ss_sp, frame, stack_size);

	return uc;
}

void __export triton_context_schedule()
{
	volatile struct _triton_context_t *ctx = (struct _triton_context_t *)this_ctx->tpd;

	log_debug2("ctx %p: enter schedule\n", ctx);
	__sync_add_and_fetch(&triton_stat.context_sleeping, 1);

	ctx->uc = alloc_context();

	getcontext(ctx->uc);

	barrier();

	ctx = (struct _triton_context_t *)this_ctx->tpd;

	spin_lock(&threads_lock);
	if (ctx->wakeup) {
		ctx->asleep = 0;
		ctx->wakeup = 0;
		spin_unlock(&threads_lock);
		_free(ctx->uc);
		ctx->uc = NULL;
		__sync_sub_and_fetch(&triton_stat.context_sleeping, 1);
		log_debug2("ctx %p: exit schedule\n", ctx);
	} else {
		ctx->asleep = 1;
		ctx->thread->ctx = NULL;
		spin_unlock(&threads_lock);
		longjmp(jmp_env, 1);
	}
}

void __export triton_context_wakeup(struct triton_context_t *ud)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	int r = 0;

	log_debug2("ctx %p: wakeup\n", ctx);

	if (ctx->init) {
		__sync_sub_and_fetch(&triton_stat.context_sleeping, 1);
		spin_lock(&ctx->lock);
		ctx->init = 0;
		if (ctx->pending)
			r = triton_queue_ctx(ctx);
		spin_unlock(&ctx->lock);
	} else {
		spin_lock(&threads_lock);
		/* In some cases (pppd_compat.c), triton_context_wakeup() might
		 * be called before triton_context_schedule(). When that
		 * happens, we must not add 'ctx' to the wakeup_list as it is
		 * still awake. However we need to set the 'wakeup' flag. This
		 * way, when triton_context_schedule() will run, it will
		 * realise that triton_context_wakeup() was already executed
		 * and will avoid putting 'ctx' in sleep mode.
		 */
		ctx->wakeup = 1;
		if (ctx->asleep) {
			list_add_tail(&ctx->entry2, &ctx->thread->wakeup_list[ctx->priority]);
			r = ctx->thread->ctx == NULL;
		}
		spin_unlock(&threads_lock);
	}

	if (r)
		triton_thread_wakeup(ctx->thread);
}

int __export triton_context_call(struct triton_context_t *ud, void (*func)(void *), void *arg)
{
	struct _triton_context_t *ctx = ud ? (struct _triton_context_t *)ud->tpd : (struct _triton_context_t *)default_ctx.tpd;
	struct _triton_ctx_call_t *call = mempool_alloc(call_pool);
	int r;

	if (!call)
		return -1;

	call->func = func;
	call->arg = arg;

	spin_lock(&ctx->lock);
	list_add_tail(&call->entry, &ctx->pending_calls);
	r = triton_queue_ctx(ctx);
	spin_unlock(&ctx->lock);

	if (r)
		triton_thread_wakeup(ctx->thread);

	return 0;
}

void __export triton_cancel_call(struct triton_context_t *ud, void (*func)(void *))
{
	struct _triton_context_t *ctx = ud ? (struct _triton_context_t *)ud->tpd : (struct _triton_context_t *)default_ctx.tpd;
	struct list_head *pos, *n;
	struct _triton_ctx_call_t *call;
	LIST_HEAD(rem_calls);

	spin_lock(&ctx->lock);
	list_for_each_safe(pos, n, &ctx->pending_calls) {
		call = list_entry(pos, typeof(*call), entry);
		if (call->func == func)
			list_move(&call->entry, &rem_calls);
	}
	spin_unlock(&ctx->lock);

	while (!list_empty(&rem_calls)) {
		call = list_first_entry(&rem_calls, typeof(*call), entry);
		list_del(&call->entry);
		mempool_free(call);
	}
}

void __export triton_collect_cpu_usage(void)
{
	struct rusage rusage;

	if (__sync_fetch_and_add(&ru_refs, 1) == 0) {
		triton_timer_add(NULL, &ru_timer, 0);
		getrusage(RUSAGE_SELF, &rusage);
		clock_gettime(CLOCK_MONOTONIC, &ru_timestamp);
		ru_utime = rusage.ru_utime;
		ru_stime = rusage.ru_stime;
		triton_stat.cpu = 0;
	}
}

void __export triton_stop_collect_cpu_usage(void)
{
	if (__sync_sub_and_fetch(&ru_refs, 1) == 0)
		triton_timer_del(&ru_timer);
}

static void ru_update(struct triton_timer_t *t)
{
	struct timespec ts;
	struct rusage rusage;
	unsigned int dt;
	unsigned int val;

	getrusage(RUSAGE_SELF, &rusage);
	clock_gettime(CLOCK_MONOTONIC, &ts);

	dt = (ts.tv_sec - ru_timestamp.tv_sec) * 1000000 + (ts.tv_nsec - ru_timestamp.tv_nsec) / 1000000;
	val = (double)((rusage.ru_utime.tv_sec - ru_utime.tv_sec) * 1000000 + (rusage.ru_utime.tv_usec - ru_utime.tv_usec) +
	      (rusage.ru_stime.tv_sec - ru_stime.tv_sec) * 1000000 + (rusage.ru_stime.tv_usec - ru_stime.tv_usec)) / dt * 100;

	triton_stat.cpu = val;

	ru_timestamp = ts;
	ru_utime = rusage.ru_utime;
	ru_stime = rusage.ru_stime;
}

void __export triton_register_init(int order, void (*func)(void))
{
	struct _triton_init_t *i1, *i = _malloc(sizeof(*i));
	struct list_head *p = init_list.next;


	i->order = order;
	i->func = func;

	while (p != &init_list) {
		i1 = list_entry(p, typeof(*i1), entry);
		if (order < i1->order)
			break;
		p = p->next;
	}
	list_add_tail(&i->entry, p);
}

int __export triton_init(const char *conf_file)
{
	int i;

	spinlock_init(&threads_lock);
	spinlock_init(&ctx_list_lock);

	ctx_pool = mempool_create(sizeof(struct _triton_context_t));
	call_pool = mempool_create(sizeof(struct _triton_ctx_call_t));

	for (i = 0; i < CTX_PRIO_MAX; i++)
		INIT_LIST_HEAD(&ctx_queue[i]);

	if (conf_load(conf_file))
		return -1;

	if (log_init())
		return -1;

	if (md_init())
		return -1;

	if (timer_init())
		return -1;

	if (event_init())
		return -1;

	triton_context_register(&default_ctx, NULL);

	return 0;
}

int __export triton_load_modules(const char *mod_sect)
{
	struct _triton_init_t *i;

	if (load_modules(mod_sect))
		return -1;

	while (!list_empty(&init_list)) {
		i = list_entry(init_list.next, typeof(*i), entry);
		i->func();
		list_del(&i->entry);
		_free(i);
	}

	return 0;
}

void __export triton_conf_reload(void (*notify)(int))
{
	spin_lock(&threads_lock);
	need_config_reload = 1;
	config_reload_notify = notify;
	if (triton_stat.thread_active == 0) {
		spin_unlock(&threads_lock);
		__config_reload(notify);
	} else
		spin_unlock(&threads_lock);
}

void __export triton_run()
{
	struct _triton_thread_t *t;
	int i;
	char *opt;
	struct timespec ts;

	opt = conf_get_opt("core", "thread-count");
	if (opt && atoi(opt) > 0)
		thread_count = atoi(opt);
	else {
		thread_count = sysconf(_SC_NPROCESSORS_ONLN);
		if (thread_count < 0) {
			triton_log_error("sysconf(_SC_NPROCESSORS_ONLN)"
					 " failed: %s\n", strerror(errno));
			thread_count = 2;
		}
	}

	for(i = 0; i < thread_count; i++) {
		t = create_thread();
		if (!t) {
			triton_log_error("triton_run:create_thread: %s", strerror(errno));
			_exit(-1);
		}

		list_add_tail(&t->entry, &threads);
		pthread_mutex_unlock(&t->sleep_lock);
	}

	clock_gettime(CLOCK_MONOTONIC, &ts);
	triton_stat.start_time = ts.tv_sec;

	md_run();
	timer_run();

	triton_context_wakeup(&default_ctx);
}

void __export triton_terminate()
{
	struct _triton_context_t *ctx;
	int r;

	need_terminate = 1;

	spin_lock(&ctx_list_lock);
	list_for_each_entry(ctx, &ctx_list, entry) {
		spin_lock(&ctx->lock);
		ctx->need_close = 1;
		r = triton_queue_ctx(ctx);
		if (r)
			triton_thread_wakeup(ctx->thread);
		spin_unlock(&ctx->lock);
	}
	spin_unlock(&ctx_list_lock);

	while (1) {
		spin_lock(&threads_lock);
		if (list_empty(&threads)) {
			spin_unlock(&threads_lock);
			break;
		}
		spin_unlock(&threads_lock);
		sleep(1);
	}

	md_terminate();
	timer_terminate();
}

