#ifndef TRITON_P_H
#define TRITON_P_H

#include <pthread.h>
#include <ucontext.h>
#include <sys/epoll.h>

#include "triton.h"
#include "list.h"
#include "spinlock.h"
#include "mempool.h"

#define CTX_PRIO_MAX 4

struct _triton_thread_t
{
	struct list_head entry;
	struct list_head entry2;
	pthread_t thread;
	int terminate;
	struct _triton_context_t *ctx;
	pthread_mutex_t sleep_lock;
	struct list_head wakeup_list[CTX_PRIO_MAX];
};

struct _triton_context_t
{
	struct list_head entry;
	struct list_head entry2;

	spinlock_t lock;
	struct _triton_thread_t *thread;

	struct list_head handlers;
	struct list_head timers;
	struct list_head pending_handlers;
	struct list_head pending_timers;
	struct list_head pending_calls;

	int init;
	int queued;
	int wakeup;
	int asleep;
	int need_close;
	int need_free;
	int pending;
	int priority;
	int refs;

	ucontext_t *uc;

	struct triton_context_t *ud;
	void *bf_arg;
};

struct _triton_md_handler_t
{
	struct list_head entry;
	struct list_head entry2;
	struct _triton_context_t *ctx;
	struct epoll_event epoll_event;
	uint32_t trig_epoll_events;
	int pending;
	unsigned int trig_level:1;
	unsigned int armed:1;
	unsigned int mod:1;
	struct triton_md_handler_t *ud;
};

struct _triton_timer_t
{
	struct list_head entry;
	struct list_head entry2;
	struct epoll_event epoll_event;
	struct _triton_context_t *ctx;
	int fd;
	unsigned int pending:1;
	struct triton_timer_t *ud;
};

struct _triton_event_t
{
	struct list_head handlers;
	unsigned int in_progress:1;
};

struct _triton_ctx_call_t
{
	struct list_head entry;

	void *arg;
	void (*func)(void *);
};

struct _triton_init_t
{
	struct list_head entry;

	int order;
	void (*func)(void);
};

int log_init(void);
int md_init();
int timer_init();
int event_init();

void md_run();
void md_terminate();
void md_rearm(struct _triton_md_handler_t *h);
void timer_run();
void timer_terminate();
extern struct triton_context_t default_ctx;
int triton_queue_ctx(struct _triton_context_t*);
void triton_thread_wakeup(struct _triton_thread_t*);
int conf_load(const char *fname);
int conf_reload(const char *fname);
void triton_log_error(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void triton_log_debug(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
int load_modules(const char *name);
void triton_context_release(struct _triton_context_t *ctx);

#endif
