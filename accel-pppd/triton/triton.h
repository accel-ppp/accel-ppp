#ifndef TRITON_H
#define TRITON_H

#include <time.h>
#include <sys/time.h>
#include <stdint.h>

#include "list.h"

struct triton_context_t
{
	const void *tpd; // triton private data, don't touch
	void (*close)(struct triton_context_t*);
	void (*free)(struct triton_context_t*);
	void (*before_switch)(struct triton_context_t *ctx, void *arg);
};

struct triton_md_handler_t
{
	const void *tpd; // triton private data, don't touch!
	int fd;
	int (*read)(struct triton_md_handler_t *);
	int (*write)(struct triton_md_handler_t *);
};

struct triton_timer_t
{
	const void *tpd; // triton private data, don't touch!
	struct timeval expire_tv;
	int period;
	void (*expire)(struct triton_timer_t *);
};

struct triton_sigchld_handler_t
{
	void *tpd;
	int pid;
	void (*handler)(struct triton_sigchld_handler_t *h, int status);
};

struct conf_option_t
{
	struct list_head entry;
	char *name;
	char *val;
	char *raw;
	struct list_head items;
};

struct conf_sect_t
{
	const char *name;
	struct list_head items;
};

struct triton_stat_t
{
	unsigned int mempool_allocated;
	unsigned int mempool_available;
	unsigned int thread_count;
	unsigned int thread_active;
	unsigned int context_count;
	unsigned int context_sleeping;
	unsigned int context_pending;
	unsigned int md_handler_count;
	unsigned int md_handler_pending;
	unsigned int timer_count;
	unsigned int timer_pending;
	time_t start_time;
	unsigned int cpu;
};

extern struct triton_stat_t triton_stat;
int triton_context_register(struct triton_context_t *, void *arg);
void triton_context_unregister(struct triton_context_t *);
void triton_context_set_priority(struct triton_context_t *, int);
void triton_context_schedule(void);
void triton_context_wakeup(struct triton_context_t *);
int triton_context_call(struct triton_context_t *, void (*func)(void *), void *arg);
void triton_cancel_call(struct triton_context_t *, void (*func)(void *));
struct triton_context_t *triton_context_self(void);

#define MD_MODE_READ 1
#define MD_MODE_WRITE 2

#define MD_TRIG_EDGE 0
#define MD_TRIG_LEVEL 1

void triton_md_register_handler(struct triton_context_t *, struct triton_md_handler_t *);
void triton_md_unregister_handler(struct triton_md_handler_t *h, int close);
int triton_md_enable_handler(struct triton_md_handler_t *h, int mode);
int triton_md_disable_handler(struct triton_md_handler_t *h,int mode);
void triton_md_set_trig(struct triton_md_handler_t *h, int mode);

int triton_timer_add(struct triton_context_t *ctx, struct triton_timer_t*,int abs_time);
int triton_timer_mod(struct triton_timer_t *,int abs_time);
void triton_timer_del(struct triton_timer_t *);

typedef void (*triton_event_func)(void *);
int triton_event_register_handler(int ev_id, triton_event_func func);
void triton_event_fire(int ev_id, void *arg);

struct conf_sect_t *conf_get_section(const char *name);
char *conf_get_opt(const char *sect, const char *name);
void triton_conf_reload(void (*notify)(int));
void config_wrlock();
void config_lock();
void config_unlock();

void triton_collect_cpu_usage(void);
void triton_stop_collect_cpu_usage(void);

int triton_module_loaded(const char *name);

void triton_register_init(int order, void (*func)(void));

static inline time_t _time()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

#define TRITON_OK          0
#define TRITON_ERR_NOCOMP -1
#define TRITON_ERR_NOSUPP -2
#define TRITON_ERR_NOINTF -3
#define TRITON_ERR_EXISTS -4
#define TRITON_ERR_NOCHAN -5
#define TRITON_ERR_NOMSG  -6
#define TRITON_ERR_BUSY   -5

int triton_init(const char *conf_file);
int triton_load_modules(const char *md_sect);
void triton_run(void);
void triton_terminate(void);


#define __init __attribute__((constructor))
#define __exit __attribute__((destructor))
#define __export __attribute__((visibility("default")))
#define __unused __attribute__((unused))

#define barrier() asm volatile ("" ::: "memory")

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define DEFINE_INIT(o, func) static void __init __init__(void){triton_register_init(o,func);}
#define DEFINE_INIT2(o, func) static void __init __init2__(void){triton_register_init(o,func);}

#endif
