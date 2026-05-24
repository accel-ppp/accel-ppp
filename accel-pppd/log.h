#ifndef __LOG_H
#define __LOG_H

#include <stdarg.h>
#include <sys/time.h>
#include "list.h"

#define LOG_MAX_SIZE 4096
#define LOG_CHUNK_SIZE 128

struct ap_session;
struct triton_context_t;

struct log_msg_t
{
	struct list_head entry;
	void *lpd;
	void *tpd;
	struct timeval timestamp;
	int level;
	struct log_chunk_t *hdr;
	struct list_head *chunks;
};

struct log_chunk_t
{
	struct list_head entry;
	int len;
	char msg[0];
};

struct log_target_t
{
	struct list_head entry;

	void (*log)(struct log_target_t *, struct log_msg_t *, struct ap_session *ses);
	void (*reopen)(void);
};

void log_free_msg(struct log_msg_t *msg);

void log_emerg(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));

void log_error(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_warn(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_info1(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_info2(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_debug(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_msg(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));

void log_ppp_error(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_ppp_warn(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_ppp_info1(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_ppp_info2(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_ppp_debug(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_ppp_msg(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));

void log_switch(struct triton_context_t *ctx, void *arg);

void log_register_target(struct log_target_t *t);
void log_unregister_target(struct log_target_t *t);

#endif
