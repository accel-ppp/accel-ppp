#ifndef LOG_H
#define LOG_H
#include <stdio.h>
#include <stdarg.h>

void log_error(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_info1(const char *fmt, ...);
void log_info2(const char *fmt, ...);
void log_debug(const char *fmt, ...);
void log_msg(const char *fmt, ...);

struct triton_context_t;
void log_switch(struct triton_context_t *ctx, void *arg);

#endif