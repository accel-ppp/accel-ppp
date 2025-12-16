#include <stdio.h>
#include <stdarg.h>
#include "triton.h" // Needed for struct triton_context_t

// Simple stub for log_error
void log_error(const char *fmt, ...)
{
    va_list args;
    fprintf(stderr, "STUB_ERROR: ");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

// Stubs for other log functions
void log_warn(const char *fmt, ...) { }
void log_info1(const char *fmt, ...) { }
void log_info2(const char *fmt, ...) { }
void log_debug(const char *fmt, ...) { }
void log_msg(const char *fmt, ...) { }

// Stub for log_switch
void log_switch(struct triton_context_t *ctx, void *arg) { }
