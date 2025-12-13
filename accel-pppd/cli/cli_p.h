#ifndef __CLI_P_H
#define __CLI_P_H

#include <stdarg.h>
#include <stddef.h>

#include "triton.h"

struct cli_client_t
{
	uint8_t *cmdline;
	int (*send)(struct cli_client_t *, const void *buf, int size);
	int (*sendv)(struct cli_client_t *, const char *fmt, va_list ap);
	void (*disconnect)(struct cli_client_t *);
	/* triton context serving this client's I/O; all sends must be
	 * serialized in it (log_stream delivers via triton_context_call) */
	struct triton_context_t *ctx;
	/* bytes pending in the transmit queue, maintained by the
	 * transport, accessed only from ctx */
	size_t queued_bytes;
};

int cli_process_cmd(struct cli_client_t *cln);

void cli_log_stream_on_disconnect(struct cli_client_t *cln);

extern char *conf_cli_passwd;
extern char *conf_cli_prompt;

#endif
