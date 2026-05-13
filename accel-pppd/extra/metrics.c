#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "triton.h"
#include "events.h"
#include "log.h"

#include "memdebug.h"

enum metrics_format {
	METRICS_FORMAT_PROMETHEUS,
	METRICS_FORMAT_JSON,
};

static enum metrics_format conf_format = METRICS_FORMAT_PROMETHEUS;
static char *conf_address;

static int parse_format(const char *opt, enum metrics_format *out)
{
	if (!strcasecmp(opt, "prometheus")) {
		*out = METRICS_FORMAT_PROMETHEUS;
		return 0;
	}
	if (!strcasecmp(opt, "json")) {
		*out = METRICS_FORMAT_JSON;
		return 0;
	}
	return -1;
}

static int load_config(void)
{
	const char *opt;
	enum metrics_format fmt = METRICS_FORMAT_PROMETHEUS;
	char *address = NULL;

	opt = conf_get_opt("metrics", "format");
	if (opt && parse_format(opt, &fmt) < 0) {
		log_error("metrics: unknown format '%s', expected 'prometheus' or 'json'\n", opt);
		return -1;
	}

	opt = conf_get_opt("metrics", "address");
	if (!opt) {
		log_emerg("metrics: 'address' option is required (host:port)\n");
		return -1;
	}
	address = _strdup(opt);
	if (!address) {
		log_emerg("metrics: out of memory while loading config\n");
		return -1;
	}

	conf_format = fmt;
	if (conf_address)
		_free(conf_address);
	conf_address = address;

	return 0;
}

static void init(void)
{
	if (load_config() < 0)
		return;

	log_info2("metrics: module loaded, listen %s, format %s\n",
		  conf_address,
		  conf_format == METRICS_FORMAT_PROMETHEUS ? "prometheus" : "json");
}

DEFINE_INIT(100, init);
