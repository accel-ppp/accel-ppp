#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "ppp.h"
#include "events.h"
#include "triton.h"
#include "log.h"

#include "memdebug.h"

struct item
{
	struct list_head entry;
	uint64_t key;
	struct timespec ts;
	int count;
};

static int conf_burst = 3;
static int conf_burst_timeout = 60 * 1000;
static int conf_limit_timeout = 5000;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(items);

int __export connlimit_check(uint64_t key)
{
	struct item *it;
	struct timespec ts;
	unsigned int d;
	struct list_head *pos, *n;
	LIST_HEAD(tmp_list);
	int r = 1;


	clock_gettime(CLOCK_MONOTONIC, &ts);

	pthread_mutex_lock(&lock);
	log_debug("connlimit: check entry %" PRIu64 "\n", key);
	list_for_each_safe(pos, n, &items) {
		it = list_entry(pos, typeof(*it), entry);

		d = (ts.tv_sec - it->ts.tv_sec) * 1000 + (ts.tv_nsec - it->ts.tv_nsec) / 1000000;

		if (it->key == key) {
			if (d >= conf_burst_timeout) {
				it->ts = ts;
				list_move(&it->entry, &items);
				it->count = 0;
				r = 0;
				break;
			}
			it->count++;
			if (it->count >= conf_burst) {
				if (d >= conf_limit_timeout) {
					it->ts = ts;
					list_move(&it->entry, &items);
					r = 0;
				} else
					r = -1;
			} else
				r = 0;
			break;
		}

		if (d > conf_burst_timeout) {
			log_debug("connlimit: remove %" PRIu64 "\n", it->key);
			list_move(&it->entry, &tmp_list);
		}
	}
	pthread_mutex_unlock(&lock);

	if (r == 1) {
		it = _malloc(sizeof(*it));
		memset(it, 0, sizeof(*it));
		it->ts = ts;
		it->key = key;

		log_debug("connlimit: add entry %" PRIu64 "\n", key);

		pthread_mutex_lock(&lock);
		list_add(&it->entry, &items);
		pthread_mutex_unlock(&lock);

		r = 0;
	}

	if (r == 0)
		log_debug("connlimit: accept %" PRIu64 "\n", key);
	else
		log_debug("connlimit: drop %" PRIu64 "\n", key);


	while (!list_empty(&tmp_list)) {
		it = list_entry(tmp_list.next, typeof(*it), entry);
		list_del(&it->entry);
		_free(it);
	}

	return r;
}

static int parse_limit(const char *opt, int *limit, int *time)
{
	char *endptr;

	*limit = strtol(opt, &endptr, 10);

	if (!*endptr) {
		*time = 1;
		return 0;
	}

	if (*endptr != '/')
		goto out_err;

	opt = endptr + 1;
	*time = strtol(opt, &endptr, 10);

	if (endptr == opt)
		*time = 1;

	if (*endptr == 's')
		return 0;

	if (*endptr == 'm') {
		*time *= 60;
		return 0;
	}

	if (*endptr == 'h') {
		*time *= 3600;
		return 0;
	}

out_err:
	log_error("connlimit: failed to parse '%s'\n", opt);
	return -1;
}

static void load_config()
{
	const char *opt;
	int n,t;

	opt = conf_get_opt("connlimit", "limit");
	if (opt) {
		if (parse_limit(opt, &n, &t))
			return;
		conf_limit_timeout = t * 1000 / n;
	}

	opt = conf_get_opt("connlimit", "burst");
	if (opt)
		conf_burst = atoi(opt);

	opt = conf_get_opt("connlimit", "timeout");
	if (opt)
		conf_burst_timeout = atoi(opt) * 1000;
}

static void reload_config(void)
{
        config_lock();
        load_config();
        config_unlock();
}

static void init()
{
	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_config);
}

DEFINE_INIT(200, init);
