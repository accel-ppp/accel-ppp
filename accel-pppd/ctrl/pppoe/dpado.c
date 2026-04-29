#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "list.h"
#include "cli.h"
#include "triton.h"
#include "log.h"
#include "memdebug.h"

#include "pppoe.h"

struct dpado_range_t
{
	struct list_head entry;
	unsigned int conn_cnt;
	int pado_delay;
};

static pthread_mutex_t dpado_range_lock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(dpado_range_list);
static struct dpado_range_t *dpado_range_next;
static struct dpado_range_t *dpado_range_prev;
int pado_delay;

void dpado_check_next(int conn_cnt)
{
	pthread_mutex_lock(&dpado_range_lock);
	if (dpado_range_next && conn_cnt == dpado_range_next->conn_cnt) {
		pado_delay = dpado_range_next->pado_delay;
		dpado_range_prev = dpado_range_next;
		if (dpado_range_next->entry.next != &dpado_range_list)
			dpado_range_next = list_entry(dpado_range_next->entry.next, typeof(*dpado_range_next), entry);
		else
			dpado_range_next = NULL;
	/*printf("active=%i, prev=%i:%i, next=%i:%i, pado_delay=%i\n", stat_active,
	dpado_range_prev?dpado_range_prev->pado_delay:0,dpado_range_prev?dpado_range_prev->conn_cnt:0,
	dpado_range_next?dpado_range_next->pado_delay:0,dpado_range_next?dpado_range_next->conn_cnt:0,
	pado_delay);*/
	}
	pthread_mutex_unlock(&dpado_range_lock);
}

void dpado_check_prev(int conn_cnt)
{
	pthread_mutex_lock(&dpado_range_lock);
	if (dpado_range_prev && conn_cnt == dpado_range_prev->conn_cnt) {
		dpado_range_next = dpado_range_prev;
		dpado_range_prev = list_entry(dpado_range_prev->entry.prev, typeof(*dpado_range_prev), entry);
		pado_delay = dpado_range_prev->pado_delay;
	/*printf("active=%i, prev=%i:%i, next=%i:%i, pado_delay=%i\n", stat_active,
	dpado_range_prev?dpado_range_prev->pado_delay:0,dpado_range_prev?dpado_range_prev->conn_cnt:0,
	dpado_range_next?dpado_range_next->pado_delay:0,dpado_range_next?dpado_range_next->conn_cnt:0,
	pado_delay);*/
	}
	pthread_mutex_unlock(&dpado_range_lock);
}

static void strip(char *str)
{
	char *ptr = str;
	char *endptr = strchr(str, 0);
	while (1) {
		ptr = strchr(ptr, ' ');
		if (ptr)
			memmove(ptr, ptr + 1, endptr - ptr - 1);
		else
			break;
	}
}

int dpado_parse(const char *str)
{
	char *str1 = _strdup(str);
	char *ptr1, *ptr2, *ptr3, *endptr;
	unsigned int active = pppoe_stat_active();
	LIST_HEAD(range_list);
	struct dpado_range_t *r;

	strip(str1);

	ptr1 = str1;

	while (1) {
		ptr2 = strchr(ptr1, ',');
		if (ptr2)
			*ptr2 = 0;
		ptr3 = strchr(ptr1, ':');
		if (ptr3)
			*ptr3 = 0;

		r = _malloc(sizeof(*r));
		memset(r, 0, sizeof(*r));

		r->pado_delay = strtol(ptr1, &endptr, 10);
		if (*endptr)
			goto out_err;

		if (list_empty(&range_list))
			r->conn_cnt = INT_MAX;
		else {
			if (!ptr3)
				goto out_err;
			r->conn_cnt = strtol(ptr3 + 1, &endptr, 10);
			if (*endptr)
				goto out_err;
		}

		list_add_tail(&r->entry, &range_list);
		//printf("parsed range: %i:%i\n", r->pado_delay, r->conn_cnt);

		if (!ptr2)
			break;

		ptr1 = ptr2 + 1;
	}

	pthread_mutex_lock(&dpado_range_lock);
	while (!list_empty(&dpado_range_list)) {
		r = list_entry(dpado_range_list.next, typeof(*r), entry);
		list_del(&r->entry);
		_free(r);
	}

	list_splice(&range_list, &dpado_range_list);

	dpado_range_next = NULL;
	dpado_range_prev = NULL;

	list_for_each_entry(r, &dpado_range_list, entry) {
		if (!dpado_range_prev || active >= r->conn_cnt) {
			dpado_range_prev = r;
			if (r->entry.next != &dpado_range_list)
				dpado_range_next = list_entry(r->entry.next, typeof(*r), entry);
			else
				dpado_range_next = NULL;
		}
	}

	if (dpado_range_prev)
		pado_delay = dpado_range_prev->pado_delay;
	else
		pado_delay = 0;

	if (conf_pado_delay)
		_free(conf_pado_delay);
	conf_pado_delay = _strdup(str);
	/*printf("active=%i, prev=%i:%i, next=%i:%i, pado_delay=%i\n", stat_active,
	dpado_range_prev?dpado_range_prev->pado_delay:0,dpado_range_prev?dpado_range_prev->conn_cnt:0,
	dpado_range_next?dpado_range_next->pado_delay:0,dpado_range_next?dpado_range_next->conn_cnt:0,
	pado_delay);*/

	pthread_mutex_unlock(&dpado_range_lock);

	_free(str1);
	return 0;

out_err:
	_free(str1);
	log_emerg("pppoe: pado_delay: invalid format\n");
	return -1;
}

