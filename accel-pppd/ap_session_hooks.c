/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <stddef.h>
#include <string.h>

#include <pthread.h>

#include "triton.h"

#include "ap_session_hooks.h"

LIST_HEAD(ap_session_hooks_list);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

__export
int ap_session_hooks_register(struct ap_session_hooks_t *h)
{
	struct ap_session_hooks_t *it = NULL;
	int ret = 0;

	if (h == NULL || h->hooks_name == NULL)
		return -1;

	pthread_mutex_lock(&lock);

	list_for_each_entry(it, &ap_session_hooks_list, entry) {
		if (!strncmp(it->hooks_name, h->hooks_name, HOOKS_MAX_NAME_LEN)) {
			ret = -1;
			goto out;
		}
	}

	list_add_tail(&h->entry, &ap_session_hooks_list);

out:
	pthread_mutex_unlock(&lock);
	return ret;
}

__export
void ap_session_hooks_unregister(struct ap_session_hooks_t *h)
{
	if (h == NULL)
		return;

	pthread_mutex_lock(&lock);
	list_del(&h->entry);
	pthread_mutex_unlock(&lock);
}

__export
struct ap_session_hooks_t * ap_session_hooks_find(const char *name)
{
	struct ap_session_hooks_t *ret = NULL;
	if (name == NULL)
		return NULL;

	pthread_mutex_lock(&lock);

	struct ap_session_hooks_t *h = NULL;
	list_for_each_entry(h, &ap_session_hooks_list, entry) {
		if (!strncmp(name, h->hooks_name, HOOKS_MAX_NAME_LEN)) {
			ret = h;
			break;
		}
	}

	pthread_mutex_unlock(&lock);
	return ret;
}
