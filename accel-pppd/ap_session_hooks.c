/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <stddef.h>
#include <string.h>

#include "triton.h"

#include "ap_session_hooks.h"

LIST_HEAD(ap_session_hooks_list);

__export
int ap_session_hooks_register(struct ap_session_hooks_t *h)
{
	if (h == NULL || h->hooks_name == NULL)
		return -1;

	list_add_tail(&h->entry, &ap_session_hooks_list);
	return 0;
}

__export
void ap_session_hooks_unregister(struct ap_session_hooks_t *h)
{
	if (h == NULL)
		return;

	list_del(&h->entry);
}

__export
struct ap_session_hooks_t * ap_session_hooks_find(const char *name)
{
	if (name == NULL)
		return NULL;

	struct ap_session_hooks_t *h = NULL;
	list_for_each_entry(h, &ap_session_hooks_list, entry) {
		if (!strcmp(name, h->hooks_name))
			return h;
	}

	return NULL;
}