/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include "list.h"

/* nnle: Netlink New Link Event */

struct nnle_handler_t {
	list_t entry;
	void (*on_new_link)(const char *name);
	void (*on_del_link)(const char *name);
};

void nnle_add_handler(struct nnle_handler_t *h);
void nnle_del_handler(struct nnle_handler_t *h);