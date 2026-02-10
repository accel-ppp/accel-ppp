#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "triton_p.h"

#include "memdebug.h"

static int max_events = 1024;
static struct _triton_event_t **events;

struct event_handler_t
{
	struct list_head entry;
	triton_event_func func;
};

int event_init(void)
{
	events = malloc(max_events * sizeof(void *));
	if (!events) {
		fprintf(stderr,"event:cann't allocate memory\n");
		return -1;
	}

	memset(events, 0, max_events * sizeof(void *));

	return 0;
}

int __export triton_event_register_handler(int ev_id, triton_event_func func)
{
	struct _triton_event_t *ev;
	struct event_handler_t *h;

	if (ev_id >= max_events)
		return -1;

	ev = events[ev_id];
	if (!ev) {
		ev = malloc(sizeof(*ev));
		if (!ev) {
			triton_log_error("event: out of memory");
			return -1;
		}
		INIT_LIST_HEAD(&ev->handlers);
		events[ev_id] = ev;
	}

	h = malloc(sizeof(*h));
	if (!h) {
		triton_log_error("event: out of memory");
		return -1;
	}

	h->func = func;
	list_add_tail(&h->entry, &ev->handlers);

	return 0;
}

int __export triton_event_unregister_handler(int ev_id, triton_event_func func)
{
	struct _triton_event_t *ev;
	struct event_handler_t *h;

	if (ev_id >= max_events)
		return -1;

	ev = events[ev_id];
	if (!ev) {
		return -1;
	}

	list_for_each_entry(h, &ev->handlers, entry) {
		if (h->func == func) {
			if (ev->in_progress)
				h->func = NULL;
			else {
				list_del(&h->entry);
				_free(h);
			}
			return 0;
		}
	}

	return -1;
}

void __export triton_event_fire(int ev_id, void *arg)
{
	struct _triton_event_t *ev;
	struct event_handler_t *h;
	struct event_handler_t *tmp;

	if (ev_id >= max_events)
		return;

	ev = events[ev_id];
	if (!ev)
		return;

	ev->in_progress = 1;
	list_for_each_entry(h, &ev->handlers, entry)
		if (h->func)
			h->func(arg);
	ev->in_progress = 0;

	list_for_each_entry_safe(h, tmp, &ev->handlers, entry) {
		if (!h->func) {
			list_del(&h->entry);
			_free(h);
		}
	}
}
