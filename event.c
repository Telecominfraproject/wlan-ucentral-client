/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

#define MAX_EVENT	250

struct event {
	struct list_head list;
	char *event;
	struct blob_attr *payload;
	time_t time;
};

static LIST_HEAD(events);
static int count;

void
event_add(char *event, struct blob_attr *payload)
{
	char *_event;
	struct blob_attr *_payload;
	struct event *e = calloc_a(sizeof(struct event),
				   &_event, strlen(event) + 1,
				   &_payload, blob_raw_len(payload));

	e->time = time(NULL);
	e->event = strcpy(_event, event);
	e->payload = memcpy(_payload, payload, blob_raw_len(payload));
	list_add_tail(&e->list, &events);

	if (count >= MAX_EVENT) {
		e = list_first_entry(&events, struct event, list);
		list_del(&e->list);
		free(e);
	} else {
		count++;
	}
}

void
event_dump(struct blob_buf *b, char *type, bool delete)
{
	void *c = blobmsg_open_array(b, type);
	struct event *e, *tmp;

	list_for_each_entry_safe(e, tmp, &events, list) {
		struct blob_attr *a;
		char *o, *p;
		size_t rem;

		if (strcmp(e->event, type))
			continue;

		o = blobmsg_open_array(b, NULL);
		blobmsg_add_u64(b, NULL, e->time);
		p = blobmsg_open_table(b, NULL);
		blobmsg_for_each_attr(a, e->payload, rem)
			blobmsg_add_blob(b, a);
		blobmsg_close_table(b, p);
		blobmsg_close_array(b, o);
		if (!delete)
			continue;
		list_del(&e->list);
#ifndef __clang_analyzer__
		/* clang reports a false positive in event_dump_all()
		 * warning: Use of memory after it is freed [unix.Malloc]
                 * char *type = strdup(e->event);
		 */
		free(e);
#endif
	}

	blobmsg_close_array(b, c);
}

void
event_dump_all(struct blob_buf *b)
{
	while (!list_empty(&events)) {
		struct event *e = list_first_entry(&events, struct event, list);

		event_dump(b, e->event, true);
	}
}

