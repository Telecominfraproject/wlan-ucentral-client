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
static LIST_HEAD(telemetry);
static int telemetry_count;
static int event_count;
static struct uloop_timeout telemetry_timer;

void
telemetry_add(char *event, struct blob_attr *payload)
{
	char *_event;
	struct blob_attr *_payload;
	struct event *e = calloc_a(sizeof(struct event),
				   &_event, strlen(event) + 1,
				   &_payload, blob_raw_len(payload));
	struct list_head *list = &telemetry;

	e->time = time(NULL);
	e->event = strcpy(_event, event);
	e->payload = memcpy(_payload, payload, blob_raw_len(payload));
	list_add_tail(&e->list, list);

	if (telemetry_count >= MAX_EVENT) {
		e = list_first_entry(list, struct event, list);
		list_del(&e->list);
		free(e);
	} else {
		telemetry_count++;
	}
}

void
event_add(struct blob_attr *payload)
{
	struct list_head *list = &events;
	struct blob_attr *_payload;
	struct event *e;

	if (websocket) {
		event_send(payload, time(NULL));
		return;
	}

	e = calloc_a(sizeof(struct event),
		     &_payload, blob_raw_len(payload));

	e->time = time(NULL);
	e->payload = memcpy(_payload, payload, blob_raw_len(payload));
	list_add_tail(&e->list, list);

	if (event_count >= MAX_EVENT) {
		e = list_first_entry(list, struct event, list);
		list_del(&e->list);
		free(e);
	} else {
		event_count++;
	}
}

int
event_dump(struct blob_buf *b, char *type, bool delete)
{
	struct event *e, *tmp;
	void *c = NULL;
	int cnt = 0;

	list_for_each_entry_safe(e, tmp, &telemetry, list) {
		struct blob_attr *a;
		char *o, *p;
		size_t rem;

		if (strcmp(e->event, type))
			continue;

		if (!c)
			c = blobmsg_open_array(b, type);
		o = blobmsg_open_array(b, NULL);
		blobmsg_add_u64(b, NULL, e->time);
		p = blobmsg_open_table(b, NULL);
		blobmsg_for_each_attr(a, e->payload, rem)
			blobmsg_add_blob(b, a);
		blobmsg_close_table(b, p);
		blobmsg_close_array(b, o);
		cnt ++;

		if (!delete)
			continue;
		list_del(&e->list);
		telemetry_count--;
#ifndef __clang_analyzer__
		/* clang reports a false positive in event_dump_all()
		 * warning: Use of memory after it is freed [unix.Malloc]
                 * char *type = strdup(e->event);
		 */
		free(e);
#endif
	}

	if (c)
		blobmsg_close_array(b, c);

	return cnt;
}

void
event_dump_all(struct blob_buf *b)
{
	while (!list_empty(&telemetry)) {
		struct event *e = list_first_entry(&telemetry, struct event, list);

		event_dump(b, e->event, true);
	}
}

void
event_backlog(void)
{
	struct event *e, *tmp;

	list_for_each_entry_safe(e, tmp, &events, list) {
		if (!websocket)
			return;
		event_send(e->payload, e->time);
		list_del(&e->list);
		free(e);
		event_count = 0;
	}
}

void
event_flush(void)
{
	struct event *e, *tmp;

	list_for_each_entry_safe(e, tmp, &telemetry, list) {
		list_del(&e->list);
		free(e);
	}
	telemetry_count = 0;
}

static void
telemetry_cb(struct uloop_timeout *t)
{
	if (websocket)
		telemetry_periodic();
	uloop_timeout_set(t, client.telemetry_interval * 1000);
}

void
event_config(void)
{
	telemetry_timer.cb = telemetry_cb;
	if (client.telemetry_interval)
		uloop_timeout_set(&telemetry_timer, client.telemetry_interval * 1000);
	else
		uloop_timeout_cancel(&telemetry_timer);
}
