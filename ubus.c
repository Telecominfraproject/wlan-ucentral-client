/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 *   Copyright (C) 2020 John Crispin <john@phrozen.org> 
 */

#include "ucentral.h"

#include <libubus.h>

static struct ubus_auto_conn conn;
static struct blob_buf u;

enum {
	LOG_MSG,
	__LOG_MAX,
};

static const struct blobmsg_policy log_policy[__LOG_MAX] = {
	[LOG_MSG] = { .name = "msg", .type = BLOBMSG_TYPE_STRING },
};

static int ubus_status_cb(struct ubus_context *ctx,
			  struct ubus_object *obj,
			  struct ubus_request_data *req,
			  const char *method, struct blob_attr *msg)
{
	time_t delta = time(NULL) - conn_time;

	blob_buf_init(&u, 0);
	blobmsg_add_u32(&u, websocket ? "connected" : "disconnected", delta);
	blobmsg_add_u32(&u, "latest", uuid_latest);
	blobmsg_add_u32(&u, "active", uuid_active);
	ubus_send_reply(ctx, req, u.head);
	return UBUS_STATUS_OK;
}

static int ubus_send_cb(struct ubus_context *ctx,
			struct ubus_object *obj,
			struct ubus_request_data *req,
			const char *method, struct blob_attr *msg)
{
	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	proto_send_raw(msg);

	return UBUS_STATUS_OK;
}

static int ubus_log_cb(struct ubus_context *ctx,
		       struct ubus_object *obj,
		       struct ubus_request_data *req,
		       const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__LOG_MAX] = {};

	blobmsg_parse(log_policy, __LOG_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[LOG_MSG])
		return UBUS_STATUS_INVALID_ARGUMENT;

	proto_send_log(blobmsg_get_string(tb[LOG_MSG]));

	return UBUS_STATUS_OK;
}

static const struct ubus_method ucentral_methods[] = {
	UBUS_METHOD_NOARG("status", ubus_status_cb),
	UBUS_METHOD_NOARG("send", ubus_send_cb),
	UBUS_METHOD_NOARG("log", ubus_log_cb),
};

static struct ubus_object_type ubus_object_type =
	UBUS_OBJECT_TYPE("ucentral", ucentral_methods);

struct ubus_object ubus_object = {
	.name = "ucentral",
	.type = &ubus_object_type,
	.methods = ucentral_methods,
	.n_methods = ARRAY_SIZE(ucentral_methods),
};

static void ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &ubus_object);
}

void ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}
