/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

#include <libubus.h>

static struct ubus_auto_conn conn;
static struct blob_buf u;
static uint32_t radius_proxy;

static int ubus_status_cb(struct ubus_context *ctx,
			  struct ubus_object *obj,
			  struct ubus_request_data *req,
			  const char *method, struct blob_attr *msg)
{
	struct timespec tp;
	time_t delta;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	delta = tp.tv_sec - conn_time;

	blob_buf_init(&u, 0);
	blobmsg_add_u32(&u, websocket ? "connected" : "disconnected", delta);
	if (!websocket)
		blobmsg_add_u32(&u, "reconnect", reconnect_time - delta);

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

	raw_send(msg);

	return UBUS_STATUS_OK;
}

static int ubus_radius_cb(struct ubus_context *ctx,
			  struct ubus_object *obj,
			  struct ubus_request_data *req,
			  const char *method, struct blob_attr *msg)
{
	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	radius_send(msg);

	return UBUS_STATUS_OK;
}

enum {
	LOG_MSG,
	LOG_SEVERITY,
	__LOG_MAX,
};

static const struct blobmsg_policy log_policy[__LOG_MAX] = {
	[LOG_MSG] = { .name = "msg", .type = BLOBMSG_TYPE_STRING },
	[LOG_SEVERITY] = { .name = "severity", .type = BLOBMSG_TYPE_INT32 },
};

static int ubus_log_cb(struct ubus_context *ctx,
		       struct ubus_object *obj,
		       struct ubus_request_data *req,
		       const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__LOG_MAX] = {};
	int severity = LOG_INFO;

	blobmsg_parse(log_policy, __LOG_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[LOG_MSG])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[LOG_SEVERITY])
		severity = blobmsg_get_u32(tb[LOG_SEVERITY]);

	log_send(blobmsg_get_string(tb[LOG_MSG]), severity);

	return UBUS_STATUS_OK;
}

enum {
	HEALTH_SANITY,
	HEALTH_DATA,
	__HEALTH_MAX,
};

static const struct blobmsg_policy health_policy[__HEALTH_MAX] = {
	[HEALTH_SANITY] = { .name = "sanity", .type = BLOBMSG_TYPE_INT32 },
	[HEALTH_DATA] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
};

static int ubus_health_cb(struct ubus_context *ctx,
			  struct ubus_object *obj,
			  struct ubus_request_data *req,
			  const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__HEALTH_MAX] = {};

	blobmsg_parse(health_policy, __HEALTH_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[HEALTH_SANITY] || !tb[HEALTH_DATA])
		return UBUS_STATUS_INVALID_ARGUMENT;

	health_send(blobmsg_get_u32(tb[HEALTH_SANITY]), tb[HEALTH_DATA]);

	return UBUS_STATUS_OK;
}

static int ubus_simulate_cb(struct ubus_context *ctx,
			    struct ubus_object *obj,
			    struct ubus_request_data *req,
			    const char *method, struct blob_attr *msg)
{
	proto_handle_simulate(msg);

	return UBUS_STATUS_OK;
}

enum {
	RESULT_STATUS,
	RESULT_UUID,
	RESULT_ID,
	__RESULT_MAX,
};

static const struct blobmsg_policy result_policy[__RESULT_MAX] = {
	[RESULT_STATUS] = { .name = "status", .type = BLOBMSG_TYPE_TABLE },
	[RESULT_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_INT32 },
	[RESULT_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
};

static int ubus_result_cb(struct ubus_context *ctx,
			  struct ubus_object *obj,
			  struct ubus_request_data *req,
			  const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__RESULT_MAX] = {};
	time_t uuid = 0;

	blobmsg_parse(result_policy, __RESULT_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[RESULT_STATUS] || !tb[RESULT_ID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[RESULT_UUID])
		uuid = blobmsg_get_u32(tb[RESULT_UUID]);

	result_send(blobmsg_get_u32(tb[RESULT_ID]), tb[RESULT_STATUS], uuid);

	return UBUS_STATUS_OK;
}

static int ubus_stats_cb(struct ubus_context *ctx,
			 struct ubus_object *obj,
			 struct ubus_request_data *req,
			 const char *method, struct blob_attr *msg)
{
	stats_send(msg);

	return UBUS_STATUS_OK;
}

static int ubus_upload_cb(struct ubus_context *ctx,
			  struct ubus_object *obj,
			  struct ubus_request_data *req,
			  const char *method, struct blob_attr *msg)
{
	upload_run(msg);

	return UBUS_STATUS_OK;
}

static int ubus_rejected_cb(struct ubus_context *ctx,
			    struct ubus_object *obj,
			    struct ubus_request_data *req,
			    const char *method, struct blob_attr *msg)
{
	config_rejected(msg);

	return UBUS_STATUS_OK;
}

static int ubus_event_cb(struct ubus_context *ctx,
			 struct ubus_object *obj,
			 struct ubus_request_data *req,
			 const char *method, struct blob_attr *msg)
{
	event_add(msg);

	return UBUS_STATUS_OK;
}

enum {
	TELEMETRY_EVENT,
	TELEMETRY_PAYLOAD,
	TELEMETRY_DUMP,
	TELEMETRY_TYPE,
	__TELEMETRY_MAX,
};

static const struct blobmsg_policy telemetry_policy[__TELEMETRY_MAX] = {
	[TELEMETRY_EVENT] = { .name = "event", .type = BLOBMSG_TYPE_STRING },
	[TELEMETRY_PAYLOAD] = { .name = "payload", .type = BLOBMSG_TYPE_TABLE },
	[TELEMETRY_DUMP] = { .name = "dump", .type = BLOBMSG_TYPE_BOOL },
	[TELEMETRY_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
};

static int ubus_telemetry_cb(struct ubus_context *ctx,
			     struct ubus_object *obj,
			     struct ubus_request_data *req,
			     const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__TELEMETRY_MAX] = {};

	blobmsg_parse(telemetry_policy, __TELEMETRY_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (tb[TELEMETRY_DUMP] && tb[TELEMETRY_TYPE]) {
		blob_buf_init(&u, 0);
		event_dump(&u, blobmsg_get_string(tb[TELEMETRY_TYPE]), false);
		ubus_send_reply(ctx, req, u.head);
		return UBUS_STATUS_OK;
	}

	if (tb[TELEMETRY_DUMP]) {
		blob_buf_init(&u, 0);
		event_dump_all(&u);
		ubus_send_reply(ctx, req, u.head);
		return UBUS_STATUS_OK;
	}

	if (!tb[TELEMETRY_EVENT] || !tb[TELEMETRY_PAYLOAD])
		return UBUS_STATUS_INVALID_ARGUMENT;

	telemetry_add(blobmsg_get_string(tb[TELEMETRY_EVENT]), tb[TELEMETRY_PAYLOAD]);

	return UBUS_STATUS_OK;
}

enum {
	CONFIG_TELEMETRY,
	__CONFIG_MAX,
};

static const struct blobmsg_policy config_policy[__CONFIG_MAX] = {
	[CONFIG_TELEMETRY] = { .name = "telemetry", .type = BLOBMSG_TYPE_INT32 },
};

static int ubus_config_cb(struct ubus_context *ctx,
			  struct ubus_object *obj,
			  struct ubus_request_data *req,
			  const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__CONFIG_MAX] = {};

	blobmsg_parse(config_policy, __CONFIG_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (tb[CONFIG_TELEMETRY])
		client.telemetry_interval = blobmsg_get_u32(tb[CONFIG_TELEMETRY]);

	event_config();

	return UBUS_STATUS_OK;
}

enum {
	PWD_PASSWORD,
	__PWD_MAX,
};

static const struct blobmsg_policy password_policy[__PWD_MAX] = {
	[PWD_PASSWORD] = { .name = "passwd", .type = BLOBMSG_TYPE_STRING },
};

static int ubus_password_cb(struct ubus_context *ctx,
			    struct ubus_object *obj,
			    struct ubus_request_data *req,
			    const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__PWD_MAX] = {};

	blobmsg_parse(password_policy, __PWD_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[PWD_PASSWORD])
		return UBUS_STATUS_INVALID_ARGUMENT;

	password_notify(blobmsg_get_string(tb[PWD_PASSWORD]));

	return UBUS_STATUS_OK;
}

void ubus_forward_radius(struct blob_buf *msg)
{
	struct ubus_request async = { };

	if (!radius_proxy) {
		ULOG_ERR("radius_proxy is not online\n");
		return;
	}
	ubus_invoke_async(&conn.ctx, radius_proxy, "frame", msg->head, &async);
        ubus_abort_request(&conn.ctx, &async);
}

static const struct ubus_method ucentral_methods[] = {
	UBUS_METHOD("health", ubus_health_cb, health_policy),
	UBUS_METHOD("result", ubus_result_cb, result_policy),
	UBUS_METHOD("log", ubus_log_cb, log_policy),
	UBUS_METHOD("telemetry", ubus_telemetry_cb, telemetry_policy),
	UBUS_METHOD("config", ubus_config_cb, config_policy),
	UBUS_METHOD("password", ubus_password_cb, password_policy),
	UBUS_METHOD_NOARG("event", ubus_event_cb),
	UBUS_METHOD_NOARG("status", ubus_status_cb),
	UBUS_METHOD_NOARG("stats", ubus_stats_cb),
	UBUS_METHOD_NOARG("send", ubus_send_cb),
	UBUS_METHOD_NOARG("radius", ubus_radius_cb),
	UBUS_METHOD_NOARG("simulate", ubus_simulate_cb),
	UBUS_METHOD_NOARG("rejected", ubus_rejected_cb),
	UBUS_METHOD_NOARG("upload", ubus_upload_cb),
};

static struct ubus_object_type ubus_object_type =
	UBUS_OBJECT_TYPE("ucentral", ucentral_methods);

struct ubus_object ubus_object = {
	.name = "ucentral",
	.type = &ubus_object_type,
	.methods = ucentral_methods,
	.n_methods = ARRAY_SIZE(ucentral_methods),
};

void venue_broadcast_handle(struct blob_attr *rpc)
{
	if (!ubus_object.has_subscribers)
		return;

	ubus_notify(&conn.ctx, &ubus_object, "venue", rpc, -1);
}

static void
event_handler_cb(struct ubus_context *ctx,  struct ubus_event_handler *ev,
             const char *type, struct blob_attr *msg)
{
	enum {
		EVENT_ID,
		EVENT_PATH,
		__EVENT_MAX
	};

	static const struct blobmsg_policy status_policy[__EVENT_MAX] = {
		[EVENT_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
		[EVENT_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__EVENT_MAX];
	char *path;
	uint32_t id;

	blobmsg_parse(status_policy, __EVENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[EVENT_ID] || !tb[EVENT_PATH])
		return;

	path = blobmsg_get_string(tb[EVENT_PATH]);
	id = blobmsg_get_u32(tb[EVENT_ID]);

	if (strcmp(path, "radius.proxy"))
		return;
	if (!strcmp("ubus.object.remove", type))
		radius_proxy = 0;
	else
		radius_proxy = id;

	ULOG_INFO("%s radius.proxy (%d)\n", radius_proxy ? "add" : "remove", radius_proxy);
}

static struct ubus_event_handler event_handler = { .cb = event_handler_cb };

static void ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &ubus_object);
	ubus_register_event_handler(ctx, &event_handler, "ubus.object.add");
	ubus_register_event_handler(ctx, &event_handler, "ubus.object.remove");

	ubus_lookup_id(ctx, "radius.proxy", &radius_proxy);

}

void ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}

void ubus_deinit(void)
{
	ubus_auto_shutdown(&conn);
}
