/* SPDX-License-Identifier: BSD-3-Clause */

#define _GNU_SOURCE
#include <stdio.h>

#include "ucentral.h"

static struct blob_buf proto;
static struct blob_buf result;
static struct blob_buf action;

enum {
	JSONRPC_VER,
	JSONRPC_METHOD,
	JSONRPC_ERROR,
	JSONRPC_PARAMS,
	JSONRPC_ID,
	__JSONRPC_MAX,
};

static const struct blobmsg_policy jsonrpc_policy[__JSONRPC_MAX] = {
	[JSONRPC_VER] = { .name = "jsonrpc", .type = BLOBMSG_TYPE_STRING },
	[JSONRPC_METHOD] = { .name = "method", .type = BLOBMSG_TYPE_STRING },
	[JSONRPC_ERROR] = { .name = "error", .type = BLOBMSG_TYPE_TABLE },
	[JSONRPC_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_TABLE },
	[JSONRPC_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
};

enum {
	PARAMS_SERIAL,
	PARAMS_UUID,
	PARAMS_COMMAND,
	PARAMS_CONFIG,
	PARAMS_PAYLOAD,
	__PARAMS_MAX,
};

static const struct blobmsg_policy params_policy[__PARAMS_MAX] = {
	[PARAMS_SERIAL] = { .name = "serial", .type = BLOBMSG_TYPE_STRING },
	[PARAMS_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_INT32 },
	[PARAMS_CONFIG] = { .name = "config", .type = BLOBMSG_TYPE_TABLE },
	[PARAMS_COMMAND] = { .name = "command", .type = BLOBMSG_TYPE_STRING },
	[PARAMS_PAYLOAD] = { .name = "payload", .type = BLOBMSG_TYPE_TABLE },
};

static void
send_blob(struct blob_buf *blob)
{
	char *msg;
	int len;

	if (!websocket) {
		ULOG_ERR("trying to send data while not connected\n");
		return;
	}

	msg = blobmsg_format_json(blob->head, true);
	len = strlen(msg) + 1;

	msg = realloc(msg, LWS_PRE + len);
	memmove(&msg[LWS_PRE], msg, len);
	memset(msg, 0, LWS_PRE);

	ULOG_DBG("TX: %s\n", &msg[LWS_PRE]);
	if (lws_write(websocket, (unsigned char *)&msg[LWS_PRE], len - 1, LWS_WRITE_TEXT) < 0)
		ULOG_ERR("failed to send message\n");

	free(msg);
}

static void
proto_send_blob()
{
	send_blob(&proto);
}

static void*
proto_new_blob(char *method)
{
	blob_buf_init(&proto, 0);
	blobmsg_add_string(&proto, "jsonrpc", "2.0");
	blobmsg_add_string(&proto, "method", method);
	return blobmsg_open_table(&proto, "params");
}

static void
result_send_blob()
{
	send_blob(&result);
}

static void*
result_new_blob(uint32_t id, time_t uuid)
{
	void *m;

	blob_buf_init(&result, 0);
	blobmsg_add_string(&result, "jsonrpc", "2.0");
	blobmsg_add_u32(&result, "id", id);
	m = blobmsg_open_table(&result, "result");
	blobmsg_add_string(&result, "serial", client.serial);
	blobmsg_add_u64(&result, "uuid", uuid);

	return m;
}

void
connect_send(void)
{
	void *m = proto_new_blob("connect");
	char path[PATH_MAX] = { };
	void *c;

	snprintf(path, PATH_MAX, "%s/capabilities.json", USYNC_CONFIG);

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_string(&proto, "firmware", client.firmware);
	blobmsg_add_u64(&proto, "uuid", uuid_active);
	c = blobmsg_open_table(&proto, "capabilities");
	if (!blobmsg_add_json_from_file(&proto, path)) {
		log_send("failed to load capabilities");
		return;
	}
	blobmsg_close_table(&proto, c);
	blobmsg_close_table(&proto, m);
	ULOG_DBG("xmit connect\n");
	proto_send_blob();
}

void
ping_send(void)
{
	void *m = proto_new_blob("ping");

	blobmsg_add_string(&proto, "serial", client.serial);
	if (uuid_active != uuid_latest) {
		blobmsg_add_u64(&proto, "active", uuid_active);
		blobmsg_add_u64(&proto, "uuid", uuid_latest);
	} else
		blobmsg_add_u64(&proto, "uuid", uuid_latest);
	blobmsg_close_table(&proto, m);
	ULOG_DBG("xmit ping\n");
	proto_send_blob();
}

/*static void
pending_send(void)
{
	void *m = proto_new_blob("cfgpending");

	if (uuid_latest && uuid_active == uuid_latest)
		return;

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u64(&proto, "active", uuid_active);
	blobmsg_add_u64(&proto, "uuid", uuid_latest);
	blobmsg_close_table(&proto, m);
	ULOG_DBG("xmit pending\n");
	proto_send_blob();
}*/

void
raw_send(struct blob_attr *a)
{
	enum {
		RAW_METHOD,
		RAW_PARAMS,
		__RAW_MAX,
	};

	static const struct blobmsg_policy raw_policy[__RAW_MAX] = {
		[RAW_METHOD] = { .name = "method", .type = BLOBMSG_TYPE_STRING },
		[RAW_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_TABLE },
	};

	struct blob_attr *tb[__PARAMS_MAX] = {};
	struct blob_attr *b;
	void *m;
	int rem;

	blobmsg_parse(raw_policy, __RAW_MAX, tb, blob_data(a), blob_len(a));
	if (!tb[RAW_METHOD] || !tb[RAW_PARAMS])
		return;
	m = proto_new_blob(blobmsg_get_string(tb[RAW_METHOD]));
	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u64(&proto, "uuid", uuid_active);
	blobmsg_for_each_attr(b, tb[RAW_PARAMS], rem)
		blobmsg_add_blob(&proto, b);
	blobmsg_close_table(&proto, m);
	proto_send_blob();
}

void
result_send(uint32_t id, struct blob_attr *a)
{
	struct blob_attr *b;
	void *m, *s;
	int rem;

	m = result_new_blob(id, uuid_active);
	s = blobmsg_open_table(&result, "status");
	blobmsg_for_each_attr(b, a, rem)
		blobmsg_add_blob(&result, b);
	blobmsg_close_table(&result, s);
	blobmsg_close_table(&result, m);
	result_send_blob();
}

void
stats_send(struct blob_attr *a)
{
	struct blob_attr *b;
	void *c;
	int rem;

	blob_buf_init(&proto, 0);
	blobmsg_add_string(&proto, "jsonrpc", "2.0");
	blobmsg_add_string(&proto, "method", "state");
	c = blobmsg_open_table(&proto, "params");
	if (blobmsg_data_len(a) >= 2 * 1024) {
		char *source = blobmsg_format_json(a, true);
		uLongf sourceLen = strlen(source) + 1;
		uLongf destLen = compressBound(sourceLen);
		unsigned char *dest = malloc(destLen);
		char *b64 = NULL;
		int ret = 0;

		if (!dest)
			ret = 1;

		if (!ret && compress(dest, &destLen, (unsigned char *)source, sourceLen) != Z_OK)
			ret = 1;

		if (!ret)
			b64 = malloc(destLen * 2);
		if (!b64)
			ret = 1;
		if (!ret) {
			int len = b64_encode(dest, destLen, b64, destLen * 2);
			if (len > 0)
				blobmsg_add_string(&proto, "compress_64", b64);
			else
				ret = 1;
		}
		if (source)
			free(source);
		if (dest)
			free(dest);
		if (b64)
			free(b64);
		if (ret) {
			ULOG_ERR("failed to compress stats");
			return;
		}
	} else {
		blobmsg_for_each_attr(b, a, rem)
			blobmsg_add_blob(&proto, b);
	}
	blobmsg_close_table(&proto, c);
	proto_send_blob();
}

void
log_send(char *message)
{
	void *m = proto_new_blob("log");

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_string(&proto, "log", message);
	blobmsg_add_u32(&proto, "severity", LOG_INFO);
	blobmsg_close_table(&proto, m);
	ULOG_ERR("%s\n", message);
	proto_send_blob();
}

void
health_send(uint32_t sanity, struct blob_attr *a)
{
	void *m = proto_new_blob("healthcheck");
	struct blob_attr *b;
	void *c;
	int rem;

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u64(&proto, "uuid", uuid_active);
	blobmsg_add_u32(&proto, "sanity", sanity);
	c = blobmsg_open_table(&proto, "data");
	blobmsg_for_each_attr(b, a, rem)
		blobmsg_add_blob(&proto, b);
	blobmsg_close_table(&proto, c);
	blobmsg_close_table(&proto, m);
	ULOG_DBG("xmit message\n");
	proto_send_blob();
}

void
result_send_error(uint32_t error, char *text, uint32_t retcode, uint32_t id)
{
	void *c, *s;

	ULOG_ERR("%s/(%d)\n", text, retcode);

	c = result_new_blob(id, uuid_active);
	s = blobmsg_open_table(&result, "status");
	blobmsg_add_u32(&result, "error", error);
	blobmsg_add_string(&result, "text", text);
	blobmsg_add_u32(&result, "resultCode", retcode);
	blobmsg_close_table(&result, s);
	blobmsg_close_table(&result, c);
	result_send_blob();
}


void
configure_reply(uint32_t error, char *text, time_t uuid, uint32_t id)
{
	void *c, *s;

	if (!id)
		return;

/*	if (error) {
		pending_send();
		return;
	}*/

	c = result_new_blob(id, uuid);
	s = blobmsg_open_table(&result, "status");
	blobmsg_add_u32(&result, "error", error);
	blobmsg_add_string(&result, "text", text);
	blobmsg_close_table(&result, s);
	blobmsg_close_table(&result, c);
	result_send_blob();
}

static void
configure_handle(struct blob_attr **rpc)
{
	struct blob_attr *tb[__PARAMS_MAX] = {};
	uint32_t id = 0;

	blobmsg_parse(params_policy, __PARAMS_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	if (!tb[PARAMS_UUID] || !tb[PARAMS_SERIAL] || !tb[PARAMS_CONFIG]) {
		ULOG_ERR("configure message is missing parameters\n");
		configure_reply(1, "invalid parameters", 0, id);
		return;
	}

	if (config_verify(tb[PARAMS_CONFIG], id)) {
		ULOG_ERR("failed to verify new config\n");
		configure_reply(1, "failed to verify new config", blobmsg_get_u64(tb[PARAMS_UUID]), id);
	}
}

static void
perform_handle(struct blob_attr **rpc)
{
	struct blob_attr *tb[__PARAMS_MAX] = {};
	uint32_t id = 0;

	blobmsg_parse(params_policy, __PARAMS_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	if (!tb[PARAMS_SERIAL] || !tb[PARAMS_COMMAND] || !tb[PARAMS_PAYLOAD]) {
		result_send_error(1, "invalid parameters", 1, id);
		return;
	}

	if (cmd_run(rpc[JSONRPC_PARAMS], id)) {
		result_send_error(1, "failed to queue command", 1, id);
		return;
	}
}

static void
action_handle(struct blob_attr **rpc, char *command)
{
	struct blob_attr *tb[__PARAMS_MAX] = {};
	uint32_t id = 0;

	blobmsg_parse(params_policy, __PARAMS_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	if (!tb[PARAMS_SERIAL]) {
		result_send_error(1, "invalid parameters", 1, id);
		return;
	}

	blob_buf_init(&action, 0);
	blobmsg_add_string(&action, "command", command);
	blobmsg_add_u32(&action, "delay", 10);
	blobmsg_add_u32(&action, "timeout", 60 * 10);
	if (rpc[JSONRPC_PARAMS]) {
		void *c = blobmsg_open_table(&action, "payload");
		struct blob_attr *b;
		int rem;

		blobmsg_for_each_attr(b, rpc[JSONRPC_PARAMS], rem)
			blobmsg_add_blob(&action, b);
		blobmsg_close_table(&action, c);
	}

	if (cmd_run(action.head, id)) {
		result_send_error(1, "failed to queue command", 1, id);
		return;
	}
	result_send_error(0, "triggered command action", 0, id);
}

static void
error_handle(struct blob_attr **rpc)
{
	enum {
		ERROR_CODE,
		ERROR_MESSAGE,
		__ERROR_MAX,
	};

	static const struct blobmsg_policy error_policy[__ERROR_MAX] = {
		[ERROR_CODE] = { .name = "code", .type = BLOBMSG_TYPE_INT32 },
		[ERROR_MESSAGE] = { .name = "message", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__ERROR_MAX] = {};
	uint32_t id = 0;

	blobmsg_parse(error_policy, __ERROR_MAX, tb, blobmsg_data(rpc[JSONRPC_ERROR]),
		      blobmsg_data_len(rpc[JSONRPC_ERROR]));

	if (!tb[ERROR_CODE] || !tb[ERROR_MESSAGE]) {
		printf("%p %p\n", tb[ERROR_CODE], tb[ERROR_MESSAGE]);
		result_send_error(1, "invalid parameters", 1, id);
		return;
	}

	ULOG_ERR("error %d - %s\n", blobmsg_get_u32(tb[ERROR_CODE]), blobmsg_get_string(tb[ERROR_MESSAGE]));
}

static void
blink_handle(struct blob_attr **rpc)
{
	enum {
		BLINK_DURATION,
		__BLINK_MAX,
	};

	static const struct blobmsg_policy blink_policy[__BLINK_MAX] = {
		[BLINK_DURATION] = { .name = "blink", .type = BLOBMSG_TYPE_INT32 },
	};

	struct blob_attr *tb[__BLINK_MAX] = {};
	uint32_t duration = 60;

	blobmsg_parse(blink_policy, __BLINK_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (tb[BLINK_DURATION])
		duration = blobmsg_get_u32(tb[BLINK_DURATION]);

	blink_run(duration);
}

static void
proto_handle_blob(void)
{
	struct blob_attr *rpc[__JSONRPC_MAX] = {};
	char *method;

	blobmsg_parse(jsonrpc_policy, __JSONRPC_MAX, rpc, blob_data(proto.head), blob_len(proto.head));
	if (!rpc[JSONRPC_VER] || (!rpc[JSONRPC_METHOD] && !rpc[JSONRPC_ERROR]) ||
	    (rpc[JSONRPC_METHOD] && !rpc[JSONRPC_PARAMS]) ||
	    strcmp(blobmsg_get_string(rpc[JSONRPC_VER]), "2.0")) {
		log_send("received invalid jsonrpc call");
		return;
	}

	if (rpc[JSONRPC_METHOD]) {
		method = blobmsg_get_string(rpc[JSONRPC_METHOD]);

		if (!strcmp(method, "configure"))
			configure_handle(rpc);
		else if (!strcmp(method, "perform"))
			perform_handle(rpc);
		else if (!strcmp(method, "reboot") ||
			 !strcmp(method, "factory") ||
			 !strcmp(method, "upgrade"))
			action_handle(rpc, method);
		else if (!strcmp(method, "blink"))
			blink_handle(rpc);
	}

	if (rpc[JSONRPC_ERROR])
		error_handle(rpc);

}

void
proto_handle(char *cmd)
{
	ULOG_DBG("RX: %s\n", cmd);

	blob_buf_init(&proto, 0);
	if (!blobmsg_add_json_from_string(&proto, cmd)) {
		log_send("failed to parse command");
		return;
	}
	proto_handle_blob();
}

void
proto_handle_simulate(struct blob_attr *a)
{
	struct blob_attr *b;
	char *msg;
	int rem;

	blob_buf_init(&proto, 0);
	blobmsg_for_each_attr(b, a, rem)
		blobmsg_add_blob(&proto, b);
	msg = blobmsg_format_json(proto.head, true);
	ULOG_DBG("RX: %s\n", msg);
	free(msg);
	proto_handle_blob();

}

void
proto_free(void)
{
	blob_buf_free(&proto);
	blob_buf_free(&result);
	blob_buf_free(&action);
}
