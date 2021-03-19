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

#define _GNU_SOURCE
#include <stdio.h>

#include "ucentral.h"

static struct blob_buf proto;
static struct blob_buf result;

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
	[JSONRPC_ERROR] = { .name = "error", .type = BLOBMSG_TYPE_STRING },
	[JSONRPC_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_TABLE },
	[JSONRPC_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
};

enum {
	PARAMS_SERIAL,
	PARAMS_UUID,
	PARAMS_COMMAND,
	PARAMS_CONFIG,
	__PARAMS_MAX,
};

static const struct blobmsg_policy params_policy[__PARAMS_MAX] = {
	[PARAMS_SERIAL] = { .name = "serial", .type = BLOBMSG_TYPE_STRING },
	[PARAMS_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_INT32 },
	[PARAMS_CONFIG] = { .name = "config", .type = BLOBMSG_TYPE_TABLE },
	[PARAMS_COMMAND] = { .name = "command", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	RAW_METHOD,
	RAW_PARAMS,
	__RAW_MAX,
};

static const struct blobmsg_policy raw_policy[__RAW_MAX] = {
	[RAW_METHOD] = { .name = "method", .type = BLOBMSG_TYPE_STRING },
	[RAW_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_TABLE },
};

static void
_proto_send_blob(struct blob_buf *blob)
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
	_proto_send_blob(&proto);
}

static void
result_send_blob()
{
	_proto_send_blob(&result);
}

static void*
proto_new_method(char *method)
{
	blob_buf_init(&proto, 0);
	blobmsg_add_string(&proto, "jsonrpc", "2.0");
	blobmsg_add_string(&proto, "method", method);
	return blobmsg_open_table(&proto, "params");
}

static void*
proto_new_result(uint32_t id)
{
	blob_buf_init(&result, 0);
	blobmsg_add_string(&result, "jsonrpc", "2.0");
	if (id)
		blobmsg_add_u32(&result, "id", id);
	return blobmsg_open_table(&result, "result");
}

void
proto_send_connect(void)
{
	void *m = proto_new_method("connect");
	char path[PATH_MAX] = { };
	void *c;

	snprintf(path, PATH_MAX, "%s/capabilities.json", USYNC_CONFIG);

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_string(&proto, "firmware", client.firmware);
	blobmsg_add_u64(&proto, "uuid", uuid_active);
	c = blobmsg_open_table(&proto, "capabilities");
	if (!blobmsg_add_json_from_file(&proto, path)) {
		proto_send_log("failed to load capabilities");
		return;
	}
	blobmsg_close_table(&proto, c);
	blobmsg_close_table(&proto, m);
	ULOG_DBG("xmit connect\n");
	proto_send_blob();
}

void
proto_send_ping(void)
{
	void *m = proto_new_method("ping");

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

static void
proto_send_pending(void)
{
	void *m = proto_new_method("cfgpending");

	if (uuid_latest && uuid_active == uuid_latest)
		return;

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u64(&proto, "active", uuid_active);
	blobmsg_add_u64(&proto, "uuid", uuid_latest);
	blobmsg_close_table(&proto, m);
	ULOG_DBG("xmit pending\n");
	proto_send_blob();
}

void
proto_send_raw(struct blob_attr *a)
{
	struct blob_attr *tb[__PARAMS_MAX] = {};
	struct blob_attr *b;
	void *m;
	int rem;

	blobmsg_parse(raw_policy, __RAW_MAX, tb, blob_data(a), blob_len(a));
	if (!tb[RAW_METHOD] || !tb[RAW_PARAMS])
		return;
	m = proto_new_method(blobmsg_get_string(tb[RAW_METHOD]));
	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u64(&proto, "uuid", time(NULL));
	blobmsg_for_each_attr(b, tb[RAW_PARAMS], rem)
		blobmsg_add_blob(&proto, b);
	blobmsg_close_table(&proto, m);
	ULOG_DBG("xmit message\n");
	proto_send_blob();
}

void
proto_send_log(char *message)
{
	void *m = proto_new_method("log");

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_string(&proto, "log", message);
	blobmsg_add_u32(&proto, "severity", LOG_INFO);
	blobmsg_close_table(&proto, m);
	ULOG_ERR("%s\n", message);
	proto_send_blob();
}

void
configure_reply(uint32_t error, char *text, time_t uuid, uint32_t id)
{
	void *c, *s;

	if (!id ) {
		if (!error)
			proto_send_ping();
		else
			proto_send_pending();
		return;
	}

	c = proto_new_result(id);
	blobmsg_add_string(&result, "serial", client.serial);
	if (uuid)
		blobmsg_add_u64(&result, "uuid", uuid);
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

void
perform_reply(uint32_t error, char *text, uint32_t retcode, uint32_t id)
{
	void *c, *s;

	ULOG_ERR("%s (%d/%d)\n", text, error, retcode);
	if (!id) {
		proto_send_log(text);
		return;
	}

	c = proto_new_result(id);
	blobmsg_add_string(&result, "serial", client.serial);
	s = blobmsg_open_table(&result, "status");
	blobmsg_add_u32(&result, "error", error);
	blobmsg_add_string(&result, "text", text);
	blobmsg_add_u32(&result, "resultCode", retcode);
	blobmsg_close_table(&result, s);
	blobmsg_close_table(&result, c);
	result_send_blob();
}

static void
perform_handle(struct blob_attr **rpc)
{
	struct blob_attr *tb[__PARAMS_MAX] = {};
	uint32_t id = 0;

	blobmsg_parse(params_policy, __JSONRPC_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	if (!tb[PARAMS_SERIAL] || !tb[PARAMS_COMMAND]) {
		perform_reply(1, "invalid parameters", 1, id);
		return;
	}

	if (cmd_run(tb[PARAMS_COMMAND], id)) {
		perform_reply(1, "failed to queue command", 1, id);
		return;
	}
}

void
proto_handle(char *cmd)
{
	struct blob_attr *rpc[__JSONRPC_MAX] = {};
	char *method;

	ULOG_DBG("RX: %s\n", cmd);

	blob_buf_init(&proto, 0);
	if (!blobmsg_add_json_from_string(&proto, cmd)) {
		proto_send_log("failed to parse command");
		return;
	}

	blobmsg_parse(jsonrpc_policy, __JSONRPC_MAX, rpc, blob_data(proto.head), blob_len(proto.head));
	if (!rpc[JSONRPC_VER] || (!rpc[JSONRPC_METHOD] && !rpc[JSONRPC_ERROR]) ||
	    !rpc[JSONRPC_PARAMS] || strcmp(blobmsg_get_string(rpc[JSONRPC_VER]), "2.0")) {
		proto_send_log("received invalid jsonrpc call");
		return;
	}

	if (rpc[JSONRPC_METHOD]) {
		method = blobmsg_get_string(rpc[JSONRPC_METHOD]);

		if (!strcmp(method, "configure"))
			configure_handle(rpc);
		else if (!strcmp(method, "perform"))
			perform_handle(rpc);
	}
}
