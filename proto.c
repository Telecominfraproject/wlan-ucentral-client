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

#include "usync.h"

static struct blob_buf proto;

enum {
	PROTO_UUID,
	PROTO_CFG,
	__PROTO_MAX,
};

static const struct blobmsg_policy proto_policy[__PROTO_MAX] = {
	[PROTO_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_INT32 },
	[PROTO_CFG] = { .name = "cfg", .type = BLOBMSG_TYPE_TABLE },
};


static void
proto_send_blob(void)
{
	char *msg = blobmsg_format_json(proto.head, true);
	int len = strlen(msg) + 1;

	if (!websocket) {
		ULOG_ERR("trying to send data while not connected\n");
		return;
	}

	msg = realloc(msg, LWS_PRE + len);
	memmove(&msg[LWS_PRE], msg, len);
	memset(msg, 0, LWS_PRE);

	ULOG_INFO("TX: %s\n", &msg[LWS_PRE]);
	if (lws_write(websocket, (unsigned char *)&msg[LWS_PRE], len - 1, LWS_WRITE_TEXT) < 0)
		ULOG_ERR("failed to send message\n");

	free(msg);
}

void
proto_send_heartbeat(void)
{
	int uuid_latest = config_get_uuid_latest();
	int uuid_active = config_get_uuid_active();

	blob_buf_init(&proto, 0);
	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u32(&proto, "uuid", uuid_latest);
	if (uuid_active != uuid_latest)
		blobmsg_add_u32(&proto, "active", uuid_active);
	proto_send_blob();
	ULOG_INFO("xmit heartbeat\n");
}

void
proto_send_capabilities(void)
{
	char path[PATH_MAX] = { };
	void *c;

	snprintf(path, PATH_MAX, "%s/capabilities.json", USYNC_CONFIG);

	blob_buf_init(&proto, 0);
	blobmsg_add_string(&proto, "serial", client.serial);
	c = blobmsg_open_table(&proto, "capab");
	if (!blobmsg_add_json_from_file(&proto, path)) {
		ULOG_ERR("failed to load capabilities\n");
		return;
	}
	blobmsg_close_table(&proto, c);
	proto_send_blob();
	ULOG_INFO("xmit capabilities\n");
}

void
proto_send_state(void)
{
	void *s;
	int ret;

	ret = system("/usr/sbin/usync_state.sh");
	ret = WEXITSTATUS(ret);
	if (ret) {
		ULOG_ERR("failed to generate state file\n");
		return;
	}

	blob_buf_init(&proto, 0);
	blobmsg_add_string(&proto, "serial", client.serial);
	s = blobmsg_open_table(&proto, "state");
	if (!blobmsg_add_json_from_file(&proto, USYNC_STATE)) {
		ULOG_ERR("failed to load state\n");
		return;
	}
	blobmsg_close_table(&proto, s);
	ULOG_INFO("xmit state\n");
}

void
proto_handle(char *cmd)
{
	struct blob_attr *tb[__PROTO_MAX] = {};

	ULOG_INFO("RX: %s\n", cmd);

	blob_buf_init(&proto, 0);
	if (!blobmsg_add_json_from_string(&proto, cmd)) {
		ULOG_ERR("failed to parse command %s\n", cmd);
		return;
	}

	blobmsg_parse(proto_policy, __PROTO_MAX, tb, blob_data(proto.head), blob_len(proto.head));
	if (tb[PROTO_CFG]) {
		if (!tb[PROTO_UUID])
			return;
		if (config_verify(blobmsg_get_u32(tb[PROTO_UUID]), tb[PROTO_CFG]))
			ULOG_ERR("failed to verify new config\n");
		proto_send_heartbeat();
	}
}
