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
proto_send(struct lws *wsi, const char *fmt, ...)
{
	size_t size = 0;
	char *p = NULL;
	va_list ap;
	int n = 0;

	va_start(ap, fmt);
	n = vsnprintf(p, size, fmt, ap);
	va_end(ap);

	if (n < 0) {
		ULOG_ERR("failed to determine message size\n");
		return;
	}

	size = (size_t) n + 1 + LWS_PRE;
	p = malloc(size);
	if (p == NULL) {
		ULOG_ERR("failed to malloc message\n");
		return;
	}

	va_start(ap, fmt);
	n = vsnprintf(&p[LWS_PRE], size - LWS_PRE, fmt, ap);
	va_end(ap);

	if (n < 0) {
		ULOG_ERR("failed to generate message\n");
		goto out;
	}

	ULOG_INFO("TX: %s\n", &p[LWS_PRE]);
	if (lws_write(wsi, (unsigned char *)&p[LWS_PRE], size - LWS_PRE - 1, LWS_WRITE_TEXT) < 0)
		ULOG_ERR("failed to send message\n");

out:
	free(p);
}

void
proto_send_heartbeat(struct lws *wsi)
{
	int uuid_latest = config_get_uuid_latest();
	int uuid_active = config_get_uuid_active();

	if (!uuid_active)
		proto_send(wsi, "{\"serial\": \"%s\", \"uuid\": %d}",
			   client.serial, uuid_latest);
	else
		proto_send(wsi, "{\"serial\": \"%s\", \"uuid\": %d, \"active\": %d }",
			   client.serial, uuid_latest, uuid_active);
}

void
proto_send_capabilities(struct lws *wsi)
{
	char path[PATH_MAX] = { };
	char *capab;

	snprintf(path, PATH_MAX, "%s/capabilities.json", client.config);

	blob_buf_init(&proto, 0);
	if (!blobmsg_add_json_from_file(&proto, path)) {
		ULOG_ERR("failed to load capabilities\n");
		return;
	}

	capab = blobmsg_format_json(proto.head, true);
	if (!capab) {
		ULOG_ERR("failed to format capabilities\n");
		return;
	}
	proto_send(wsi, "{\"serial\": \"%s\", \"capab\": %s}", client.serial, capab);
	free(capab);
}

void
proto_handle(struct lws *wsi, char *cmd)
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
		proto_send_heartbeat(wsi);
	}
}
