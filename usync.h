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

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <glob.h>
#include <libgen.h>

#include <libwebsockets.h>

#include <libubox/ulog.h>
#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

struct client_config {
	const char *server;
	int port;
	const char *cert;
	const char *user;
	const char *pass;
	const char *path;
	const char *serial;
	const char *config;
};
extern struct client_config client;

void config_init(void);
int config_get_uuid_latest(void);
int config_get_uuid_active(void);
int config_verify(uint32_t uuid, struct blob_attr *attr);

void proto_send_heartbeat(struct lws *wsi);
void proto_send_capabilities(struct lws *wsi);
void proto_handle(struct lws *wsi, char *cmd);
