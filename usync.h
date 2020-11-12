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

#define USYNC_CERT	"/etc/usync/cert.pem"
#define USYNC_CONFIG	 "/etc/usync/"
#define USYNC_STATE	 "/tmp/usync.state"

struct client_config {
	const char *server;
	int port;
	const char *user;
	const char *pass;
	const char *path;
	const char *serial;
	int reporting;
};
extern struct client_config client;

extern struct lws *websocket;

extern uint32_t uuid_latest;
extern uint32_t uuid_active;

void config_init(int apply);
int config_verify(struct blob_attr *attr);

void proto_send_heartbeat(void);
void proto_send_capabilities(void);
void proto_send_state(void);
void proto_handle(char *cmd);
