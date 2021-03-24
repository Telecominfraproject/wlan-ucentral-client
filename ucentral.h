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
#include <zlib.h>

#include <libwebsockets.h>

#include <libubox/ulog.h>
#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/runqueue.h>
#include <libubox/blobmsg_json.h>

#define ULOG_DBG(fmt, ...) ulog(LOG_DEBUG, fmt, ## __VA_ARGS__)

#define USYNC_CERT	"/etc/ucentral/cert.pem"
#define USYNC_CONFIG	 "/etc/ucentral/"
#define USYNC_STATE	 "/tmp/ucentral.state"

struct client_config {
	const char *server;
	int port;
	const char *path;
	const char *serial;
	const char *firmware;
	int debug;
};
extern struct client_config client;

struct task {
	int run_time;
	int delay;
	void (*run)(time_t uuid);
	void (*complete)(struct task *t, time_t uuid, uint32_t id, int ret);
	int pending;
};

extern struct runqueue runqueue;
extern struct lws *websocket;
extern time_t conn_time;

extern time_t uuid_latest;
extern time_t uuid_active;

void config_init(int apply, uint32_t id);
int config_verify(struct blob_attr *attr, uint32_t id);

int cmd_run(struct blob_attr *tb, uint32_t id);

void connect_send(void);
void ping_send(void);
void raw_send(struct blob_attr *a);
void log_send(char *message);
void health_send(uint32_t sanity, struct blob_attr *a);
void result_send(uint32_t id, struct blob_attr *a);
void result_send_error(uint32_t error, char *text, uint32_t retcode, uint32_t id);
void stats_send(struct blob_attr *a);

void proto_handle(char *cmd);
void proto_handle_simulate(struct blob_attr *a);
void proto_free(void);

void configure_reply(uint32_t error, char *text, time_t uuid, uint32_t id);

void config_deinit(void);

void ubus_init(void);
void ubus_deinit(void);

void task_run(struct task *task, time_t uuid, uint32_t id);
