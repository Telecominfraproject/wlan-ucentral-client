/* SPDX-License-Identifier: BSD-3-Clause */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
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

#define UCENTRAL_CONFIG	"/etc/ucentral/"
#define UCENTRAL_STATE	"/tmp/ucentral.state"
#define UCENTRAL_TMP	"/tmp/ucentral.cfg"
#define UCENTRAL_LATEST	"/etc/ucentral/ucentral.active"


struct client_config {
	const char *server;
	int port;
	const char *path;
	const char *serial;
	const char *firmware;
	int selfsigned;
	int debug;
	int recovery;
	int telemetry_interval;
	const char *boot_cause;
	int hostname_validate;
};
extern struct client_config client;

struct ucentral_task;
struct task {
	int run_time;
	int delay;
	int periodic;
	void (*run)(time_t uuid, uint32_t id);
	void (*complete)(struct task *t, time_t uuid, uint32_t id, int ret);
	int pending;
	struct ucentral_task *t;
	int cancelled;
	char *priv;
};

extern struct runqueue adminqueue;
extern struct runqueue runqueue;
extern struct runqueue applyqueue;
extern struct runqueue telemetryqueue;
extern struct lws *websocket;
extern time_t conn_time;
extern int reconnect_time;

extern time_t uuid_latest;
extern time_t uuid_active;
extern time_t uuid_applied;

extern struct blob_buf rejected;

void config_init(int apply, uint32_t id);
int config_verify(struct blob_attr *attr, uint32_t id);

int cmd_run(struct blob_attr *tb, uint32_t id, int admin);

void connect_send(void);
void ping_send(void);
void raw_send(struct blob_attr *a);
void log_send(char *message, int severity);
void health_send(uint32_t sanity, struct blob_attr *a);
void result_send(uint32_t id, struct blob_attr *a, uint32_t uuid);
void result_send_error(uint32_t error, char *text, uint32_t retcode, uint32_t id);
void stats_send(struct blob_attr *a);
void radius_send(struct blob_attr *a);

void proto_handle(char *cmd);
void proto_handle_simulate(struct blob_attr *a);
void proto_free(void);

void configure_reply(uint32_t error, char *text, time_t uuid, uint32_t id);

void config_deinit(void);
void config_rejected(struct blob_attr *b);

void ubus_init(void);
void ubus_deinit(void);
void ubus_forward_radius(struct blob_buf *msg);
void ubus_set_client_status(char *status);
void ubus_blink_leds(int duration);

void health_run(uint32_t id, uint32_t immediate);
void health_update_interval(uint32_t periodic);
void health_deinit(void);

void upload_run(struct blob_attr *b);

void apply_run(uint32_t id);
extern int apply_pending;

void ip_collide_run(void);

void verify_run(uint32_t id);

void failsafe_init(void);

void task_run(struct task *task, time_t uuid, uint32_t id, int admin);
void task_config(struct task *task, time_t uuid, uint32_t id);
void task_telemetry(struct task *task, time_t uuid, uint32_t id);
void task_stop(struct task *task);

void crashlog_init(void);
void consolelog_init(void);
void rebootlog_send(char *type, struct blob_attr *b);

int event_dump(struct blob_buf *b, char *type, bool delete);
void event_dump_all(struct blob_buf *b);
void event_stream(int interval, struct blob_attr *types);
void event_flush(void);
void event_config(void);
void event_send(struct blob_attr *a, time_t time);
void event_add(struct blob_attr *payload);
void event_backlog(void);

void telemetry_periodic(void);
void telemetry_add(char *event, struct blob_attr *payload);

void set_conn_time(void);

void password_notify(char *pwd);

void venue_broadcast_handle(struct blob_attr *rpc);
void venue_broadcast_send(struct blob_attr *payload);

const char *installPackage(const char *pkgName, const char *pkgURL);
const char *removePackage(const char *pkgName);

static inline void safe_free(char **mem)
{
	if (!*mem)
		return;
	free(*mem);
	*mem = NULL;
}
