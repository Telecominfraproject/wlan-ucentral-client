/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libubox/uloop.h>

#include "ucentral.h"

static int reconnect_timeout;
static struct lws_context *context;

static struct uloop_timeout periodic;
static struct uloop_fd sock;
struct lws *websocket = NULL;
time_t conn_time;
struct runqueue runqueue;
struct runqueue applyqueue;
struct runqueue telemetryqueue;

struct per_vhost_data__minimal {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	lws_sorted_usec_list_t sul;
	struct lws_client_connect_info i;
	struct lws *client_wsi;
};

struct client_config client = {
	.server = "localhost",
	.port = 11783,
	.path = "/",
	.serial = "00:11:22:33:44:55",
	.firmware = "v1.0",
	.health_interval = 600,
	.debug = 0,
};

void
set_conn_time(void)
{
	struct timespec tp;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	conn_time = tp.tv_sec;
}

static int
get_reconnect_timeout(void)
{
#define MAX_RECONNECT	(60 * 15)
	int ret = reconnect_timeout++;

	ret *= 10;
	if (ret >= MAX_RECONNECT)
		ret = MAX_RECONNECT;

	ULOG_INFO("next reconnect in %ds\n", ret);

	return ret * LWS_US_PER_SEC;
}

static void
sul_connect_attempt(struct lws_sorted_usec_list *sul)
{
	struct per_vhost_data__minimal *vhd;

	vhd = lws_container_of(sul, struct per_vhost_data__minimal, sul);

	vhd->i.context = vhd->context;
	vhd->i.port = client.port;
	vhd->i.address = client.server;
	vhd->i.path = client.path;
	vhd->i.host = vhd->i.address;
	vhd->i.origin = vhd->i.address;
	vhd->i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	if (client.selfsigned)
		vhd->i.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;

	vhd->i.protocol = "ucentral-broker";
	vhd->i.pwsi = &vhd->client_wsi;

	if (!lws_client_connect_via_info(&vhd->i))
		lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, 10 * LWS_US_PER_SEC);
}

static unsigned int
uloop_event_to_pfd(unsigned int e)
{
	int ret = 0;

	if (e & ULOOP_READ)
		ret |= POLLIN;
	if (e & ULOOP_WRITE)
		ret |= POLLOUT;
	return ret;
}

static void
sock_cb(struct uloop_fd *fd, unsigned int revents)
{
	struct pollfd pfd;

	pfd.events = uloop_event_to_pfd(fd->flags);
	pfd.revents = uloop_event_to_pfd(revents);
	pfd.fd = fd->fd;

	if (fd->eof)
		pfd.revents |= POLLHUP;
	if (fd->error)
		pfd.revents |= LWS_POLLHUP;
	lws_service_fd(context, &pfd);

	for (int count = 30; count && !lws_service_adjust_timeout(context, 1, 0); --count)
		lws_plat_service_tsi(context, -1, 0);
}

static int
callback_broker(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct per_vhost_data__minimal *vhd =
			(struct per_vhost_data__minimal *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	int r = 0;

	struct lws_pollargs *in_pollargs = (struct lws_pollargs *)in;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__minimal));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		sul_connect_attempt(&vhd->sul);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lws_sul_cancel(&vhd->sul);
		return r;

	case LWS_CALLBACK_ADD_POLL_FD:
	case LWS_CALLBACK_CHANGE_MODE_POLL_FD: {
		int event = 0;

		if (in_pollargs->events & POLLIN)
			event |= ULOOP_READ;
		if (in_pollargs->events & POLLOUT)
			event |= ULOOP_WRITE;
		sock.fd = in_pollargs->fd;
		sock.cb = sock_cb;
		uloop_fd_add(&sock, event);
		return 0;
	}

	case LWS_CALLBACK_DEL_POLL_FD:
		uloop_fd_delete(&sock);
		return 0;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		ULOG_INFO("connection established\n");
		reconnect_timeout = 1;
		set_conn_time();
		websocket = wsi;
		connect_send();
		crashlog_init();
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		proto_handle((char *) in);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		ULOG_ERR("connection error: %s\n",
			 in ? (char *)in : "(null)");

#ifdef __clang_analyzer__
		__attribute__ ((fallthrough));
#endif

	case LWS_CALLBACK_CLIENT_CLOSED:
		ULOG_INFO("connection closed\n");
		websocket = NULL;
		set_conn_time();
		vhd->client_wsi = NULL;
		lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, get_reconnect_timeout());
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct
lws_protocols protocols[] = {
	{ "ucentral-broker", callback_broker, 0, 32 * 1024, 0, NULL, 0},
	{ }
};

static void
periodic_cb(struct uloop_timeout *t)
{
	struct pollfd pfd = { .events = POLLIN | POLLOUT };

	lws_service_fd(context, &pfd);
	lws_service_tsi(context, -1, 0);
        uloop_timeout_set(t, 100);
}

static int print_usage(const char *daemon)
{
	fprintf(stderr, "Usage: %s [options]\n"
			"\t-i <insecure/selfsigned>\n"
			"\t-S <serial>\n"
			"\t-s <server>\n"
			"\t-P <port>\n"
			"\t-d <debug>\n"
			"\t-f <firmware>\n"
			"\t-H <health interval>\n"
			"\t-r <boot in recovery mode>\n"
			"\t-v <venue>\n", daemon);
	return -1;
}

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_CLIENT;
	struct stat st;
	int ch;

	while ((ch = getopt(argc, argv, "S:s:P:v:f:H:dir")) != -1) {
		switch (ch) {
		case 's':
			client.server = optarg;
			break;
		case 'f':
			client.firmware = optarg;
			break;
		case 'P':
			client.port = atoi(optarg);
			break;
		case 'H':
			client.health_interval = atoi(optarg);
			break;
		case 'd':
			client.debug = 1;
			logs |= LLL_DEBUG;
			break;
		case 'v':
			client.path = optarg;
			break;
		case 'S':
			client.serial = optarg;
			break;
		case 'i':
			client.selfsigned = 1;
			break;
		case 'r':
			client.recovery = 1;
			break;
		case 'h':
		default:
			return print_usage(*argv);
		}
	}

	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "ucentral");
	if (!client.debug)
		ulog_threshold(LOG_INFO);

	runqueue_init(&runqueue);
	runqueue.max_running_tasks = 1;
	runqueue_init(&applyqueue);
	applyqueue.max_running_tasks = 1;
	runqueue_init(&telemetryqueue);
	telemetryqueue.max_running_tasks = 1;
	config_init(1, 0);

	lws_set_log_level(logs, NULL);

	memset(&info, 0, sizeof info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.client_ssl_cert_filepath = UCENTRAL_CONFIG"cert.pem";
	if (!stat(UCENTRAL_CONFIG"key.pem", &st))
		info.client_ssl_private_key_filepath = UCENTRAL_CONFIG"key.pem";
	info.ssl_ca_filepath = UCENTRAL_CONFIG"cas.pem";
	info.protocols = protocols;
	info.fd_limit_per_thread = 1 + 1 + 1;
        info.timeout_secs = 60;
        info.connect_timeout_secs = 30;

	set_conn_time();
	context = lws_create_context(&info);
	if (!context) {
		ULOG_INFO("failed to start LWS context\n");
		return -1;
	}

	uloop_init();
	ubus_init();
	periodic.cb = periodic_cb;
        uloop_timeout_set(&periodic, 100);
	lws_service(context, 0);

	uloop_run();

	uloop_done();
	proto_free();
	runqueue_kill(&runqueue);
	runqueue_kill(&applyqueue);
	runqueue_kill(&telemetryqueue);
	lws_context_destroy(context);
	ubus_deinit();
	config_deinit();
	health_deinit();

	return 0;
}
