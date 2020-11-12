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

#include <string.h>
#include <signal.h>
#include <getopt.h>

#include <libubox/uloop.h>

#include "usync.h"

static int reconnect_timeout;
static struct lws_context *context;

static struct uloop_timeout reporting;
static struct uloop_timeout periodic;
static struct uloop_fd sock;
struct lws *websocket = NULL;

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
	.user = "test",
	.pass = "test",
	.serial = "00:11:22:33:44:55",
	.reporting = 1,
};

static int
get_reconnect_timeout(void)
{
#define MAX_RECONNECT	(60 * 15)
	int ret = reconnect_timeout++;

	ret *= 30;
	if (ret >= MAX_RECONNECT)
		ret = MAX_RECONNECT;

	lwsl_user("next reconnect in %ds\n", ret);

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
	vhd->i.ssl_connection = LCCSCF_USE_SSL |
		LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
		LCCSCF_ALLOW_SELFSIGNED;

	vhd->i.protocol = "usync-broker";
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

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		ULOG_ERR("connection error: %s\n",
			 in ? (char *)in : "(null)");
		websocket = NULL;
		vhd->client_wsi = NULL;
		lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, get_reconnect_timeout());
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		ULOG_INFO("connection established\n");
		reconnect_timeout = 1;
		websocket = wsi;
		proto_send_capabilities();
		proto_send_heartbeat();
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		proto_handle((char *) in);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		ULOG_INFO("connection closed\n");
		websocket = NULL;
		vhd->client_wsi = NULL;
		lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, get_reconnect_timeout());
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	{
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;
		char b[128];

		if (lws_http_basic_auth_gen(client.user, client.pass, b, sizeof(b)))
			break;
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_AUTHORIZATION,
				(unsigned char *)b, (int)strlen(b), p, end))
			return -1;

		break;
	}

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct
lws_protocols protocols[] = {
	{ "usync-broker", callback_broker, 0, 0, 0, NULL, 0},
	{ }
};

static void
periodic_cb(struct uloop_timeout *t)
{
	struct pollfd pfd = { };

	lws_service_fd(context, &pfd);
	lws_service_tsi(context, -1, 0);
        uloop_timeout_set(t, 1000);
}

static void
reporting_cb(struct uloop_timeout *t)
{
	if (websocket)
		proto_send_state();

        uloop_timeout_set(t, client.reporting * 60 * 1000);
}

static int print_usage(const char *daemon)
{
	fprintf(stderr, "Usage: %s [options]\n"
			"\t-S <serial>\n"
			"\t-u <username>\n"
			"\t-p <password>\n"
			"\t-s <server>\n"
			"\t-P <port>\n"
			"\t-v <venue>\n", daemon);
	return -1;
}

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int ch;

	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "usync");

	while ((ch = getopt(argc, argv, "S:u:p:s:P:v:")) != -1) {
		switch (ch) {
		case 'u':
			client.user = optarg;
			break;
		case 'p':
			client.pass = optarg;
			break;
		case 's':
			client.server = optarg;
			break;
		case 'P':
			client.port = atoi(optarg);
			break;
		case 'v':
			client.path = optarg;
			break;
		case 'S':
			client.serial = optarg;
			break;
		case 'h':
		default:
			return print_usage(*argv);
		}
	}

	config_init(1);

	lws_set_log_level(logs, NULL);

	memset(&info, 0, sizeof info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.ssl_cert_filepath = USYNC_CERT;
	info.protocols = protocols;
	info.fd_limit_per_thread = 1 + 1 + 1;

	context = lws_create_context(&info);
	if (!context) {
		ULOG_INFO("failed to start LWS context\n");
		return -1;
	}

	uloop_init();
	periodic.cb = periodic_cb;
        uloop_timeout_set(&periodic, 1000);
	reporting.cb = reporting_cb;
        uloop_timeout_set(&reporting, client.reporting * 60 * 1000);
	lws_service(context, 0);
	uloop_run();
	uloop_done();

	lws_context_destroy(context);

	return 0;
}
