/* SPDX-License-Identifier: BSD-3-Clause */

#define _GNU_SOURCE
#include <stdio.h>

#include "ucentral.h"

static struct blob_buf proto;
static struct blob_buf result;
static struct blob_buf action;
static char *password;
static bool state_compress = true;
static int telemetry_interval;
static struct blob_attr *telemetry_filter;

enum {
	JSONRPC_VER,
	JSONRPC_METHOD,
	JSONRPC_ERROR,
	JSONRPC_PARAMS,
	JSONRPC_ID,
	JSONRPC_RADIUS,
	__JSONRPC_MAX,
};

static const struct blobmsg_policy jsonrpc_policy[__JSONRPC_MAX] = {
	[JSONRPC_VER] = { .name = "jsonrpc", .type = BLOBMSG_TYPE_STRING },
	[JSONRPC_METHOD] = { .name = "method", .type = BLOBMSG_TYPE_STRING },
	[JSONRPC_ERROR] = { .name = "error", .type = BLOBMSG_TYPE_TABLE },
	[JSONRPC_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_TABLE },
	[JSONRPC_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
	[JSONRPC_RADIUS] = { .name = "radius", .type = BLOBMSG_TYPE_STRING },
};

enum {
	PARAMS_SERIAL,
	PARAMS_UUID,
	PARAMS_COMMAND,
	PARAMS_CONFIG,
	PARAMS_PAYLOAD,
	PARAMS_REJECTED,
	PARAMS_COMPRESS,
	PARAMS_COMPRESS_64,
	PARAMS_COMPRESS_SZ,
	__PARAMS_MAX,
};

static const struct blobmsg_policy params_policy[__PARAMS_MAX] = {
	[PARAMS_SERIAL] = { .name = "serial", .type = BLOBMSG_TYPE_STRING },
	[PARAMS_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_INT32 },
	[PARAMS_CONFIG] = { .name = "config", .type = BLOBMSG_TYPE_TABLE },
	[PARAMS_COMMAND] = { .name = "command", .type = BLOBMSG_TYPE_STRING },
	[PARAMS_PAYLOAD] = { .name = "payload", .type = BLOBMSG_TYPE_TABLE },
	[PARAMS_REJECTED] = { .name = "rejected", .type = BLOBMSG_TYPE_ARRAY },
	[PARAMS_COMPRESS] = { .name = "compress", .type = BLOBMSG_TYPE_BOOL },
	[PARAMS_COMPRESS_64] = {.name = "compress_64", .type = BLOBMSG_TYPE_STRING},
	[PARAMS_COMPRESS_SZ] = {.name = "compress_sz", .type = BLOBMSG_TYPE_INT32},
};

#if 0
static void
send_blob_frag(struct blob_buf *blob)
{
#define FRAG_SZ	(128 * 1024)
	char *msg, fragment[FRAG_SZ + LWS_PRE], *ptr;
	int len, first = 1;
	int cnt = 0;
	FILE *fp = fopen("/dump", "w+");
	ptr = msg = blobmsg_format_json(blob->head, true);
	fprintf(fp, "%s", msg);
	fclose(fp);
	len = strlen(msg) + 1;
	ULOG_DBG("TX: %s\n", msg);
	if (!websocket) {
		ULOG_ERR("trying to send data while not connected\n");
		return;
	}

	do {
		int opt = LWS_WRITE_TEXT;
		int frag_len = len >= FRAG_SZ ? FRAG_SZ : len;

		if (first && len > FRAG_SZ)
			opt |= LWS_WRITE_NO_FIN;
		else if (!first && len > FRAG_SZ)
			opt = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
		else if (!first && len <= FRAG_SZ)
			opt = LWS_WRITE_CONTINUATION;

		memcpy(&fragment[LWS_PRE], ptr, frag_len);

		if (lws_write(websocket, (unsigned char *)&fragment[LWS_PRE], frag_len, opt) < 0)
			ULOG_ERR("failed to send message\n");
		len -= FRAG_SZ;
		ptr += FRAG_SZ;
		first = 0;
	} while(len > 0);
}
#endif

static void
send_blob(struct blob_buf *blob)
{
	char *msg;
	int len;

	msg = blobmsg_format_json(blob->head, true);
	len = strlen(msg) + 1;

	msg = realloc(msg, LWS_PRE + len);
	memmove(&msg[LWS_PRE], msg, len);
	memset(msg, 0, LWS_PRE);

	ULOG_DBG("TX: %s\n", &msg[LWS_PRE]);
	if (!websocket)
		ULOG_ERR("trying to send data while not connected\n");
	else if (lws_write(websocket, (unsigned char *)&msg[LWS_PRE], len - 1, LWS_WRITE_TEXT) < 0)
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
password_notify(char *pwd)
{
	void *m;

	if (password) {
		memset(password, 0, strlen(password));
		free(password);
		password = NULL;
	}

	if (!websocket) {
		password = strdup(pwd);
		return;
	}

	m = proto_new_blob("deviceupdate");
	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_string(&proto, "currentPassword", pwd);
	blobmsg_close_table(&proto, m);
	ULOG_DBG("xmit password\n");
	proto_send_blob();
	memset(pwd, 0, strlen(pwd));
}

void
connect_send(void)
{
	void *m = proto_new_blob("connect");
	struct stat statbuf = { };
	char path[PATH_MAX] = { };
	void *c;

	snprintf(path, PATH_MAX, "%s/capabilities.json", UCENTRAL_CONFIG);

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_string(&proto, "firmware", client.firmware);
	if (client.recovery)
		blobmsg_add_u64(&proto, "uuid", 0);
	else
		blobmsg_add_u64(&proto, "uuid", uuid_active ? uuid_active : 1);
	if (client.boot_cause) {
		blobmsg_add_string(&proto, "reason", client.boot_cause);
		client.boot_cause = NULL;
	} else {
		blobmsg_add_string(&proto, "reason", "socket");
	}
	if (password) {
		blobmsg_add_string(&proto, "password", password);
		memset(password, 0, strlen(password));
		free(password);
		password = NULL;
	}
	if (!stat("/etc/ucentral/ucentral.defaults", &statbuf)) {
		c = blobmsg_open_table(&proto, "defaults");
		if (!blobmsg_add_json_from_file(&proto, "/etc/ucentral/ucentral.defaults")) {
			log_send("failed to load defaults", LOG_ERR);
			return;
		}
		blobmsg_close_table(&proto, c);
	}
	if (!stat("/tmp/udhcpc-vsi.json", &statbuf)) {
		c = blobmsg_open_table(&proto, "udhcpc-vsi");
		if (!blobmsg_add_json_from_file(&proto, "/tmp/udhcpc-vsi.json")) {
			log_send("failed to load udhcpc-vsi", LOG_WARNING);
		}
		blobmsg_close_table(&proto, c);
	}
	c = blobmsg_open_table(&proto, "capabilities");
	if (!blobmsg_add_json_from_file(&proto, path)) {
		log_send("failed to load capabilities", LOG_ERR);
		return;
	}
	blobmsg_close_table(&proto, c);
	if (!stat("/etc/ucentral/restrictions.json", &statbuf))
		blobmsg_add_u8(&proto, "restricted", 1);
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
	size_t rem;

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
event_send(struct blob_attr *a, time_t time)
{
	struct blob_attr *b;
	void *m, *d, *e, *p;
	size_t rem;

	m = proto_new_blob("event");
	blobmsg_add_string(&proto, "serial", client.serial);
	d = blobmsg_open_table(&proto, "data");
	e = blobmsg_open_array(&proto, "event");
	blobmsg_add_u64(&proto, NULL, time);
	p = blobmsg_open_table(&proto, NULL);
	blobmsg_for_each_attr(b, a, rem)
		blobmsg_add_blob(&proto, b);
	blobmsg_close_table(&proto, p);
	blobmsg_close_array(&proto, e);
	blobmsg_close_table(&proto, d);
	blobmsg_close_table(&proto, m);
	proto_send_blob();
}

void
radius_send(struct blob_attr *a)
{
	enum {
		RADIUS_TYPE,
		RADIUS_DATA,
		__RADIUS_MAX,
	};

	static const struct blobmsg_policy radius_policy[__RADIUS_MAX] = {
		[RADIUS_TYPE] = { .name = "radius", .type = BLOBMSG_TYPE_STRING },
		[RADIUS_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__PARAMS_MAX] = {};

	blobmsg_parse(radius_policy, __RADIUS_MAX, tb, blob_data(a), blob_len(a));
	if (!tb[RADIUS_TYPE] || !tb[RADIUS_DATA])
		return;
	blob_buf_init(&proto, 0);
	blobmsg_add_string(&proto, "radius", blobmsg_get_string(tb[RADIUS_TYPE]));
	blobmsg_add_string(&proto, "data", blobmsg_get_string(tb[RADIUS_DATA]));
	proto_send_blob();
}

void
result_send(uint32_t id, struct blob_attr *a, uint32_t _uuid)
{
	time_t uuid = (time_t) _uuid;
	struct blob_attr *b;
	void *m, *s;
	size_t rem;

	m = result_new_blob(id, uuid ? uuid : uuid_active);
	s = blobmsg_open_table(&result, "status");
	blobmsg_for_each_attr(b, a, rem)
		blobmsg_add_blob(&result, b);
	blobmsg_close_table(&result, s);
	blobmsg_close_table(&result, m);
	result_send_blob();
}

static char *stats_request_uuid;

static char *
comp(char *src, int len, int *rlen)
{
	uLongf sourceLen = len;
	uLongf destLen = compressBound(len);
	unsigned char *dest = malloc(destLen);

	memset(dest, 0, destLen);

	if (compress(dest, &destLen, (unsigned char *)src, sourceLen) != Z_OK) {
		printf("compress failed\n");
		free(dest);
		return NULL;
	}
	*rlen = destLen;
	return (char *)dest;
}

static char *
decomp(char *src, int len)
{
        uLong ucompSize = len + 1;
        uLong compSize = compressBound(ucompSize);
        char *dest = malloc(ucompSize);

        if (uncompress((Bytef *)dest, &ucompSize, (Bytef *)src, compSize) != Z_OK)
        {
                free(dest);
                return NULL;
        };
        return (char *)dest;
}

static char *
b64(char *src, int len)
{
	char *dst;
	int ret;

	if (!src)
		return NULL;
	dst = malloc(len * 4);
	ret = b64_encode(src, len, dst, len * 4);
	if (ret < 1) {
		free(dst);
		return NULL;
	}
	return dst;
}

static char *
decode_b64(char *src, int len)
{
        char *dst;
        int ret;

        if (!src)
                return NULL;
        dst = malloc(len);
        ret = b64_decode(src, dst, len);
        if (ret < 1)
        {
                free(dst);
                return NULL;
        }
        return dst;
}

static void
decode_and_inflate(struct blob_attr **encoded_param, struct blob_attr *ret[__JSONRPC_MAX]) {
        int compress_sz = blobmsg_get_u32(encoded_param[PARAMS_COMPRESS_SZ]);
        char *cp64 = blobmsg_get_string(encoded_param[PARAMS_COMPRESS_64]);
        char *cp = decode_b64(cp64, compress_sz);
        if (cp == NULL) {
                ULOG_ERR("base64 decode failed for message\n");
                ret = NULL;
                return;
        }
        char *params = decomp(cp, compress_sz);
        if (params == NULL) {
                ULOG_ERR("failed to uncompress message\n");
                ret = NULL;
                return;
	}

        static struct blob_buf pbuf;
        blob_buf_init(&pbuf, 0);
        void *c;
        c = blobmsg_open_table(&pbuf, "params");
        blobmsg_add_json_from_string(&pbuf, params);
        free(params);
        blobmsg_close_table(&pbuf, c);
        blobmsg_parse(jsonrpc_policy, __JSONRPC_MAX, ret, blob_data(pbuf.head), blob_len(pbuf.head));
}

static void
stats_add_request_uuid(struct blob_buf *b)
{
	if (!stats_request_uuid)
		return;
	blobmsg_add_string(b, "request_uuid", stats_request_uuid);
	free(stats_request_uuid);
	stats_request_uuid = NULL;
}

static char *
stats_get_string(struct blob_attr *a)
{
	struct blob_attr *b;
	size_t rem;

	blob_buf_init(&result, 0);
	stats_add_request_uuid(&result);
	blobmsg_for_each_attr(b, a, rem)
		blobmsg_add_blob(&result, b);

	return blobmsg_format_json(result.head, true);
}

void
stats_send(struct blob_attr *a)
{
	struct blob_attr *b;
	void *c;
	size_t rem;

	blob_buf_init(&proto, 0);
	blobmsg_add_string(&proto, "jsonrpc", "2.0");
	blobmsg_add_string(&proto, "method", "state");
	c = blobmsg_open_table(&proto, "params");
	if (state_compress && blobmsg_data_len(a) >= 2 * 1024) {
		char *source = stats_get_string(a);
		int comp_len = 0, orig_len = strlen(source);
		char *compressed = comp(source, orig_len, &comp_len);
		char *encoded = b64(compressed, comp_len);

		free(compressed);
		free(source);
		if (encoded) {
			blobmsg_add_string(&proto, "compress_64", encoded);
			blobmsg_add_u32(&proto, "compress_sz", orig_len);
			free(encoded);
		} else {
			ULOG_ERR("failed to compress stats");
			return;
		}
	} else {
		stats_add_request_uuid(&proto);
		blobmsg_for_each_attr(b, a, rem)
			blobmsg_add_blob(&proto, b);
	}
	blobmsg_close_table(&proto, c);
	proto_send_blob();
}

void
log_send(char *message, int severity)
{
	void *m = proto_new_blob("log");

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_string(&proto, "log", message);
	blobmsg_add_u32(&proto, "severity", severity);
	blobmsg_close_table(&proto, m);
	ULOG_ERR("%s\n", message);
	proto_send_blob();
}

static char *health_request_uuid;

void
health_send(uint32_t sanity, struct blob_attr *a)
{
	void *m = proto_new_blob("healthcheck");
	struct blob_attr *b;
	void *c;
	size_t rem;

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u64(&proto, "uuid", uuid_active);
	if (health_request_uuid) {
		blobmsg_add_string(&proto, "request_uuid", health_request_uuid);
		free(health_request_uuid);
		health_request_uuid = NULL;
	}
	blobmsg_add_u32(&proto, "sanity", sanity);
	c = blobmsg_open_table(&proto, "data");
	blobmsg_for_each_attr(b, a, rem)
		blobmsg_add_blob(&proto, b);
	blobmsg_close_table(&proto, c);
	blobmsg_close_table(&proto, m);
	proto_send_blob();
}

void
rebootlog_send(char *type, struct blob_attr *a)
{
	void *m = proto_new_blob("rebootLog");
	struct blob_attr *b;
	void *c;
	size_t rem;

	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u64(&proto, "uuid", uuid_active);
	blobmsg_add_string(&proto, "type", type);
	blobmsg_add_u64(&proto, "date", time(NULL));
	c = blobmsg_open_array(&proto, "info");
	blobmsg_for_each_attr(b, a, rem)
		blobmsg_add_blob(&proto, b);
	blobmsg_close_array(&proto, c);
	blobmsg_close_table(&proto, m);
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
venue_broadcast_send(struct blob_attr *payload)
{
	struct blob_attr *b;
	void *m, *d;
	size_t rem;

	m = proto_new_blob("venue_broadcast");
	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u64(&proto, "timestamp", time(NULL));
	d = blobmsg_open_table(&proto, "data");
	blobmsg_for_each_attr(b, payload, rem)
		blobmsg_add_blob(&proto, b);
	blobmsg_close_table(&proto, d);
	blobmsg_close_table(&proto, m);
	proto_send_blob();
}

void
configure_reply(uint32_t error, char *text, time_t uuid, uint32_t id)
{
	struct blob_attr *b;
	void *c, *s, *r;
	size_t rem;

	if (!id)
		return;

	c = result_new_blob(id, uuid);
	s = blobmsg_open_table(&result, "status");
	blobmsg_add_string(&result, "text", text);
	if (blob_len(rejected.head)) {
		struct blob_attr *tb[__PARAMS_MAX] = {};

		blobmsg_parse(params_policy, __PARAMS_MAX, tb, blob_data(rejected.head),
			      blob_len(rejected.head));
		if (tb[PARAMS_REJECTED]) {
			r = blobmsg_open_array(&result, "rejected");
			blobmsg_for_each_attr(b, tb[PARAMS_REJECTED], rem)
				blobmsg_add_blob(&result, b);
			blobmsg_close_array(&result, r);
		}
		if (!error)
			error = 1;
	}
	blobmsg_add_u32(&result, "error", error);
	blobmsg_close_table(&result, s);
	blobmsg_close_table(&result, c);
	result_send_blob();
}

static void
configure_handle(struct blob_attr **rpc)
{
	struct blob_attr *tb[__PARAMS_MAX] = {};
	char *path = NULL;
	uint32_t id = 0;
	char *cfg;
	FILE *fp;

	blobmsg_parse(params_policy, __PARAMS_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

        if (tb[PARAMS_COMPRESS_64] && tb[PARAMS_COMPRESS_SZ])
        {
                ULOG_INFO("configuration message is compressed, decode and uncompress\n");
                struct blob_attr *tb2[__JSONRPC_MAX] = {};
		decode_and_inflate(tb,tb2);
		if (!tb2[JSONRPC_PARAMS])
                {
                        ULOG_ERR("after decode and uncompress, configure message is missing parameters\n");
                        configure_reply(1, "after decode and uncompress, configure message is missing parameters", 0, id);
                        return;
                }

                blobmsg_parse(params_policy, __PARAMS_MAX, tb, blobmsg_data(tb2[JSONRPC_PARAMS]),
                                          blobmsg_data_len(tb2[JSONRPC_PARAMS]));
        }

	if (!tb[PARAMS_UUID] || !tb[PARAMS_SERIAL] || !tb[PARAMS_CONFIG]) {
		ULOG_ERR("configure message is missing parameters\n");
		configure_reply(1, "invalid parameters", 0, id);
		return;
	}

	if (tb[PARAMS_COMPRESS])
		state_compress = blobmsg_get_bool(tb[PARAMS_COMPRESS]);

	if (asprintf(&path, "/etc/ucentral/ucentral.cfg.%010lu", (unsigned long int)blobmsg_get_u32(tb[PARAMS_UUID])) < 0) {
		configure_reply(1, "failed to store the configuration", 0, id);
		return;
	}

	fp = fopen(path, "w+");
	free(path);
	if (!fp) {
		configure_reply(1, "failed to store the configuration", 0, id);
		return;
	}
	cfg = blobmsg_format_json(tb[PARAMS_CONFIG], true);
	if (!cfg) {
		fclose(fp);
		configure_reply(1, "failed to store the configuration", 0, id);
		return;
	}
	fprintf(fp, "%s", cfg);
	free(cfg);
	fclose(fp);
	config_init(1, id);
}

static void
action_handle(struct blob_attr **rpc, char *command, int reply, int delay, int admin, int timeout)
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
	blobmsg_add_u32(&action, "delay", delay);
	blobmsg_add_u32(&action, "timeout", timeout ? timeout : 60 * 10);
	if (rpc[JSONRPC_PARAMS]) {
		void *c = blobmsg_open_table(&action, "payload");
		struct blob_attr *b;
		size_t rem;

		blobmsg_for_each_attr(b, rpc[JSONRPC_PARAMS], rem)
			blobmsg_add_blob(&action, b);
		blobmsg_close_table(&action, c);
	}

	if (cmd_run(action.head, id, admin)) {
		result_send_error(1, "failed to queue command", 1, id);
		return;
	}
	if (reply)
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
request_handle(struct blob_attr **rpc)
{
	enum {
		REQUEST_MESSAGE,
		REQUEST_UUID,
		__REQUEST_MAX,
	};

	static const struct blobmsg_policy request_policy[__REQUEST_MAX] = {
		[REQUEST_MESSAGE] = { .name = "message", .type = BLOBMSG_TYPE_STRING },
		[REQUEST_UUID] = { .name = "request_uuid", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__REQUEST_MAX] = {};
	char *message, *uuid;
	uint32_t id = 0;
	int ret;

	blobmsg_parse(request_policy, __REQUEST_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	if (!tb[REQUEST_MESSAGE] || !tb[REQUEST_UUID]) {
		result_send_error(1, "invalid parameters", 1, id);
		return;
	}

	message = blobmsg_get_string(tb[REQUEST_MESSAGE]);
	uuid = blobmsg_get_string(tb[REQUEST_UUID]);

	if (!strcmp(message, "state")) {
		stats_request_uuid = strdup(uuid);
		ret = system("/etc/init.d/ustats restart");
		if (ret) {
			result_send_error(1, "failed to execute ustats", ret, id);
			return;
		}
	} else if (!strcmp(message, "healthcheck")) {
		health_request_uuid = strdup(uuid);
		ret = system("/etc/init.d/uhealth restart");
                if (ret) {
                        result_send_error(1, "failed to execute uhealth", ret, id);
                        return;
                }
	} else {
		result_send_error(1, "invalid parameters", 1, id);
		return;
	}
	result_send_error(0, "success", 0, id);
}

static void
leds_handle(struct blob_attr **rpc)
{
	enum {
		LED_DURATION,
		LED_PATTERN,
		LED_ENDLESS,
		__LED_MAX,
	};

	static const struct blobmsg_policy led_policy[__LED_MAX] = {
		[LED_DURATION] = { .name = "duration", .type = BLOBMSG_TYPE_INT32 },
		[LED_PATTERN] = { .name = "pattern", .type = BLOBMSG_TYPE_STRING },
		[LED_ENDLESS] = { .name = "endless", .type = BLOBMSG_TYPE_BOOL },
	};

	struct blob_attr *tb[__LED_MAX] = {};
	uint32_t duration = 0;
	uint32_t id = 0;

	blobmsg_parse(led_policy, __LED_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	if (tb[LED_DURATION])
		duration = blobmsg_get_u32(tb[LED_DURATION]);
	
	if (tb[LED_ENDLESS] && blobmsg_get_bool(tb[LED_ENDLESS]))
		duration = 0xffff;

	if (!strcmp(blobmsg_get_string(tb[LED_PATTERN]), "blink")) {
		result_send_error(0, "success", 0, id);
		ubus_blink_leds(duration);
		return;
	}
	ubus_blink_leds(0);
	action_handle(rpc, "leds", 1, 1, 1, 0);
}

static void
event_handle(struct blob_attr **rpc)
{
	enum {
		REALTIME_TYPES,
		__REALTIME_MAX,
	};

	static const struct blobmsg_policy event_policy[__REALTIME_MAX] = {
		[REALTIME_TYPES] = { .name = "types", .type = BLOBMSG_TYPE_ARRAY },
	};

	struct blob_attr *tb[__REALTIME_MAX] = {};
	struct blob_attr *b;
	uint32_t id = 0;
	void *m, *s;
	size_t rem;

	blobmsg_parse(event_policy, __REALTIME_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	m = result_new_blob(id, uuid_active);
	s = blobmsg_open_table(&result, "status");
	blobmsg_add_u32(&result, "error", 0);
	blobmsg_add_string(&result, "text", "Success");
	blobmsg_close_table(&result, s);
	s = blobmsg_open_table(&result, "events");
	if (tb[REALTIME_TYPES])
		blobmsg_for_each_attr(b, tb[REALTIME_TYPES], rem) {
			if (blobmsg_type(b) != BLOBMSG_TYPE_STRING)
				continue;
			event_dump(&result, blobmsg_get_string(b), true);
		}
	else
		event_dump_all(&result);

	blobmsg_close_table(&result, s);
	blobmsg_close_table(&result, m);
	result_send_blob();
}

void
telemetry_periodic(void)
{
        void *m, *s;
	int count = 0;

	m = proto_new_blob("telemetry");
	blobmsg_add_string(&proto, "serial", client.serial);
	blobmsg_add_u8(&proto, "adhoc", 1);
	s = blobmsg_open_table(&proto, "data");
	count += event_dump(&proto, "dhcp-snooping", true);
	count += event_dump(&proto, "wifi-frames", true);
	count += event_dump(&proto, "event", true);
	blobmsg_close_table(&proto, s);
	blobmsg_close_table(&proto, m);
	if (count)
		proto_send_blob();
}

static void
telemetry_complete_cb(struct task *t, time_t uuid, uint32_t id, int ret)
{
	struct blob_attr *b;
        void *m, *s;
	size_t rem;

	m = proto_new_blob("telemetry");
	blobmsg_add_string(&proto, "serial", client.serial);
	s = blobmsg_open_table(&proto, "data");
	blobmsg_for_each_attr(b, telemetry_filter, rem) {
		if (blobmsg_type(b) != BLOBMSG_TYPE_STRING)
			continue;
		event_dump(&proto, blobmsg_get_string(b), true);
	}
	blobmsg_close_table(&proto, s);
	blobmsg_close_table(&proto, m);
	proto_send_blob();
}

static void
telemetry_run_cb(time_t uuid, uint32_t _id)
{
	ULOG_INFO("running telemetry task\n");

	execlp("/usr/share/ucentral/telemetry.uc", "/usr/share/ucentral/telemetry.uc", NULL);
	exit(1);
}

struct task telemetry_task = {
	.run_time = 60,
	.run = telemetry_run_cb,
	.complete = telemetry_complete_cb,
};

static void
telemetry_handle(struct blob_attr **rpc)
{
	enum {
		TELEMETRY_INTERVAL,
		TELEMETRY_TYPES,
		__TELEMETRY_MAX,
	};

	static const struct blobmsg_policy telemetry_policy[__TELEMETRY_MAX] = {
		[TELEMETRY_INTERVAL] = { .name = "interval", .type = BLOBMSG_TYPE_INT32 },
		[TELEMETRY_TYPES] = { .name = "types", .type = BLOBMSG_TYPE_ARRAY },
	};

	struct blob_attr *tb[__TELEMETRY_MAX] = {};
	uint32_t id = 0;
	void *m, *s;
	int err = 0;

	blobmsg_parse(telemetry_policy, __TELEMETRY_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	if (tb[TELEMETRY_INTERVAL])
		telemetry_interval = blobmsg_get_u32(tb[TELEMETRY_INTERVAL]);
	else
		telemetry_interval = 0;
	if (telemetry_filter) {
		free(telemetry_filter);
		telemetry_filter = NULL;
	}
	if (tb[TELEMETRY_TYPES])
		telemetry_filter = blob_memdup(tb[TELEMETRY_TYPES]);

	if (telemetry_interval && !telemetry_filter) {
		err = 2;
		telemetry_interval = 0;
	}
	if (client.telemetry_interval) {
		err = 3;
	} else if (!telemetry_interval) {
		task_stop(&telemetry_task);
		unlink("/tmp/ucentral.telemetry");
	} else if (telemetry_task.periodic) {
		err = 2;
	} else {
		event_flush();
		telemetry_task.periodic = telemetry_interval;
		task_telemetry(&telemetry_task, uuid_latest, id);
	}

	m = result_new_blob(id, uuid_active);
	s = blobmsg_open_table(&result, "status");
	blobmsg_add_u32(&result, "error", err);
	switch (err) {
	case 0:
		blobmsg_add_string(&result, "text", "Success");
		break;
	case 3:
		blobmsg_add_string(&result, "text", "Periodic telemetry is enabled");
		break;
	default:
		blobmsg_add_string(&result, "text", "Invalid Arguments");
		break;
	}
	blobmsg_close_table(&result, s);
	blobmsg_close_table(&result, m);
	result_send_blob();
}

static void
package_handle(struct blob_attr **rpc)
{
	enum {
		PACKAGE_NAME,
		PACKAGE_URL,
		PACKAGE_RESULT,
		__PACKAGE_MAX,
	};

	enum {
		ROOT_OP,
		ROOT_PACKAGE,
		ROOT_PACKAGES,
		ROOT_SERIAL,
		__ROOT_MAX,
	};

	static const struct blobmsg_policy package_policy[__PACKAGE_MAX] = {
		[PACKAGE_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
		[PACKAGE_URL] = { .name = "url", .type = BLOBMSG_TYPE_STRING },
		[PACKAGE_RESULT] = { .name = "result", .type = BLOBMSG_TYPE_STRING },
	};

	static const struct blobmsg_policy root_policy[__ROOT_MAX] = {
		[ROOT_OP] = { .name = "op", .type = BLOBMSG_TYPE_STRING },
		[ROOT_PACKAGE] = { .name = "package", .type = BLOBMSG_TYPE_STRING },
		[ROOT_PACKAGES] = { .name = "packages", .type = BLOBMSG_TYPE_ARRAY },
		[ROOT_SERIAL] = { .name = "serial", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb_root[__ROOT_MAX] = {};
	struct blob_attr *tb[__PACKAGE_MAX] = {};
	struct blob_attr *cur;
	uint32_t id = 0;
	int rem;
	int error_count = 0;

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	if (!rpc[JSONRPC_PARAMS]) {
		result_send_error(1, "invalid parameters: params missing", 1, id);
		return;
	}

	blobmsg_parse(root_policy, __ROOT_MAX, tb_root, blobmsg_data(rpc[JSONRPC_PARAMS]), blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (!tb_root[ROOT_OP]) {
		result_send_error(1, "invalid parameters: missing operation", 1, id);
		return;
	}

	const char *op = blobmsg_get_string(tb_root[ROOT_OP]);
	if (strcmp(op, "install") && strcmp(op, "delete") && strcmp(op, "list")) {
		result_send_error(1, "invalid parameters: unrecognized operation", 1, id);
		return;
	}

	if (!strcmp(op, "list")) {
		// if (!tb_root[ROOT_PACKAGE]) {
		// 	result_send_error(1, "invalid parameters: missing package name", 1, id);
		// 	return;
		// }

		// if (blobmsg_type(tb_root[ROOT_PACKAGE]) != BLOBMSG_TYPE_STRING) {
		// 	result_send_error(1, "invalid parameters: package must be a string", 1, id);
		// 	return;
		// }
		const char *result_str = cpm_list();

		if (strcmp(result_str, "Success")) {
			result_send_error(1, "Failed to generate package list", 1, id);
		}

		void *m, *s;
		m = result_new_blob(id, uuid_active);
		s = blobmsg_open_table(&result, "status");

		struct stat statbuf = { };
		if (!stat("/tmp/packages.json", &statbuf)) {
			FILE *fp = fopen("/tmp/packages.json", "r");
			if (!fp) {
				log_send("failed to open packages.json", LOG_ERR);
				blobmsg_close_table(&result, s);
				blobmsg_close_table(&result, m);
				return;
			}

			char *source = malloc(statbuf.st_size + 1);
			if (!source) {
				log_send("failed to allocate memory for packages.json", LOG_ERR);
				fclose(fp);
				blobmsg_close_table(&result, s);
				blobmsg_close_table(&result, m);
				return;
			}

			size_t read_size = fread(source, 1, statbuf.st_size, fp);
			fclose(fp);
			source[read_size] = '\0';

			int comp_len = 0, orig_len = strlen(source);
			char *compressed = comp(source, read_size, &comp_len);
			char *encoded = b64(compressed, comp_len);

			if (encoded) {
				blobmsg_add_string(&result, "compress_64", encoded);
				blobmsg_add_u32(&result, "compress_sz", orig_len);
				free(encoded);
			} else {
				ULOG_ERR("failed to compress stats");
				return;
			}
		}

		blobmsg_add_string(&result, "text", "Success");
		blobmsg_close_table(&result, s);
		blobmsg_close_table(&result, m);
		result_send_blob();
	}
	else {
		if (!tb_root[ROOT_PACKAGES]) {
			result_send_error(1, "invalid parameters: missing packages array", 1, id);
			return;
		}

		if (blobmsg_type(tb_root[ROOT_PACKAGES]) != BLOBMSG_TYPE_ARRAY) {
			result_send_error(1, "invalid parameters: packages must be an array", 1, id);
			return;
		}

		blobmsg_for_each_attr(cur, tb_root[ROOT_PACKAGES], rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE) {
				result_send_error(1, "invalid parameters: package array elements must be objects", 1, id);
				return;
			}

			blobmsg_parse(package_policy, __PACKAGE_MAX, tb, blobmsg_data(cur), blobmsg_data_len(cur));

			if (!tb[PACKAGE_NAME]) {
				result_send_error(1, "invalid parameters: missing package name", 1, id);
				return;
			}

			if (!strcmp(op, "install")) {
				if (!tb[PACKAGE_URL]) {
					result_send_error(1, "invalid parameters: missing package url for installation", 1, id);
					return;
				}

				// Validate URL scheme (http or https)
				const char *url = blobmsg_get_string(tb[PACKAGE_URL]);
				if (!url || (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0)) {
					result_send_error(1, "invalid parameters: package url must start with http:// or https://", 1, id);
					return;
				}
			}

			if (!strcmp(op, "delete")) {
				if (!tb[PACKAGE_NAME]) {
					result_send_error(1, "invalid parameters: missing package name for removal", 1, id);
					return;
				}
			}

			ULOG_DBG("Processing package: name=%s, url=%s\n", blobmsg_get_string(tb[PACKAGE_NAME]), blobmsg_get_string(tb[PACKAGE_URL]));
		}

		void *m, *s, *p;
		m = result_new_blob(id, uuid_active);
		s = blobmsg_open_table(&result, "status");
		p = blobmsg_open_array(&result, "packages");

		blobmsg_for_each_attr(cur, tb_root[ROOT_PACKAGES], rem) {
			blobmsg_parse(package_policy, __PACKAGE_MAX, tb, blobmsg_data(cur), blobmsg_data_len(cur));

			const char *pkg_name = blobmsg_get_string(tb[PACKAGE_NAME]);
			const char *result_str = NULL;
			void *pkg = blobmsg_open_table(&result, NULL);

			if (!strcmp(op, "install")) {
				const char *pkg_url = blobmsg_get_string(tb[PACKAGE_URL]);
				result_str = cpm_install(pkg_name, pkg_url);
			} else if (!strcmp(op, "delete")) {
				result_str = cpm_remove(pkg_name);
			}

			blobmsg_add_string(&result, "name", pkg_name);
			blobmsg_add_string(&result, "result", result_str);
			if (strcmp(result_str, "Success") != 0) {
				error_count++;
			}
			blobmsg_close_table(&result, pkg);
		}

		blobmsg_close_array(&result, p);
		blobmsg_add_u32(&result, "error", error_count);
		blobmsg_add_string(&result, "text", error_count ? "Some operations failed" : "Success");
		blobmsg_close_table(&result, s);
		blobmsg_close_table(&result, m);
		result_send_blob();
	}

	return;
}

static void
ping_handle(struct blob_attr **rpc)
{
	uint32_t id = 0;
	void *m, *s;

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	m = result_new_blob(id, uuid_active);
	s = blobmsg_open_table(&result, "status");
	blobmsg_add_u32(&result, "error", 0);
	blobmsg_add_string(&result, "text", "Success");
	blobmsg_close_table(&result, s);
	blobmsg_close_table(&result, m);
	result_send_blob();
}

/*static void
transfer_handle(struct blob_attr **rpc)
{
	enum {
		TRANSFER_SERVER,
		TRANSFER_PORT,
		__TRANSFER_MAX,
	};

	static const struct blobmsg_policy transfer_policy[__TRANSFER_MAX] = {
		[TRANSFER_SERVER] = { .name = "server", .type = BLOBMSG_TYPE_STRING },
		[TRANSFER_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
	};

	struct blob_attr *tb[__TRANSFER_MAX] = {};
	uint32_t id = 0;
	char *gateway;
	FILE *fp;

	blobmsg_parse(transfer_policy, __TRANSFER_MAX, tb, blobmsg_data(rpc[JSONRPC_PARAMS]),
		      blobmsg_data_len(rpc[JSONRPC_PARAMS]));

	if (rpc[JSONRPC_ID])
		id = blobmsg_get_u32(rpc[JSONRPC_ID]);

	if (!tb[TRANSFER_SERVER] || !tb[TRANSFER_PORT]) {
		result_send_error(1, "invalid parameters", 1, id);
		return;
	}

	fp = fopen("/etc/ucentral/gateway.json", "w+");
	if (!fp) {
		configure_reply(1, "failed to store the new gateway", 0, id);
		return;
	}
	gateway = blobmsg_format_json(rpc[JSONRPC_PARAMS], true);
	if (!gateway) {
		fclose(fp);
		configure_reply(1, "failed to store the new gateway", 0, id);
		return;
	}
	fprintf(fp, "%s", gateway);
	free(gateway);
	fclose(fp);
	result_send_error(0, "success", 0, id);
}*/

static void
proto_handle_blob(void)
{
	struct blob_attr *rpc[__JSONRPC_MAX] = {};
	char *method;

	blobmsg_parse(jsonrpc_policy, __JSONRPC_MAX, rpc, blob_data(proto.head), blob_len(proto.head));
	if (rpc[JSONRPC_RADIUS]) {
		ubus_forward_radius(&proto);
		return;
	}

	if (!rpc[JSONRPC_VER] || (!rpc[JSONRPC_METHOD] && !rpc[JSONRPC_ERROR]) ||
	    (rpc[JSONRPC_METHOD] && !rpc[JSONRPC_PARAMS]) ||
	    strcmp(blobmsg_get_string(rpc[JSONRPC_VER]), "2.0")) {
		log_send("received invalid jsonrpc call", LOG_ERR);
		return;
	}

	if (rpc[JSONRPC_METHOD]) {
		method = blobmsg_get_string(rpc[JSONRPC_METHOD]);

		if (!strcmp(method, "configure"))
			configure_handle(rpc);
		else if (!strcmp(method, "ping"))
			ping_handle(rpc);
		else if (!strcmp(method, "reboot") ||
			 !strcmp(method, "transfer") ||
			 !strcmp(method, "factory"))
			action_handle(rpc, method, 1, 10, 1, 0);
		else if (!strcmp(method, "upgrade"))
			action_handle(rpc, method, 0, 10, 1, 0);
		else if (!strcmp(method, "perform") ||
			 !strcmp(method, "rtty") ||
			 !strcmp(method, "certupdate") ||
			 !strcmp(method, "script") ||
			 !strcmp(method, "rrm") ||
			 !strcmp(method, "fixedconfig") ||
			 !strcmp(method, "fingerprint") ||
			 !strcmp(method, "trace"))
			action_handle(rpc, method, 0, 1, 0, 0);
		else if (!strcmp(method, "wifiscan"))
			action_handle(rpc, method, 0, 1, 0, 120);
		else if (!strcmp(method, "leds"))
			leds_handle(rpc);
		else if (!strcmp(method, "request"))
			request_handle(rpc);
		else if (!strcmp(method, "event"))
			event_handle(rpc);
		else if (!strcmp(method, "telemetry"))
			telemetry_handle(rpc);
		else if (!strcmp(method, "venue_broadcast"))
			venue_broadcast_handle(rpc[JSONRPC_PARAMS]);
		else if (!strcmp(method, "package"))
			package_handle(rpc);
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
		log_send("failed to parse command", LOG_CRIT);
		return;
	}
	proto_handle_blob();
}

void
proto_handle_simulate(struct blob_attr *a)
{
	struct blob_attr *b;
	char *msg;
	size_t rem;

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
