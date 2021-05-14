/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

static int upload_pending = 0;
static char *upload_uuid;
static char *upload_file;
static char *upload_uri;

static void
upload_run_cb(time_t uuid, uint32_t id)
{
	char *file;
	char *name;

	if (asprintf(&file, "data=@%s", upload_file) == -1 ||
	    asprintf(&name, "name=%s", upload_uuid) == -1) {
		ULOG_INFO("failed to start upload task\n");
		exit(1);
	}
	ULOG_INFO("Calling /usr/bin/curl -F %s -F %s %s %s", name,  file, upload_uri,
	          client.selfsigned ? "--insecure" : "");

	execlp("/usr/bin/curl", "/usr/bin/curl",
	       "-F", name, "-F", file, upload_uri,
	       client.selfsigned ? "--insecure" : NULL,
	       NULL);
	ULOG_ERR("curl was not executed");
	exit(1);
}

static void
upload_complete_cb(struct task *t, time_t uuid, uint32_t id, int ret)
{
	upload_pending = 0;

	if (ret) {
		ULOG_ERR("ucentral: curl returned (%d)", ret);
		log_send("failed to upload file");
		return;
	}
	log_send("upload complete");
}

struct task upload_task = {
	.run = upload_run_cb,
	.complete = upload_complete_cb,
};

void
upload_run(struct blob_attr *a)
{
	enum {
		UPLOAD_UUID,
		UPLOAD_FILE,
		UPLOAD_URI,
		__UPLOAD_MAX,
	};

	static const struct blobmsg_policy error_policy[__UPLOAD_MAX] = {
		[UPLOAD_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_STRING },
		[UPLOAD_FILE] = { .name = "file", .type = BLOBMSG_TYPE_STRING },
		[UPLOAD_URI] = { .name = "uri", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__UPLOAD_MAX] = {};
	uint32_t id = 0;

	if (upload_pending) {
		log_send("could not upload file due to another pending upload");
		return;
	}

	blobmsg_parse(error_policy, __UPLOAD_MAX, tb, blobmsg_data(a),
		      blobmsg_data_len(a));

	if (!tb[UPLOAD_UUID] || !tb[UPLOAD_FILE] || !tb[UPLOAD_URI]) {
		log_send("invalid upload request");
		return;
	}

	safe_free(&upload_uuid);
	safe_free(&upload_file);
	safe_free(&upload_uri);

	upload_uuid = strdup(blobmsg_get_string(tb[UPLOAD_UUID]));
	upload_file = strdup(blobmsg_get_string(tb[UPLOAD_FILE]));
	upload_uri = strdup(blobmsg_get_string(tb[UPLOAD_URI]));

	upload_pending = 1;
	task_run(&upload_task, uuid_latest, id);
}
