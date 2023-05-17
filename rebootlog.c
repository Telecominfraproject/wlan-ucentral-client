/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

#define CRASHLOG	"/tmp/crashlog"
#define CONSOLELOG	"/tmp/consolelog"

static struct blob_buf rebootlog;
enum {
	REBOOT_LOG,
	__REBOOT_MAX,
};

static const struct blobmsg_policy crash_policy[__REBOOT_MAX] = {
	[REBOOT_LOG] = { .name = "crashlog", .type = BLOBMSG_TYPE_ARRAY },
};

static const struct blobmsg_policy console_policy[__REBOOT_MAX] = {
	[REBOOT_LOG] = { .name = "consolelog", .type = BLOBMSG_TYPE_ARRAY },
};


static void
rebootlog_init(const struct blobmsg_policy *policy, char *type, char *file)
{
	struct blob_attr *tb[__REBOOT_MAX] = {};
	struct stat s = {};

	if (stat(file, &s))
		return;

	blob_buf_init(&rebootlog, 0);
	if (blobmsg_add_json_from_file(&rebootlog, file)) {
		blobmsg_parse(policy, __REBOOT_MAX, tb, blob_data(rebootlog.head),
		      blob_len(rebootlog.head));
		if (tb[REBOOT_LOG])
			rebootlog_send(type, tb[REBOOT_LOG]);
		else
			log_send("failed to parse the rebootlog", LOG_ERR);
	} else {
		log_send("found a rebootlog that is not valid json", LOG_ERR);
	}
	blob_buf_free(&rebootlog);
	unlink(file);
}

void
crashlog_init(void) {
	rebootlog_init(crash_policy, "crashlog", CRASHLOG);
}

void
consolelog_init(void) {
	rebootlog_init(console_policy, "console", CONSOLELOG);
}
