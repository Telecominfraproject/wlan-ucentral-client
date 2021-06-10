/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

#define CRASHLOG	"/tmp/crashlog"

static struct blob_buf crashlog;

void
crashlog_init(void)
{
	enum {
		CRASH_LOG,
		__CRASH_MAX,
	};

	static const struct blobmsg_policy crash_policy[__CRASH_MAX] = {
		[CRASH_LOG] = { .name = "crashlog", .type = BLOBMSG_TYPE_ARRAY },
	};

	struct blob_attr *tb[__CRASH_MAX] = {};
	struct stat s = {};

	if (stat(CRASHLOG, &s))
		return;

	blob_buf_init(&crashlog, 0);
	if (blobmsg_add_json_from_file(&crashlog, CRASHLOG)) {
		blobmsg_parse(crash_policy, __CRASH_MAX, tb, blob_data(crashlog.head),
		      blob_len(crashlog.head));
		if (tb[CRASH_LOG])
			crashlog_send(tb[CRASH_LOG]);
		else
			log_send("failed to parse the crashlog", LOG_ERR);
	} else {
		log_send("found a crashlog that is not valid json", LOG_ERR);
	}
	blob_buf_free(&crashlog);
	unlink(CRASHLOG);
}
