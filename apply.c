/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

static void
apply_run_cb(time_t uuid)
{
	char str[64];

	ULOG_INFO("running apply task\n");

	sprintf(str, "/etc/ucentral/ucentral.cfg.%010ld", uuid);
	execlp("/usr/libexec/ucentral/ucentral_apply.sh", "/usr/libexec/ucentral/ucentral_apply.sh", str, NULL);
	exit(1);
}

static void
apply_complete_cb(struct task *t, time_t uuid, uint32_t id, int ret)
{
	if (ret) {
		log_send("failed to apply config");
		ULOG_ERR("apply task returned %d\n", ret);
		config_init(0, id);
		configure_reply(1, "failed to apply config", uuid, id);
		return;
	}
	uuid_active = uuid_applied = uuid_latest;
	ULOG_INFO("applied cfg:%ld\n", uuid_latest);
	configure_reply(0, "applied config", uuid_active, id);
	health_run(id);
}

struct task apply_task = {
	.run_time = 60,
	.run = apply_run_cb,
	.complete = apply_complete_cb,
};

void
apply_run(uint32_t id)
{
	task_run(&apply_task, uuid_latest, id);
}
