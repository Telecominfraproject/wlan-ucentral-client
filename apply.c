/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

int apply_pending = 0;

static void
apply_run_cb(time_t uuid, uint32_t _id)
{
	char str[64];
	char id[32];

	ULOG_INFO("running apply task\n");

	sprintf(str, "/etc/ucentral/ucentral.cfg.%010ld", uuid);
	sprintf(id, "%d", _id);
	execlp("/usr/share/ucentral/ucentral.uc", "/usr/share/ucentral/ucentral.uc", str, id, NULL);
	exit(1);
}

static void
apply_complete_cb(struct task *t, time_t uuid, uint32_t id, int ret)
{
	apply_pending = 0;

	if (ret) {
		ULOG_ERR("apply task returned %d\n", ret);
		config_init(0, id);
		return;
	}
	uuid_active = uuid_applied = uuid_latest;
	ULOG_INFO("applied cfg:%ld\n", uuid_latest);
	//health_run(id, 0);
}

struct task apply_task = {
	.run_time = 60,
	.run = apply_run_cb,
	.complete = apply_complete_cb,
};

void
apply_run(uint32_t id)
{
	apply_pending = 1;
	task_apply(&apply_task, uuid_latest, id);
}
