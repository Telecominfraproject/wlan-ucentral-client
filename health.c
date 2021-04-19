/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

static void
health_run_cb(time_t uuid)
{
	ULOG_INFO("running health task\n");

	execlp("/usr/bin/ucode", "/usr/bin/ucode", "-m", "ubus",
	       "-m", "fs", "-m", "uci", "-i",
	       "/usr/share/ucentral/health.uc", NULL);
	exit(1);
}

static void
health_complete_cb(struct task *t, time_t uuid, uint32_t id, int ret)
{
}

struct task health_task = {
	.run_time = 120,
	.delay = 120,
	.periodic = 600,
	.run = health_run_cb,
	.complete = health_complete_cb,
};

void
health_run(uint32_t id, uint32_t immediate)
{
	if (immediate)
		health_task.delay = 0;
	else
		health_task.delay = 120;
	task_stop(&health_task);
	task_run(&health_task, uuid_active, id);
}

void
health_deinit(void)
{
	task_stop(&health_task);
}
