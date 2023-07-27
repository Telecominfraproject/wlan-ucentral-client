/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

struct task ip_collide_task;

static void
ip_collide_run_cb(time_t uuid, uint32_t _id)
{
	ULOG_INFO("running ip-collide task\n");

	execlp("/usr/share/ucentral/ip-collide.uc", "/usr/share/ucentral/ip-collide.uc", NULL);
	exit(1);
}

static void
ip_collide_complete_cb(struct task *t, time_t uuid, uint32_t id, int ret)
{
	ip_collide_task.pending = 0;
}

struct task ip_collide_task = {
	.run_time = 60,
	.run = ip_collide_run_cb,
	.complete = ip_collide_complete_cb,
};

void
ip_collide_run(void)
{
	if (ip_collide_task.pending)
		return;
	ip_collide_task.pending = 1;
	task_config(&ip_collide_task, uuid_latest, 0);
}
