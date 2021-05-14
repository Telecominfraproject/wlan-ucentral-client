/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

static uint32_t blink_running;

static void
blink_run_cb(time_t uuid, uint32_t id)
{
	char duration[32];

	ULOG_INFO("running blink task\n");

	snprintf(duration, sizeof(duration), "%ld", uuid);
	execlp("/usr/libexec/ucentral/ucentral_led_blink.sh", "/usr/libexec/ucentral/ucentral_led_blink.sh", duration, NULL);
	exit(1);
}

static void
blink_complete_cb(struct task *t, time_t uuid, uint32_t id, int ret)
{
	blink_running = 0;
	result_send_error(ret ? 1 : 0, "led blinking completed", ret, id);
}

struct task blink_task = {
	.run = blink_run_cb,
	.complete = blink_complete_cb,
};

void
blink_run(uint32_t duration, uint32_t id)
{
	if (blink_running) {
		result_send_error(1, "command already running", 1, id);
		return;
	}

	blink_task.run_time = duration + 15;
	blink_running = 1;
	task_run(&blink_task, duration, id);
}
