/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

static void
verify_run_cb(time_t uuid)
{
	char str[64];

	ULOG_INFO("running verify task\n");

	sprintf(str, "%010ld", uuid);
	execlp("/usr/libexec/ucentral/ucentral_verify.sh", "/usr/libexec/ucentral/ucentral_verify.sh", UCENTRAL_TMP, str, NULL);
	exit(1);
}

static void
verify_complete_cb(struct task *t, time_t uuid, uint32_t id, int ret)
{
	if (ret) {
		ULOG_ERR("verify task returned %d\n", ret);
		configure_reply(1, "failed to verify config", uuid, id);
		return;
	}
	ULOG_DBG("verify task succeeded, calling config with apply flag\n");
	config_init(1, id);
}

struct task verify_task = {
	.run_time = 10,
	.run = verify_run_cb,
	.complete = verify_complete_cb,
};

void
verify_run(uint32_t id)
{
	task_run(&verify_task, uuid_latest, id);
}
