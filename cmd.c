/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

enum {
	CMD_COMMAND,
	CMD_TIMEOUT,
	CMD_DELAY,
	__CMD_MAX,
};

static const struct blobmsg_policy cmd_policy[__CMD_MAX] = {
	[CMD_COMMAND] = { .name = "command", .type = BLOBMSG_TYPE_STRING },
	[CMD_TIMEOUT] = { .name = "timeout", .type = BLOBMSG_TYPE_INT32 },
	[CMD_DELAY] = { .name = "delay", .type = BLOBMSG_TYPE_INT32 },
};

static void
cmd_run_cb(time_t uuid, uint32_t _id)
{
	char str[128];
	char id[32];

	ULOG_INFO("running command task\n");

	sprintf(str, "/tmp/ucentral.cmd.%010ld", uuid);
	snprintf(id, sizeof(id), "%d", _id);
	execlp("/usr/share/ucentral/cmd.uc", "/usr/share/ucentral/cmd.uc", str, id, NULL);
	exit(1);
}

static void
cmd_complete_cb(struct task *t, time_t uuid, uint32_t id, int ret)
{
	char str[128];
	sprintf(str, "/tmp/ucentral.cmd.%010ld", uuid);
	unlink(str);
	if (ret)
		result_send_error(1, "command returned an error code", ret, id);
}

int
cmd_run(struct blob_attr *attr, uint32_t id, int admin)
{
	static struct blob_attr *tb[__CMD_MAX];
	char *json = NULL;
	FILE *fp = NULL;
	char path[128];
	int ret = -1;
	time_t t = id;

	blobmsg_parse(cmd_policy, __CMD_MAX, tb, blobmsg_data(attr), blobmsg_data_len(attr));
	if (!tb[CMD_COMMAND]) {
		ULOG_ERR("cmd has invalid parameters\n");
		goto out;
	}

	json = blobmsg_format_json(attr, true);
	if (!json) {
		ULOG_ERR("failed to format cmd json\n");
		goto out;
	}

	snprintf(path, sizeof(path), "/tmp/ucentral.cmd.%010ld", t);
	fp = fopen(path, "w+");
	if (!fp) {
		ULOG_ERR("failed to open %s\n", path);
		goto out;
	}
	if (fwrite(json, strlen(json), 1, fp) == 1) {
		struct task *task = calloc(1, sizeof(*task));

		if (tb[CMD_TIMEOUT])
			task->run_time = blobmsg_get_u32(tb[CMD_TIMEOUT]);
		else
			task->run_time = 60;
		if (tb[CMD_DELAY])
			task->delay = blobmsg_get_u32(tb[CMD_DELAY]);
		task->run = cmd_run_cb;
		task->complete = cmd_complete_cb;
		fclose(fp);
		fp = NULL;
		task_run(task, t, id, admin);
		ret = 0;
	}

out:
	if (json)
		free(json);
	if (fp)
		fclose(fp);

	return ret;
}
