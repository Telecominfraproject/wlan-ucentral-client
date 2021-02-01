/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 *   Copyright (C) 2020 John Crispin <john@phrozen.org> 
 */

#include "ucentral.h"

enum {
	CMD_CMD,
	CMD_UUID,
	__CMD_MAX,
};

static const struct blobmsg_policy cmd_policy[__CMD_MAX] = {
	[CMD_CMD] = { .name = "cmd", .type = BLOBMSG_TYPE_STRING },
	[CMD_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_INT32 },
};

static void
cmd_run_cb(time_t uuid)
{
	char str[64];

	ULOG_INFO("running command task\n");

	sprintf(str, "/tmp/ucentral.cmd.%010ld", uuid);
	execlp("/usr/sbin/ucentral_cmd.sh", "/usr/sbin/ucentral_cmd.sh", str, NULL);
	exit(1);
}

static void
cmd_complete_cb(struct task *t, time_t uuid, int ret)
{
	ULOG_INFO("executed command: %d\n", ret);
	free(t);
}

int
cmd_run(struct blob_attr *attr)
{
	static struct blob_attr *tb[__CMD_MAX];
	char *json = NULL;
	FILE *fp = NULL;
	char path[256];
	int ret = -1;
	time_t t;

	blobmsg_parse(cmd_policy, __CMD_MAX, tb, blobmsg_data(attr), blobmsg_data_len(attr));
	if (!tb[CMD_CMD] || !tb[CMD_UUID]) {
		goto out;
	}

	t = blobmsg_get_u32(tb[CMD_UUID]);

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

		task->run_time = 60;
		task->run = cmd_run_cb;
		task->complete = cmd_complete_cb;
		fclose(fp);
		fp = NULL;
		task_run(task, t);
		ret = 0;
	}

out:
	if (json)
		free(json);
	if (fp)
		fclose(fp);

	return ret;
}
