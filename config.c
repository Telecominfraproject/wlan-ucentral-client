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

#include "usync.h"

#define USYNC_TMP	"/tmp/usync.tmp"
#define USYNC_LATEST	"/etc/usync/usync.active"

enum {
	CONFIG_UUID,
	__CONFIG_MAX,
};

static const struct blobmsg_policy config_policy[__CONFIG_MAX] = {
	[CONFIG_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_INT32 },
};

static struct blob_attr *config_tb[__CONFIG_MAX];
static struct blob_buf cfg;

static uint32_t uuid_applied;
uint32_t uuid_latest = 0;
uint32_t uuid_active = 0;

static int
config_load(const char *path)
{
	blob_buf_init(&cfg, 0);
	if (!blobmsg_add_json_from_file(&cfg, path)) {
		ULOG_ERR("failed to load %s\n", path);
		return 0;
	}

	memset(config_tb, 0, sizeof(config_tb));
	blobmsg_parse(config_policy, __CONFIG_MAX, config_tb, blob_data(cfg.head), blob_len(cfg.head));
	if (config_tb[CONFIG_UUID])
		return blobmsg_get_u32(config_tb[CONFIG_UUID]);

	return 0;
}

static void
config_apply(void)
{
	char path[PATH_MAX] = { };
	int ret;

	if (uuid_latest && (uuid_latest == uuid_applied))
		return;

	ULOG_INFO("applying cfg:%d\n", uuid_latest);
	snprintf(path, sizeof(path), "/usr/sbin/usync_apply.sh /etc/usync/usync.cfg.%010d", uuid_latest);
	ret = system(path);
	ret = WEXITSTATUS(ret);

	if (!ret) {
		uuid_applied = uuid_latest;
		ULOG_INFO("applied cfg:%d\n", uuid_latest);
		return;
	}
	ULOG_INFO("failed to apply cfg:%d\n", uuid_latest);
	config_load(USYNC_LATEST);
}

void
config_init(int apply)
{
	char path[PATH_MAX] = { };
	char link[PATH_MAX] = { };
	struct stat s;
	glob_t gl;

	uuid_active = 0;

	snprintf(path, PATH_MAX, "%s/usync.cfg.*", USYNC_CONFIG);
	if (glob(path, 0, NULL, &gl))
                return;
	if (!gl.gl_pathc)
		goto out;

	uuid_latest = config_load(gl.gl_pathv[gl.gl_pathc - 1]);

	if (apply)
		config_apply();

	snprintf(path, PATH_MAX, "%s/usync.active", USYNC_CONFIG);
	if (readlink(path, link, PATH_MAX) < 0) {
		ULOG_INFO("no active symlink found\n");
		goto out;
	}

	snprintf(path, PATH_MAX, "%s/%s", USYNC_CONFIG, basename(link));
	if (stat(path, &s)) {
		ULOG_INFO("active config not found\n");
		goto out;
	}

	uuid_active = config_load(path);

out:
	globfree(&gl);
	ULOG_INFO("config_init latest:%d active:%d\n", uuid_latest, uuid_active);
}

int
config_verify(struct blob_attr *attr)
{
	static struct blob_attr *tb[__CONFIG_MAX];
	int ret = -1;
	FILE *fp = NULL;
	char buf[128];
	char *cfg;

	blobmsg_parse(config_policy, __CONFIG_MAX, tb, blobmsg_data(attr), blobmsg_data_len(attr));
	if (!tb[CONFIG_UUID])
		return -1;

	cfg = blobmsg_format_json(attr, true);
	if (!cfg)
		goto err;

	fp = fopen(USYNC_TMP, "w+");
	if (!fp)
		goto err;
	if (fwrite(cfg, strlen(cfg), 1, fp) != 1)
		goto err;
	fclose(fp);
	fp = NULL;

	snprintf(buf, sizeof(buf), "/usr/sbin/usync_verify.sh %s %010d", USYNC_TMP,
		 blobmsg_get_u32(tb[CONFIG_UUID]));
	ret = system(buf);
	ret = WEXITSTATUS(ret);

err:
	if (cfg)
		free(cfg);
	if (fp)
		fclose(fp);

	config_init(!ret);

	return ret;
}


