/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

enum {
	CONFIG_UUID,
	__CONFIG_MAX,
};

static const struct blobmsg_policy config_policy[__CONFIG_MAX] = {
	[CONFIG_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_INT32 },
};

static struct blob_attr *config_tb[__CONFIG_MAX];
static struct blob_buf cfg;

time_t uuid_applied;
time_t uuid_latest = 0;
time_t uuid_active = 0;

static time_t
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
config_apply(uint32_t id)
{
	if (uuid_latest && (uuid_latest == uuid_applied))
		return;
	ULOG_INFO("applying cfg:%ld\n", uuid_latest);
	apply_run(id);
}

void
config_init(int apply, uint32_t id)
{
	char path[PATH_MAX] = { };
	char link[PATH_MAX] = { };
	struct stat s;
	glob_t gl;

	uuid_active = 0;

	snprintf(path, PATH_MAX, "%s/ucentral.cfg.*", USYNC_CONFIG);
	if (glob(path, 0, NULL, &gl))
                return;
	if (!gl.gl_pathc)
		goto out;

	uuid_latest = config_load(gl.gl_pathv[gl.gl_pathc - 1]);

	if (apply)
		config_apply(id);

	snprintf(path, PATH_MAX, "%s/ucentral.active", USYNC_CONFIG);
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
	ULOG_INFO("config_init latest:%ld active:%ld\n", uuid_latest, uuid_active);
}

int
config_verify(struct blob_attr *attr, uint32_t id)
{
	static struct blob_attr *tb[__CONFIG_MAX];
	FILE *fp = NULL;
	char *cfg;
	int ret = -1;

	ULOG_DBG("starting verification\n");

	blobmsg_parse(config_policy, __CONFIG_MAX, tb, blobmsg_data(attr), blobmsg_data_len(attr));
	if (!tb[CONFIG_UUID]) {
		log_send("received config with no uuid");
		ULOG_ERR("received config with no uuid\n");
		return -1;
	}
	cfg = blobmsg_format_json(attr, true);
	if (!cfg) {
		log_send("failed to format config");
		ULOG_ERR("failed to format config\n");
		goto err;
	}
	fp = fopen(USYNC_TMP, "w+");
	if (!fp) {
		log_send("failed to store config");
		ULOG_ERR("failed to open %s\n", USYNC_TMP);
		goto err;
	}
	if (fwrite(cfg, strlen(cfg), 1, fp) != 1) {
		log_send("failed to store config");
		ULOG_ERR("failed to write %s\n", USYNC_TMP);
		goto err;
	}
	fclose(fp);
	fp = NULL;

	uuid_latest = (time_t)blobmsg_get_u32(tb[CONFIG_UUID]);
	ret = 0;

err:
	if (cfg)
		free(cfg);
	if (fp)
		fclose(fp);

	if (!ret &&
	    (!uuid_active || uuid_active != uuid_latest))
		verify_run(id);

	return 0;
}

void
config_deinit(void)
{
	blob_buf_free(&cfg);
}
