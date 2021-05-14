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
struct blob_buf rejected;

time_t uuid_applied = 0;
time_t uuid_latest = 0;
time_t uuid_active = 0;

void
config_rejected(struct blob_attr *b)
{
	struct blob_attr *a;
	size_t rem;

	blob_buf_init(&rejected, 0);
	blobmsg_for_each_attr(a, b, rem)
		blobmsg_add_blob(&rejected, a);
}

static time_t
config_load(const char *path)
{
	blob_buf_init(&rejected, 0);
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

	snprintf(path, PATH_MAX, "%s/ucentral.cfg.*", UCENTRAL_CONFIG);
	if (glob(path, 0, NULL, &gl))
		return;

	if (!gl.gl_pathc)
		goto out;

	uuid_latest = config_load(gl.gl_pathv[gl.gl_pathc - 1]);

	if (apply)
		config_apply(id);

	snprintf(path, PATH_MAX, "%s/ucentral.active", UCENTRAL_CONFIG);
	if (readlink(path, link, PATH_MAX) < 0) {
		ULOG_INFO("no active symlink found\n");
		goto out;
	}

	snprintf(path, PATH_MAX, "%s/%s", UCENTRAL_CONFIG, basename(link));
	if (stat(path, &s)) {
		ULOG_INFO("active config not found\n");
		goto out;
	}

	uuid_active = config_load(path);

out:
	globfree(&gl);
	ULOG_INFO("config_init latest:%ld active:%ld\n", uuid_latest, uuid_active);
}

void
config_deinit(void)
{
	blob_buf_free(&cfg);
}
