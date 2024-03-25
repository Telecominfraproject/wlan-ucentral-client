/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

#define VERSION	"/etc/ucentral/version.json"

static struct blob_buf version;
enum {
	MAJOR,
	MINOR,
	PATCH,
	__VERSION_MAX,
};

static const struct blobmsg_policy version_policy[__VERSION_MAX] = {
	[MAJOR] = { .name = "major", .type = BLOBMSG_TYPE_INT32 },
	[MINOR] = { .name = "minor", .type = BLOBMSG_TYPE_INT32 },
	[PATCH] = { .name = "patch", .type = BLOBMSG_TYPE_INT32 },
};


void
version_init(struct blob_buf *b)
{
	struct blob_attr *tb[__VERSION_MAX] = {};
	struct stat s = {};

	if (stat(VERSION, &s))
		return;

	blob_buf_init(&version, 0);
	if (blobmsg_add_json_from_file(&version, VERSION)) {
		void *c = blobmsg_open_table(b, "version");

		blobmsg_parse(version_policy, __VERSION_MAX, tb, blob_data(version.head),
		      blob_len(version.head));
		
		if (tb[MAJOR])
			blobmsg_add_u32(b, "major", blobmsg_get_u32(tb[MAJOR]));
		if (tb[MINOR])
			blobmsg_add_u32(b, "minor", blobmsg_get_u32(tb[MINOR]));
		if (tb[PATCH])
			blobmsg_add_u32(b, "patch", blobmsg_get_u32(tb[PATCH]));
		blobmsg_close_table(b, c);
	}
	blob_buf_free(&version);
}
