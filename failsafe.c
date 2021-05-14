/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

static void
failsafe_timeout_handler(struct uloop_timeout *t)
{
	ULOG_INFO("cheking for failsafe %ld %d\n", uuid_applied, apply_pending);
	if (uuid_applied > 1 || apply_pending > 1)
		return;

	ULOG_ERR("failed to get a config, load failsafe\n");
	if (system("/usr/share/ucentral/ucentral.uc /etc/ucentral/maverick.json"))
		ULOG_ERR("failed to load failsafe\n");
}

static struct uloop_timeout failsafe_timeout = {
	.cb = failsafe_timeout_handler,
};

void
failsafe_init(void)
{
	uloop_timeout_set(&failsafe_timeout, 150 * 1000);
}
