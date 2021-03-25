/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

static void
failsafe_timeout_handler(struct uloop_timeout *t)
{
	if (uuid_applied || apply_pending)
		return;

	ULOG_ERR("failed to get a config, load failsafe\n");
	if (!system("/usr/libexec/ucentral/ucentral_failsafe.sh"))
		config_init(1, 0);
}

static struct uloop_timeout failsafe_timeout = {
	.cb = failsafe_timeout_handler,
};

void
failsafe_init(void)
{
	uloop_timeout_set(&failsafe_timeout, 60 * 10 * 1000);
}
