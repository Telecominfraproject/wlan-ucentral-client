/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>

#include "ucentral.h"

int cpm_name_escape(const char *name) 
{
	if (name == NULL || strlen(name) == 0)
		return -1; // Invalid input

	for (size_t i = 0; name[i] != '\0'; i++) {
		if (!isalnum(name[i]) && name[i] != '_' && name[i] != '-' && name[i] != '.')
			return -1; // Invalid character detected
	}

	return 0;
}

int ipk_download(const char *name, const char *url)
{
	char command[512];
	snprintf(command, sizeof(command), "wget -O /tmp/cpm/%s.ipk %s", name, url);

	return system(command);
}

int ipk_install(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "opkg install -i /tmp/cpm/%s.ipk --force-reinstall", name);

	return system(command);
}

int ipk_delete(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "rm /tmp/cpm/%s.ipk", name);

	return system(command);
}

int opkg_check(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "opkg list-installed | grep ^%s", name);

	return system(command);
}

int opkg_remove(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "opkg remove %s", name);

	return system(command);
}

const char *cpm_install(const char *pkgName, const char *pkgURL)
{
	int ret = ipk_download(pkgName, pkgURL);
	ULOG_DBG("Function ipk_download returned with status %d", ret);
	if (ret) {
		if (ret == (8 << 8))
			return "Failed to download.";

		return "Unknown error.";
	}

	ret = ipk_install(pkgName);
	ULOG_DBG("Function ipk_install returned with status %d", ret);
	if (ret) {
		if (ret == (255 << 8))
			return "Failed to install package.";

		return "Unknown error.";
	}

	ipk_delete(pkgName);
	return "Success";
}

const char *cpm_remove(const char *pkgName)
{
	int ret = opkg_check(pkgName);
	ULOG_DBG("Function opkg_check returned with status %d", ret);
	if (ret) {
		if (ret == (1 << 8))
			return "No such package.";

		return "Unknown error.";
	}

	ret = opkg_remove(pkgName);
	ULOG_DBG("Function opkg_remove returned with status %d", ret);
	if (ret) {
		if (ret == (255 << 8))
			return "Failed to remove package, please check dependency before proceeding.";

		return "Unknown error.";
	}

	return "Success";
}

const char *cpm_list()
{
	int ret = system("opkg list-installed > /tmp/packages.state");
	if (ret) {
		return "Failed to dump opkg packages.";
	}

	ret = system("/usr/share/ucentral/package_list.uc");
	if (ret) {
		return "Failed to execute script /usr/share/ucentral/package.uc";
	}

	return "Success";
}
