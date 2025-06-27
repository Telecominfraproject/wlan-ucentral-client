/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>

#include "ucentral.h"

int escape_package_name(const char *name) {
	if (name == NULL || strlen(name) == 0) {
		return -1; // Invalid input
	}

	for (size_t i = 0; name[i] != '\0'; i++) {
		if (!isalnum(name[i]) && name[i] != '_' && name[i] != '-' && name[i] != '.') {
			return -1; // Invalid character detected
		}
	}

	return 0;
}

int download_ipk(const char *name, const char *url)
{
	char command[512];
	snprintf(command, sizeof(command), "wget -O /tmp/cpm/%s.ipk %s", name, url);

	return system(command);
}

int install_ipk(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "opkg install -i /tmp/cpm/%s.ipk --force-reinstall", name);

	return system(command);
}

int delete_ipk(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "rm /tmp/cpm/%s.ipk", name);

	return system(command);
}

int check_pkg(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "opkg list-installed | grep ^%s", name);

	return system(command);
}

int remove_pkg(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "opkg remove %s", name);

	return system(command);
}

const char *install_package(const char *pkgName, const char *pkgURL) {
	int ret = download_ipk(pkgName, pkgURL);
	ULOG_DBG("Function download_ipk returned with status %d", ret);
	if (ret) {
		if (ret == (8 << 8)) {
			return "Failed to download.";
		}
		return "Unknown error.";
	}

	ret = install_ipk(pkgName);
	ULOG_DBG("Function install_ipk returned with status %d", ret);
	if (ret) {
		if (ret == (255 << 8)) {
			return "Failed to install package.";
		}
		return "Unknown error.";
	}

	delete_ipk(pkgName);
	return "Success";
}

const char *remove_package(const char *pkgName) {
	int ret = check_pkg(pkgName);
	ULOG_DBG("Function check_pkg returned with status %d", ret);
	if (ret) {
		if (ret == (1 << 8)) {
			return "No such package.";
		}
		return "Unknown error.";
	}

	ret = remove_pkg(pkgName);
	ULOG_DBG("Function remove_pkg returned with status %d", ret);
	if (ret) {
		if (ret == (255 << 8)) {
			return "Failed to remove package, please check dependency before proceding.";
		}
		return "Unknown error.";
	}

	return "Success";
}