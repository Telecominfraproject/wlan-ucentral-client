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

int apk_download(const char *name, const char *url)
{
	char command[512];
	snprintf(command, sizeof(command), "wget -O /tmp/cpm/%s.apk %s", name, url);

	return system(command);
}

int apk_install(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "apk add --allow-untrusted /tmp/cpm/%s.apk", name);

	return system(command);
}

int apk_delete(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "rm /tmp/cpm/%s.apk", name);

	return system(command);
}

int apk_check(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "apk info -e %s", name);

	return system(command);
}

int apk_remove(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "apk del %s", name);

	return system(command);
}

int apk_search(const char *name)
{
	char command[512];
	snprintf(command, sizeof(command), "apk list -I %s > /tmp/package.version", name);

	return system(command);
}

const char *cpm_install(const char *pkgName, const char *pkgURL)
{
	int ret = apk_download(pkgName, pkgURL);
	ULOG_DBG("Function apk_download returned with status %d", ret);
	if (ret) {
		if (ret == (8 << 8))
			return "Failed to download.";

		return "Unknown error.";
	}

	ret = apk_install(pkgName);
	ULOG_DBG("Function apk_install returned with status %d", ret);
	if (ret) {
		if (ret == (255 << 8))
			return "Failed to install package.";

		return "Unknown error.";
	}

	apk_delete(pkgName);
	return "Success";
}

const char *cpm_remove(const char *pkgName)
{
	int ret = apk_check(pkgName);
	ULOG_DBG("Function apk_check returned with status %d", ret);
	if (ret) {
		if (ret == (1 << 8))
			return "No such package.";

		return "Unknown error.";
	}

	ret = apk_remove(pkgName);
	ULOG_DBG("Function apk_remove returned with status %d", ret);
	if (ret) {
		if (ret == (255 << 8))
			return "Failed to remove package, please check dependency before proceeding.";

		return "Unknown error.";
	}

	return "Success";
}

const char *cpm_list(const char *pkgName)
{
	int ret = system("apk list -I > /tmp/packages.state");
	if (ret) {
		return "Failed to dump installed packages.";
	}

	ret = apk_search(pkgName);
	if (ret) {
		return "No such package";
	}

	return "Success";
}
