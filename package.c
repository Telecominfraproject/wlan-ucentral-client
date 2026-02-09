/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "ucentral.h"

int cpm_name_escape(const char *name)
{
	if (name == NULL || strlen(name) == 0)
		return -1;

	for (size_t i = 0; name[i] != '\0'; i++) {
		if (!isalnum(name[i]) && name[i] != '_' && name[i] != '-' && name[i] != '.')
			return -1;
	}

	return 0;
}

static int run_cmd(char *const argv[], const char *stdout_file)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		if (stdout_file) {
			int fd = open(stdout_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fd < 0)
				_exit(127);
			dup2(fd, STDOUT_FILENO);
			close(fd);
		}
		execvp(argv[0], argv);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) < 0)
		return -1;

	return status;
}

int apk_download(const char *name, const char *url)
{
	char path[256];

	snprintf(path, sizeof(path), "/tmp/cpm/%s.apk", name);
	char *const argv[] = { "wget", "-O", path, (char *)url, NULL };

	return run_cmd(argv, NULL);
}

int apk_install(const char *name)
{
	char path[256];

	snprintf(path, sizeof(path), "/tmp/cpm/%s.apk", name);
	char *const argv[] = { "apk", "add", "--allow-untrusted", path, NULL };

	return run_cmd(argv, NULL);
}

int apk_delete(const char *name)
{
	char path[256];

	snprintf(path, sizeof(path), "/tmp/cpm/%s.apk", name);

	return unlink(path);
}

int apk_check(const char *name)
{
	char *const argv[] = { "apk", "info", "-e", (char *)name, NULL };

	return run_cmd(argv, NULL);
}

int apk_remove(const char *name)
{
	char *const argv[] = { "apk", "del", (char *)name, NULL };

	return run_cmd(argv, NULL);
}

int apk_search(const char *name)
{
	char *const argv[] = { "apk", "list", "-I", (char *)name, NULL };

	return run_cmd(argv, "/tmp/package.version");
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
	char *const argv[] = { "apk", "list", "-I", NULL };
	int ret = run_cmd(argv, "/tmp/packages.state");
	if (ret)
		return "Failed to dump installed packages.";

	ret = apk_search(pkgName);
	if (ret)
		return "No such package";

	return "Success";
}
