#include <curl/curl.h>

#include "ucentral.h"

int escapePackageName(const char *name) {
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

int validatePackageURL(const char *url) {
    return 0;
}

int downloadIPK(const char *name, const char *url)
{
    char command[512];
    snprintf(command, sizeof(command), "wget -O /tmp/cpm/%s.ipk %s", name, url);

    return system(command);
}

int installIPK(const char *name)
{
    char command[512];
    snprintf(command, sizeof(command), "opkg install -i /tmp/cpm/%s.ipk", name);

    return system(command);
}

int deleteIPK(const char *name)
{
    char command[512];
    snprintf(command, sizeof(command), "rm /tmp/cpm/%s.ipk", name);

    return system(command);
}

int checkPKG(const char *name)
{
    char command[512];
    snprintf(command, sizeof(command), "opkg list-installed | grep ^%s", name);

    return system(command);
}

int removePKG(const char *name)
{
    char command[512];
    snprintf(command, sizeof(command), "opkg remove %s", name);

    return system(command);
}

const char *installPackage(const char *pkgName, const char *pkgURL) {
    int ret = downloadIPK(pkgName, pkgURL);
    ULOG_DBG("Function downloadIPK returned with status %d", ret);
    if (ret) {
        if (ret == 8) {
            return "Failed to download.";
        }
        return "Unknown error.";
    }

    ret = installIPK(pkgName);
    ULOG_DBG("Function installIPK returned with status %d", ret);
    if (ret) {
        if (ret == 255) {
            return "Failed to install package.";
        }
        return "Unknown error."
    }

    deleteIPK(pkgName);
    return "Success.";
}

const char *removePackage(const char *pkgName) {
    int ret = checkPKG(pkgName);
    ULOG_DBG("Function checkPKG returned with status %d", ret);
    if (ret) {
        if (ret == 1) {
            return "No such package.";
        }
        return "Unknown error.";
    }

    ret = removePKG(pkgName);
    ULOG_DBG("Function removePKG returned with status %d", ret);
    if (ret) {
        if (ret == 255) {
            return "Failed to remove package, please check dependency before proceding.";
        }
        return "Unknown error.";
    }

    return "Success.";
}