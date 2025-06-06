#include "ucentral.h"

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
    if (ret) {
        if (ret == 8) {
            return "Failed to download.";
        }
        return "Unknown error.";
    }

    ret = installIPK(pkgName);
    if (ret) {
        if (ret == 255) {
            return "Failed to install package.";
        }
    }

    deleteIPK(pkgName);
    return "Success";
}

const char *removePackage(const char *pkgName) {
    int ret = checkPKG(pkgName);
    if (ret) {
        if (ret == 1) {
            return "No such package";
        }
        return "Unknown error.";
    }

    ret = removePKG(pkgName);
    if (ret) {
        if (ret == 255) {
            return "Failed to remove package, please check dependency before proceding.";
        }
    }

    return "Success";
}