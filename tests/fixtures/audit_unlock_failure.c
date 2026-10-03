#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

/* Linux test fixture: fail only the armed, owned lock after real unlock. */
int flock(int descriptor, int operation) {
    typedef int (*flock_function)(int, int);
    flock_function native = (flock_function)dlsym(RTLD_NEXT, "flock");
    if (native == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int result = native(descriptor, operation);
    if (result != 0 || (operation & LOCK_UN) == 0) {
        return result;
    }
    const char *expected = getenv("OMG_AUDIT_UNLOCK_FILE");
    const char *marker = getenv("OMG_AUDIT_UNLOCK_MARKER");
    if (expected == NULL || marker == NULL || access(marker, F_OK) != 0) {
        return result;
    }
    char descriptor_path[64];
    char actual_path[4096];
    int length = snprintf(descriptor_path, sizeof(descriptor_path), "/proc/self/fd/%d", descriptor);
    if (length <= 0 || (size_t)length >= sizeof(descriptor_path)) {
        return result;
    }
    ssize_t bytes = readlink(descriptor_path, actual_path, sizeof(actual_path) - 1);
    if (bytes < 0 || (size_t)bytes >= sizeof(actual_path) - 1) {
        return result;
    }
    actual_path[bytes] = '\0';
    if (strcmp(actual_path, expected) != 0) {
        return result;
    }
    int receipt = open(marker, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    if (receipt >= 0) {
        ssize_t written = write(receipt, "1", 1);
        int closed = close(receipt);
        if (written != 1 || closed != 0) {
            errno = ENOSPC;
            return -1;
        }
    }
    errno = EIO;
    return -1;
}
