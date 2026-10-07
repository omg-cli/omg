#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/vhost.h>
#include <linux/vm_sockets.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int main(void) {
    if (geteuid() == 0) return 2;
    int device = open("/dev/vhost-vsock", O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int device_error = device < 0 ? errno : 0;
    int owner = -1, features = -1, closed = -1;
    uint64_t feature_mask = 0;
    struct stat identity = {0};
    if (device >= 0) {
        if (fstat(device, &identity) != 0) device_error = errno;
        else if (!S_ISCHR(identity.st_mode)) device_error = ENODEV;
        else {
            owner = ioctl(device, VHOST_SET_OWNER, 0);
            if (owner != 0) device_error = errno;
            else {
                features = ioctl(device, VHOST_GET_FEATURES, &feature_mask);
                if (features != 0) device_error = errno;
            }
        }
        closed = close(device);
        if (closed != 0) device_error = errno;
        else if (fcntl(device, F_GETFD) != -1 || errno != EBADF) return 3;
    }
    int stream = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int socket_error = stream < 0 ? errno : 0;
    int bound = -1, listened = -1;
    struct sockaddr_vm address = {.svm_family = AF_VSOCK,
        .svm_cid = VMADDR_CID_HOST, .svm_port = VMADDR_PORT_ANY};
    if (stream >= 0) {
        bound = bind(stream, (struct sockaddr *)&address, sizeof(address));
        if (bound != 0) socket_error = errno;
        else {
            listened = listen(stream, 1);
            if (listened != 0) socket_error = errno;
        }
        if (close(stream) != 0) socket_error = errno;
    }
    printf("{\"effective_uid\":%u,\"effective_gid\":%u,"
           "\"device_open\":%s,\"device_owner_result\":%d,"
           "\"device_is_character\":%s,\"device_major\":%u,\"device_minor\":%u,"
           "\"device_uid\":%u,\"device_gid\":%u,\"device_mode\":%u,"
           "\"features_result\":%d,\"features\":%llu,"
           "\"device_close_result\":%d,\"device_errno\":%d,"
           "\"socket_created\":%s,\"host_bind_result\":%d,"
           "\"listen_result\":%d,\"socket_errno\":%d,"
           "\"guest_cid_assigned\":false,\"guest_transport_proven\":false}\n",
           (unsigned)geteuid(), (unsigned)getegid(), device >= 0 ? "true" : "false",
           owner, S_ISCHR(identity.st_mode) ? "true" : "false",
           (unsigned)major(identity.st_rdev), (unsigned)minor(identity.st_rdev),
           (unsigned)identity.st_uid, (unsigned)identity.st_gid, (unsigned)(identity.st_mode & 0777),
           features, (unsigned long long)feature_mask, closed, device_error,
           stream >= 0 ? "true" : "false", bound, listened, socket_error);
    return 0;
}
