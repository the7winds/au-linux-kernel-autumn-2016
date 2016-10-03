#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "vsd_ioctl.h"
/*
 * TODO parse command line arguments and call proper
 * VSD_IOCTL_* using C function 'ioctl' (see man ioctl).
 */

const char* err_message = "wrong argument\nuse: 'size_get' or 'size_set [SIZE IN BYTES]'\n";
const char* get_size_key = "size_get";
const char* set_size_key = "size_set";

unsigned int parse_args(int argc, char** argv, int* size) {
    if (argc == 2) {
        if (strcmp(get_size_key, argv[1]) == 0) {
            return VSD_IOCTL_GET_SIZE;
        }
    } else if (argc == 3) {
        if (strcmp(set_size_key, argv[1]) == 0) {
            char* endptr;
            long r = strtol(argv[2], &endptr, 10);
            if (endptr == argv[2] + strlen(argv[2])) {
                *size = r;
                return VSD_IOCTL_SET_SIZE;
            }
        }
    }

    return _IOC_NONE;
}

int main(int argc, char **argv) {

    int size = 0;
    unsigned long type = parse_args(argc, argv, &size);

    if (type == VSD_IOCTL_GET_SIZE) {
        int fd = open("/dev/vsd", O_RDONLY);

        if (fd != -1) {
            vsd_ioctl_get_size_arg_t arg;
            int res = ioctl(fd, type, &arg);

            close(fd);

            if (res)
                goto fail_exit;

            printf("%lu\n", arg.size);
        } else
            goto fail_exit;
    } else if (type == VSD_IOCTL_SET_SIZE) {
        int fd = open("/dev/vsd", O_RDONLY);

        if (fd != -1) {
            vsd_ioctl_set_size_arg_t arg;
            arg.size = size;
            int res = ioctl(fd, type, &arg);

            close(fd);

            if (res)
                goto fail_exit;
        } else
            goto fail_exit;
    } else {
        printf("%s\n", err_message);
        goto fail_exit;
    }

    return EXIT_SUCCESS;

fail_exit:
    return EXIT_FAILURE;
}
