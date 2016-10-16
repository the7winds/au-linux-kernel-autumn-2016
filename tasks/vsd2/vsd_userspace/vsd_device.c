#include "vsd_device.h"
#include "vsd_ioctl.h"

#include <sys/types.h>
#include <fcntl.h>

static const char* vsd_path = "/dev/vsd";
static int vsd_fd;

int vsd_init()
{
    if ((vsd_fd = open(vsd_path, O_RDWR)) == -1)
        return -1;
    return 0;
}

int vsd_deinit()
{
    return close(vsd_fd);
}

int vsd_get_size(size_t *out_size)
{
    vsd_ioctl_get_size_arg_t arg;
    if (ioctl(vsd_fd, VSD_IOCTL_GET_SIZE, &arg))
        return -1;

    *out_size = arg.size;

    return 0;
}

int vsd_set_size(size_t size)
{
    vsd_ioctl_set_size_arg_t arg = {
        .size = size
    };

    return ioctl(vsd_fd, VSD_IOCTL_SET_SIZE, &arg);
}

ssize_t vsd_read(char* dst, off_t offset, size_t size)
{
    off_t seeked = lseek(vsd_fd, offset, SEEK_SET);
    if (seeked != offset)
        return -1;

    return read(vsd_fd, dst, size);
}

ssize_t vsd_write(const char* src, off_t offset, size_t size)
{
    off_t seeked = lseek(vsd_fd, offset, SEEK_SET);
    if (seeked != offset)
        return -1;

    return write(vsd_fd, src, size);
}

void* vsd_mmap(size_t offset)
{
    size_t vsd_size;
    if (vsd_get_size(&vsd_size))
        return NULL;

    size_t length = vsd_size - offset;

    void *p = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, vsd_fd, offset);
    if (p == MAP_FAILED)
        return NULL;
    else
        return p;
}

int vsd_munmap(void* addr, size_t offset)
{
    size_t vsd_size;
    if (vsd_get_size(&vsd_size))
        return -1;

    size_t length = vsd_size - offset;
    return munmap(addr, length);
}
