#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/platform_device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>

#include "../vsd_device/vsd_hw.h"
#include "vsd_ioctl.h"

#define LOG_TAG "[VSD_CHAR_DEVICE] "

#define VSD_DEV_CMD_QUEUE_MAX_LEN 10

typedef struct vsd_dev {
    struct miscdevice mdev;
    struct tasklet_struct dma_op_complete_tsk;
    volatile vsd_hw_regs_t *hwregs;
    wait_queue_head_t wait_queue;
    struct task_struct* kthread;
    struct mutex poslock;
} vsd_dev_t;
static vsd_dev_t *vsd_dev;

#define CMD_DONE 0
#define CMD_AWAITED 1
#define CMD_NONBLOCK 2

struct cmd_desc {
    vsd_hw_regs_t hwregs;
    uint8_t status;
    void (*callback)(struct cmd_desc*);
};

static inline void cmd_desc_init(struct cmd_desc *desc,
    uint8_t cmd, void* dma_vaddr, uint64_t dma_size, uint64_t dev_offset,
    uint8_t status, void (*callback)(struct cmd_desc*))
{
    desc->hwregs.cmd = cmd;
    desc->hwregs.dma_paddr = virt_to_phys(dma_vaddr);
    desc->hwregs.dma_size = dma_size;
    desc->hwregs.dev_offset = dev_offset;
    desc->status = status;
    desc->callback = callback;
}

static inline int cmd_desc_is_done(struct cmd_desc *desc)
{
    rmb();
    return desc->status == CMD_DONE;
}

struct cmd_queue_struct {
    struct cmd_desc *cmd[VSD_DEV_CMD_QUEUE_MAX_LEN];
    int begin;
    int end;
    uint8_t size;
    spinlock_t lock;
    wait_queue_head_t wait_queue;
} *cmd_queue;

static int cmd_queue_is_empty(void)
{
    int ret;

    spin_lock_bh(&cmd_queue->lock);
    ret = !cmd_queue->size;
    spin_unlock_bh(&cmd_queue->lock);

    return ret;
}

static int cmd_queue_is_full(void)
{
    int ret;

    spin_lock_bh(&cmd_queue->lock);
    ret = cmd_queue->size == VSD_DEV_CMD_QUEUE_MAX_LEN;
    spin_unlock_bh(&cmd_queue->lock);

    return ret;
}

// 1 on success, 0 on failure
static int cmd_queue_try_push(struct cmd_desc *cmd)
{
    int ret;

    spin_lock_bh(&cmd_queue->lock);

    if (cmd_queue->size == VSD_DEV_CMD_QUEUE_MAX_LEN) {
        spin_unlock_bh(&cmd_queue->lock);
        ret = 0;
    } else {
        int i = cmd_queue->end++;
        cmd_queue->end %= VSD_DEV_CMD_QUEUE_MAX_LEN;
        cmd_queue->cmd[i] = cmd;
        ++cmd_queue->size;
        // unlocks here because must be barrier
        spin_unlock_bh(&cmd_queue->lock);

        wake_up(&cmd_queue->wait_queue);
        ret = 1;
    }

    return ret;
}

static struct cmd_desc* cmd_queue_pop(void)
{
    struct cmd_desc* ret = NULL;

    spin_lock_bh(&cmd_queue->lock);

    if (cmd_queue->size) {
        int i = cmd_queue->begin++;
        cmd_queue->begin %= VSD_DEV_CMD_QUEUE_MAX_LEN;
        ret = cmd_queue->cmd[i];
        --cmd_queue->size;
    }

    spin_unlock_bh(&cmd_queue->lock);

    return ret;
}

static struct cmd_desc* cmd_queue_top(void)
{
    struct cmd_desc* ret = NULL;

    spin_lock_bh(&cmd_queue->lock);

    if (cmd_queue->size) {
        int i = cmd_queue->begin;
        ret = cmd_queue->cmd[i];
    }

    spin_unlock_bh(&cmd_queue->lock);

    return ret;
}

static void vsd_dev_push_cmd(struct cmd_desc* cmd)
{
    vsd_dev->hwregs->dma_paddr = cmd->hwregs.dma_paddr;
    vsd_dev->hwregs->dma_size = cmd->hwregs.dma_size;
    vsd_dev->hwregs->dev_offset = cmd->hwregs.dev_offset;
    vsd_dev->hwregs->tasklet_vaddr = (uint64_t) &vsd_dev->dma_op_complete_tsk;
    wmb();
    vsd_dev->hwregs->cmd = cmd->hwregs.cmd;
    wmb();
}

static int vsd_dev_push_cmd_finish_cmd_condition(void)
{
    rmb();
    return vsd_dev->hwregs->cmd == VSD_CMD_NONE || kthread_should_stop();
}

static int cmd_queue_isnt_empty_condition(void)
{
    return !cmd_queue_is_empty() || kthread_should_stop();
}

static int vsd_dev_cmd_push_kthread_func(void *data)
{
    while (!kthread_should_stop()) {
        struct cmd_desc* cmd = cmd_queue_top();

        if (cmd) {
            vsd_dev_push_cmd(cmd);
            wait_event(vsd_dev->wait_queue,
                vsd_dev_push_cmd_finish_cmd_condition());
        } else {
            wait_event(cmd_queue->wait_queue,
                cmd_queue_isnt_empty_condition());
        }
    }
    pr_notice(LOG_TAG "cmd push thread exited\n");
    return 0;
}

#define LOCAL_DEBUG 0
static void print_vsd_dev_hw_regs(vsd_dev_t *vsd_dev)
{
    if (!LOCAL_DEBUG)
        return;

    pr_notice(LOG_TAG "VSD dev hwregs: \n"
            "CMD: %x \n"
            "RESULT: %x \n"
            "TASKLET_VADDR: %llx \n"
            "dma_paddr: %llx \n"
            "dma_size:  %llx \n"
            "dev_offset: %llx \n"
            "dev_size: %llx \n",
            vsd_dev->hwregs->cmd,
            vsd_dev->hwregs->result,
            vsd_dev->hwregs->tasklet_vaddr,
            vsd_dev->hwregs->dma_paddr,
            vsd_dev->hwregs->dma_size,
            vsd_dev->hwregs->dev_offset,
            vsd_dev->hwregs->dev_size
    );
}

static int vsd_dev_open(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev opened\n");
    return 0;
}

static int vsd_dev_release(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev closed\n");
    return 0;
}

static void vsd_dev_dma_op_complete_tsk_func(unsigned long unused)
{
    struct cmd_desc* cmd = cmd_queue_pop();
    if (cmd) {
        cmd->callback(cmd);
    }
    wake_up(&vsd_dev->wait_queue);
}

static void vsd_dev_block_callback(struct cmd_desc* cmd)
{
    rmb();
    cmd->hwregs.result = vsd_dev->hwregs->result;
    cmd->status = CMD_DONE;
    wmb();
}

static ssize_t vsd_dev_read(struct file *filp,
    char __user *read_user_buf, size_t read_size, loff_t *fpos)
{
    ssize_t ret;
    char *buf;
    struct cmd_desc* cmd;

    if (filp->f_flags & (O_NONBLOCK | FASYNC)) {
        ret = -EAGAIN;
        goto err;
    }

    buf = kzalloc(read_size, GFP_KERNEL);
    if (!buf) {
        ret = -EFAULT;
        goto err;
    }

    cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
    if (!cmd) {
        ret = -EFAULT;
        goto buf_free;
    }
    cmd_desc_init(cmd, VSD_CMD_READ, buf,
        read_size, *fpos, CMD_AWAITED, vsd_dev_block_callback);

    while (!cmd_queue_try_push(cmd)) {
        wait_event(vsd_dev->wait_queue, !cmd_queue_is_full());
    }

    wait_event(vsd_dev->wait_queue, cmd_desc_is_done(cmd));

    rmb();
    if ((ret = cmd->hwregs.result) >= 0) {
        if (copy_to_user(read_user_buf, buf, read_size)) {
            ret = -EFAULT;
            goto cmd_free;
        }
        *fpos += ret;
    }

cmd_free:
    kfree(cmd);
buf_free:
    kfree(buf);
err:
    return ret;
}

static void vsd_dev_nonblock_callback(struct cmd_desc* cmd)
{
    kfree(phys_to_virt(cmd->hwregs.dma_paddr));
    kfree(cmd);
}

static ssize_t vsd_dev_nonblock_write(struct file *filp,
    const char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    ssize_t ret;
    char *buf;
    struct cmd_desc *cmd;

    buf = kzalloc(write_size, GFP_ATOMIC);
    if (!buf) {
        ret = -EAGAIN;
        goto buf_alloc_error;
    }

    pagefault_disable();
    if ((ret = copy_from_user(buf, write_user_buf, write_size))) {
        pagefault_enable();
        ret = -EFAULT;
        goto copy_error;
    }
    pagefault_enable();

    cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
    if (!cmd) {
        ret = -EFAULT;
        goto cmd_alloc_error;
    }
    cmd_desc_init(cmd, VSD_CMD_WRITE, buf,
        write_size, *fpos, CMD_NONBLOCK, vsd_dev_nonblock_callback);

    if (cmd_queue_try_push(cmd)) {
        *fpos += write_size;
        ret = write_size;
    } else {
        ret = -EAGAIN;
        goto push_error;
    }

    // we don't free memory on success
    // it will do the callback

    return ret;

push_error:
    kfree(cmd);
cmd_alloc_error:
copy_error:
    kfree(buf);
buf_alloc_error:
    return ret;
}

static ssize_t vsd_dev_block_write(struct file *filp,
    const char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    int ret;
    char *buf;
    struct cmd_desc *cmd;

    if (vsd_dev->hwregs->dev_size < write_size) {
        ret = -EINVAL;
        goto err;
    }

    buf = kzalloc(write_size, GFP_KERNEL);
    if (!buf) {
        ret = -EFAULT;
        goto err;
    }

    if ((ret = copy_from_user(buf, write_user_buf, write_size))) {
        ret = -EFAULT;
        goto buf_free;
    }

    cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
    if (!cmd) {
        ret = -EFAULT;
        goto buf_free;
    }
    cmd_desc_init(cmd, VSD_CMD_WRITE, buf,
        write_size, *fpos, CMD_AWAITED, vsd_dev_block_callback);

    while (!cmd_queue_try_push(cmd)) {
        wait_event(vsd_dev->wait_queue, !cmd_queue_is_full());
    }

    wait_event(vsd_dev->wait_queue, cmd_desc_is_done(cmd));

    rmb();
    if ((ret = cmd->hwregs.result) >= 0) {
        *fpos += ret;
    }

    kfree(cmd);
buf_free:
    kfree(buf);
err:
    return ret;
}

static ssize_t vsd_dev_write(struct file *filp,
    const char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    if (filp->f_flags & (O_NONBLOCK | FASYNC)) {
        return vsd_dev_nonblock_write(filp, write_user_buf, write_size, fpos);
    } else {
        return vsd_dev_block_write(filp, write_user_buf, write_size, fpos);
    }
}

static loff_t vsd_dev_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t ret;
    loff_t newpos = 0;
    if ((ret = mutex_lock_killable(&vsd_dev->poslock))) {
        goto err;
    }

    switch(whence) {
        case SEEK_SET:
            newpos = off;
            break;
        case SEEK_CUR:
            newpos = filp->f_pos + off;
            break;
        case SEEK_END:
            newpos = vsd_dev->hwregs->dev_size - off;
            break;
        default: /* can't happen */
            ret = -EINVAL;
            goto err_unlock;
    }
    if (newpos < 0) {
        ret = -EINVAL;
        goto err_unlock;
    }
    if (newpos >= vsd_dev->hwregs->dev_size)
        newpos = vsd_dev->hwregs->dev_size;

    filp->f_pos = newpos;
    ret = newpos;
err_unlock:
    mutex_unlock(&vsd_dev->poslock);
err:
    return ret;
}

static long vsd_ioctl_get_size(vsd_ioctl_get_size_arg_t __user *uarg)
{
    vsd_ioctl_get_size_arg_t arg;

    rmb();
    arg.size = vsd_dev->hwregs->dev_size;

    if (copy_to_user(uarg, &arg, sizeof(arg))) {
        pagefault_enable();
        return -EFAULT;
    }

    return 0;
}

static long vsd_ioctl_set_size(vsd_ioctl_set_size_arg_t __user *uarg)
{
    int ret;
    vsd_ioctl_set_size_arg_t arg;
    struct cmd_desc* cmd;

    if (copy_from_user(&arg, uarg, sizeof(arg))) {
        ret = -EFAULT;
        goto err;
    }

    cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
    if (!cmd) {
        ret = -EFAULT;
        goto err;
    }

    cmd_desc_init(cmd, VSD_CMD_SET_SIZE, 0, 0, arg.size, CMD_AWAITED, vsd_dev_block_callback);

    while (!cmd_queue_try_push(cmd)) {
        wait_event(vsd_dev->wait_queue, !cmd_queue_is_full());
    }

    wait_event(vsd_dev->wait_queue, cmd_desc_is_done(cmd));

    rmb();
    ret = cmd->hwregs.result;

    kfree(cmd);
err:
    return ret;
}

static long vsd_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    long ret;
    if ((ret = mutex_lock_killable(&vsd_dev->poslock))) {
        goto err;
    }

    switch(cmd) {
        case VSD_IOCTL_GET_SIZE:
            ret = vsd_ioctl_get_size((vsd_ioctl_get_size_arg_t __user*)arg);
            break;
        case VSD_IOCTL_SET_SIZE:
            ret = vsd_ioctl_set_size((vsd_ioctl_set_size_arg_t __user*)arg);
            break;
        default:
            ret = -ENOTTY;
            goto err_unlock;
    }

err_unlock:
    mutex_unlock(&vsd_dev->poslock);
err:
    return ret;
}

static unsigned int vsd_dev_poll(struct file *filp, struct poll_table_struct *poll_table)
{
    unsigned int poll_evs = 0;

    poll_wait(filp, &vsd_dev->wait_queue, poll_table);
    if (!cmd_queue_is_full()) {
        poll_evs |= (POLLOUT | POLLWRNORM);
    }

    return poll_evs;
}

static struct file_operations vsd_dev_fops = {
    .owner = THIS_MODULE,
    .open = vsd_dev_open,
    .release = vsd_dev_release,
    .read = vsd_dev_read,
    .write = vsd_dev_write,
    .llseek = vsd_dev_llseek,
    .unlocked_ioctl = vsd_dev_ioctl,
    .poll = vsd_dev_poll
};

#undef LOG_TAG
#define LOG_TAG "[VSD_DRIVER] "

static int vsd_driver_probe(struct platform_device *pdev)
{
    int ret = 0;
    struct resource *vsd_control_regs_res = NULL;
    pr_notice(LOG_TAG "probing for device %s\n", pdev->name);

    cmd_queue = kzalloc(sizeof(*cmd_queue), GFP_KERNEL);
    if (!cmd_queue) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory for cmd_queue\n");
        goto error_alloc_cmd_queue;
    }
    spin_lock_init(&cmd_queue->lock);
    init_waitqueue_head(&cmd_queue->wait_queue);

    vsd_dev = (vsd_dev_t*)
        kzalloc(sizeof(*vsd_dev), GFP_KERNEL);
    if (!vsd_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory for vsd_dev\n");
        goto error_alloc;
    }
    mutex_init(&vsd_dev->poslock);
    init_waitqueue_head(&vsd_dev->wait_queue);
    tasklet_init(&vsd_dev->dma_op_complete_tsk,
            vsd_dev_dma_op_complete_tsk_func, 0);
    vsd_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    vsd_dev->mdev.name = "vsd";
    vsd_dev->mdev.fops = &vsd_dev_fops;
    vsd_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;

    if ((ret = misc_register(&vsd_dev->mdev)))
        goto error_misc_reg;

    vsd_control_regs_res = platform_get_resource_byname(
            pdev, IORESOURCE_REG, "control_regs");
    if (!vsd_control_regs_res) {
        ret = -ENOMEM;
        goto error_get_res;
    }
    vsd_dev->hwregs = (volatile vsd_hw_regs_t*)
        phys_to_virt(vsd_control_regs_res->start);

    print_vsd_dev_hw_regs(vsd_dev);

    vsd_dev->kthread = kthread_create(vsd_dev_cmd_push_kthread_func,
            NULL, "vsd_cmd_push_kthread");
    if (IS_ERR_OR_NULL(vsd_dev->kthread)) {
        goto error_thread;
    }

    wake_up_process(vsd_dev->kthread);

    pr_notice(LOG_TAG "VSD dev with MINOR %u"
        " has started successfully\n", vsd_dev->mdev.minor);
    return 0;

error_thread:
    vsd_control_regs_res = NULL;
error_get_res:
    misc_deregister(&vsd_dev->mdev);
error_misc_reg:
    kfree(vsd_dev);
    vsd_dev = NULL;
error_alloc:
    kfree(cmd_queue);
    cmd_queue = NULL;
error_alloc_cmd_queue:
    return ret;
}

static int vsd_driver_remove(struct platform_device *dev)
{
    // module can't be unloaded if its users has even single
    // opened fd
    pr_notice(LOG_TAG "removing device %s\n", dev->name);
    kthread_stop(vsd_dev->kthread);
    misc_deregister(&vsd_dev->mdev);
    kfree(cmd_queue);
    cmd_queue = NULL;
    kfree(vsd_dev);
    vsd_dev = NULL;
    return 0;
}

static struct platform_driver vsd_driver = {
    .probe = vsd_driver_probe,
    .remove = vsd_driver_remove,
    .driver = {
        .name = "au-vsd",
        .owner = THIS_MODULE,
    }
};

static int __init vsd_driver_init(void)
{
    return platform_driver_register(&vsd_driver);
}

static void __exit vsd_driver_exit(void)
{
    // This indirectly calls vsd_driver_remove
    platform_driver_unregister(&vsd_driver);
}

module_init(vsd_driver_init);
module_exit(vsd_driver_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU Virtual Storage Device driver module");
MODULE_AUTHOR("Kernel hacker!");
