#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/genhd.h>

#ifdef CONFIG_X86_32
#define ARG1 ax
#define ARG2 bx
#elif defined CONFIG_X86_64
#define ARG1 di
#define ARG2 si
#elif defined CONFIG_ARM || CONFIG_ARM64
#define ARG1 regs[0]
#define ARG2 regs[1]
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10)
#define ARG ARG1
static char func_name[NAME_MAX] = "add_disk";
#else // after 4.7.10, add_disk is a macro pointing to device_add_disk, which has the disk as its 2nd argument
#define ARG ARG2
static char func_name[NAME_MAX] = "device_add_disk";
#endif

static bool enabled = 1;
module_param(enabled, bool, 0664);
static bool block_all = 0;
module_param(block_all, bool, 0664);
static bool block_once = 0;
module_param(block_once, bool, 0664);

static char * blocklist[20];
static int nr_blocklist;
module_param_array(blocklist, charp, &nr_blocklist, 0664);

struct instance_data {
    struct gendisk *disk;
};

static int is_blocklisted(struct pt_regs *regs, struct gendisk * disk)
{
    char *devpath;
    struct kobject * parent;
    int idx;
    int len;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10)
    parent = (struct kobject *)(disk->driverfs_dev);
#else
    parent = (struct kobject *)(regs->ARG1);
#endif

    if (!parent) return 0;

    devpath = kobject_get_path(parent, GFP_KERNEL);
    len = strlen(devpath);
    for (idx = 0; idx < nr_blocklist; ++idx) {
        if (!strncmp(devpath, blocklist[idx], len)) {
            // ignore trailing newlines
            if (blocklist[idx][len] != '\0' && blocklist[idx][len] != '\n') continue;
            kfree(devpath);
            return 1;
        }
    }
    kfree(devpath);
    return 0;
}

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct instance_data *data;
    struct gendisk *disk;

    data = (struct instance_data *)ri->data;
    disk = (struct gendisk *)(regs->ARG);

    if (!enabled || disk->flags & GENHD_FL_NO_PART_SCAN || !(block_all || block_once || is_blocklisted(regs, disk))) {
        data->disk = NULL;
    } else {
        block_once = 0;
        pr_warn("Intercepted partition read for disk: %s.\n", disk->disk_name);
        disk->flags |= (GENHD_FL_NO_PART_SCAN);
        data->disk = disk; // store this so we can remove the NO_PARTSCAN flag on function return
    }
    return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gendisk *disk;

    disk = ((struct instance_data *)ri->data)->disk;
    if (disk) disk->flags &= ~(GENHD_FL_NO_PART_SCAN);

    return 0;
}

static struct kretprobe my_kretprobe = {
    .handler        = ret_handler,
    .entry_handler  = entry_handler,
    .data_size      = sizeof(struct instance_data),
    .maxactive      = 20,
};

static int __init kretprobe_init(void)
{
    int ret;

    my_kretprobe.kp.symbol_name = func_name;
    ret = register_kretprobe(&my_kretprobe);
    if (ret < 0) {
        pr_warn("register_kretprobe failed, returned %d\n", ret);
        return ret;
    }
    return 0;
}

static void __exit kretprobe_exit(void)
{
    unregister_kretprobe(&my_kretprobe);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");