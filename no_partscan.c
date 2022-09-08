#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/genhd.h>
#include <linux/slab.h>

#include "regs.h"

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

#define MAX_PATHS 20

static char blocklist[MAX_PATHS][PATH_MAX];
static int nr_blocklist = 0;
static char blocklist_once[MAX_PATHS][PATH_MAX];
static int nr_blocklist_once = 0;

static int index_of(const char * path, char list[][PATH_MAX], int * count, int exact)
{
    int i, len;

    if (exact) {
        for (i=0; i<*count; ++i)
            if (!strncmp(list[i], path, PATH_MAX)) return i;
    } else for (i=0; i<*count; ++i) {
        len = strlen(list[i]);
        if (list[i][len-1] == '/') --len;
        if (!strncmp(list[i], path, len) && (list[i][len] == path[len] || path[len] == '\0')) return i;
    }

    return -1;
}

// We use !exact when looking up a path to block - then we want to forget *any* matching path
static int forget_path(const char * path, char list[][PATH_MAX], int * count, int exact)
{
    int i;

    i = index_of(path, list, count, exact);
    if (i < 0) return -ENOENT;

    do {
        (*count)--;
        memcpy(list[i], list[i+1], (*count - i) * PATH_MAX);
        // if not exact, loop until no more matches
        i = exact ? -1 : index_of(path, list, count, exact);
    } while (i >= 0);

    return 0;
}

static int add_path(const char * path, char list[][PATH_MAX], int * count)
{
    if (index_of(path, list, count, 1) >= 0) return 0;
    if (*count == MAX_PATHS) return -ENOMEM;
    strncpy(list[(*count)++], path, PATH_MAX);
    return 0;
}

static char * normalize_path(char * path) // allow paths retrieved from sysfs
{
    char * bptr;
    int len;

    bptr = strstr(path, "/block");
    if (bptr)
        bptr[0] = '\0';
    else { // wildcard
        len = strlen(path);
        path[len++] = '/';
        path[len] = '\0';
    }
    if (!strncmp(path, "/sys/", 5)) return path + 4;
    if (path[0] == '.' && path[1] == '/') path += 1;
    if (path[0] == '.' && path[1] == '.' && path[2] == '/') path += 2;
    while (!strncmp(path, "/../", 4)) path += 3;

    return path;
}

char _path[PATH_MAX];
static int set_path(const char * val, const struct kernel_param *kp)
{
    char * path;

    strcpy(_path, val);
    path = normalize_path(_path);

    if (kp->arg == NULL) {
        return forget_path(path, blocklist_once, &nr_blocklist_once, 1) & forget_path(path, blocklist, &nr_blocklist, 1);
    } else if (kp->arg == blocklist_once) {
        return add_path(val, blocklist_once, &nr_blocklist_once);
    } else if (kp->arg == blocklist) {
        return add_path(path, blocklist, &nr_blocklist);
    }

    return -EBADMSG;
}

struct kernel_param_ops path_ops = { 0, set_path, NULL, NULL};

module_param_cb(block_path, &path_ops, &blocklist, 0220);
module_param_cb(block_path_once, &path_ops, &blocklist_once, 0220);
module_param_cb(forget_path, &path_ops, NULL, 0220);

static unsigned long timeout_jiffies = 0;
static int set_timeout(const char * val, const struct kernel_param *kp)
{
    unsigned long timeout_j;
    if (kstrtoul(val, 0, &timeout_j))
        return -EBADMSG;
    timeout_j *= HZ; 
    timeout_j += jiffies;
    if (timeout_j > timeout_jiffies) timeout_jiffies = timeout_j;
    return 0;
}

static int get_timeout(char *buffer, const struct kernel_param *kp)
{
    unsigned long jiffies_now = jiffies;
    unsigned long timeout_s = (jiffies_now < timeout_jiffies) ? 
      (timeout_jiffies - jiffies_now) / HZ 
    : 0;
    return scnprintf(buffer, PAGE_SIZE, "%lu", timeout_s);
}

struct kernel_param_ops timeout_ops = {0, set_timeout, get_timeout, NULL};
module_param_cb(block_timeout_s, &timeout_ops, NULL, 0664);

struct instance_data {
    struct gendisk *disk;
};

// Will remove the path from blocklist_once
static int is_blocklisted(struct pt_regs *regs, struct gendisk * disk) // todo: allow removal from list (i.e. _once)
{
    char *devpath;
    struct kobject * parent;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10)
    parent = (struct kobject *)(disk->driverfs_dev);
#else // driverfs_dev removed and device passed directly to the function
    parent = (struct kobject *)(regs->ARG1);
#endif
    if (!parent) return 0;

    devpath = kobject_get_path(parent, GFP_KERNEL);
    if (!devpath) return 0;

    if (!forget_path(devpath, blocklist_once, &nr_blocklist_once, 0) || index_of(devpath, blocklist, &nr_blocklist, 0) >= 0) {
        kfree(devpath);
        return 1;
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

    if (!enabled
        || (!is_blocklisted(regs, disk) && !block_all && !block_once && (jiffies > timeout_jiffies))
        || (block_once = 0, disk->flags & GENHD_FL_NO_PART_SCAN)) {
        data->disk = NULL;
    } else {
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

#include <scsi/scsi_host.h>

/*
#include <linux/usb.h>
#include "/home/emsaks/WSL2-Linux-Kernel/drivers/usb/storage/usb.h"

static int set_cancel_sg(const char * val, const struct kernel_param *kp)
{
    unsigned long hostnum;
    struct Scsi_Host * host;
    struct us_data *us;
    if (kstrtoul(val, 0, &hostnum))
        return -EBADMSG;

    host = scsi_host_lookup(hostnum);
    if (IS_ERR_OR_NULL(host))
        return -ENODEV;
    
    us = host_to_us(host);
    // todo: ensure is usb!

    usb_sg_cancel(&us->current_sg);
    scsi_host_put(host);
    return 0;
}

struct kernel_param_ops cancel_sg_ops = {0, set_usb_stop, NULL, NULL};
module_param_cb(cancel_sg, &cancel_sg_ops, NULL, 0664);
*/

typedef unsigned long (*usb_stor_stop_transport_t)(void * us);
usb_stor_stop_transport_t usb_stor_stop_transport;

static int set_usb_stop(const char * val, const struct kernel_param *kp)
{
    unsigned long hostnum;
    struct Scsi_Host * host;

    if (kstrtoul(val, 0, &hostnum))
        return -EBADMSG;

    host = scsi_host_lookup(hostnum);
    if (IS_ERR_OR_NULL(host))
        return -ENODEV;
    
    // todo: ensure is usb?
    usb_stor_stop_transport(host->hostdata);
    scsi_host_put(host);
    return 0;
}

struct kernel_param_ops usb_stop_ops = {0, set_usb_stop, NULL, NULL};
module_param_cb(cancel_sg, &usb_stop_ops, NULL, 0664);



int init_usb()
{
    static struct kprobe kp = {
        .symbol_name = "usb_stor_stop_transport"
    };
    register_kprobe(&kp);
    usb_stor_stop_transport = (usb_stor_stop_transport_t) kp.addr;
    unregister_kprobe(&kp);
}

static int __init kretprobe_init(void)
{
    int ret;

    my_kretprobe.kp.symbol_name = func_name;
    ret = register_kretprobe(&my_kretprobe);
    if (ret < 0) {
        pr_warn("register_kretprobe failed, returned %d\n", ret);
        return ret;
    }

    init_usb();

    return 0;
}

static void __exit kretprobe_exit(void)
{
    unregister_kretprobe(&my_kretprobe);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");