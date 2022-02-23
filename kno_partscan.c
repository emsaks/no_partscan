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
        || (!is_blocklisted(regs, disk) && !block_all && !block_once)
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