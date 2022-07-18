#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
//#include "dm.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/dax.h>
#include <linux/slab.h>
#include <linux/device-mapper.h>
#include <linux/raid/md_p.h>
#include <linux/version.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <uapi/linux/kdev_t.h>

#define PERSIST_VER "1"
static char * holder = "dm_persist"PERSIST_VER" held disk.";

#ifndef bdev_kobj
	#define bdev_kobj(_bdev) (&(disk_to_dev((_bdev)->bd_disk)->kobj))
#endif

#define DM_MSG_PREFIX "persist"PERSIST_VER

/*
 * persist: maps a persistent range of a device.
 */

#define pw(fmt, ...) pr_warn("[%s] "fmt, pc->name, ## __VA_ARGS__)

struct persist_opts {
	char * script_on_added;
	int disk_flags;
	uint32_t io_timeout_jiffies;
	uint32_t new_disk_addtl_jiffies;
};
struct persist_c {
	struct list_head node;

	char name[DM_NAME_LEN+1];

	atomic_t 	next_dev;
	dev_t 		this_dev;
	struct completion disk_added;

	struct block_device * blkdev;
	sector_t start;
	sector_t capacity;

	char *	match_path;
	int 	match_len;
	int 	addtl_depth;

	atomic_t ios_in_flight;
	struct completion ios_finished;
	struct mutex io_lock;

	int timed_out;

	uint swapped_count;
	unsigned long jiffies_when_added;

	struct persist_opts opts;
};

DEFINE_MUTEX(instance_lock);
static LIST_HEAD(instance_list);
uint instances;

static char * normalize_path(char * path) // allow paths retrieved from sysfs
{
    if (!strncmp(path, "/sys/", 5)) return path + 4;
    if (path[0] == '.' && path[1] == '/') path += 1;
    if (path[0] == '.' && path[1] == '.' && path[2] == '/') path += 2;
    while (!strncmp(path, "/../", 4)) path += 3;

    return path;
}

/**
 * @brief test 'target' for 'pattern'
 * 
 * @param target will be modified
 * @param pattern 
 * @param pattern_len 
 * @return int negative on failure, additional '/' in target on success
 */
static int test_path(char * target, const char * pattern, int pattern_len)
{
	int i;
	int depth = 0;

	if (strlen(target) < pattern_len)
		return -1;
	if (target[pattern_len] && target[pattern_len] != '/')
		return -1;

	for (i = 0; i < pattern_len; ++i) {
		if (pattern[i] == '?') {
			if (target[i] == '/')
				return -1;
			target[i] = '?';
		}
	}

	if (memcmp(target, pattern, pattern_len))
		return -1;

	for (i = pattern_len; target[i] != '\0'; ++i)
		if (target[i] == '/') depth++;

	return depth;
}

#include "regs.h"

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10)
#define ARG ARG1
static char add_func[NAME_MAX] = "add_disk";
#else // after 4.7.10, add_disk is a macro pointing to device_add_disk, which has the disk as its 2nd argument
#define ARG ARG2
static char add_func[NAME_MAX] = "device_add_disk";
#endif

struct add_data {
	struct gendisk * disk;
	int old_flags;
	char * path;
};

static int add_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gendisk * disk = (void*)regs->ARG;
	struct add_data * d = (void*)ri->data;
	struct persist_c * pc;
	struct kobject * parent;

	d->disk = NULL;

	if (!disk) {
		pr_warn("Disk argument is NULL!\n");
		return 0;
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10)
    parent = &(disk->driverfs_dev->kobj);
#else // driverfs_dev removed and device passed directly to the function
    parent = &(((struct device *)(regs->ARG1))->kobj);
#endif

	if (!parent) {
		pr_warn("Disk [%s] has no parent device! Skipping\n", disk->disk_name);
		return 0;
	}
	d->path = kobject_get_path(parent, GFP_KERNEL);

	if (!d->path) {
		pr_warn("No path retrieved for disk [%s]! Skipping\n", disk->disk_name);
		return 0;
	}

	d->old_flags = disk->flags;

	mutex_lock(&instance_lock);
	list_for_each_entry(pc, &instance_list, node) {
		if (test_path(d->path, pc->match_path, pc->match_len) != pc->addtl_depth) {
			pw("Disk [%s] is not on path: %s != %s\n", disk->disk_name, d->path, pc->match_path);
			continue;
		}

		if (get_capacity(disk) != pc->capacity) {
			pw("New disk [%s] capacity doesn't match! Skipping.\n", disk->disk_name);
			continue;
		}

		disk->flags |= pc->opts.disk_flags;
		d->disk = disk;
	}
	mutex_unlock(&instance_lock);

	if (!d->disk) {
		kfree(d->path);
		d->path = NULL;
	} else {
		if (!(d->old_flags & GENHD_FL_NO_PART_SCAN) && (disk->flags & GENHD_FL_NO_PART_SCAN))
			pr_warn("Suppressed partscan on disk %s\n", disk->disk_name);
	}

	return 0;
}

static int add_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct persist_c * pc;
	struct add_data * d = (void*)ri->data;

	if (!d->disk) return 0;

	if (regs_return_value(regs))
		goto out;

	mutex_lock(&instance_lock);
	list_for_each_entry(pc, &instance_list, node) {
		if (test_path(d->path, pc->match_path, pc->match_len) != pc->addtl_depth)
			continue;

		pw("Flagging for new disk [%s]\n", d->disk->disk_name);
		atomic_set(&pc->next_dev, disk_devt(d->disk));
		complete(&pc->disk_added);
	}
	mutex_unlock(&instance_lock);

out:
	kfree(d->path);
	return 0;
}

static int del_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	dev_t del_dev;
	struct gendisk * disk = (struct gendisk *)regs->ARG1;
	struct persist_c * pc;

	if (IS_ERR_OR_NULL(disk)) { pr_warn("Deleted disk is NULL\n"); return 0; }

	del_dev = disk_devt(disk);

	mutex_lock(&instance_lock);
	list_for_each_entry(pc, &instance_list, node) {
		if (atomic_cmpxchg(&pc->next_dev, del_dev, 0) == del_dev) {
			pw("Clearing next_dev\n");
			goto nxt;
		}

		if (pc->this_dev == del_dev) {
			pw("Clearing this_dev\n");
			pc->this_dev = 0;
		}
		nxt:;
	}
	mutex_unlock(&instance_lock);
	return 0;
}

static int del_ret(struct kretprobe_instance *ri, struct pt_regs *regs) { return 0; }

static struct kretprobe del_probe;

static struct kretprobe add_probe;

static int plant_probes(void)
{
	int ret;

	memset(&del_probe, 0, sizeof(del_probe));
	del_probe.handler        = del_ret,
    del_probe.entry_handler  = del_entry,
    del_probe.maxactive      = 20,
	del_probe.kp.symbol_name = "del_gendisk";

	ret = register_kretprobe(&del_probe);
    if (ret < 0) {
        pr_warn("register_kretprobe for del_probe failed, returned %d\n", ret);
        return ret;
    }

	memset(&add_probe, 0, sizeof(add_probe));
	add_probe.handler        = add_ret,
    add_probe.entry_handler  = add_entry,
    add_probe.data_size      = sizeof(struct add_data),
    add_probe.maxactive      = 20,
	add_probe.kp.symbol_name = add_func;

	ret = register_kretprobe(&add_probe);
    if (ret < 0) {
        pr_warn("register_kretprobe for add_probe failed, returned %d\n", ret);
		unregister_kretprobe(&del_probe);
        return ret;
    }

	return 0;
}

static void rip_probes(void)
{
	unregister_kretprobe(&del_probe);
	unregister_kretprobe(&add_probe);
}

// call after setting  defaults
static int parse_opts(struct dm_target *ti, struct persist_c * pc, int argc, char ** argv)
{
	struct persist_opts * opts = &pc->opts;
	int tmp; 
	char dummy;
	int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "io_timeout")) {
			if (++i == argc) goto err;
			if (sscanf(argv[i], "%u%c", &tmp, &dummy) != 1) {
				ti->error = "Bad io timeout";
				return -ENOPARAM;
			}
			pw("Setting io timeout to %i seconds\n", tmp);
			opts->io_timeout_jiffies = tmp*HZ;
		} else if(!strcmp(argv[i], "disk_timeout")) {
			if (++i == argc) goto err;
			if (sscanf(argv[i], "%u%c", &tmp, &dummy) != 1) {
				ti->error = "Bad disk timeout";
				return -ENOPARAM;
			}
			pw("Setting disk to %i seconds\n", tmp);
			opts->new_disk_addtl_jiffies = tmp*HZ;
		} else if (!strcmp(argv[i], "script")) {
			if (++i == argc) goto err;
			if (*argv[i] != '/') {
				pw("Script parameter requires an absolute path; won't use %s\n", argv[i]);
				ti->error = "Script parameter requires an absolute path";
				return -ENOPARAM;
			}
			kfree(opts->script_on_added);
			opts->script_on_added = kstrdup(argv[i], GFP_KERNEL);
			if (!opts->script_on_added) {
				ti->error = "Failed to allocate memory for string";
				return -ENOMEM;
			}
			pw("Using script at %s on disk reset\n", argv[i]);
		} else if (!strcmp(argv[i], "partscan")) {
			if (++i == argc) goto err;
			if (*argv[i] == '0')
				opts->disk_flags |= GENHD_FL_NO_PART_SCAN;
			else
				opts->disk_flags &= ~GENHD_FL_NO_PART_SCAN;
		} else {
			pw("Unknown parameter %s\n", argv[i]);
			ti->error = "Unknown parameter";
			return -ENOPARAM;
		}
	}

	if (opts->new_disk_addtl_jiffies > opts->io_timeout_jiffies)
		opts->new_disk_addtl_jiffies -= opts->io_timeout_jiffies;
	else opts->new_disk_addtl_jiffies = 0;

	return 0;
err:
	ti->error = "Missing parameter value";
	return -ENOPARAM;
}

/*
 * Construct a persist mapping: <dev_path> <offset>
 */
static int persist_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct persist_c *pc;
	unsigned long long tmp;
	char dummy;
	int ret;
	char * devpath;
	char * match_path;
	struct mapped_device * md;

	if (argc < 3) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	pc = kmalloc(sizeof(*pc), GFP_KERNEL);
	if (pc == NULL) {
		ti->error = "Cannot allocate persist context";
		return -ENOMEM;
	}
	memset(pc, 0, sizeof(*pc));

	ret = -EINVAL;
	if (sscanf(argv[1], "%llu%c", &tmp, &dummy) != 1 || tmp != (sector_t)tmp) {
		ti->error = "Invalid device sector";
		goto bad_instance;
	}
	pc->start = tmp;

	pc->blkdev = blkdev_get_by_path(argv[0], dm_table_get_mode(ti->table), holder);
	if (IS_ERR(pc->blkdev)) {
		ret = PTR_ERR(pc->blkdev);
		ti->error = "Device lookup failed";
		goto bad_instance;
	}

	if (!disk_to_dev(pc->blkdev->bd_disk)->parent) {
		ret = -ENODEV;
		ti->error = "No parent device found";
		goto bad_disk;
	}

	devpath = kobject_get_path(&(disk_to_dev(pc->blkdev->bd_disk)->parent->kobj), GFP_KERNEL);

	match_path = normalize_path(argv[2]);
	pc->match_len = strlen(match_path);
	pc->addtl_depth = test_path(devpath, match_path, pc->match_len);
	if (pc->addtl_depth < 0) {
		pr_warn("Device is not on path: %s != %s\n", devpath, argv[1]);
		ti->error = "Device is not on provided path";
		ret = -EBADMSG;
		goto bad_path;
	}

	devpath[pc->match_len] = '\0';
	pc->match_path = devpath;

	md = dm_table_get_md(ti->table);
	dm_copy_name_and_uuid(md, pc->name, NULL);

	pc->jiffies_when_added = jiffies;
	pc->capacity = get_capacity(pc->blkdev->bd_disk);
	pc->this_dev = disk_devt(pc->blkdev->bd_disk);

	pc->opts.disk_flags = GENHD_FL_NO_PART_SCAN;
	pc->opts.io_timeout_jiffies = 30*HZ;
	pc->opts.new_disk_addtl_jiffies = 60*HZ;

	ret = parse_opts(ti, pc, argc - 3, &argv[3]);
	if (ret) goto bad_path;
	
	init_completion(&pc->ios_finished);
	init_completion(&pc->disk_added);
	mutex_init(&pc->io_lock);
	atomic_set(&pc->ios_in_flight, 0);

	INIT_LIST_HEAD(&pc->node);
	
	mutex_lock(&instance_lock);
	list_add(&pc->node, &instance_list);
	if (!instances) {
		ret = plant_probes();
		if (ret) {
			ti->error = "Failed to plant disk probes";
			goto bad_path;
		}
	}
	++instances;
	mutex_unlock(&instance_lock);

	pr_warn("Finished init\n");

	ti->private = pc;
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_secure_erase_bios = 1;
	ti->num_write_zeroes_bios = 1;

	return 0;

	  bad_path:
	kfree(devpath);
	  bad_disk:
	blkdev_put(pc->blkdev, dm_table_get_mode(ti->table));
      bad_instance:
	kfree(pc);
	return ret;
}

static void persist_dtr(struct dm_target *ti)
{
	struct persist_c *pc = (struct persist_c *) ti->private;

	mutex_lock(&instance_lock);
	list_del(&pc->node);
	if (!--instances)
		rip_probes();
	mutex_unlock(&instance_lock);

	if (!IS_ERR_OR_NULL(pc->blkdev)) blkdev_put(pc->blkdev, dm_table_get_mode(ti->table));
	kfree(pc->match_path);
	kfree(pc->opts.script_on_added);
	kfree(pc);
}

static sector_t persist_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct persist_c *pc = ti->private;

	return pc->start + dm_target_offset(ti, bi_sector);
}

int try_script(struct persist_c *pc) {
	int ret;
	char * envp[] = { "HOME=/", NULL };
	char * argv[] = { "/bin/bash", pc->opts.script_on_added, pc->name, pc->blkdev->bd_disk->disk_name, NULL };

	if (!pc->opts.script_on_added)
		return 0;

	pw("Calling user script %s\n", pc->opts.script_on_added);

	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (ret) 
		pw("Script failed with error code %i\n", ret);

	return ret;
}

static struct block_device * get_dev(struct dm_target *ti)
{
	struct persist_c *pc = ti->private;

	mutex_lock(&pc->io_lock); {
		if (pc->timed_out) {
			pw("Fast timeout\n");
			mutex_unlock(&pc->io_lock);
			return NULL;
		}
		if (!pc->this_dev) { // cleared by disk_del
			unsigned long uptime = jiffies - pc->jiffies_when_added;
			int io_jiffies = wait_for_completion_io_timeout(&pc->ios_finished, pc->opts.io_timeout_jiffies);

			if (!atomic_read(&pc->ios_in_flight)) {
				if (IS_ERR_OR_NULL(pc->blkdev)) { pw("Can't free NULL device!\n"); } else {
					blkdev_put(pc->blkdev, dm_table_get_mode(ti->table));
					pc->blkdev = NULL;
				}
			} else {
				pw("Forgetting %u ios_in_flight\n", atomic_read(&pc->ios_in_flight));
				atomic_set(&pc->ios_in_flight, 0);
			}

wait:		if (!wait_for_completion_timeout(&pc->disk_added, pc->opts.new_disk_addtl_jiffies + io_jiffies)) {
				pw("Disk wait timeout\n");
				pc->timed_out = 1;
				mutex_unlock(&pc->io_lock);
				return NULL;
			}

			do {
				pc->this_dev = atomic_read(&pc->next_dev);
			} while (atomic_cmpxchg(&pc->next_dev, pc->this_dev, 0) != pc->this_dev);

			pc->blkdev = blkdev_get_by_dev(pc->this_dev, dm_table_get_mode(ti->table), holder);
			pc->jiffies_when_added = jiffies;
			if (IS_ERR(pc->blkdev)) {
				pw("Failed to get new disk: %u with error %pe\n", pc->this_dev, pc->blkdev);
				io_jiffies = pc->opts.io_timeout_jiffies;
				goto wait;
			}

			// todo: do we need to check path again?

			if (get_capacity(pc->blkdev->bd_disk) != pc->capacity) {
				pw("New disk [%s] capacity doesn't match! Skipping.\n", pc->blkdev->bd_disk->disk_name);
				blkdev_put(pc->blkdev, dm_table_get_mode(ti->table));
				pc->blkdev = NULL;
				io_jiffies = pc->opts.io_timeout_jiffies;
				goto wait;
			}

			pc->swapped_count++;
			pw("Added new disk [%s] (#%i); Previous uptime: %lum%lus\n",
				pc->blkdev->bd_disk->disk_name,
				pc->swapped_count, 
				uptime / (HZ*60), (uptime % (HZ*60)) / HZ);

			try_script(pc);
		}
		atomic_inc(&pc->ios_in_flight);
	} mutex_unlock(&pc->io_lock);

	return pc->blkdev;
}

static int persist_map(struct dm_target *ti, struct bio *bio)
{
	struct block_device * dev = get_dev(ti);
	if (!dev) return DM_MAPIO_KILL;

	bio_set_dev(bio, dev);
	bio->bi_iter.bi_sector = persist_map_sector(ti, bio->bi_iter.bi_sector);

	return DM_MAPIO_REMAPPED;
}

static int persist_endio(struct dm_target *ti, struct bio *bio, blk_status_t *error)
{
	struct persist_c *pc = ti->private;

	if (atomic_dec_and_test(&pc->ios_in_flight))
		complete(&pc->ios_finished);

	return DM_ENDIO_DONE;
}

#ifndef DM_TARGET_PASSES_CRYPTO
	#define DM_TARGET_PASSES_CRYPTO 0
#endif
#ifndef DM_TARGET_NOWAIT
	#define DM_TARGET_NOWAIT 0
#endif

static struct target_type persist_target = {
	.name   = "persist"PERSIST_VER,
	.version = {1, 4, 0},
	.features = DM_TARGET_PASSES_INTEGRITY | DM_TARGET_NOWAIT |
		    DM_TARGET_ZONED_HM | DM_TARGET_PASSES_CRYPTO,
	.module = THIS_MODULE,
	.ctr    = persist_ctr,
	.dtr    = persist_dtr,
	.map    = persist_map,
	.end_io = persist_endio,
};

int __init dm_persist_init(void)
{
	int r = dm_register_target(&persist_target);
	if (r < 0)
		DMERR("register failed %d", r);

	return 0;
}

void dm_persist_exit(void)
{
	dm_unregister_target(&persist_target);
	pr_warn("unregistered target");
}

module_init(dm_persist_init)
module_exit(dm_persist_exit)
MODULE_LICENSE("GPL");