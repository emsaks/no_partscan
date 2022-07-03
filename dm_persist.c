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

/*
 * Copyright (C) 2001-2003 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#define DM_MSG_PREFIX "persist"PERSIST_VER

/*
 * persist: maps a persistent range of a device.
 */
struct persist_c {
	struct list_head node;

	atomic_t 	next_dev;
	dev_t 		this_dev;
	struct completion disk_added;

	struct block_device * blkdev;
	sector_t capacity;

	char *	match_path;
	int 	match_len;
	int 	addtl_depth;

	sector_t start;

	atomic_t ios_in_flight;
	struct completion ios_finished;
	struct mutex io_lock;

	int timed_out;
	uint32_t io_timeout_jiffies;
	uint32_t new_disk_addtl_jiffies;

	uint swapped_count;
	unsigned long jiffies_when_added;
};

DEFINE_MUTEX(instance_lock);
static LIST_HEAD(instance_list);
atomic_t instances;

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
	for (i = 0; i < pattern_len; ++i)
		if (pattern[i] == '?') target[i] = '?';
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

static int add_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	*(struct gendisk **)ri->data = (struct gendisk *)regs->ARG;
	return 0;
}

static int add_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gendisk * disk;
	char * devpath;
	struct persist_c * lc;

	if (regs_return_value(regs))
		return 0;

	disk = *(struct gendisk **)(ri->data);

	if (!disk) { pr_warn("No disk stashed!\n"); return 0; }
	devpath = kobject_get_path(&disk_to_dev(disk)->kobj, GFP_KERNEL);
	if (!devpath) { pr_warn("No path returned for kobj!\n"); return 0; }

	mutex_lock(&instance_lock);
	list_for_each_entry(lc, &instance_list, node) {
		if (test_path(devpath, lc->match_path, lc->match_len) != lc->addtl_depth) {
			pr_warn("Device is not on path: %s != %s\n", devpath, lc->match_path);
			goto out;
		}

		if (get_capacity(disk) != lc->capacity) {
			pr_warn("New disk capacity doesn't match! Skipping.\n");
			goto out;
		}

		pr_warn("Flagging for new disk %s\n", disk->disk_name);
		atomic_set(&lc->next_dev, disk_devt(disk));
		complete(&lc->disk_added);
	}
out:
	mutex_unlock(&instance_lock);
	kfree(devpath);
	return 0;
}

static int del_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	dev_t del_dev;
	struct gendisk * disk = (struct gendisk *)regs->ARG1;
	struct persist_c * lc;

	if (IS_ERR_OR_NULL(disk)) { pr_warn("Deleted disk is NULL\n"); return 0; }

	del_dev = disk_devt(disk);

	mutex_lock(&instance_lock);
	list_for_each_entry(lc, &instance_list, node) {
		if (atomic_cmpxchg(&lc->next_dev, del_dev, 0) == del_dev) {
			pr_warn("Clearing next_dev\n");
			goto nxt;
		}

		if (lc->this_dev == del_dev) {
			pr_warn("Clearing this_dev\n");
			lc->this_dev = 0;
		}
		nxt:
	}
	mutex_unlock(&instance_lock);
	return 0;
}

static int del_ret(struct kretprobe_instance *ri, struct pt_regs *regs) { return 0; }

static struct kretprobe del_probe = {
    .handler        = del_ret,
    .entry_handler  = del_entry,
    .maxactive      = 20,
};

static struct kretprobe add_probe = {
    .handler        = add_ret,
    .entry_handler  = add_entry,
    .data_size      = sizeof(struct gendisk *),
    .maxactive      = 20,
};

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
    add_probe.data_size      = sizeof(struct gendisk *),
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

/*
 * Construct a persist mapping: <dev_path> <offset>
 */
static int persist_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct persist_c *lc;
	unsigned long long tmp;
	char dummy;
	int ret;
	char * devpath;
	char * match_path;

	if (atomic_inc_return(&instances) == 1) {
		ret = plant_probes();
		if (ret) {
			ti->error = "Failed to plant disk probes";
			return ret;
		}
	}

	if (argc != 3) {
		ti->error = "Invalid argument count";
		atomic_dec(&instances);
		return -EINVAL;
	}

	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (lc == NULL) {
		ti->error = "Cannot allocate persist context";
		atomic_dec(&instances);
		return -ENOMEM;
	}
	memset(lc, 0, sizeof(*lc));

	ret = -EINVAL;
	if (sscanf(argv[2], "%llu%c", &tmp, &dummy) != 1 || tmp != (sector_t)tmp) {
		ti->error = "Invalid device sector";
		goto bad;
	}
	lc->start = tmp;

	lc->blkdev = blkdev_get_by_path(argv[0], dm_table_get_mode(ti->table), holder);
	if (IS_ERR(lc->blkdev)) {
		ret = PTR_ERR(lc->blkdev);
		ti->error = "Device lookup failed";
		goto bad;
	}

	devpath = kobject_get_path(bdev_kobj(lc->blkdev), GFP_KERNEL);

	match_path = normalize_path(argv[1]);
	lc->match_len = strlen(match_path);
	lc->addtl_depth = test_path(devpath, match_path, lc->match_len);
	if (lc->addtl_depth < 0) {
		pr_warn("Device is not on path: %s != %s\n", devpath, argv[1]);
		ti->error = "Device is not on provided path";
		ret = -EBADMSG;
		goto bad2;
	}

	devpath[lc->match_len] = '\0';
	lc->match_path = devpath;

	lc->jiffies_when_added = jiffies;
	lc->capacity = get_capacity(lc->blkdev->bd_disk);
	lc->io_timeout_jiffies = 30*HZ;
	lc->new_disk_addtl_jiffies = 30*HZ;
	lc->this_dev = disk_devt(lc->blkdev->bd_disk);
	
	init_completion(&lc->ios_finished);
	init_completion(&lc->disk_added);
	mutex_init(&lc->io_lock);
	atomic_set(&lc->ios_in_flight, 0);

	INIT_LIST_HEAD(&lc->node);
	mutex_lock(&instance_lock);
	list_add(&lc->node, &instance_list);
	mutex_unlock(&instance_lock);

	pr_warn("Finished init\n");

	ti->private = lc;
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_secure_erase_bios = 1;
	ti->num_write_zeroes_bios = 1;
	return 0;

	  bad2:
	kfree(devpath);
	blkdev_put(lc->blkdev, dm_table_get_mode(ti->table));
      bad:
	if (atomic_dec_and_test(&instances))
		rip_probes();
	kfree(lc);
	return ret;
}

static void persist_dtr(struct dm_target *ti)
{
	struct persist_c *lc = (struct persist_c *) ti->private;

	kfree(lc->match_path);
	if (!IS_ERR_OR_NULL(lc->blkdev)) blkdev_put(lc->blkdev, dm_table_get_mode(ti->table));

	mutex_lock(&instance_lock);
	list_del(&lc->node);
	mutex_unlock(&instance_lock);
	if (atomic_dec_and_test(&instances))
		rip_probes();
	kfree(lc);
}

static sector_t persist_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct persist_c *lc = ti->private;

	return lc->start + dm_target_offset(ti, bi_sector);
}

static struct block_device * get_dev(struct dm_target *ti)
{
	struct persist_c *lc = ti->private;

	mutex_lock(&lc->io_lock); {
		if (lc->timed_out) {
			pr_warn("Fast timeout\n");
			mutex_unlock(&lc->io_lock);
			return NULL;
		}
		if (!lc->this_dev) { // cleared by disk_del
			unsigned long uptime = jiffies - lc->jiffies_when_added;
			int io_jiffies = wait_for_completion_io_timeout(&lc->ios_finished, lc->io_timeout_jiffies);

			if (!atomic_read(&lc->ios_in_flight)) {
				if (IS_ERR_OR_NULL(lc->blkdev)) { pr_warn("Can't free NULL device!\n"); } else
				blkdev_put(lc->blkdev, dm_table_get_mode(ti->table));
			} else {
				pr_warn("Forgetting %u ios_in_flight\n", atomic_read(&lc->ios_in_flight));
				atomic_set(&lc->ios_in_flight, 0);
			}

wait:		if (!wait_for_completion_timeout(&lc->disk_added, lc->new_disk_addtl_jiffies + io_jiffies)) {
				pr_warn("Disk wait timeout\n");
				lc->timed_out = 1;
				mutex_unlock(&lc->io_lock);
				return NULL;
			}

			do {
				lc->this_dev = atomic_read(&lc->next_dev);
			} while (atomic_cmpxchg(&lc->next_dev, lc->this_dev, 0) != lc->this_dev);

			lc->blkdev = blkdev_get_by_dev(lc->this_dev, dm_table_get_mode(ti->table), holder);
			lc->jiffies_when_added = jiffies;
			if (IS_ERR(lc->blkdev)) {
				pr_warn("Failed to get new disk: %u with error %pe\n", lc->this_dev, lc->blkdev);
				goto wait;
			}

			if (get_capacity(lc->blkdev->bd_disk) != lc->capacity) {
				pr_warn("New disk capacity doesn't match! Skipping.\n");
				blkdev_put(lc->blkdev, dm_table_get_mode(ti->table));
				goto wait;
			}

			lc->swapped_count++;
			pr_warn("Added new disk %s (#%i); Previous uptime: %lum%lus\n",
				lc->blkdev->bd_disk->disk_name,
				lc->swapped_count, 
				uptime / (HZ*60), (uptime % (HZ*60)) / HZ);
		}
		atomic_inc(&lc->ios_in_flight);
	} mutex_unlock(&lc->io_lock);

	return lc->blkdev;
}

static int persist_map(struct dm_target *ti, struct bio *bio)
{
	//struct persist_c *lc = ti->private;

	struct block_device * dev = get_dev(ti);
	if (!dev) return DM_MAPIO_KILL;

	bio_set_dev(bio, dev);
	bio->bi_iter.bi_sector = persist_map_sector(ti, bio->bi_iter.bi_sector);

	return DM_MAPIO_REMAPPED;
}

static void persist_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	//struct persist_c *lc = (struct persist_c *) ti->private;
	size_t sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		//DMEMIT("%s %llu", lc->dev->name, (unsigned long long)lc->start);
		break;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
	case STATUSTYPE_IMA:
		DMEMIT_TARGET_NAME_VERSION(ti->type);
		//DMEMIT(",device_name=%s,start=%llu;", lc->dev->name,
		//       (unsigned long long)lc->start);
		break;
#endif
	}
}

static int persist_endio(struct dm_target *ti, struct bio *bio, blk_status_t *error)
{
	struct persist_c *lc = ti->private;

	if (atomic_dec_and_test(&lc->ios_in_flight))
		complete(&lc->ios_finished);

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
	.status = persist_status,
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