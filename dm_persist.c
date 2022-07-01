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

#define PERSIST_VER "6"
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
	struct block_device * other_block;
	struct completion disk_added;
	atomic_t next_dev;
	dev_t this_dev;
	struct dm_dev *dev;
	char * match_path;
	int match_len;
	sector_t start;
	struct completion ios_finished;
	atomic_t ios_in_flight;
	struct mutex io_lock;
	int timed_out;
	int io_timeout_jiffies;
	int new_disk_addtl_jiffies;
} * g;

atomic_t instances;

static char * normalize_path(char * path) // allow paths retrieved from sysfs
{
    if (!strncmp(path, "/sys/", 5)) return path + 4;
    if (path[0] == '.' && path[1] == '/') path += 1;
    if (path[0] == '.' && path[1] == '.' && path[2] == '/') path += 2;
    while (!strncmp(path, "/../", 4)) path += 3;

    return path;
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

	pr_warn("pre inc instances\n");
	if (atomic_inc_return(&instances) > 1) {
		pr_warn("pre dec instances\n");
		atomic_dec(&instances);
		ti->error = "Mulitple instances not supported";
		return -ENOTSUPP;
	}
	pr_warn("post inc instances\n");

	pr_warn("enter ctr\n");
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
	pr_warn("after alloc\n");
	memset(lc, 0, sizeof(*lc));

	pr_warn("pre scanf\n");
	ret = -EINVAL;
	if (sscanf(argv[2], "%llu%c", &tmp, &dummy) != 1 || tmp != (sector_t)tmp) {
		ti->error = "Invalid device sector";
		goto bad;
	}
	lc->start = tmp;
	

	pr_warn("pre get device\n");
	pr_warn("dm mode: %u\n", dm_table_get_mode(ti->table));
	ret = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &lc->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}
	pr_warn("post get device\n");
	devpath = kobject_get_path(bdev_kobj(lc->dev->bdev), GFP_KERNEL);

	pr_warn("after path\n");
	match_path = normalize_path(argv[1]);
	lc->match_len = strlen(match_path);

	pr_warn("after normalize\n");
	if (memcmp(devpath, match_path, lc->match_len)) {
		pr_warn("Device is not on path: %s != %s\n", devpath, argv[1]);
		ti->error = "Device is not on provided path";
		ret = -EBADMSG;
		goto bad2;
	}

	pr_warn("after cmp\n");
	devpath[lc->match_len] = '\0';
	lc->match_path = devpath;

	atomic_set(&lc->ios_in_flight, 0);
	lc->io_timeout_jiffies = 30*HZ;
	lc->new_disk_addtl_jiffies = 30*HZ;
	lc->this_dev = disk_devt(lc->dev->bdev->bd_disk);
	init_completion(&lc->ios_finished);
	init_completion(&lc->disk_added);
	g = lc;
	pr_warn("after init\n");

	ti->private = lc;
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_secure_erase_bios = 1;
	ti->num_write_zeroes_bios = 1;
	return 0;

	  bad2:
	kfree(devpath);
	dm_put_device(ti, lc->dev);
      bad:
	kfree(lc);
	atomic_dec(&instances);
	return ret;
}

static void persist_dtr(struct dm_target *ti)
{
	struct persist_c *lc = (struct persist_c *) ti->private;

	kfree(lc->match_path);
	dm_put_device(ti, lc->dev);
	atomic_dec(&instances);
	g = NULL;
	kfree(lc);
}

static sector_t persist_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct persist_c *lc = ti->private;

	return lc->start + dm_target_offset(ti, bi_sector);
}

static char * holder = "dm_persist"PERSIST_VER" held disk.";
static struct block_device * get_dev(struct dm_target *ti)
{
	int ret;
	struct block_device *new;
	struct block_device * old;
	struct persist_c *lc = ti->private;
	char devname[9];

	mutex_lock(&lc->io_lock); {
		pr_warn("entered lock\n");
		if (lc->timed_out) {
			pr_warn("fast timeout\n");
			mutex_unlock(&lc->io_lock);
			return NULL;
		}
		if (!lc->this_dev) { // cleared by disk_del
			int jiffies = wait_for_completion_io_timeout(&lc->ios_finished, lc->io_timeout_jiffies);
			pr_warn("after io wait\n");
wait:		if (!wait_for_completion_timeout(&lc->disk_added, lc->new_disk_addtl_jiffies + jiffies)) {
				pr_warn("disk timeout\n");
				lc->timed_out = 1;
				mutex_unlock(&lc->io_lock);
				return NULL;
			}
			pr_warn("after disk wait\n");
			do {
				lc->this_dev = atomic_read(&lc->next_dev);
			} while (atomic_cmpxchg(&lc->next_dev, lc->this_dev, 0) != lc->this_dev);

			new = blkdev_get_by_dev(lc->this_dev, dm_table_get_mode(ti->table), holder);

			if (!new) {
				pr_warn("Failed to get new disk: %u with error %i\n", lc->this_dev, ret);
				goto wait;
			}

			// todo: check size matches

			old = lc->other_block;
			lc->other_block = new;
			if (atomic_read(&lc->ios_in_flight)) {
				pr_warn("pre put\n");
				if (old) 
					blkdev_put(lc->dev->bdev, dm_table_get_mode(ti->table));
				else { 
					dm_put_device(ti, lc->dev);
				}
				pr_warn("post put\n");
			} else {
				atomic_set(&lc->ios_in_flight, 0); // if we timed out, just forget the device
				pr_warn("forget dev\n");
			}
		}
		atomic_inc(&lc->ios_in_flight);
	} mutex_unlock(&lc->io_lock);

	pr_warn("return dev\n");
	return lc->other_block ? lc->other_block : lc->dev->bdev;
}

static int persist_map(struct dm_target *ti, struct bio *bio)
{
	struct persist_c *lc = ti->private;

	struct block_device * dev = get_dev(ti);
	if (!dev) return DM_MAPIO_KILL;

	pr_warn("map %lu, of %u\n", bio_offset(bio), bio_sectors(bio));
	bio_set_dev(bio, dev);
	bio->bi_iter.bi_sector = persist_map_sector(ti, bio->bi_iter.bi_sector);

	atomic_inc(&lc->ios_in_flight);
	return DM_MAPIO_REMAPPED;
}

static void persist_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	struct persist_c *lc = (struct persist_c *) ti->private;
	size_t sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s %llu", lc->dev->name, (unsigned long long)lc->start);
		break;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
	case STATUSTYPE_IMA:
		DMEMIT_TARGET_NAME_VERSION(ti->type);
		DMEMIT(",device_name=%s,start=%llu;", lc->dev->name,
		       (unsigned long long)lc->start);
		break;
#endif
	}
}

static int persist_endio(struct dm_target *ti, struct bio *bio, blk_status_t *error)
{
	struct persist_c *lc = ti->private;

	pr_warn("endio\n");

	if (atomic_dec_and_test(&lc->ios_in_flight)) {
		pr_warn("calling io complete\n");
		complete(&lc->ios_finished);
		pr_warn("post calling io complete\n");
	}

	return DM_ENDIO_DONE;
}

static int persist_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct persist_c *lc = ti->private;
	if (lc->other_block) return 0; // todo: is this ok?
	return fn(ti, lc->dev, lc->start, ti->len, data);
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
	.iterate_devices = persist_iterate_devices,
};

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
	pr_warn("add dev %p\n", (void*)regs->ARG);
	
	*(struct gendisk **)ri->data = regs->ARG;
	return 0;
}

static int add_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gendisk * disk;
	char * devpath;

	if (regs_return_value(regs))
		return 0;

	disk = *(struct gendisk **)(ri->data);
	
	pr_warn("pre get path: %p\n", disk);
	if (!disk) { pr_warn("no disk\n"); return 0; }

	devpath = kobject_get_path(&disk_to_dev(disk)->kobj, GFP_KERNEL);
	pr_warn("after path\n");
	
	READ_ONCE(g);

	if (!devpath) { pr_warn("no devpath\n"); return 0; }
	if (!g) { pr_warn("no g\n"); return 0; }

	if (memcmp(devpath, g->match_path, g->match_len)) {
		pr_warn("device is not on path: %s != %s\n", devpath, g->match_path);
		goto out;
	}
	pr_warn("after cmp\n");

	// todo: check size matches!
	// to check proper number of trailing parts

	atomic_set(&g->next_dev, disk_devt(disk));
	pr_warn("calling disk complete");
	complete(&g->disk_added);
	pr_warn("post calling disk complete");
out:
	kfree(devpath);
	return 0;
}

static int del_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{	
	struct gendisk * disk = (struct gendisk *)regs->ARG1;
	
	if (!disk) { pr_warn("del no disk\n"); return 0; }

	dev_t del_dev = disk_devt(disk);
	READ_ONCE(g);
	if (!g) { pr_warn("del g empty\n"); return 0; }

	pr_warn("del dev %u", del_dev);
	if (atomic_cmpxchg(&g->next_dev, del_dev, 0) == del_dev) {
		pr_warn("clear next dev");
		return 0;
	}

	if (g->this_dev == del_dev) {
		pr_warn("clear this dev");
		g->this_dev = 0;
	}

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

int __init dm_persist_init(void)
{
	int r;

	del_probe.kp.symbol_name = "del_gendisk";
	add_probe.kp.symbol_name = add_func;

	r = register_kretprobe(&del_probe);
    if (r < 0) {
        pr_warn("register_kretprobe for del_probe failed, returned %d\n", r);
        return r;
    }
	pr_warn("registered del");

	r = register_kretprobe(&add_probe);
    if (r < 0) {
        pr_warn("register_kretprobe for add_probe failed, returned %d\n", r);
		unregister_kretprobe(&del_probe);
        return r;
    }
	pr_warn("registered add");
	
	r = dm_register_target(&persist_target);

	if (r < 0) {
		unregister_kretprobe(&del_probe);
		unregister_kretprobe(&add_probe);
		DMERR("register failed %d", r);
	}

	

	return 0;
}

void dm_persist_exit(void)
{
	unregister_kretprobe(&del_probe);
	pr_warn("unregistered del");
	unregister_kretprobe(&add_probe);
	pr_warn("unregistered add");
	dm_unregister_target(&persist_target);
	pr_warn("unregistered target");
}

module_init(dm_persist_init)
module_exit(dm_persist_exit)
MODULE_LICENSE("GPL");