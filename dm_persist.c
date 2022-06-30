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

/*
 * Copyright (C) 2001-2003 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#define DM_MSG_PREFIX "persist"

/*
 * persist: maps a persistent range of a device.
 */
struct persist_c {
	struct dm_dev *dev;
	char * match_path;
	int match_len;
	sector_t start;
	atomic_t ios_in_flight;
	struct kretprobe probe;
};

static char * normalize_path(char * path) // allow paths retrieved from sysfs
{
    if (!strncmp(path, "/sys/", 5)) return path + 4;
    if (path[0] == '.' && path[1] == '/') path += 1;
    if (path[0] == '.' && path[1] == '.' && path[2] == '/') path += 2;
    while (!strncmp(path, "/../", 4)) path += 3;

    return path;
}

#include "regs.h"

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10)
#define ARG ARG1
static char func_name[NAME_MAX] = "add_disk";
#else // after 4.7.10, add_disk is a macro pointing to device_add_disk, which has the disk as its 2nd argument
#define ARG ARG2
static char func_name[NAME_MAX] = "device_add_disk";
#endif

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int plant_probe(struct persist_c *lc)
{
	int ret;

	lc->probe.handler		= ret_handler;
	lc->probe.entry_handler	= entry_handler;
	lc->probe.data_size		= sizeof(struct persists_c *); // do we need to define a struct?
	lc->probe.maxactive		= 20;

    lc->probe.kp.symbol_name = func_name;
    ret = register_kretprobe(&lc->probe);
    if (ret < 0) {
        pr_warn("register_kretprobe failed, returned %d\n", ret);
        return ret;
    }

	return 0;
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

	if (argc != 3) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (lc == NULL) {
		ti->error = "Cannot allocate persist context";
		return -ENOMEM;
	}

	ret = -EINVAL;
	if (sscanf(argv[2], "%llu%c", &tmp, &dummy) != 1 || tmp != (sector_t)tmp) {
		ti->error = "Invalid device sector";
		goto bad;
	}
	lc->start = tmp;

	pr_warn("pre get device\n");
	ret = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &lc->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}
	pr_warn("post get device\n");
	devpath = kobject_get_path(&disk_to_dev(lc->dev->bdev->bd_disk)->kobj, GFP_KERNEL);

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

	pr_warn("pre plant\n");
	if (plant_probe(lc)) {
		pr_warn("plant fail\n");
		ti->error = "Failed to plant probe on add_device";
		ret = -EADDRNOTAVAIL;
		goto bad2;
	}

	pr_warn("post plant\n");
	atomic_set(&lc->ios_in_flight, 0);
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
	return ret;
}

static void persist_dtr(struct dm_target *ti)
{
	struct persist_c *lc = (struct persist_c *) ti->private;

	kfree(lc->match_path);
	unregister_kretprobe(&lc->probe);

	dm_put_device(ti, lc->dev);
	kfree(lc);
}

static sector_t persist_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct persist_c *lc = ti->private;

	return lc->start + dm_target_offset(ti, bi_sector);
}

static struct dm_dev * get_dev(struct persist_c *lc)
{
	atomic_inc(&lc->ios_in_flight);

	if (lc->dev && lc->dev->bdev->bd_disk->state == (1<<MD_DISK_REMOVED)) {
		if (!atomic_dec_and_test(&lc->ios_in_flight)) {
			
		} else {
			// wait 0 
		}
		// we want to make sure all ios acquiesce before releaseing
		// map() might be in the process of submitting a bio
		// so we need to increment *before* testing bad disk
		// if bad, dec_and_test OR wait

		wait_event( , !lc->ios_in_flight)
		// wait on 0 ios_in_flight;
		// take lock, release old disk <if not released>

		// wait on new disk
		// take lock, get new <if not gotten>

		
	}
	return lc->dev;

}
static int persist_map(struct dm_target *ti, struct bio *bio)
{
	struct persist_c *lc = ti->private;

	pr_warn("map %lu, of %u\n", bio_offset(bio), bio_sectors(bio));
	bio_set_dev(bio, get_dev(lc)->bdev);
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
		DMEMIT("%s %llu", get_dev(lc)->name, (unsigned long long)lc->start);
		break;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
	case STATUSTYPE_IMA:
		DMEMIT_TARGET_NAME_VERSION(ti->type);
		DMEMIT(",device_name=%s,start=%llu;", get_dev(lc)->name,
		       (unsigned long long)lc->start);
		break;
#endif
	}
}

static int persist_endio(struct dm_target *ti, struct bio *bio, blk_status_t *error)
{
	struct persist_c *lc = ti->private;

	pr_warn("endio\n");

	if (!atomic_dec_and_test(&lc->ios_in_flight)) {
		// todo: if bad disk, wake wait_acquiesce
	}

	return DM_ENDIO_DONE;
}

static int persist_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct persist_c *lc = ti->private;

	return fn(ti, get_dev(lc), lc->start, ti->len, data);
}
#ifndef DM_TARGET_PASSES_CRYPTO
	#define DM_TARGET_PASSES_CRYPTO 0
#endif
#ifndef DM_TARGET_NOWAIT
	#define DM_TARGET_NOWAIT 0
#endif

static struct target_type persist_target = {
	.name   = "persist",
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

int __init dm_persist_init(void)
{
	int r = dm_register_target(&persist_target);

	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

void dm_persist_exit(void)
{
	dm_unregister_target(&persist_target);
}

module_init(dm_persist_init)
module_exit(dm_persist_exit)
MODULE_LICENSE("GPL");