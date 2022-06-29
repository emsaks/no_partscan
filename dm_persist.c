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
 * persist: maps a persist range of a device.
 */
struct persist_c {
	struct dm_dev *dev;
	char * match_path;
	int match_len;
	sector_t start;
};

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
	struct dm_dev * dev;

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

	ret = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	devpath = kobject_get_path(&disk_to_dev(lc->dev->bdev->bd_disk)->kobj, GFP_KERNEL);

	lc->match_len = strlen(argv[1]);
	if (memcmp(devpath, argv[1], lc->match_len)) {
		pr_warn("persist: Device is not on path: %s != %s\n", devpath, argv[1]);
		ti->error = "Device is not on provided path";
		kfree(devpath);
		dm_put_device(ti, dev);
		goto bad;
	}
	kfree(devpath);

	lc->dev = dev;
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_secure_erase_bios = 1;
	ti->num_write_zeroes_bios = 1;
	ti->private = lc;
	return 0;

      bad:
	kfree(lc);
	return ret;
}

static void persist_dtr(struct dm_target *ti)
{
	struct persist_c *lc = (struct persist_c *) ti->private;

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
	//if (lc->dev->bdev->bd_disk->state == (1<<MD_DISK_REMOVED)) {
		// wait on update with new disk, using timeout;
		// if we timeout, suspend <until flagged is toggled>
		// check toggle value: return old disk, can we just put the old disk and quit somehow?
	//}
	//pr_warn("dev flags: %i, state: %lu\n", lc->dev->bdev->bd_disk->flags, lc->dev->bdev->bd_disk->state);
	if (!lc) pr_warn ("no lc\n");
	if (!lc->dev) pr_warn("no dev\n");
	return lc->dev;

}
static int persist_map(struct dm_target *ti, struct bio *bio)
{
	struct persist_c *lc = ti->private;

	bio_set_dev(bio, get_dev(lc)->bdev);
	bio->bi_iter.bi_sector = persist_map_sector(ti, bio->bi_iter.bi_sector);

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
	.name   = "persist2",
	.version = {1, 4, 0},
	.features = DM_TARGET_PASSES_INTEGRITY | DM_TARGET_NOWAIT |
		    DM_TARGET_ZONED_HM | DM_TARGET_PASSES_CRYPTO,
	.module = THIS_MODULE,
	.ctr    = persist_ctr,
	.dtr    = persist_dtr,
	.map    = persist_map,
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