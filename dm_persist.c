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

#define PERSIST_VER "2"
static char * holder = "dm_persist"PERSIST_VER" held disk.";

#ifndef bdev_kobj
	#define bdev_kobj(_bdev) (&(disk_to_dev((_bdev)->bd_disk)->kobj))
#endif

#define DM_MSG_PREFIX "persist"PERSIST_VER

/*
 * persist: maps a persistent range of a device.
 */

#define lc_w(fmt, ...) pr_warn("[%s] "fmt, lc->name, ## __VA_ARGS__)

struct persist_opts {
	char * script_on_added;
	int disk_flags;
	uint32_t io_timeout_jiffies;
	uint32_t new_disk_addtl_jiffies;
};
struct persist_c {
	struct list_head node;

	char * name;

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
	struct persist_c * lc;
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
		pr_warn("Disk %s has no parent device! Skipping\n", disk->disk_name);
		return 0;
	}
	d->path = kobject_get_path(parent, GFP_KERNEL);

	if (!d->path) {
		pr_warn("No path retrieved for disk %s! Skipping\n", disk->disk_name);
		return 0;
	}

	d->old_flags = disk->flags;

	mutex_lock(&instance_lock);
	list_for_each_entry(lc, &instance_list, node) {
		if (test_path(d->path, lc->match_path, lc->match_len) != lc->addtl_depth) {
			lc_w("Disk [%s] is not on path: %s != %s\n", disk->disk_name, d->path, lc->match_path);
			continue;
		}

		if (get_capacity(disk) != lc->capacity) {
			lc_w("New disk [%s] capacity doesn't match! Skipping.\n", disk->disk_name);
			continue;
		}

		disk->flags |= lc->opts.disk_flags;
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
	struct persist_c * lc;
	struct add_data * d = (void*)ri->data;

	if (!d->disk) return 0;

	if (regs_return_value(regs))
		goto out;

	mutex_lock(&instance_lock);
	list_for_each_entry(lc, &instance_list, node) {
		if (test_path(d->path, lc->match_path, lc->match_len) != lc->addtl_depth)
			continue;

		lc_w("Flagging for new disk [%s]\n", d->disk->disk_name);
		atomic_set(&lc->next_dev, disk_devt(d->disk));
		complete(&lc->disk_added);
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
	struct persist_c * lc;

	if (IS_ERR_OR_NULL(disk)) { pr_warn("Deleted disk is NULL\n"); return 0; }

	del_dev = disk_devt(disk);

	mutex_lock(&instance_lock);
	list_for_each_entry(lc, &instance_list, node) {
		if (atomic_cmpxchg(&lc->next_dev, del_dev, 0) == del_dev) {
			lc_w("Clearing next_dev\n");
			goto nxt;
		}

		if (lc->this_dev == del_dev) {
			lc_w("Clearing this_dev\n");
			lc->this_dev = 0;
		}
		nxt:;
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
    .data_size      = sizeof(struct add_data),
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

// call after setting  defaults
static int parse_opts(struct dm_target *ti, struct persist_c * lc, int argc, char ** argv)
{
	struct persist_opts * opts = &lc->opts;
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
			lc_w("Setting io timeout to %i seconds\n", tmp);
			opts->io_timeout_jiffies = tmp*HZ;
		} else if(!strcmp(argv[i], "disk_timeout")) {
			if (++i == argc) goto err;
			if (sscanf(argv[i], "%u%c", &tmp, &dummy) != 1) {
				ti->error = "Bad disk timeout";
				return -ENOPARAM;
			}
			lc_w("Setting disk to %i seconds\n", tmp);
			opts->new_disk_addtl_jiffies = tmp*HZ;
		} else if (!strcmp(argv[i], "script")) {
			if (++i == argc) goto err;
			if (*argv[i] != '/') {
				lc_w("Script parameter requires an absolute path; won't use %s\n", argv[i]);
				ti->error = "Script parameter requires an absolute path";
				return -ENOPARAM;
			}
			kfree(opts->script_on_added);
			opts->script_on_added = kstrdup(argv[i], GFP_KERNEL);
			if (!opts->script_on_added) {
				ti->error = "Failed to allocate memory for string";
				return -ENOMEM;
			}
			lc_w("Using script at %s on disk reset\n", argv[i]);
		} else if (!strcmp(argv[i], "partscan")) {
			if (++i == argc) goto err;
			if (*argv[i] == '0')
				opts->disk_flags |= GENHD_FL_NO_PART_SCAN;
			else
				opts->disk_flags &= ~GENHD_FL_NO_PART_SCAN;
		} else {
			lc_w("Unknown parameter %s\n", argv[i]);
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
	struct persist_c *lc;
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

	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (lc == NULL) {
		ti->error = "Cannot allocate persist context";
		return -ENOMEM;
	}
	memset(lc, 0, sizeof(*lc));

	ret = -EINVAL;
	if (sscanf(argv[1], "%llu%c", &tmp, &dummy) != 1 || tmp != (sector_t)tmp) {
		ti->error = "Invalid device sector";
		goto bad_instance;
	}
	lc->start = tmp;

	lc->blkdev = blkdev_get_by_path(argv[0], dm_table_get_mode(ti->table), holder);
	if (IS_ERR(lc->blkdev)) {
		ret = PTR_ERR(lc->blkdev);
		ti->error = "Device lookup failed";
		goto bad_instance;
	}

	if (!disk_to_dev(lc->blkdev->bd_disk)->parent) {
		ret = -ENODEV;
		ti->error = "No parent device found";
		goto bad_disk;
	}

	devpath = kobject_get_path(&(disk_to_dev(lc->blkdev->bd_disk)->parent->kobj), GFP_KERNEL);

	match_path = normalize_path(argv[2]);
	lc->match_len = strlen(match_path);
	lc->addtl_depth = test_path(devpath, match_path, lc->match_len);
	if (lc->addtl_depth < 0) {
		pr_warn("Device is not on path: %s != %s\n", devpath, argv[1]);
		ti->error = "Device is not on provided path";
		ret = -EBADMSG;
		goto bad_path;
	}

	devpath[lc->match_len] = '\0';
	lc->match_path = devpath;

	md = dm_table_get_md(ti->table);
	lc->name = kmalloc(DM_NAME_LEN+1, GFP_KERNEL);
	lc->name[0] = '\0';
	dm_copy_name_and_uuid(md, lc->name, NULL);

	lc->jiffies_when_added = jiffies;
	lc->capacity = get_capacity(lc->blkdev->bd_disk);
	lc->this_dev = disk_devt(lc->blkdev->bd_disk);

	lc->opts.disk_flags = GENHD_FL_NO_PART_SCAN;
	lc->opts.io_timeout_jiffies = 30*HZ;
	lc->opts.new_disk_addtl_jiffies = 60*HZ;

	if (!lc->name) lc->name = kcalloc(1, 1, GFP_KERNEL); // emptry string for no name
	ret = parse_opts(ti, lc, argc - 3, &argv[3]);
	if (ret) goto bad_path;
	
	init_completion(&lc->ios_finished);
	init_completion(&lc->disk_added);
	mutex_init(&lc->io_lock);
	atomic_set(&lc->ios_in_flight, 0);

	INIT_LIST_HEAD(&lc->node);
	
	mutex_lock(&instance_lock);
	list_add(&lc->node, &instance_list);
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

	ti->private = lc;
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_secure_erase_bios = 1;
	ti->num_write_zeroes_bios = 1;

	return 0;

	  bad_path:
	kfree(devpath);
	  bad_disk:
	blkdev_put(lc->blkdev, dm_table_get_mode(ti->table));
      bad_instance:
	kfree(lc);
	return ret;
}

static void persist_dtr(struct dm_target *ti)
{
	struct persist_c *lc = (struct persist_c *) ti->private;

	mutex_lock(&instance_lock);
	list_del(&lc->node);
	if (!--instances)
		rip_probes();
	mutex_unlock(&instance_lock);

	if (!IS_ERR_OR_NULL(lc->blkdev)) blkdev_put(lc->blkdev, dm_table_get_mode(ti->table));
	kfree(lc->match_path);
	kfree(lc->opts.script_on_added);
	kfree(lc->name);
	kfree(lc);
}

static sector_t persist_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct persist_c *lc = ti->private;

	return lc->start + dm_target_offset(ti, bi_sector);
}

int try_script(struct persist_c *lc) {
	int ret;
	char * envp[] = { "HOME=/", NULL };
	char * argv[] = { "/bin/bash", lc->opts.script_on_added, lc->blkdev->bd_disk->disk_name, NULL };

	if (!lc->opts.script_on_added)
		return 0;

	lc_w("Calling user script %s\n", lc->opts.script_on_added);

	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (ret) 
		lc_w("Script failed with error code %i\n", ret);

	return ret;
}

static struct block_device * get_dev(struct dm_target *ti)
{
	struct persist_c *lc = ti->private;

	mutex_lock(&lc->io_lock); {
		if (lc->timed_out) {
			lc_w("Fast timeout\n");
			mutex_unlock(&lc->io_lock);
			return NULL;
		}
		if (!lc->this_dev) { // cleared by disk_del
			unsigned long uptime = jiffies - lc->jiffies_when_added;
			int io_jiffies = wait_for_completion_io_timeout(&lc->ios_finished, lc->opts.io_timeout_jiffies);

			if (!atomic_read(&lc->ios_in_flight)) {
				if (IS_ERR_OR_NULL(lc->blkdev)) { lc_w("Can't free NULL device!\n"); } else
				blkdev_put(lc->blkdev, dm_table_get_mode(ti->table));
			} else {
				lc_w("Forgetting %u ios_in_flight\n", atomic_read(&lc->ios_in_flight));
				atomic_set(&lc->ios_in_flight, 0);
			}

wait:		if (!wait_for_completion_timeout(&lc->disk_added, lc->opts.new_disk_addtl_jiffies + io_jiffies)) {
				lc_w("Disk wait timeout\n");
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
				lc_w("Failed to get new disk: %u with error %pe\n", lc->this_dev, lc->blkdev);
				io_jiffies = lc->opts.io_timeout_jiffies;
				goto wait;
			}

			// todo: do we need to check path again?

			if (get_capacity(lc->blkdev->bd_disk) != lc->capacity) {
				lc_w("New disk [%s] capacity doesn't match! Skipping.\n", lc->blkdev->bd_disk->disk_name);
				blkdev_put(lc->blkdev, dm_table_get_mode(ti->table));
				io_jiffies = lc->opts.io_timeout_jiffies;
				goto wait;
			}

			lc->swapped_count++;
			lc_w("Added new disk [%s] (#%i); Previous uptime: %lum%lus\n",
				lc->blkdev->bd_disk->disk_name,
				lc->swapped_count, 
				uptime / (HZ*60), (uptime % (HZ*60)) / HZ);

			try_script(lc);
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