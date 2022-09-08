#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/device-mapper.h>
#include <linux/raid/md_p.h>
#include <linux/version.h>

void dm_internal_suspend_fast(struct mapped_device *md);
void dm_internal_resume_fast(struct mapped_device *md);
void dm_internal_suspend_noflush(struct mapped_device *md);
void dm_internal_resume(struct mapped_device *md);

#define PERSIST_VER "1"
#define DM_MSG_PREFIX "persist"PERSIST_VER

static char * holder = "dm_persist"PERSIST_VER" held disk.";

/*
 * persist: maps a persistent range of a device.
 */

#define pw(fmt, ...) pr_warn("[%s] "fmt, pc->name, ## __VA_ARGS__)

struct persist_opts {
	char * script_on_added;
	int disk_flags;
	uint32_t new_disk_timeout_jiffies;
};

struct persist_c {
	struct dm_target *target;
	char name[DM_NAME_LEN+1];

	struct kretprobe add_probe, del_probe;

	struct block_device * blkdev;
	sector_t start, capacity;

	char *	path_pattern;
	int 	addtl_depth;

	uint swapped_count;
	unsigned long jiffies_when_removed, jiffies_when_added;

	struct persist_opts opts;
};

static char * normalize_path(char * path) // allow paths retrieved from sysfs
{
    if (!strncmp(path, "/sys/", 5)) return path + 4;
    if (path[0] == '.' && path[1] == '/') path += 1;
    if (path[0] == '.' && path[1] == '.' && path[2] == '/') path += 2;
    while (!strncmp(path, "/../", 4)) path += 3;

    return path;
}

static int test_path(struct kobject * kobj, const char * pattern, int rewind)
{
	const char * part, * pp, * kp;

	if (!kobj) return 1;
	while (rewind--) if (!(kobj = kobj->parent)) { return 1; }

	part = pattern + strlen(pattern); 
	do {
		part -= strlen(kobj->name) + 1;
		if (part < pattern || *part != '/')
			{ return 1; }

		for (kp = kobj->name, pp = part+1; *kp; ++kp, ++pp)
			if ((*kp != *pp) && (*pp != '?'))
				{ return 1; }
	} while ((kobj = kobj->parent));

	return part != pattern;
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
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define get_kretprobe(ri) (ri->rp)
#else
#define get_kretprobe(ri) (ri->rph->rp)
#endif

static int add_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gendisk * disk = (void*)regs->ARG;
	struct add_data * d = (void*)ri->data;
	struct persist_c * pc = container_of(get_kretprobe(ri), struct persist_c, add_probe);
	struct kobject * parent;

	d->disk = NULL;

	if (!disk) {
		pr_warn("Disk argument is NULL!\n");
		return 0;
	}

// we must use parent because the block/sd* parts may not yet have been set
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10)
    parent = &(disk->driverfs_dev->kobj);
#else // driverfs_dev removed and device passed directly to the function
    parent = &(((struct device *)(regs->ARG1))->kobj);
#endif

	if (!parent) {
		pw("Disk [%s] has no parent device! Skipping\n", disk->disk_name);
		return 0;
	}

	d->old_flags = disk->flags;

	if (test_path(parent, pc->path_pattern, pc->addtl_depth)) {
		pw("Disk [%s] is not on path: %s\n", disk->disk_name, pc->path_pattern);
	} else if (get_capacity(disk) != pc->capacity) {
		pw("New disk [%s] capacity doesn't match! Skipping.\n", disk->disk_name);
	} else {
		pw("Matched new disk [%s]\n", disk->disk_name);
		disk->flags |= pc->opts.disk_flags;
		d->disk = disk;

		if ((d->old_flags ^ disk->flags) & GENHD_FL_NO_PART_SCAN)
			pw("Suppressed partscan on disk %s\n", disk->disk_name);
	}

	return 0;
}

static int add_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct persist_c * pc = container_of(get_kretprobe(ri), struct persist_c, add_probe);
	struct add_data * d = (void*)ri->data;
	unsigned long downtime = jiffies - pc->jiffies_when_removed;
	struct block_device * bd;

	if (!d->disk) return 0;

	// todo: restore flags?

	if (regs_return_value(regs))
		return 0;

	if (pc->blkdev) {
		pw("New disk found before old one was deleted; Ignoring.\n");
		return 0;
	}

	if (pc->opts.new_disk_timeout_jiffies && (pc->jiffies_when_removed + pc->opts.new_disk_timeout_jiffies < jiffies)) {
		pw("Not loading new disk after timeout.\n");
		return 0;
	}

	pc->jiffies_when_added = jiffies;
	bd = blkdev_get_by_dev(disk_devt(d->disk), dm_table_get_mode(pc->target->table), holder);
	if (IS_ERR_OR_NULL(bd)) {
		pw("Failed to load new disk [%s]\n", d->disk->disk_name);
		return 0;
	}

	if (cmpxchg(&pc->blkdev, NULL, bd)) {
		pw("Lost race to replace block device with [%s]\n", d->disk->disk_name);
		blkdev_put(bd, dm_table_get_mode(pc->target->table));
		return 0;
	}

	try_script(pc);
	dm_internal_resume(dm_table_get_md(pc->target->table));

	pw("Loaded new disk #%i [%s]; Downtime %lum%lus\n",
				++pc->swapped_count,
				d->disk->disk_name,
				downtime / (HZ*60), (downtime % (HZ*60)) / HZ);

	return 0;
}

static int del_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gendisk * disk = (struct gendisk *)regs->ARG1;
	struct persist_c * pc = container_of(get_kretprobe(ri), struct persist_c, del_probe);
	unsigned long uptime = jiffies - pc->jiffies_when_added;
	struct block_device * bd;

	if (IS_ERR_OR_NULL(pc->blkdev) || IS_ERR_OR_NULL(disk) || disk_devt(pc->blkdev->bd_disk) != disk_devt(disk))
		return 0;

	pw("Removing disk [%s]; Uptime: %lum%lus\n",
				pc->blkdev->bd_disk->disk_name,
				uptime / (HZ*60), (uptime % (HZ*60)) / HZ);

	dm_internal_suspend_noflush(dm_table_get_md(pc->target->table));
	bd = pc->blkdev;
	pc->blkdev = NULL;
	blkdev_put(bd, dm_table_get_mode(pc->target->table));
	pc->jiffies_when_removed = jiffies;

	return 0;
}

static int del_ret(struct kretprobe_instance *ri, struct pt_regs *regs) { return 0; }

static int plant_probe(struct kretprobe * probe, kretprobe_handler_t entry, kretprobe_handler_t ret, char * symbol_name, size_t data_size)
{
	int e;

	memset(probe, 0, sizeof(*probe));
	probe->handler        = ret,
    probe->entry_handler  = entry,
    probe->maxactive      = 20,
	probe->data_size	  = data_size;
	probe->kp.symbol_name = symbol_name;

	e = register_kretprobe(probe);
    if (e < 0) {
        pr_warn("register_kretprobe for %s failed, returned %d\n", symbol_name, e);
        return e;
    }

	return 0;
}
static int plant_probes(struct kretprobe * add_probe, struct kretprobe * del_probe)
{
	if (plant_probe(del_probe, del_entry, del_ret, "del_gendisk", 0)) return -1;
	if (plant_probe(add_probe, add_entry, add_ret, add_func, sizeof(struct add_data))) {
		unregister_kretprobe(del_probe);
		return -1;
	}
	
	return 0;
}

static void rip_probes(struct kretprobe * add_probe, struct kretprobe * del_probe)
{
	unregister_kretprobe(add_probe);
	unregister_kretprobe(del_probe);
}

// call after setting  defaults
static int parse_opts(struct dm_target *ti, struct persist_c * pc, int argc, char ** argv)
{
	struct persist_opts * opts = &pc->opts;
	int tmp; 
	char dummy;
	int i;

	for (i = 0; i < argc; i++) {
		if(!strcmp(argv[i], "disk_timeout")) {
			if (++i == argc) goto err;
			if (sscanf(argv[i], "%u%c", &tmp, &dummy) != 1) {
				ti->error = "Bad disk timeout";
				return -ENOPARAM;
			}
			pw("Setting new disk timeout to %i seconds\n", tmp);
			opts->new_disk_timeout_jiffies = tmp*HZ;
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
		} else if (!strcmp(argv[i], "offset")) {
			unsigned long long tmp;
			char dummy;
			if (++i == argc) goto err;
			if (sscanf(argv[i], "%llu%c", &tmp, &dummy) != 1 || tmp != (sector_t)tmp) {
				ti->error = "Invalid device sector";
				return -EINVAL;
			}
			pc->start = tmp;
		} else {
			pw("Unknown parameter %s\n", argv[i]);
			ti->error = "Unknown parameter";
			return -ENOPARAM;
		}
	}

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
	int ret;
	char * devpath;
	char * pattern;
	char *kp, *pp, *kt;
	struct mapped_device * md;

	if (argc < 2) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	pc = kmalloc(sizeof(*pc), GFP_KERNEL);
	if (pc == NULL) {
		ti->error = "Cannot allocate persist context";
		return -ENOMEM;
	}
	memset(pc, 0, sizeof(*pc));
	pc->target = ti;

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
	pattern = normalize_path(argv[1]);

	for (kp = devpath, pp = pattern; *kp; ++kp, ++pp) {
		if (*kp != *pp) {
			if (*pp != '?' || *kp == '/') break;
			*kp = '?'; // '?' is a wildcard
		}
	}

	if (*pp || (*kp && *kp != '/')) { // this will exclude trailing '/' in pattern
		pr_warn("Device is not on path: [%.*s]%s != %s\n", (int)(kp - devpath), devpath, kp, pp);
		ti->error = "Device is not on provided path";
		ret = -EINVAL;
		goto bad_path;
	}

	kt = kp;
	while (*kp) if (*kp++ == '/') pc->addtl_depth++;
	*kt = '\0';

	pc->path_pattern = devpath;

	md = dm_table_get_md(ti->table);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	dm_copy_name_and_uuid(md, pc->name, NULL);
#else
	strcpy(pc->name, dm_device_name(md));
#endif

	pc->jiffies_when_added = jiffies;
	pc->capacity = get_capacity(pc->blkdev->bd_disk);

	pc->opts.disk_flags = GENHD_FL_NO_PART_SCAN;
	pc->opts.new_disk_timeout_jiffies = 90*HZ;

	ret = parse_opts(ti, pc, argc - 3, &argv[3]);
	if (ret) goto bad_path;

	ret = plant_probes(&pc->add_probe, &pc->del_probe);
	if (ret) {
		ti->error = "Failed to plant disk probes";
		goto bad_path;
	}

	pw("Finished constructor\n");

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

	rip_probes(&pc->add_probe, &pc->del_probe);

	if (!IS_ERR_OR_NULL(pc->blkdev)) blkdev_put(pc->blkdev, dm_table_get_mode(ti->table));
	kfree(pc->path_pattern);
	kfree(pc->opts.script_on_added);
	pw("Finishing destructor\n");
	kfree(pc);
}

static sector_t persist_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct persist_c *pc = ti->private;

	return pc->start + dm_target_offset(ti, bi_sector);
}

static int persist_map(struct dm_target *ti, struct bio *bio)
{
	struct persist_c *pc = ti->private;

	if (IS_ERR_OR_NULL(pc->blkdev))
		return DM_MAPIO_DELAY_REQUEUE;
	bio_set_dev(bio, pc->blkdev);
	bio->bi_iter.bi_sector = persist_map_sector(ti, bio->bi_iter.bi_sector);

	return DM_MAPIO_REMAPPED;
}

static int persist_message(struct dm_target *ti, unsigned argc, char **argv, char *result, unsigned maxlen)
{
	if (argc && !strcmp(argv[0], "resume")) {
		// dm_internal_resume(dm_table_get_md(ti->table));
	}
	return 0;
}

static struct target_type persist_target = {
	.name   = "persist"PERSIST_VER,
	.version = {1, 4, 0},
	.features = DM_TARGET_PASSES_INTEGRITY 
#ifdef DM_TARGET_NOWAIT
		| DM_TARGET_NOWAIT
#endif
#ifdef DM_TARGET_PASSES_CRYPTO
		| DM_TARGET_PASSES_CRYPTO
#endif
		| DM_TARGET_ZONED_HM,
	.module  = THIS_MODULE,
	.ctr     = persist_ctr,
	.dtr     = persist_dtr,
	.map     = persist_map,
	.message = persist_message,
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