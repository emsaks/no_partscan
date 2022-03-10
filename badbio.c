#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "regs.h"

static bool enabled = 1;
module_param(enabled, bool, 0664);

static bool show_success = 0;
module_param(show_success, bool, 0664);

static bool match_bios = 1;
module_param(match_bios, bool, 0664);

//static char * target_dev;
//module_param(target_dev, charp, 0664);

struct bio_info {
	struct bio * bio;
	unsigned int size;
};


// we use a ring buffer and might overwrite a few
#define MAX_BIOS 1000
struct bio_info bios[MAX_BIOS];
int bio_idx = 0;

struct bio_info * find_bio(struct bio * bio)
{
	int i;

	// we need check backwards from bio_idx to ensure that
	// the most recent reference is found, not a stale one
	for (i = bio_idx - 1; i > 0; --i)
		if (bios[i].bio == bio) return &bios[i];
	for (i = bio_idx; i < MAX_BIOS; ++i)
		if (bios[i].bio == bio) return &bios[i];

	return NULL;
}

static int entry_handler_submit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct bio *bio;
	if (bio_idx >= MAX_BIOS) bio_idx = 0;
	bio = (struct bio*)regs->ARG1;
	bios[bio_idx].bio = bio;
	bios[bio_idx].size = bio->bi_iter.bi_size;
	bio_idx++;
	return 0;
}

static int ret_handler_submit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int entry_handler_end(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct bio *bio;
	struct bio_info * ifo;
	int err;
	unsigned int size = 0;

	if (!enabled) return 0;
	bio = (struct bio*)regs->ARG1;
	err = blk_status_to_errno(bio->bi_status);
	if (match_bios) {
		if((ifo = find_bio(bio)))
			size = ifo->size;
	}
	if (err || show_success) {
		if (size) 
			pr_warn("%s> %s (%i); @%llu: -%u, +%u/%u bytes.\n", current->comm, bio->bi_bdev ? bio->bi_bdev->bd_disk->disk_name : "(null)", err, bio->bi_iter.bi_sector, bio->bi_iter.bi_size, bio->bi_iter.bi_bvec_done, size);
		else
			pr_warn("%s> %s (%i); @%llu: -%u, +%u bytes.\n", current->comm, bio->bi_bdev ? bio->bi_bdev->bd_disk->disk_name : "(null)", err, bio->bi_iter.bi_sector, bio->bi_iter.bi_size, bio->bi_iter.bi_bvec_done);
	}
    return 0;
}

static int ret_handler_end(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return 0;
}

#define MAX_PROBES 5
static int nr_probes = 0;
static struct kretprobe probes[MAX_PROBES];
static struct kretprobe submit_probe = {
	.handler        = ret_handler_submit,
    .entry_handler  = entry_handler_submit,
    .data_size      = 0,
    .maxactive      = 20,
};


int register_probe(char * name)
{
    int ret;
    struct kretprobe * probe;

    if (nr_probes >= MAX_PROBES) return -1;
    probe = &probes[nr_probes];

    probe->handler = ret_handler_end;
    probe->entry_handler = entry_handler_end;
    probe->data_size = 0;
    probe->maxactive = 20;
    probe->kp.symbol_name = name;

    ret = register_kretprobe(probe);
    if (ret < 0) {
        pr_warn("register_kretprobe %s failed, returned %d\n", name, ret);
        return ret;
    }
	nr_probes++;
    return 0;
}

static int __init kretprobe_init(void)
{
    int ret;
    if ((ret = register_probe("blkdev_bio_end_io"))) goto err;
    if ((ret = register_probe("blkdev_bio_end_io_simple"))) goto err;
	if ((ret = register_probe("end_bio_bh_io_sync"))) goto err;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
    if ((ret = register_probe("blkdev_bio_end_io_async"))) goto err;
#endif

	submit_probe.kp.symbol_name = "submit_bio";
	ret = register_kretprobe(&submit_probe);
    if (ret < 0) {
        pr_warn("register_kretprobe submit_bio failed, returned %d\n", ret);
        goto err;
    }
    return 0;
err:
	while (--nr_probes >= 0) unregister_kretprobe(&probes[nr_probes]);
	return ret;
}

static void __exit kretprobe_exit(void)
{
    while (--nr_probes >= 0) unregister_kretprobe(&probes[nr_probes]);
	unregister_kretprobe(&submit_probe);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");