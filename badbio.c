#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "regs.h"

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct bio *bio;
	int err;

    pr_info("Ended bio.\n");
	//bio = (struct bio*)regs->ARG1;
	//err = blk_status_to_errno(bio->bi_status);
	//if (err) {
	//	pr_warn("Bio for disk %s has error %i; %u bytes remaining.\n",bio->bi_bdev ? bio->bi_bdev->bd_disk->disk_name : "(null)", err, bio->bi_iter.bi_size);
	//}
    return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return 0;
}

#define MAX_PROBES 3
static int nr_probes = 0;
static struct kretprobe probes[MAX_PROBES];

int register_probe(char * name)
{
    int ret;
    struct kretprobe * probe;

    if (nr_probes >= MAX_PROBES) return -1;
    probe = &probes[nr_probes];

    probe->handler = ret_handler;
    probe->entry_handler = entry_handler;
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
    if ((ret = register_probe("blkdev_bio_end_io_async"))) goto err;
    return 0;
err:
	while (--nr_probes >= 0) unregister_kretprobe(&probes[nr_probes]);
	return ret;
}

static void __exit kretprobe_exit(void)
{
    while (--nr_probes >= 0) unregister_kretprobe(&probes[nr_probes]);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");