#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "regs.h"

static int __kprobes submit_pre(struct kprobe *p, struct pt_regs *regs);
static int __kprobes end_io_pre(struct kprobe *p, struct pt_regs *regs);

static bool enabled = 1;
module_param(enabled, bool, 0664);

static bool show_success = 0;
module_param(show_success, bool, 0664);

static bool show_submit = 0;
module_param(show_submit, bool, 0664);

static bool match_bios = 1;
module_param(match_bios, bool, 0664);

#define MAX_PROBES 200
static struct kprobe submit_probe = { .symbol_name = "submit_bio", .pre_handler = submit_pre };
static struct kprobe probes[MAX_PROBES];
static int nr_probes = 0;
DEFINE_MUTEX(probe_mutex);

struct bio_info {
	struct bio * bio;
	unsigned int size;
};

// we use a ring buffer and might overwrite a few entries...
// i think we can skip using a lock; there might a few races but it's unimportant
#define MAX_BIOS 1000
struct bio_info bios[MAX_BIOS];
int bio_idx = 0;

struct bio_info * find_bio(struct bio * bio)
{
	int i;

	// we need check backwards from bio_idx to ensure that
	// the most recent reference is found, not a stale one
	for (i = bio_idx - 1; i >= 0; --i)
		if (bios[i].bio == bio) return &bios[i];
	for (i = MAX_BIOS - 1; i >= bio_idx; --i)
		if (bios[i].bio == bio) return &bios[i];

	return NULL;
}

static int __kprobes submit_pre(struct kprobe *p, struct pt_regs *regs)
{
	int ret, i, _nr_probes;
	struct  bio * bio;

	if (!enabled) return 0;

	bio = (struct bio*)regs->ARG1;

	_nr_probes = READ_ONCE(nr_probes);
	for (i = 0; i < _nr_probes; ++i)
		if (probes[i].addr == (void *)bio->bi_end_io) break;

	if (i >= _nr_probes) {
		// if probe is not found, we need to take
		// a lock and check if it has been added in the meantime
		if (mutex_lock_interruptible(&probe_mutex) != 0) {
			//notify
			goto out;
		}
		READ_ONCE(nr_probes); // todo: do we need this inside the lock?
		for (; i < nr_probes; ++i)
			if (probes[i].addr == (void *)bio->bi_end_io) break;
		if (i >= nr_probes) {
			mutex_unlock(&probe_mutex);
		} else if (i >= MAX_PROBES) {
			mutex_unlock(&probe_mutex);
			// notify
			goto out;
		} else {
			probes[nr_probes].addr = (void *)bio->bi_end_io;
			probes[nr_probes].pre_handler = end_io_pre;
			ret = register_kprobe(&probes[nr_probes]);
			if (ret >= 0) {
				nr_probes++;
				mutex_unlock(&probe_mutex);
				// notify plant
			} else {
				mutex_unlock(&probe_mutex);
				// notify
				goto out;
			}
		}
	}

	if (match_bios) {
		if (bio_idx >= MAX_BIOS) bio_idx = 0;
		bios[bio_idx].bio = bio;
		bios[bio_idx].size = bio->bi_iter.bi_size;
		bio_idx++;
	}

out:
	if (show_submit) {
		// todo
		// we can get endio info from probes[i]
	}

	return 0;
}

static int __kprobes end_io_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct bio *bio;
	struct bio_info * ifo;
	int err;
	unsigned int size = 0; // fixme: use ~0 as flag

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

static int __init kprobe_init(void)
{
	int ret;

	mutex_init(&probe_mutex);
	ret = register_kprobe(&submit_probe);
	if (ret < 0) {
		pr_err("register_kprobe failed for submit_bio, returned %d\n", ret);
		return ret;
	}

	return 0;
}

static void __exit kprobe_exit(void)
{
	int i;

	unregister_kprobe(&submit_probe);
	for (i = 0; i < nr_probes; ++i)
		unregister_kprobe(&probes[i]);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
