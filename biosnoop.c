#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

/*
	This module uses probes on each unique end_io function
	encountered.
	A better options would be to replace the end_io with a
	custom function, and restore the original+private_data
	when called. This avoids a lookup on end_io because we
	could store the information in private_data.
	It would also avoid planting probes, and would further
	allow a non-locking list of cached data.
	However, I don't know if any kernel code performs some
	chicanary with private_data (i.e. relies on inspecting
	private_data when a bio is submitted) so it may not be
	safe to play with it.
*/

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

static int missed_bios = 0;
module_param(missed_bios, int, 0444);

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
	static char sym_buf[KSYM_SYMBOL_LEN];
	char * sym_ptr;
	int ret, i, _nr_probes;
	struct  bio * bio;

	if (!enabled) return 0;

	bio = (struct bio*)regs->ARG1;

	_nr_probes = READ_ONCE(nr_probes);
	for (i = 0; i < _nr_probes; ++i)
		if (probes[i].addr == (void *)bio->bi_end_io) break;

	if (i >= _nr_probes) {
		if (nr_probes >= MAX_PROBES) {
			if (!missed_bios++) pr_warn("Can't allocate a new probe.\n");
			goto out;
		}
		// if probe is not found, we need to take
		// a lock and check if it has been added in the meantime
		if (mutex_lock_interruptible(&probe_mutex) != 0) {
			pr_warn("Interrupted when taking lock.\n");
			goto out;
		}
		READ_ONCE(nr_probes); // todo: do we really need this inside the lock?
		for (; i < nr_probes; ++i)
			if (probes[i].addr == (void *)bio->bi_end_io) break;
		if (i < nr_probes) {
			mutex_unlock(&probe_mutex);
		} else if (i >= MAX_PROBES) {
			mutex_unlock(&probe_mutex);
			if (!missed_bios++) pr_warn("Can't allocate a new probe.\n");
			goto out;
		} else {
			probes[nr_probes].addr = (void *)bio->bi_end_io;
			probes[nr_probes].pre_handler = end_io_pre;
			ret = register_kprobe(&probes[nr_probes]);
			if (ret >= 0) {
				nr_probes++;
				mutex_unlock(&probe_mutex);
				if (sprint_symbol(sym_buf, (unsigned long)bio->bi_end_io)) {
					if ((sym_ptr = kzalloc(KSYM_SYMBOL_LEN, GFP_KERNEL))) {
						strcpy(sym_ptr, sym_buf);
						probes[nr_probes-1].symbol_name = sym_ptr;
					}
					pr_info("Planted probe at %s.\n", sym_buf);
				} else pr_info("Planted probe at address %p.\n", bio->bi_end_io);
			} else {
				mutex_unlock(&probe_mutex);
				if (sprint_symbol(sym_buf, (unsigned long)bio->bi_end_io)) pr_info("Failed to plant probe at %s.\n", sym_buf);
				else pr_warn("Failed to plant probe at address %p.\n", bio->bi_end_io);
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
			pr_warn("%s (%s) > %s (%i); @%llu: +%u/%u (-%u) bytes.\n", current->comm, p->symbol_name, bio->bi_bdev ? bio->bi_bdev->bd_disk->disk_name : "(null)", err, bio->bi_iter.bi_sector, bio->bi_iter.bi_bvec_done, bio->bi_iter.bi_size, size);
		else
			pr_warn("%s (%s) > %s (%i); @%llu: +%u (-%u) bytes.\n", current->comm, p->symbol_name, bio->bi_bdev ? bio->bi_bdev->bd_disk->disk_name : "(null)", err, bio->bi_iter.bi_sector, bio->bi_iter.bi_bvec_done, bio->bi_iter.bi_size);
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
	pr_info("Planted probe for submit_bio at %p\n", submit_probe.addr);

	return 0;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&submit_probe);
	while (--nr_probes >= 0) {
		// we may have allocated a string when planting the probe
		kfree(probes[nr_probes].symbol_name);
		unregister_kprobe(&probes[nr_probes]);
	}
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
