#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>

#include <linux/fs.h>
#include <linux/genhd.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,4,179)

static int livepatch_rescan_partitions(struct gendisk *disk, struct block_device *bdev)
{
	pr_warn("Intercepted partition read for disk: %s.\n", disk->disk_name);
	return -EIO;
}

static struct klp_func funcs[] = {
	{
		.old_name = "rescan_partitions",
		.new_func = livepatch_rescan_partitions,
	}, { }
};

#else

static int livepatch_blk_add_partitions(struct gendisk *disk)
{
	pr_warn("Intercepted partition read for disk: %s.\n", disk->disk_name);
	return 0;
}

#endif

static struct klp_func funcs[] = {
	{
		.old_name = "blk_add_partitions",
		.new_func = livepatch_blk_add_partitions,
	}, { }
};

static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,0,21)

static int livepatch_init(void)
{
	int ret;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,15,18) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,12)
	if (!klp_have_reliable_stack() && !patch.immediate) {
		 // Use of this option will also prevent removal of the patch.
		 // See Documentation/livepatch/livepatch.txt for more details.
		patch.immediate = true;
		pr_notice("The consistency model isn't supported for your architecture.  Bypassing safety mechanisms and applying the patch immediately.\n");
	}
#endif

	ret = klp_register_patch(&patch);
	if (ret)
		return ret;
	ret = klp_enable_patch(&patch);
	if (ret) {
		WARN_ON(klp_unregister_patch(&patch));
		return ret;
	}
	return 0;
}

static void livepatch_exit(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,11,12)
	WARN_ON(klp_disable_patch(&patch));	
#endif
	WARN_ON(klp_unregister_patch(&patch));
}

#else

static int livepatch_init(void)
{
	return klp_enable_patch(&patch);
}

static void livepatch_exit(void)
{
}

#endif

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");