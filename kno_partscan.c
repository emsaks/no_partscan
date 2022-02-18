#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/genhd.h>

#ifdef CONFIG_X86_32
#define ARG1 ax
#define ARG2 bx
#elif defined CONFIG_X86_64
#define ARG1 di
#define ARG2 si
#elif defined CONFIG_ARM || CONFIG_ARM64
#define ARG1 regs[0]
#define ARG2 regs[1]
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10)
#define ARG ARG1
static char func_name[NAME_MAX] = "add_disk";
#else // after 4.7.10, add_disk is a macro pointing to device_add_disk, which has the disk as its 2nd argument
#define ARG ARG2
static char func_name[NAME_MAX] = "device_add_disk";
#endif

static int enabled = 1;
module_param(enabled, int, 0664);
MODULE_PARM_DESC(enabled, "Enable intercepting disk initializing so we can block partscan.");

struct instance_data {
	struct gendisk *disk;
};

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct instance_data *data;
	struct gendisk *disk;

	data = (struct instance_data *)ri->data;
	disk = (struct gendisk *)(regs->ARG);

	if (!enabled || disk->flags & GENHD_FL_NO_PART_SCAN) {
		data->disk = NULL;
	} else {
		pr_warn("Intercepted partition read for disk: %s.\n", disk->disk_name);
		disk->flags |= (GENHD_FL_NO_PART_SCAN);
		data->disk = disk; // store this so we can remove the NO_PARTSCAN flag on function return
	}
	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct instance_data *data;

	data = (struct instance_data *)ri->data;
	if (data->disk)
		data->disk->flags &= ~(GENHD_FL_NO_PART_SCAN);

	return 0;
}

static struct kretprobe my_kretprobe = {
	.handler		= ret_handler,
	.entry_handler	= entry_handler,
	.data_size		= sizeof(struct instance_data),
	.maxactive		= 20,
};

static int __init kretprobe_init(void)
{
	int ret;

	my_kretprobe.kp.symbol_name = func_name;
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		pr_warn("register_kretprobe failed, returned %d\n", ret);
		return ret;
	}
	return 0;
}

static void __exit kretprobe_exit(void)
{
	unregister_kretprobe(&my_kretprobe);
	pr_info("kretprobe at unregistered\n");

	/* nmissed > 0 suggests that maxactive was set too low. */
	if (my_kretprobe.nmissed) pr_warn("Missed probing %d instances.\n", my_kretprobe.nmissed);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");