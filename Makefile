obj-m := no_partscan.o badbio.o biosnoop.o dm_persist3.o
dm_persist3-objs := dm_persist.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
bio:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	if [ -e /sys/module/badbio ]; then rmmod badbio.ko; fi
	insmod badbio.ko
pers:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	if [ -e /sys/module/dm_persist3 ]; then rmmod dm_persist3.ko; fi
	insmod dm_persist3.ko