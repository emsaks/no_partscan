VER := 1
obj-m := dm_persist$(VER).o dm_persist_b.o # no_partscan.o badbio.o  biosnoop.o 
dm_persist$(VER)-objs := dm_persist.o
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
	if [ -e /sys/module/dm_persist$(VER) ]; then rmmod dm_persist$(VER).ko; fi
	insmod dm_persist$(VER).ko
