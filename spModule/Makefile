obj-m += spModule.o

KDIR = /usr/src/linux-headers-4.4.0-170-generic

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order
