ifneq  ($(KERNELRELEASE),)

obj-m += hashtable.o
obj-m += hashtable_unit.o

else

KDIR := /usr/lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.symvers *.cmd *.cmd.o *.mod.c modules.order
endif
