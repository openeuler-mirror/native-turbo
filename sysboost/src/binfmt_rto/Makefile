KERNELDIR := /root/kernel

obj-m := binfmt_rto.o
PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

.PHONEY: clean

clean:
	rm -f *.o
	rm -f *.ko
	rm -f .*.cmd
	rm -rf .tmp_versions
	rm -f *.mod.c
	rm -f Module.symvers
	rm -f modules.order
