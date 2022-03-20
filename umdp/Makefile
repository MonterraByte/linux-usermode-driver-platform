ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
obj-m  := umdp.o

else
# normal makefile
KERNEL_VER ?= `uname -r`
KERNEL_DIR ?= /lib/modules/$(KERNEL_VER)/build

default:
	$(MAKE) -C $(KERNEL_DIR) M=$$PWD

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$$PWD clean

endif
