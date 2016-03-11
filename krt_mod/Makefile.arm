# Makefile for compile kernel for Andriod
#KERNEL_DIR := /home/jeremy/Data/taint/tdroid-4.3_r1/goldfish/
KERNEL_DIR := /home/jeremy/Data/kernel/msm1/
#CROSS_COMPILE := /home/jeremy/Data/tdroid-4.3_r1/prebuilts/gcc/linux-x86/arm/arm-eabi-4.6/bin/arm-eabi-
#CROSS_COMPILE := /home/jeremy/Data/taint/android-4.3_r2.2/prebuilts/gcc/linux-x86/arm/arm-eabi-4.6/bin/arm-eabi-
CROSS_COMPILE := /home/jeremy/Data/art/Android-4.4.2/prebuilts/gcc/linux-x86/arm/arm-eabi-4.7/bin/arm-eabi-
EXTRA_CFLAGS := -g -Wall
ARCH := arm
PWD := $(shell pwd)
obj-m := krt.o
krt-objs := pktrx.o pkthijack.o nlksp.o pkttx.o rulelist.o hash.o

.PHONY: modules package clean
default:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules
clean:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean
