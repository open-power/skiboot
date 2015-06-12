# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = relocate.o console.o backtrace.o init.o chip.o mem_region.o
CORE_OBJS += malloc.o lock.o cpu.o utils.o fdt.o opal.o interrupts.o
CORE_OBJS += timebase.o opal-msg.o pci.o pci-opal.o fast-reboot.o
CORE_OBJS += device.o exceptions.o trace.o affinity.o vpd.o
CORE_OBJS += hostservices.o platform.o nvram.o flash-nvram.o hmi.o
CORE_OBJS += console-log.o ipmi.o time-utils.o i2c.o
CORE=core/built-in.o

$(CORE): $(CORE_OBJS:%=core/%)
