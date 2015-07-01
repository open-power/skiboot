# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = relocate.o console.o stack.o init.o chip.o mem_region.o
CORE_OBJS += malloc.o lock.o cpu.o utils.o fdt.o opal.o interrupts.o
CORE_OBJS += timebase.o opal-msg.o pci.o pci-opal.o fast-reboot.o
CORE_OBJS += device.o exceptions.o trace.o affinity.o vpd.o
CORE_OBJS += hostservices.o platform.o nvram.o nvram-format.o hmi.o
CORE_OBJS += console-log.o ipmi.o time-utils.o pel.o pool.o errorlog.o
CORE_OBJS += timer.o i2c.o rtc.o flash.o sensor.o

ifeq ($(SKIBOOT_GCOV),1)
CORE_OBJS += gcov-profiling.o
endif

CORE=core/built-in.o

CFLAGS_SKIP_core/relocate.o = -pg -fstack-protector-all
CFLAGS_SKIP_core/relocate.o += -fstack-protector -fstack-protector-strong
CFLAGS_SKIP_core/relocate.o += -fprofile-arcs -ftest-coverage

$(CORE): $(CORE_OBJS:%=core/%)
