ARCH=$(shell ./get_arch.sh "$(CROSS_COMPILE)")

ifeq ($(ARCH),ARCH_ARM)
arch = arm
ARCH_OBJS = common/arch_flash_common.o common/arch_flash_arm.o ast-sf-ctrl.o
else
ifeq ($(ARCH),ARCH_POWERPC)
arch = powerpc
ARCH_OBJS = common/arch_flash_common.o common/arch_flash_powerpc.o
else
ifeq ($(ARCH),ARCH_X86)
arch = x86
ARCH_OBJS = common/arch_flash_common.o common/arch_flash_x86.o
else
$(error Unsupported architecture $(ARCH))
endif
endif
endif

.DEFAULT_GOAL := all

CFLAGS  = -O2 -Wall -I.
LDFLAGS	= -lrt
OBJS    = pflash.o progress.o version.o
OBJS	+= libflash/libflash.o libflash/libffs.o libflash/ecc.o libflash/blocklevel.o libflash/file.o
OBJS	+= $(ARCH_OBJS)
EXE     = pflash

CC	= $(CROSS_COMPILE)gcc

PFLASH_VERSION ?= $(shell ./make_version.sh $(EXE))

version.c: make_version.sh .version
	@(if [ "a$(PFLASH_VERSION)" = "a" ]; then \
	echo "#error You need to set PFLASH_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(PFLASH_VERSION)\";" ;\
	fi) > $@

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

