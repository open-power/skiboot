ARCH=$(shell ./get_arch.sh $(CROSS_COMPILE))

ifeq ($(ARCH),ARCH_POWERPC)
ARCH_OBJS = powerpc_io.o sfc-ctrl.o
else
ifeq ($(ARCH),ARCH_ARM)
ARCH_OBJS = arm_io.o
else
$(error Unsupported architecture $(ARCH))
endif
endif

.DEFAULT_GOAL := all

CFLAGS  = -O2 -Wall -I.
LDFLAGS	= -lrt
OBJS    = pflash.o progress.o ast-sf-ctrl.o version.o
OBJS	+= libflash/libflash.o libflash/libffs.o libflash/ecc.o libflash/blocklevel.o
OBJS	+= $(ARCH_OBJS)
EXE     = pflash

CC	= $(CROSS_COMPILE)gcc

PFLASH_VERSION ?= $(shell ./make_version.sh $(EXE))

version.c: make_version.sh .version
	@(if [ "a$(PFLASH_VERSION)" = "a" ]; then \
	echo "#error You need to set SKIBOOT_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(PFLASH_VERSION)\";" ;\
	fi) > $@

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

