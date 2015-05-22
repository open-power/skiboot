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

CFLAGS  = -O2 -Wall -I.
LDFLAGS	= -lrt
OBJS    = pflash.o progress.o ast-sf-ctrl.o version.o
OBJS	+= libflash/libflash.o libflash/libffs.o libflash/ecc.o
OBJS	+= $(ARCH_OBJS)
EXE     = pflash

CC	= $(CROSS_COMPILE)gcc

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: $(EXE)

.PHONY: links
links:
	ln -sf ../../libflash .
	ln -sf ../../ccan .
	ln -sf ../../hw/sfc-ctrl.c .
	ln -sf ../../hw/ast-bmc/ast-sf-ctrl.c
	ln -sf ../../make_version.sh

PFLASH_VERSION ?= $(shell ./make_version.sh $(EXE))

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(PFLASH_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp

version.c: make_version.sh .version
	@(if [ "a$(PFLASH_VERSION)" = "a" ]; then \
	echo "#error You need to set SKIBOOT_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(PFLASH_VERSION)\";" ;\
	fi) > $@

$(OBJS) : links

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(OBJS) $(EXE) *.o *.d libflash/test/test_flash libflash/test/*.o
distclean: clean
	rm -f *.c~ *.h~ *.sh~ Makefile~ config.mk~ libflash/*.c~ libflash/*.h~
	rm -f libflash ccan sfc-ctrl.c ast-sf-ctrl.c .version .version.tmp
