CC = $(CROSS_COMPILE)gcc

CFLAGS += -m64 -Werror -Wall -g2 -ggdb
LDFLAGS += -m64
ASFLAGS = -m64
CPPFLAGS += -I. -I../../include -I../../

prefix = /usr/local/
sbindir = $(prefix)/sbin
datadir = $(prefix)/share
mandir = $(datadir)/man

all: opal-prd

GET_ARCH = ../../external/common/get_arch.sh
include ../../external/common/rules.mk

# Use make V=1 for a verbose build.
ifndef V
        Q_CC=	@echo '    CC ' $@;
        Q_LINK=	@echo '  LINK ' $@;
        Q_LN=   @echo '    LN ' $@;
        Q_MKDIR=@echo ' MKDIR ' $@;
endif

LIBFLASH_OBJS = libflash-blocklevel.o libflash-libffs.o \
                libflash-libflash.o libflash-ecc.o \
                libflash-file.o

OBJS = opal-prd.o thunk.o pnor.o i2c.o module.o version.o \
       $(LIBFLASH_OBJS) common-arch_flash.o

LINKS = ccan common libflash $(ARCH_LINKS)

OPAL_PRD_VERSION ?= $(shell ../../make_version.sh opal-prd)

ifdef KERNEL_DIR
LINKS += asm/opal-prd.h
endif

ccan:
	$(Q_LN)ln -sfr ../../ccan ./ccan

libflash:
	$(Q_LN)ln -sfr ../../libflash ./libflash

common:
	$(Q_LN)ln -sfr ../common ./common

asm/opal-prd.h:
	$(Q_MKDIR)mkdir -p asm
	$(Q_LN)ln -sfr $(KERNEL_DIR)/arch/powerpc/include/uapi/asm/opal-prd.h \
			asm/opal-prd.h

$(OBJS): | $(LINKS)

%.o: %.c
	$(Q_CC)$(COMPILE.c) $< -o $@

$(LIBFLASH_OBJS): libflash-%.o : libflash/%.c
	$(Q_CC)$(COMPILE.c) $< -o $@

%.o: %.S
	$(Q_CC)$(COMPILE.S) $< -o $@

opal-prd: $(OBJS)
	$(Q_LINK)$(LINK.o) -o $@ $^

version.c: ../../make_version.sh .version
	@(if [ "a$(OPAL_PRD_VERSION)" = "a" ]; then \
	echo "#error You need to set OPAL_PRD_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(OPAL_PRD_VERSION)\";" ;\
	fi) > $@

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(OPAL_PRD_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp

test: $(LINKS) test/test_pnor

test/test_pnor: test/test_pnor.o pnor.o $(LIBFLASH_OBJS) common-arch_flash.o
	$(Q_LINK)$(LINK.o) -o $@ $^

install: all
	install -D opal-prd $(DESTDIR)$(sbindir)/opal-prd
	install -D -m 0644 opal-prd.8 $(DESTDIR)$(mandir)/man8/opal-prd.8

clean:
	$(RM) *.[odsa] opal-prd
	$(RM) test/*.[odsa] test/test_pnor

distclean: clean
	$(RM) -f $(LINKS) asm
