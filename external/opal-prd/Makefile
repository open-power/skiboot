CC = $(CROSS_COMPILE)gcc

CFLAGS = -m64 -Werror -Wall -g2 -ggdb
LDFLAGS = -m64
ASFLAGS = -m64
CPPFLAGS = -I. -I../../include -I../../

# Use make V=1 for a verbose build.
ifndef V
        Q_CC=	@echo '    CC ' $@;
        Q_LINK=	@echo '  LINK ' $@;
        Q_LN=   @echo '    LN ' $@;
endif

OBJS = opal-prd.o thunk.o pnor.o i2c.o libffs.o libflash.o ecc.o

all: opal-prd

LINKS = ccan

ifdef KERNEL_DIR
LINKS += asm/opal-prd.h
endif

ccan:
	$(Q_LN)ln -sfr ../../ccan ./ccan

asm/opal-prd.h:
	$(Q_LN)ln -sfr $(KERNEL_DIR)/arch/powerpc/include/uapi/asm/opal-prd.h \
			asm/opal-prd.h

$(OBJS): $(LINKS)

%.o: %.c
	$(Q_CC)$(COMPILE.c) $< -o $@

%.o: ../../libflash/%.c
	$(Q_CC)$(COMPILE.c) $< -o $@

%.o: %.S
	$(Q_CC)$(COMPILE.S) $< -o $@

opal-prd: $(OBJS)
	$(Q_LINK)$(LINK.o) -o $@ $^

test: test/test_pnor

test/test_pnor: test/test_pnor.o pnor.o libflash/libflash.o libflash/libffs.o
	$(Q_LINK)$(LINK.o) -o $@ $^

clean:
	$(RM) *.[odsa] opal-prd
	$(RM) test/*.[odsa] test/test_pnor

distclean: clean
	$(RM) -f $(LINKS) asm
