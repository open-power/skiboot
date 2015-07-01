include rules.mk

all: $(EXE)

.PHONY: links
links: libflash ccan sfc-ctrl.c ast-sf-ctrl.c make_version.sh

libflash:
	ln -sf ../../libflash .

ccan:
	ln -sf ../../ccan .

sfc-ctrl.c:
	ln -sf ../../hw/sfc-ctrl.c .

ast-sf-ctrl.c:
	ln -sf ../../hw/ast-bmc/ast-sf-ctrl.c

make_version.sh:
	ln -sf ../../make_version.sh

$(OBJS) : links

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(PFLASH_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp

.PHONY: dist
#File is named $(PFLASH_VERSION).tar because the expectation is that pflash-
#is always at the start of the verion. This remains consistent with skiboot
#version strings
dist: links .version
	find -L ../pflash/ -iname '*.[ch]' -print0 | xargs -0 tar -rhf $(PFLASH_VERSION).tar
	tar --transform 's/Makefile.dist/Makefile/' -rhf $(PFLASH_VERSION).tar \
		../pflash/get_arch.sh ../pflash/Makefile.dist ../pflash/rules.mk \
		../pflash/.version ../pflash/make_version.sh

clean:
	rm -f $(OBJS) $(EXE) *.o *.d libflash/test/test_flash libflash/test/*.o
distclean: clean
	rm -f *.c~ *.h~ *.sh~ Makefile~ config.mk~ libflash/*.c~ libflash/*.h~
	rm -f libflash ccan sfc-ctrl.c ast-sf-ctrl.c .version .version.tmp
