include rules.mk
GET_ARCH = ../../external/common/get_arch.sh
include ../../external/common/rules.mk

all: $(EXE)

.PHONY: links
links: libflash ccan common make_version.sh

libflash:
	ln -sf ../../libflash .

ccan:
	ln -sf ../../ccan .

common:
	ln -sf ../common .

make_version.sh:
	ln -sf ../../make_version.sh

$(OBJS): | links arch_links

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
		../pflash/Makefile.dist ../pflash/rules.mk \
		../pflash/.version ../pflash/make_version.sh \
		../pflash/common/*

clean: arch_clean
	rm -f $(OBJS) $(EXE) *.o *.d libflash/test/test_flash libflash/test/*.o
distclean: clean
	rm -f *.c~ *.h~ *.sh~ Makefile~ config.mk~ libflash/*.c~ libflash/*.h~
	rm -f libflash ccan .version .version.tmp
	rm -f common io.h make_version.sh
