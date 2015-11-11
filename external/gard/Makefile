# This tool is a linux userland tool and should be completely stand alone
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

#Rebuild version.o so that the the version always matches
#what the test suite will get from ./make_version.sh
check: version.o all
	@ln -sf ../../test/test.sh test/test.sh
	@test/test-gard

$(OBJS): | links arch_links

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(GARD_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp

clean: arch_clean
	rm -f $(OBJS) $(EXE) *.o *.d .version .version.tmp

distclean: clean
	rm -f *.c~ *.h~ *.sh~ Makefile~ config.mk~ libflash/*.c~ libflash/*.h~
	rm -f libflash ccan common io.h make_version.sh

