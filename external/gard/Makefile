# This tool is a linux userland tool and should be completely stand alone
include rules.mk
GET_ARCH = ../../external/common/get_arch.sh
include ../../external/common/rules.mk

all: $(EXE)

.PHONY: links
links: libflash ccan common

libflash:
	ln -sf ../../libflash .

ccan:
	ln -sf ../../ccan .

common:
	ln -sf ../common .

check: all
	@ln -sf ../../test/test.sh test/test.sh
	@test/test-gard

$(OBJS): | links arch_links

clean: arch_clean
	rm -f $(OBJS) $(EXE) *.o *.d

distclean: clean
	rm -f *.c~ *.h~ *.sh~ Makefile~ config.mk~ libflash/*.c~ libflash/*.h~
	rm -f libflash ccan .version .version.tmp
	rm -f common io.h make_version.sh

