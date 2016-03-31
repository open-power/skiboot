ARCH := $(shell $(GET_ARCH) "$(CROSS_COMPILE)")

ifeq ($(ARCH),ARCH_ARM)
arch := arm
ARCH_FILES := arch_flash_common.c arch_flash_arm.c ast-sf-ctrl.c
else
ifeq ($(ARCH),ARCH_POWERPC)
arch := powerpc
ARCH_FILES := arch_flash_common.c arch_flash_powerpc.c
else
ifeq ($(ARCH),ARCH_X86)
arch := x86
ARCH_FILES := arch_flash_common.c arch_flash_x86.c
else
$(error Unsupported architecture $(ARCH))
endif
endif
endif

# Use make V=1 for a verbose build.
ifndef V
        Q_CC=	@echo '    CC ' $@;
        Q_LINK=	@echo '  LINK ' $@;
        Q_LN=   @echo '    LN ' $@;
        Q_MKDIR=@echo ' MKDIR ' $@;
endif


.PHONY: links
links: libflash ccan common

libflash:
	$(Q_LN)ln -sf ../../libflash ./libflash

ccan:
	$(Q_LN)ln -sf ../../ccan ./ccan

common:
	$(Q_LN)ln -sf ../common ./common

make_version.sh:
	$(Q_LN)ln -sf ../../make_version.sh

ARCH_SRC := $(addprefix common/,$(ARCH_FILES))
ARCH_OBJS := $(addprefix common-,$(ARCH_FILES:.c=.o))

# Arch links are like this so we can have dependencies work (so that we don't
# run the rule when the links exist), pretty build output (knowing the target
# name) and a list of the files so we can clean them up.
ARCH_LINKS := common/ast-sf-ctrl.c common/ast.h common/io.h

arch_links: $(ARCH_LINKS)
common/ast.h : ../../include/ast.h | common
	$(Q_LN)ln -sf ../../include/ast.h common/ast.h

common/io.h : ../common/arch_flash_$(arch)_io.h | common
	$(Q_LN)ln -sf arch_flash_$(arch)_io.h common/io.h

common/ast-sf-ctrl.c : ../../hw/ast-bmc/ast-sf-ctrl.c | common
	$(Q_LN)ln -sf ../../hw/ast-bmc/ast-sf-ctrl.c common/ast-sf-ctrl.c

.PHONY: arch_clean
arch_clean:
	rm -rf $(ARCH_OBJS) $(ARCH_LINKS)

$(ARCH_SRC): | common

$(ARCH_OBJS): common-%.o: common/%.c
	$(Q_CC)$(CROSS_COMPILE)gcc $(CFLAGS) $(CPPFLAGS) -c $< -o $@

common-arch_flash.o: $(ARCH_OBJS)
	$(Q_LD)$(CROSS_COMPILE)ld -r $(ARCH_OBJS) -o $@

