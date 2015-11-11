ARCH = $(shell $(GET_ARCH) "$(CROSS_COMPILE)")

ifeq ($(ARCH),ARCH_ARM)
arch = arm
ARCH_OBJS = common/arch_flash_common.o common/arch_flash_arm.o common/ast-sf-ctrl.o
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

.PHONY: arch_links
arch_links:
	ln -sf ../../hw/ast-bmc/ast-sf-ctrl.c common/ast-sf-ctrl.c
	ln -sf arch_flash_$(arch)_io.h common/io.h

.PHONY: arch_clean
arch_clean:
	rm -rf $(ARCH_OBJS)

#If arch changes make won't realise it needs to rebuild...
.PHONY: .FORCE
common/arch_flash_common.o: common/arch_flash_common.c .FORCE
	$(CROSS_COMPILE)gcc $(CFLAGS) -c $< -o $@

common/arch_flash.o: $(ARCH_OBJS)
	$(CROSS_COMPILE)ld $(LDFLAGS) -r $(ARCH_OBJS) -o $@

