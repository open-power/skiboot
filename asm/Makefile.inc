# -*-Makefile-*-

SUBDIRS += asm 
ASM_OBJS = head.o misc.o kernel-wrapper.o cvc_entry.o
ASM=asm/built-in.o

# Add extra dependency to the kernel wrapper
kernel_wrapper.o : $(KERNEL)

$(ASM): $(ASM_OBJS:%=asm/%)

