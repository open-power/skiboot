SUBDIRS += $(PLATDIR)/bmc

BMC_OBJS = palmetto.o pnor.o
BMC = $(PLATDIR)/bmc/built-in.o
$(BMC): $(BMC_OBJS:%=$(PLATDIR)/bmc/%)

