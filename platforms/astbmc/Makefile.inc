SUBDIRS += $(PLATDIR)/astbmc

ASTBMC_OBJS = palmetto.o pnor.o common.o
ASTBMC = $(PLATDIR)/astbmc/built-in.o
$(ASTBMC): $(ASTBMC_OBJS:%=$(PLATDIR)/astbmc/%)

