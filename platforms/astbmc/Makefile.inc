SUBDIRS += $(PLATDIR)/astbmc

ASTBMC_OBJS = palmetto.o habanero.o pnor.o common.o
ASTBMC = $(PLATDIR)/astbmc/built-in.o
$(ASTBMC): $(ASTBMC_OBJS:%=$(PLATDIR)/astbmc/%)

