PLATDIR = platforms

SUBDIRS += $(PLATDIR)
PLATFORMS = $(PLATDIR)/built-in.o

include $(SRC)/$(PLATDIR)/ibm-fsp/Makefile.inc
include $(SRC)/$(PLATDIR)/rhesus/Makefile.inc
include $(SRC)/$(PLATDIR)/astbmc/Makefile.inc

$(PLATFORMS): $(IBM_FSP) $(RHESUS) $(ASTBMC)
