all: getscom putscom getsram

XSCOM_VERSION ?= $(shell ../../make_version.sh xscom-utils)
CFLAGS?=-O2 -g -Wall -m64
override CFLAGS += -DVERSION=\"$(XSCOM_VERSION)\"

getscom: getscom.c xscom.c
	$(CC) $(CFLAGS) -o $@ $^

getsram: getsram.c xscom.c sram.c
	$(CC) $(CFLAGS) -o $@ $^

putscom: putscom.c xscom.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -rf getscom putscom getsram

.PHONY: distclean
distclean: clean
	rm -rf *.c~ *.h~ *.i *.s Makefile~

