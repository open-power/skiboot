.DEFAULT_GOAL := all

override CFLAGS += -O2 -Wall -Werror -I.
OBJS      = gard.o
OBJS     += libflash/file.o libflash/libflash.o libflash/libffs.o libflash/ecc.o libflash/blocklevel.o
OBJS     += common/arch_flash.o
EXE       = gard

CC = $(CROSS_COMPILE)gcc

prefix = /usr/local/
sbindir = $(prefix)/sbin
datadir = $(prefix)/share
mandir = $(datadir)/man

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

install: all
	install -D gard $(DESTDIR)$(sbindir)/opal-gard
	install -D -m 0644 opal-gard.1 $(DESTDIR)$(mandir)/man1/opal-gard.1


