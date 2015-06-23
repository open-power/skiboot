# This tool is a linux userland tool and should be completely stand alone

prefix = /usr/local/
sbindir = $(prefix)/sbin
datadir = $(prefix)/share
mandir = $(datadir)/man

CC = $(CROSS_COMPILE)gcc
CFLAGS += -m64 -Werror -Wall -g2 -ggdb
LDFLAGS += -m64
ASFLAGS = -m64
CPPFLAGS += -I. -I../../

OBJS = file_flash.o gard.o libflash.o libffs.o ecc.o

EXE = gard

all: $(EXE)

%.o: %.c
	$(COMPILE.c) $< -o $@

%.o: ../../libflash/%.c
	$(COMPILE.c) $< -o $@

$(EXE): $(OBJS)
	$(LINK.o) -o $@ $^

install: all
	install -D gard $(DESTDIR)$(sbindir)/opal-gard
	install -D -m 0644 opal-gard.1 $(DESTDIR)$(mandir)/man1/opal-gard.1

clean:
	rm -f $(OBJS) $(EXE) *.d

distclean: clean

