# This tool is a linux userland tool and should be completely stand alone

CC = $(CROSS_COMPILE)gcc
CFLAGS = -m64 -Werror -Wall -g2 -ggdb
LDFLAGS = -m64
ASFLAGS = -m64
CPPFLAGS = -I. -I../../

OBJS = file_flash.o gard.o libflash.o libffs.o ecc.o

EXE = gard

all: $(EXE)

%.o: %.c
	$(COMPILE.c) $< -o $@

%.o: ../../libflash/%.c
	$(COMPILE.c) $< -o $@

$(EXE): $(OBJS)
	$(LINK.o) -o $@ $^

clean:
	rm -f $(OBJS) $(EXE) *.d

