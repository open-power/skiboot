.DEFAULT_GOAL := all

override CFLAGS  += -O2 -Wall -I.
OBJS    = pflash.o progress.o version.o
LIBFLASH_OBJS += libflash-libflash.o libflash-libffs.o libflash-ecc.o libflash-blocklevel.o libflash-file.o
OBJS	+= $(LIBFLASH_OBJS)
OBJS	+= common-arch_flash.o
EXE     = pflash

CC	= $(CROSS_COMPILE)gcc

PFLASH_VERSION ?= $(shell ./make_version.sh $(EXE))

version.c: make_version.sh .version
	@(if [ "a$(PFLASH_VERSION)" = "a" ]; then \
	echo "#error You need to set PFLASH_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(PFLASH_VERSION)\";" ;\
	fi) > $@

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBFLASH_OBJS): libflash-%.o : libflash/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $^ -lrt -o $@

