all: getscom putscom

VERSION=0.1
CFLAGS=-O2 -g -Wall -m64 -DVERSION=$(VERSION)

getscom: getscom.c xscom.c
	$(CC) $(CFLAGS) -o $@ $^

putscom: putscom.c xscom.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -rf getscom putscom

.PHONY: distclean
distclean: clean
	rm -rf *.c~ *.h~ *.i *.s Makefile~

