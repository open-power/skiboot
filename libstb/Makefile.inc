# -*-Makefile-*-

LIBSTB_DIR = libstb

SUBDIRS += $(LIBSTB_DIR)

LIBSTB_SRCS = container.c
LIBSTB_OBJS = $(LIBSTB_SRCS:%.c=%.o)
LIBSTB = $(LIBSTB_DIR)/built-in.o

$(LIBSTB): $(LIBSTB_OBJS:%=$(LIBSTB_DIR)/%)
