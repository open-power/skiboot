# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# -*-Makefile-*-

SECVAR_DIR = $(SRC)/libstb/secvar

SUBDIRS += $(SECVAR_DIR)

include $(SECVAR_DIR)/storage/Makefile.inc
include $(SECVAR_DIR)/backend/Makefile.inc

SECVAR_SRCS = secvar_main.c secvar_util.c secvar_devtree.c
SECVAR_SRCS = secvar_main.c secvar_util.c secvar_devtree.c secvar_api.c
SECVAR_OBJS = $(SECVAR_SRCS:%.c=%.o)
SECVAR = $(SECVAR_DIR)/built-in.a

$(SECVAR): $(SECVAR_OBJS:%=$(SECVAR_DIR)/%) $(SECVAR_STORAGE) $(SECVAR_BACKEND)
