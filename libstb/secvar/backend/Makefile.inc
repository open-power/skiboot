# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# -*-Makefile-*-

SECVAR_BACKEND_DIR = $(SRC)/libstb/secvar/backend

SUBDIRS += $(SECVAR_BACKEND_DIR)

SECVAR_BACKEND_SRCS = edk2-compat.c edk2-compat-process.c edk2-compat-reset.c
SECVAR_BACKEND_OBJS = $(SECVAR_BACKEND_SRCS:%.c=%.o)
SECVAR_BACKEND = $(SECVAR_BACKEND_DIR)/built-in.a

$(SECVAR_BACKEND): $(SECVAR_BACKEND_OBJS:%=$(SECVAR_BACKEND_DIR)/%)
