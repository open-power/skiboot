# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# -*-Makefile-*-

SECVAR_STORAGE_DIR = $(SRC)/libstb/secvar/storage

SUBDIRS += $(SECVAR_STORAGE_DIR)

# Swap the comment on these two lines to use the fake TPM NV
# implementation hardware without a TPM
SECVAR_STORAGE_SRCS = secboot_tpm.c tpmnv_ops.c
#SECVAR_STORAGE_SRCS = secboot_tpm.c fakenv_ops.c

SECVAR_STORAGE_OBJS = $(SECVAR_STORAGE_SRCS:%.c=%.o)
SECVAR_STORAGE = $(SECVAR_STORAGE_DIR)/built-in.a

$(SECVAR_STORAGE): $(SECVAR_STORAGE_OBJS:%=$(SECVAR_STORAGE_DIR)/%)
