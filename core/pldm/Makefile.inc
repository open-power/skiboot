# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright 2022 IBM Corp

PLDM_DIR ?= core/pldm
SUBDIRS += $(PLDM_DIR)

CPPFLAGS += -I$(SRC)/pldm/include/
CPPFLAGS += -I$(SRC)/pldm/include/libpldm/oem/ibm/

PLDM_OBJS = pldm-mctp.o

PLDM = $(PLDM_DIR)/built-in.a
$(PLDM): $(PLDM_OBJS:%=$(PLDM_DIR)/%)
