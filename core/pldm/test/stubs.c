// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2019 IBM Corp
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <timer.h>
#include <signal.h>
#include <timebase.h>
#include <compiler.h>
#include "../../ccan/list/list.c"

void _prlog(int log_level __unused, const char *fmt, ...) __attribute__((format (printf, 2, 3)));

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif
#define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while (0)

void _prlog(int log_level __unused, const __unused char *fmt, ...)
{
}

/* Add any stub functions required for linking here. */
static void stub_function(void)
{
	abort();
}


#define STUB(fnname) \
	void fnname(void) __attribute__((weak, alias("stub_function")))

STUB(fdt_begin_node);
STUB(fdt_property);
STUB(fdt_end_node);
STUB(fdt_create_with_flags);
STUB(fdt_add_reservemap_entry);
STUB(fdt_finish_reservemap);
STUB(fdt_strerror);
STUB(fdt_check_header);
STUB(fdt_check_node_offset_);
STUB(fdt_next_tag);
STUB(fdt_string);
STUB(fdt_get_name);
STUB(dt_first);
STUB(dt_next);
STUB(dt_has_node_property);
STUB(dt_get_address);
STUB(add_chip_dev_associativity);
STUB(pci_check_clear_freeze);
STUB(prd_occ_reset);
STUB(ast_mctp_init);
STUB(ast_mctp_exit);
STUB(ast_mctp_ready);
