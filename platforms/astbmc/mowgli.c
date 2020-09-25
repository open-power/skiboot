// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2020 Wistron Corp.
 * Copyright 2017-2019 IBM Corp.
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <npu-regs.h>

#include "astbmc.h"

ST_PLUGGABLE(mowgli_slot1, "Pcie Slot1 (16x)");
ST_PLUGGABLE(mowgli_slot2, "Pcie Slot2 (8x)");
ST_BUILTIN_DEV(mowgli_builtin_bmc, "BMC");
ST_PLUGGABLE(mowgli_slot3, "Pcie Slot3 (8x)");
ST_BUILTIN_DEV(mowgli_builtin_usb, "Builtin USB");

static const struct slot_table_entry mowgli_phb_table[] = {
	ST_PHB_ENTRY(0, 0, mowgli_slot1),
	ST_PHB_ENTRY(0, 1, mowgli_slot2),
	ST_PHB_ENTRY(0, 2, mowgli_builtin_bmc),
	ST_PHB_ENTRY(0, 3, mowgli_slot3),
	ST_PHB_ENTRY(0, 4, mowgli_builtin_usb),

	{ .etype = st_end },
};

static bool mowgli_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,mowgli"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	slot_table_init(mowgli_phb_table);

	return true;
}

DECLARE_PLATFORM(mowgli) = {
	.name			= "Mowgli",
	.probe			= mowgli_probe,
	.init			= astbmc_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &bmc_plat_ast2500_openbmc,
	.pci_get_slot_info	= slot_table_get_slot_info,
	.pci_probe_complete	= check_all_slot_table,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= astbmc_exit,
	.terminate		= ipmi_terminate,
	.op_display		= op_display_lpc,
};
