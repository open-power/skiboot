/* Copyright 2017 Supermicro Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <npu-regs.h>

#include "astbmc.h"

static const struct slot_table_entry p9dsu1u_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_2_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard LAN",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_3_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard SAS",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_4_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard BMC",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_5_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard USB",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb8_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb8_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO-R Slot",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb8_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb8_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = p9dsu1u_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = p9dsu1u_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = p9dsu1u_phb0_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,3),
		.children = p9dsu1u_phb0_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,4),
		.children = p9dsu1u_phb0_4_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,5),
		.children = p9dsu1u_phb0_5_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,0),
		.children = p9dsu1u_phb8_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,1),
		.children = p9dsu1u_phb8_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,2),
		.children = p9dsu1u_phb8_2_slot,
	},
		{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,3),
		.children = p9dsu1u_phb8_3_slot,
	},
	{ .etype = st_end },
};


static const struct slot_table_entry p9dsu2u_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_2_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard LAN",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_3_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard SAS",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_4_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard BMC",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_5_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard USB",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO-R Slot",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_4_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};


static const struct slot_table_entry p9dsu2u_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = p9dsu2u_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = p9dsu2u_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = p9dsu2u_phb0_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,3),
		.children = p9dsu2u_phb0_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,4),
		.children = p9dsu2u_phb0_4_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,5),
		.children = p9dsu2u_phb0_5_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,0),
		.children = p9dsu2u_phb8_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,1),
		.children = p9dsu2u_phb8_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,2),
		.children = p9dsu2u_phb8_2_slot,
	},
		{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,3),
		.children = p9dsu2u_phb8_3_slot,
	},
			{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,4),
		.children = p9dsu2u_phb8_4_slot,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_uio_plx_down[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x1,0),
		.name = "UIO Slot2",
		.power_limit = 75,
	},
    	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0x8,0),
		.name = "PLX switch",
		.power_limit = 75,
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0x9,0),
		.name = "Onboard LAN",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_uio_plx_up[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = p9dsu2uess_uio_plx_down,
		.name = "PLX up",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_wio_plx_down[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x1,0),
		.name = "WIO Slot1",
		.power_limit = 75,
	},
    	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0x8,0),
		.name = "PLX switch",
		.power_limit = 75,
	},
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x9,0),
		.name = "WIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_wio_plx_up[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = p9dsu2uess_wio_plx_down,
		.name = "PLX up",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_1_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = p9dsu2uess_uio_plx_up,
		.name = "PLX",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_2_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_3_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard SAS",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_4_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard BMC",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_5_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard USB",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb8_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb8_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO-R Slot",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb8_2_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = p9dsu2uess_wio_plx_up,
		.name = "PLX",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb8_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot4",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = p9dsu2uess_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = p9dsu2uess_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = p9dsu2uess_phb0_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,3),
		.children = p9dsu2uess_phb0_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,4),
		.children = p9dsu2uess_phb0_4_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,5),
		.children = p9dsu2uess_phb0_5_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,0),
		.children = p9dsu2uess_phb8_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,1),
		.children = p9dsu2uess_phb8_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,2),
		.children = p9dsu2uess_phb8_2_slot,
	},
		{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,3),
		.children = p9dsu2uess_phb8_3_slot,
	},
	{ .etype = st_end },
};


/*
 * HACK: Hostboot doesn't export the correct data for the system VPD EEPROM
 *       for this system. So we need to work around it here.
 */
static void p9dsu_dt_fixups(void)
{
	struct dt_node *n = dt_find_by_path(dt_root,
		"/xscom@603fc00000000/i2cm@a2000/i2c-bus@0/eeprom@50");

	if (n) {
		dt_check_del_prop(n, "compatible");
		dt_add_property_string(n, "compatible", "atmel,24c256");

		dt_check_del_prop(n, "label");
		dt_add_property_string(n, "label", "system-vpd");
	}
}

static bool p9dsu1u_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "supermicro,p9dsu1u"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	p9dsu_dt_fixups();

	slot_table_init(p9dsu1u_phb_table);

	return true;
}
static bool p9dsu2u_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "supermicro,p9dsu2u"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	p9dsu_dt_fixups();

	slot_table_init(p9dsu2u_phb_table);

	return true;
}


static bool p9dsu2uess_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "supermicro,p9dsu2uess"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	p9dsu_dt_fixups();

	slot_table_init(p9dsu2uess_phb_table);

	return true;
}


static const struct bmc_platform astbmc_smc = {
	.name = "SMC",
	.ipmi_oem_partial_add_esel   = IPMI_CODE(0x3a, 0xf0),
};

DECLARE_PLATFORM(p9dsu1u) = {
	.name			= "p9dsu1u",
	.probe			= p9dsu1u_probe,
	.init			= astbmc_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &astbmc_smc,
	.pci_get_slot_info	= slot_table_get_slot_info,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= ipmi_wdt_final_reset,
	.terminate		= ipmi_terminate,
};
DECLARE_PLATFORM(p9dsu2u) = {
	.name			= "p9dsu2u",
	.probe			= p9dsu2u_probe,
	.init			= astbmc_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &astbmc_smc,
	.pci_get_slot_info	= slot_table_get_slot_info,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= ipmi_wdt_final_reset,
	.terminate		= ipmi_terminate,
};

DECLARE_PLATFORM(p9dsu2uess) = {
	.name			= "p9dsu2uess",
	.probe			= p9dsu2uess_probe,
	.init			= astbmc_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &astbmc_smc,
	.pci_get_slot_info	= slot_table_get_slot_info,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= ipmi_wdt_final_reset,
	.terminate		= ipmi_terminate,
};

