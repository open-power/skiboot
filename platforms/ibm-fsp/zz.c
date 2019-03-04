/* Copyright 2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
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
#include <fsp.h>
#include <pci.h>
#include <pci-cfg.h>
#include <chip.h>
#include <i2c.h>
#include <timebase.h>
#include <hostservices.h>
#include <npu2.h>

#include "ibm-fsp.h"
#include "lxvpd.h"

/* We don't yet create NPU device nodes on ZZ, but these values are correct */
static const struct platform_ocapi zz_ocapi = {
	.i2c_engine          = 1,
	.i2c_port            = 4,
	.i2c_reset_addr      = 0x20,
	.i2c_reset_brick2    = (1 << 1),
	.i2c_reset_brick3    = (1 << 6),
	.i2c_reset_brick4    = 0, /* unused */
	.i2c_reset_brick5    = 0, /* unused */
	.i2c_presence_addr   = 0x20,
	.i2c_presence_brick2 = (1 << 2), /* bottom connector */
	.i2c_presence_brick3 = (1 << 7), /* top connector */
	.i2c_presence_brick4 = 0, /* unused */
	.i2c_presence_brick5 = 0, /* unused */
	.odl_phy_swap        = true,
};

static bool zz_probe(void)
{
	/* FIXME: make this neater when the dust settles */
	if (dt_node_is_compatible(dt_root, "ibm,zz-1s2u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-1s4u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-2s2u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-2s4u"))
		return true;

	return false;
}

static uint32_t ibm_fsp_occ_timeout(void)
{
	/* Use a fixed 60s value for now */
	return 60;
}

static void zz_init(void)
{
	hservices_init();
	ibm_fsp_init();
}

DECLARE_PLATFORM(zz) = {
	.name			= "ZZ",
	.probe			= zz_probe,
	.init			= zz_init,
	.exit			= ibm_fsp_exit,
	.cec_power_down		= ibm_fsp_cec_power_down,
	.cec_reboot		= ibm_fsp_cec_reboot,
	.pci_setup_phb		= firenze_pci_setup_phb,
	.pci_get_slot_info	= firenze_pci_get_slot_info,
	.pci_probe_complete	= firenze_pci_send_inventory,
	.nvram_info		= fsp_nvram_info,
	.nvram_start_read	= fsp_nvram_start_read,
	.nvram_write		= fsp_nvram_write,
	.occ_timeout		= ibm_fsp_occ_timeout,
	.elog_commit		= elog_fsp_commit,
	.start_preload_resource	= fsp_start_preload_resource,
	.resource_loaded	= fsp_resource_loaded,
	.sensor_read		= ibm_fsp_sensor_read,
	.terminate		= ibm_fsp_terminate,
	.ocapi			= &zz_ocapi,
	.npu2_device_detect	= npu2_i2c_presence_detect,
};
