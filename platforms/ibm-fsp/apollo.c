/* Copyright 2013-2014 IBM Corp.
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

#include "ibm-fsp.h"
#include "lxvpd.h"

static bool apollo_probe(void)
{
	return dt_node_is_compatible(dt_root, "ibm,apollo");
}

static void apollo_setup_phb(struct phb *phb, unsigned int index)
{
	struct dt_node *ioc_node;

	/* Grab the device-tree node of the IOC */
	ioc_node = phb->dt_node->parent;
	if (!ioc_node)
		return;

	/*
	 * Process the pcie slot entries from the lx vpd lid
	 *
	 * FIXME: We currently assume chip 1 always, this will have to be
	 * fixed once we understand the right way to get the BRxy/BRxy "x"
	 * "x" value. (this actually seems to work...)
	 */
	lxvpd_process_slot_entries(phb, ioc_node, 1, index);
}

DECLARE_PLATFORM(apollo) = {
	.name			= "Apollo",
	.probe			= apollo_probe,
	.init			= ibm_fsp_init,
	.cec_power_down		= ibm_fsp_cec_power_down,
	.cec_reboot		= ibm_fsp_cec_reboot,
	.pci_setup_phb		= apollo_setup_phb,
	.pci_get_slot_info	= lxvpd_get_slot_info,
	.nvram_info		= fsp_nvram_info,
	.nvram_start_read	= fsp_nvram_start_read,
	.nvram_write		= fsp_nvram_write,
	.elog_commit		= elog_fsp_commit,
	.load_resource		= fsp_load_resource,
};
