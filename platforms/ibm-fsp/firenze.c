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
#include <pci-cfg.h>
#include <chip.h>
#include <hostservices.h>

#include "ibm-fsp.h"
#include "lxvpd.h"

/* Structure used to send PCIe card info to FSP */
struct fsp_pcie_entry {
	uint32_t	hw_proc_id;
	uint16_t	slot_idx;
	uint16_t	reserved;
	uint16_t	vendor_id;
	uint16_t	device_id;
	uint16_t	subsys_vendor_id;
	uint16_t	subsys_device_id;
};

struct fsp_pcie_inventory {
	uint32_t		version; /* currently 1 */
	uint32_t		num_entries;
	uint32_t		entry_size;
	uint32_t		entry_offset;
	struct fsp_pcie_entry	entries[];
};

static struct fsp_pcie_inventory *fsp_pcie_inv;
static unsigned int fsp_pcie_inv_alloc_count;
#define FSP_PCIE_INV_ALLOC_CHUNK	4

static struct dt_node *dt_create_i2c_master(struct dt_node *n, uint32_t eng_id)
{
	struct dt_node *i2cm;

	/* Each master registers set is of length 0x20 */
	i2cm = dt_new_addr(n, "i2cm", 0xa0000 + eng_id * 0x20);
	if (!i2cm)
		return NULL;

	dt_add_property_string(i2cm, "compatible",
			       "ibm,power8-i2cm");
	dt_add_property_cells(i2cm, "reg", 0xa0000 + eng_id * 0x20,
			      0x20);
	dt_add_property_cells(i2cm, "clock-frequency", 50000000);
	dt_add_property_cells(i2cm, "chip-engine#", eng_id);
	dt_add_property_cells(i2cm, "#address-cells", 1);
	dt_add_property_cells(i2cm, "#size-cells", 0);

	return i2cm;
}

static struct dt_node *dt_create_i2c_bus(struct dt_node *i2cm,
					 const char *port_name, uint32_t port_id)
{
	static struct dt_node *port;

	port = dt_new_addr(i2cm, "i2c-bus", port_id);
	if (!port)
		return NULL;

	dt_add_property_strings(port, "compatible", "ibm,power8-i2c-port",
				"ibm,opal-i2c");
	dt_add_property_string(port, "ibm,port-name", port_name);
	dt_add_property_cells(port, "reg", port_id);
	dt_add_property_cells(port, "bus-frequency", 400000);
	dt_add_property_cells(port, "#address-cells", 1);
	dt_add_property_cells(port, "#size-cells", 0);

	return port;
}

static struct dt_node *dt_create_i2c_device(struct dt_node *bus, uint8_t addr,
					    const char *name, const char *compat,
					    const char *label)
{
	struct dt_node *dev;

	dev = dt_new_addr(bus, name, addr);
	if (!dev)
		return NULL;

	dt_add_property_string(dev, "compatible", compat);
	dt_add_property_string(dev, "label", label);
	dt_add_property_cells(dev, "reg", addr);
	dt_add_property_string(dev, "status", "reserved");

	return dev;
}

static void firenze_dt_fixup_i2cm(void)
{
	struct dt_node *master, *bus, *dev;
	struct proc_chip *c;
	const uint32_t *p;
	char name[32];
	uint64_t lx;

	if (dt_find_compatible_node(dt_root, NULL, "ibm,power8-i2cm"))
		return;

	p = dt_prop_get_def(dt_root, "ibm,vpd-lx-info", NULL);
	if (!p)
		return;

	lx = ((uint64_t)p[1] << 32) | p[2];

	switch (lx) {
	case LX_VPD_2S4U_BACKPLANE:
	case LX_VPD_2S2U_BACKPLANE:
	case LX_VPD_SHARK_BACKPLANE: /* XXX confirm ? */
		/* i2c nodes on chip 0x10 */
		c = get_chip(0x10);
		if (c) {
			/* Engine 1 */
			master = dt_create_i2c_master(c->devnode, 1);
			assert(master);
			snprintf(name, sizeof(name), "p8_%08x_e%dp%d", c->id, 1, 0);
			bus = dt_create_i2c_bus(master, name, 0);
			assert(bus);
			dev = dt_create_i2c_device(bus, 0x39, "power-control",
						   "maxim,5961", "pcie-hotplug");
			assert(dev);
			dt_add_property_strings(dev, "target-list", "slot-C4",
						"slot-C5");

			dev = dt_create_i2c_device(bus, 0x3a, "power-control",
						   "maxim,5961", "pcie-hotplug");
			assert(dev);
			dt_add_property_strings(dev, "target-list", "slot-C2",
						"slot-C3");
		} else {
			prlog(PR_INFO, "PLAT: Chip not found for the id 0x10\n");
		}

	/* Fall through */
	case LX_VPD_1S4U_BACKPLANE:
	case LX_VPD_1S2U_BACKPLANE:
		/* i2c nodes on chip 0 */
		c = get_chip(0);
		if (!c) {
			prlog(PR_INFO, "PLAT: Chip not found for the id 0x0\n");
			break;
		}

		/* Engine 1*/
		master = dt_create_i2c_master(c->devnode, 1);
		assert(master);
		snprintf(name, sizeof(name), "p8_%08x_e%dp%d", c->id, 1, 0);
		bus = dt_create_i2c_bus(master, name, 0);
		assert(bus);
		dev = dt_create_i2c_device(bus, 0x32, "power-control",
					   "maxim,5961", "pcie-hotplug");
		assert(dev);
		dt_add_property_strings(dev, "target-list", "slot-C10", "slot-C11");

		dev = dt_create_i2c_device(bus, 0x35, "power-control",
					   "maxim,5961", "pcie-hotplug");
		assert(dev);
		dt_add_property_strings(dev, "target-list", "slot-C6", "slot-C7");

		dev = dt_create_i2c_device(bus, 0x36, "power-control",
					   "maxim,5961", "pcie-hotplug");
		assert(dev);
		dt_add_property_strings(dev, "target-list", "slot-C8", "slot-C9");

		dev = dt_create_i2c_device(bus, 0x39, "power-control", "maxim,5961",
					   "pcie-hotplug");
		assert(dev);
		dt_add_property_strings(dev, "target-list", "slot-C12");
		break;
	default:
		break;
	}
}

static bool firenze_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,firenze"))
		return false;

	firenze_dt_fixup_i2cm();

	return true;
}

static void firenze_send_pci_inventory(void)
{
	uint64_t base, abase, end, aend, offset;
	int64_t rc;

	if (!fsp_pcie_inv)
		return;

	prlog(PR_DEBUG, "PLAT: Sending PCI inventory to FSP, table has"
	      " %d entries\n",
	      fsp_pcie_inv->num_entries);

	{
		unsigned int i;

		prlog(PR_DEBUG, "HWP SLT VDID DVID SVID SDID\n");
		prlog(PR_DEBUG, "---------------------------\n");
		for (i = 0; i < fsp_pcie_inv->num_entries; i++) {
			struct fsp_pcie_entry *e = &fsp_pcie_inv->entries[i];

			prlog(PR_DEBUG, "%03d %03d %04x %04x %04x %04x\n",
			      e->hw_proc_id, e->slot_idx,
			      e->vendor_id, e->device_id,
			      e->subsys_vendor_id, e->subsys_device_id);
		}
	}

	/*
	 * Get the location of the table in a form we can send
	 * to the FSP
	 */
	base = (uint64_t)fsp_pcie_inv;
	end = base + sizeof(struct fsp_pcie_inventory) +
		fsp_pcie_inv->num_entries * fsp_pcie_inv->entry_size;
	abase = base & ~0xffful;
	aend = (end + 0xffful) & ~0xffful;
	offset = PSI_DMA_PCIE_INVENTORY + (base & 0xfff);

	/* We can only accomodate so many entries in the PSI map */
	if ((aend - abase) > PSI_DMA_PCIE_INVENTORY_SIZE) {
		prerror("PLAT: PCIe inventory too large (%lld bytes)\n",
			aend - abase);
		goto bail;
	}

	/* Map this in the TCEs */
	fsp_tce_map(PSI_DMA_PCIE_INVENTORY, (void *)abase, aend - abase);

	/* Send FSP message */
	rc = fsp_sync_msg(fsp_mkmsg(FSP_CMD_PCI_POWER_CONF, 3,
				    hi32(offset), lo32(offset),
				    end - base), true);
	if (rc)
		prerror("PLAT: FSP error %lld sending inventory\n", rc);

	/* Unmap */
	fsp_tce_unmap(PSI_DMA_PCIE_INVENTORY, aend - abase);
 bail:
	/*
	 * We free the inventory. We'll have to redo that on hotplug
	 * when we support it but that isn't the case yet
	 */
	free(fsp_pcie_inv);
	fsp_pcie_inv = NULL;
}

static void firenze_add_pcidev_to_fsp_inventory(struct phb *phb,
						struct pci_device *pd)
{
	struct fsp_pcie_entry *entry;
	struct proc_chip *chip;

	/* Check if we need to do some (Re)allocation */
	if (!fsp_pcie_inv ||
	    fsp_pcie_inv->num_entries == fsp_pcie_inv_alloc_count) {
		unsigned int new_count;
		size_t new_size;
		bool need_init = !fsp_pcie_inv;

		/* (Re)allocate the block to the new size */
		new_count = fsp_pcie_inv_alloc_count + FSP_PCIE_INV_ALLOC_CHUNK;
		new_size = sizeof(struct fsp_pcie_inventory);
		new_size += sizeof(struct fsp_pcie_entry) * new_count;
		fsp_pcie_inv = realloc(fsp_pcie_inv, new_size);
		fsp_pcie_inv_alloc_count = new_count;

		/* Initialize the header for a new inventory */
		if (need_init) {
			fsp_pcie_inv->version = 1;
			fsp_pcie_inv->num_entries = 0;
			fsp_pcie_inv->entry_size =
				sizeof(struct fsp_pcie_entry);
			fsp_pcie_inv->entry_offset =
				offsetof(struct fsp_pcie_inventory, entries);
		}
	}

	/* Add entry */
	entry = &fsp_pcie_inv->entries[fsp_pcie_inv->num_entries++];
	chip = get_chip(dt_get_chip_id(phb->dt_node));
	if (!chip) {
		prerror("PLAT: Failed to get chip for PHB !\n");
		return;
	}
	entry->hw_proc_id = chip->pcid;
	entry->slot_idx = pd->parent->slot_info->slot_index;
	entry->reserved = 0;
	pci_cfg_read16(phb, pd->bdfn, PCI_CFG_VENDOR_ID, &entry->vendor_id);
	pci_cfg_read16(phb, pd->bdfn, PCI_CFG_DEVICE_ID, &entry->device_id);
	if (pd->is_bridge) {
		int64_t ssvc = pci_find_cap(phb, pd->bdfn,
					    PCI_CFG_CAP_ID_SUBSYS_VID);
		if (ssvc < 0) {
			entry->subsys_vendor_id = 0xffff;
			entry->subsys_device_id = 0xffff;
		} else {
			pci_cfg_read16(phb, pd->bdfn,
				       ssvc + PCICAP_SUBSYS_VID_VENDOR,
				       &entry->subsys_vendor_id);
			pci_cfg_read16(phb, pd->bdfn,
				       ssvc + PCICAP_SUBSYS_VID_DEVICE,
				       &entry->subsys_device_id);
		}
	} else {
		pci_cfg_read16(phb, pd->bdfn, PCI_CFG_SUBSYS_VENDOR_ID,
			       &entry->subsys_vendor_id);
		pci_cfg_read16(phb, pd->bdfn, PCI_CFG_SUBSYS_ID,
			       &entry->subsys_device_id);
	}
}

static void firenze_get_slot_info(struct phb *phb, struct pci_device * pd)
{
	/* Call the main LXVPD function first */
	lxvpd_get_slot_info(phb, pd);

	/*
	 * Do we need to add that to the FSP inventory for power management ?
	 *
	 * For now, we only add devices that:
	 *
	 *  - Are function 0
	 *  - Are not an RC or a downstream bridge
	 *  - Have a direct parent that has a slot entry
	 *  - Slot entry says pluggable
	 *  - Aren't an upstream switch that has slot info
	 */
	if (!pd || !pd->parent)
		return;
	if (pd->bdfn & 7)
		return;
	if (pd->dev_type == PCIE_TYPE_ROOT_PORT ||
	    pd->dev_type == PCIE_TYPE_SWITCH_DNPORT)
		return;
	if (pd->dev_type == PCIE_TYPE_SWITCH_UPPORT &&
	    pd->slot_info)
		return;
	if (!pd->parent->slot_info)
		return;
	if (!pd->parent->slot_info->pluggable)
		return;
	firenze_add_pcidev_to_fsp_inventory(phb, pd);
}

static void firenze_setup_phb(struct phb *phb, unsigned int index)
{
	uint32_t hub_id;

	/* Grab Hub ID used to parse VPDs */
	hub_id = dt_prop_get_u32_def(phb->dt_node, "ibm,hub-id", 0);

	/* Process the pcie slot entries from the lx vpd lid */
	lxvpd_process_slot_entries(phb, dt_root, hub_id, index);
}

static uint32_t ibm_fsp_occ_timeout(void)
{
	/* Use a fixed 60s value for now */
	return 60;
}

static void firenze_init(void)
{
	/* We call hservices_init to relocate the hbrt image now, as the FSP
	 * may request an OCC load any time after ibm_fsp_init.
	 */
	hservices_init();

	ibm_fsp_init();

	/* Preload hostservices lids */
	hservices_lid_preload();

}

DECLARE_PLATFORM(firenze) = {
	.name			= "Firenze",
	.probe			= firenze_probe,
	.init			= firenze_init,
	.exit			= ibm_fsp_exit,
	.cec_power_down		= ibm_fsp_cec_power_down,
	.cec_reboot		= ibm_fsp_cec_reboot,
	.pci_setup_phb		= firenze_setup_phb,
	.pci_get_slot_info	= firenze_get_slot_info,
	.pci_probe_complete	= firenze_send_pci_inventory,
	.nvram_info		= fsp_nvram_info,
	.nvram_start_read	= fsp_nvram_start_read,
	.nvram_write		= fsp_nvram_write,
	.occ_timeout		= ibm_fsp_occ_timeout,
	.elog_commit		= elog_fsp_commit,
	.load_resource		= fsp_load_resource,
} ;
