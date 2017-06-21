/* Copyright 2015 IBM Corp.
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
#include <console.h>
#include <chip.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>

#include "astbmc.h"

static const struct slot_table_entry *slot_top_table;

void slot_table_init(const struct slot_table_entry *top_table)
{
	slot_top_table = top_table;
}

static const struct slot_table_entry *match_slot_phb_entry(struct phb *phb)
{
	uint32_t chip_id = dt_get_chip_id(phb->dt_node);
	uint32_t phb_idx = dt_prop_get_u32_def(phb->dt_node,
					       "ibm,phb-index", 0);
	const struct slot_table_entry *ent;

	if (!slot_top_table)
		return NULL;

	for (ent = slot_top_table; ent->etype != st_end; ent++) {
		if (ent->etype != st_phb) {
			prerror("SLOT: Bad DEV entry type in table !\n");
			continue;
		}
		if (ent->location == ST_LOC_PHB(chip_id, phb_idx))
			return ent;
	}
	return NULL;
}

static const struct slot_table_entry *match_slot_dev_entry(struct phb *phb,
							   struct pci_device *pd)
{
	const struct slot_table_entry *parent, *ent;
	uint32_t bdfn;

	/* Find a parent recursively */
	if (pd->parent)
		parent = match_slot_dev_entry(phb, pd->parent);
	else {
		/* No parent, this is a root complex, find the PHB */
		parent = match_slot_phb_entry(phb);
	}
	/* No parent ? Oops ... */
	if (!parent || !parent->children)
		return NULL;
	for (ent = parent->children; ent->etype != st_end; ent++) {
		if (ent->etype == st_phb) {
			prerror("SLOT: Bad PHB entry type in table !\n");
			continue;
		}

		/* NPU slots match on device, not function */
		if (ent->etype == st_npu_slot)
			bdfn = pd->bdfn & 0xf8;
		else
			bdfn = pd->bdfn & 0xffff;

		if (ent->location == bdfn)
			return ent;
	}
	return NULL;
}

static void add_slot_properties(struct pci_slot *slot,
				struct dt_node *np)
{
	struct phb *phb = slot->phb;
	struct pci_device *pd = slot->pd;
	struct slot_table_entry *ent = slot->data;
	size_t base_loc_code_len, slot_label_len;
	char label[8], loc_code[LOC_CODE_SIZE];

	if (!np)
		return;

	if (ent) {
		dt_add_property_string(np, "ibm,slot-label", ent->name);
		slot_label_len = strlen(ent->name);
	} else {
		snprintf(label, 8, "S%04x%02x", phb->opal_id, pd->secondary_bus);
		dt_add_property_string(np, "ibm,slot-label", label);
		slot_label_len = strlen(label);
	}

	base_loc_code_len = phb->base_loc_code ? strlen(phb->base_loc_code) : 0;
	if ((base_loc_code_len + slot_label_len + 1) >= LOC_CODE_SIZE)
		return;

	/* Location code */
	if (phb->base_loc_code) {
		strcpy(loc_code, phb->base_loc_code);
		strcat(loc_code, "-");
	} else {
		loc_code[0] = '\0';
	}

	if (ent)
		strcat(loc_code, ent->name);
	else
		strcat(loc_code, label);
	dt_add_property(np, "ibm,slot-location-code",
			loc_code, strlen(loc_code) + 1);
}

static void init_slot_info(struct pci_slot *slot, bool pluggable, void *data)
{
	slot->data = data;
	slot->ops.add_properties = add_slot_properties;

	slot->pluggable      = pluggable;
	slot->power_ctl      = false;
	slot->wired_lanes    = PCI_SLOT_WIRED_LANES_UNKNOWN;
	slot->connector_type = PCI_SLOT_CONNECTOR_PCIE_NS;
	slot->card_desc      = PCI_SLOT_DESC_NON_STANDARD;
	slot->card_mech      = PCI_SLOT_MECH_NONE;
	slot->power_led_ctl  = PCI_SLOT_PWR_LED_CTL_NONE;
	slot->attn_led_ctl   = PCI_SLOT_ATTN_LED_CTL_NONE;
}

static void create_dynamic_slot(struct phb *phb, struct pci_device *pd)
{
	uint32_t ecap, val;
	struct pci_slot *slot;

	if (!phb || !pd || pd->slot)
		return;

	/* Try to create slot whose details aren't provided by platform.
	 * We only care the downstream ports of PCIe switch that connects
	 * to root port.
	 */
	if (pd->dev_type != PCIE_TYPE_SWITCH_DNPORT ||
	    !pd->parent || !pd->parent->parent ||
	    pd->parent->parent->parent)
		return;

	ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
	pci_cfg_read32(phb, pd->bdfn, ecap + PCICAP_EXP_SLOTCAP, &val);
	if (!(val & PCICAP_EXP_SLOTCAP_HPLUG_CAP))
		return;

	slot = pcie_slot_create(phb, pd);
	assert(slot);
	init_slot_info(slot, true, NULL);

	/* On superMicro's "p8dnu" platform, we create dynamic PCI slots
	 * for all downstream ports of PEX9733 that is connected to PHB
	 * direct slot. The power supply to the PCI slot is lost after
	 * PCI adapter is removed from it. The power supply can't be
	 * turned on when the slot is in empty state. The power supply
	 * isn't turned on automatically when inserting PCI adapter to
	 * the slot at later point. We set a flag to the slot here, to
	 * turn on the power supply in (suprise or managed) hot-add path.
	 *
	 * We have same issue with PEX8718 as above on "p8dnu" platform.
	 */
	if (dt_node_is_compatible(dt_root, "supermicro,p8dnu") && slot->pd &&
	    (slot->pd->vdid == 0x973310b5 || slot->pd->vdid == 0x871810b5))
		pci_slot_add_flags(slot, PCI_SLOT_FLAG_FORCE_POWERON);
}

void slot_table_get_slot_info(struct phb *phb, struct pci_device *pd)
{
	const struct slot_table_entry *ent;
	struct pci_slot *slot;
	bool pluggable;

	if (!pd || pd->slot)
		return;
	ent = match_slot_dev_entry(phb, pd);
	if (!ent || !ent->name) {
		create_dynamic_slot(phb, pd);
		return;
	}

	slot = pcie_slot_create(phb, pd);
	assert(slot);

	pluggable = !!(ent->etype == st_pluggable_slot);
	init_slot_info(slot, pluggable, (void *)ent);
}

static int __pci_find_dev_by_location(struct phb *phb,
				      struct pci_device *pd, void *userdata)
{
	uint16_t location = *((uint16_t *)userdata);

	if (!phb || !pd)
		return 0;

	if ((pd->bdfn & 0xff) == location)
		return 1;

	return 0;
}

static struct pci_device *pci_find_dev_by_location(struct phb *phb, uint16_t location)
{
	return pci_walk_dev(phb, NULL, __pci_find_dev_by_location, &location);
}

static struct phb* get_phb_by_location(uint32_t location)
{
	struct phb *phb = NULL;
	uint32_t chip_id, phb_idx;

	for_each_phb(phb) {
		chip_id = dt_get_chip_id(phb->dt_node);
		phb_idx = dt_prop_get_u32_def(phb->dt_node,
					      "ibm,phb-index", 0);
		if (location == ST_LOC_PHB(chip_id, phb_idx))
			break;
	}

	return phb;
}

static int check_slot_table(struct phb *phb,
			    const struct slot_table_entry *parent)
{
	const struct slot_table_entry *ent;
	struct pci_device *dev = NULL;
	int r = 0;

	if (parent == NULL)
		return 0;

	for (ent = parent; ent->etype != st_end; ent++) {
		switch (ent->etype) {
		case st_phb:
			phb = get_phb_by_location(ent->location);
			if (!phb) {
				prlog(PR_ERR, "PCI: PHB %s (%x) not found\n",
				      ent->name, ent->location);
				r++;
			}
			break;
		case st_pluggable_slot:
		case st_builtin_dev:
			if (!phb)
				break;
			phb_lock(phb);
			dev = pci_find_dev_by_location(phb, ent->location);
			phb_unlock(phb);
			if (!dev) {
				prlog(PR_ERR, "PCI: built-in device not found: %s (loc: %x)\n",
				      ent->name, ent->location);
				r++;
			}
			break;
		case st_end:
		case st_npu_slot:
			break;
		}
		if (ent->children)
			r+= check_slot_table(phb, ent->children);
	}
	return r;
}

void check_all_slot_table(void)
{
	if (!slot_top_table)
		return;

	prlog(PR_DEBUG, "PCI: Checking slot table against detected devices\n");
	check_slot_table(NULL, slot_top_table);
}
