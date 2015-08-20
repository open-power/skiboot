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
#include <pci.h>

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
		if (ent->location == (pd->bdfn & 0xff))
			return ent;
	}
	return NULL;
}

void slot_table_get_slot_info(struct phb *phb, struct pci_device * pd)
{
	const struct slot_table_entry *ent;
	struct pci_slot_info *si;

	if (!pd || pd->slot_info)
		return;
	ent = match_slot_dev_entry(phb, pd);
	if (!ent || !ent->name)
		return;
	pd->slot_info = si = zalloc(sizeof(struct pci_slot_info));
	assert(pd->slot_info);
	strncpy(si->label, ent->name, sizeof(si->label) - 1);
	si->pluggable = ent->etype == st_pluggable_slot;
	si->power_ctl = false;
	si->wired_lanes = -1;
	si->bus_clock = -1;
	si->connector_type = -1;
	si->card_desc = -1;
	si->card_mech = -1;
	si->pwr_led_ctl = -1;
	si->attn_led_ctl = -1;
}
