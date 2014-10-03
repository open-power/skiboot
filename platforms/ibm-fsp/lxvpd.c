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
/*
 * LXVPD support
 *
 */


#include <skiboot.h>
#include <device.h>
#include <vpd.h>
#include <pci.h>
#include <pci-cfg.h>

#include "lxvpd.h"

/*
 * XXX TODO: Add 1006 maps to add function loc codes and loc code maps
 * (ie. -Tn part of the location code) 
 */
struct lxvpd_slot_info_data {
	uint8_t			num_slots;
	struct pci_slot_info	info[];
};

static bool lxvpd_supported_slot(struct phb *phb, struct pci_device *pd)
{
	/* PCI/PCI-X we only support top level PHB with NULL "pd" */
	if (phb->phb_type < phb_type_pcie_v1)
		return pd == NULL;

	/* Now we have PCI Express, we should never have a NULL "pd" */
	if (!pd)
		return false;

	/* We support the root complex at the top level */
	if (pd->dev_type == PCIE_TYPE_ROOT_PORT && !pd->parent)
		return true;

	/* We support an upstream switch port below the root complex */
	if (pd->dev_type == PCIE_TYPE_SWITCH_UPPORT &&
	    pd->parent && pd->parent->dev_type == PCIE_TYPE_ROOT_PORT &&
	    !pd->parent->parent)
		return true;

	/* We support a downstream switch port below an upstream port
	 * below the root complex
	 */
	if (pd->dev_type == PCIE_TYPE_SWITCH_DNPORT &&
	    pd->parent && pd->parent->dev_type == PCIE_TYPE_SWITCH_UPPORT &&
	    pd->parent->parent &&
	    pd->parent->parent->dev_type == PCIE_TYPE_ROOT_PORT &&
	    !pd->parent->parent->parent)
		return true;

	/* Anything else, bail */
	return false;
}

void lxvpd_get_slot_info(struct phb *phb, struct pci_device * pd)
{
	struct lxvpd_slot_info_data *sdata = phb->platform_data;
	bool is_phb = (pd && pd->parent) ? false : true;
	bool entry_found = false;
	uint8_t idx;

	/* Check if we have slot info */
	if (!sdata)
		return;

	prlog(PR_TRACE, "LXVPD: Get Slot Info PHB%d pd=%x\n", phb->opal_id,
	    pd ? pd->bdfn : 0);

	/*
	 * This code only handles PHBs and PCIe switches at the top level.
	 *
	 * We do not handle any other switch nor any other type of PCI/PCI-X
	 * bridge.
	 */
	if (!lxvpd_supported_slot(phb, pd)) {
		prlog(PR_TRACE, "LXVPD: Unsupported slot\n");
		return;
	}

	/* Iterate the slot map */
	for (idx = 0; idx <= sdata->num_slots; idx++) {
		struct pci_slot_info *info = &sdata->info[idx];
		uint8_t pd_dev = (pd->bdfn >> 3) & 0x1f;

		/* Match PHB with switch_id == 0 */
		if (is_phb && info->switch_id == 0) {
			entry_found = true;
			break;
		}

		/* Match switch port with switch_id != 0 */
		if (!is_phb && info->switch_id !=0 && info->dev_id == pd_dev) {
			entry_found = true;
			break;
		}
	}

	if (entry_found) {
		pd->slot_info = &sdata->info[idx];
		prlog(PR_TRACE, "PCI: PCIE Slot Info: \n"
		      "       Label       %s\n"
		      "       Pluggable   0x%x\n"
		      "       Power Ctl   0x%x\n"
		      "       Wired Lanes 0x%x\n"
		      "       Bus Clock   0x%x\n"
		      "       Connector   0x%x\n"
		      "       Slot Index  %d\n",
		      pd->slot_info->label,
		      pd->slot_info->pluggable?1:0,
		      pd->slot_info->power_ctl?1:0,
		      pd->slot_info->wired_lanes,
		      pd->slot_info->bus_clock,
		      pd->slot_info->connector_type,
		      pd->slot_info->slot_index);
	} else {
		prlog(PR_TRACE, "PCI: PCIE Slot Info Not Found\n");
	}
}

static struct pci_slot_info *lxvpd_alloc_slot_info(struct phb *phb, int count)
{
	struct lxvpd_slot_info_data *data;

	data = zalloc(sizeof(struct lxvpd_slot_info_data) *
		      count * sizeof(struct pci_slot_info));
	assert(data);
	data->num_slots = count;
	phb->platform_data = data;

	return data->info;
}

static void lxvpd_parse_1004_map(struct phb *phb, const uint8_t *sm, uint8_t sz)
{
	const struct pci_slot_entry_1004 *entry = NULL;
	struct pci_slot_info *slot_info, *info;
	uint8_t num_slots, slot, idx;

	num_slots = (sz / sizeof(struct pci_slot_entry_1004));
	slot_info = lxvpd_alloc_slot_info(phb, num_slots);

	/* Iterate thru the entries in the keyword */
	entry = (const struct pci_slot_entry_1004 *)sm;
	for (slot = 0; slot < num_slots; slot++) {
		info = &slot_info[slot];

		/* Put slot info into pci device structure */
		info->switch_id = entry->pba >> 4;
		info->vswitch_id = entry->pba &0xf;
		info->dev_id = entry->sba;
		for (idx = 0; idx < 3; idx++)
			info->label[idx] = entry->label[idx];
		info->label[3] = 0;
		info->pluggable = ((entry->p0.byte & 0x20) == 0);
		info->power_ctl = ((entry->p0.power_ctl & 0x40) == 1);
		switch(entry->p1.wired_lanes) {
		case 1: info->wired_lanes = PCI_SLOT_WIRED_LANES_PCIX_32; break;
		case 2: /* fall through */
		case 3: info->wired_lanes = PCI_SLOT_WIRED_LANES_PCIX_64; break;
		case 4: info->wired_lanes = PCI_SLOT_WIRED_LANES_PCIE_X1; break;
		case 5: info->wired_lanes = PCI_SLOT_WIRED_LANES_PCIE_X4; break;
		case 6: info->wired_lanes = PCI_SLOT_WIRED_LANES_PCIE_X8; break;
		case 7: info->wired_lanes = PCI_SLOT_WIRED_LANES_PCIE_X16; break;
		default:
			info->wired_lanes = PCI_SLOT_WIRED_LANES_UNKNOWN;
		}
		info->wired_lanes = (entry->p1.wired_lanes - 3);
		info->bus_clock = (entry->p2.bus_clock - 4);
		info->connector_type = (entry->p2.connector_type - 5);
		if (entry->p3.byte < 0xC0)
			info->card_desc = ((entry->p3.byte >> 6) - 4) ;
		else
			info->card_desc = (entry->p3.byte >> 6);
		info->card_mech = ((entry->p3.byte >> 4) & 0x3);
		info->pwr_led_ctl = ((entry->p3.byte & 0xF) >> 2);
		info->attn_led_ctl = (entry->p3.byte & 0x3);
		info->slot_index = entry->slot_index;
		entry++;
	}
}

static void lxvpd_parse_1005_map(struct phb *phb, const uint8_t *sm, uint8_t sz)
{
	const struct pci_slot_entry_1005 *entry = NULL;
	struct pci_slot_info *slot_info, *info;
	uint8_t num_slots, slot, idx;

	num_slots = (sz / sizeof(struct pci_slot_entry_1005));
	slot_info = lxvpd_alloc_slot_info(phb, num_slots);

	/* Iterate thru the entries in the keyword */
	entry = (const struct pci_slot_entry_1005 *)sm;
	for (slot = 0; slot < num_slots; slot++) {
		info = &slot_info[slot];

		/* Put slot info into pci device structure */
		info->switch_id = entry->pba >> 4;
		info->vswitch_id = entry->pba &0xf;
		info->dev_id = entry->switch_device_id;
		for (idx = 0; idx < 8; idx++)
			info->label[idx] = entry->label[idx];
		info->label[8] = 0;
		info->pluggable = (entry->p0.pluggable == 0);
		info->power_ctl = entry->p0.power_ctl;
		info->wired_lanes = entry->p1.wired_lanes;
		if (info->wired_lanes > PCI_SLOT_WIRED_LANES_PCIE_X32)
			info->wired_lanes = PCI_SLOT_WIRED_LANES_UNKNOWN;
		info->bus_clock = entry->p2.bus_clock;
		info->connector_type = entry->p2.connector_type;
		info->card_desc = (entry->p3.byte >> 6);
		info->card_mech = ((entry->p3.byte >> 4) & 0x3);
		info->pwr_led_ctl = ((entry->p3.byte & 0xF) >> 2);
		info->attn_led_ctl = (entry->p3.byte & 0x3);
		info->slot_index = entry->slot_index;
		entry++;
	}
}

void lxvpd_process_slot_entries(struct phb *phb,
				struct dt_node *node,
				uint8_t chip_id,
				uint8_t index)
{
	const void *lxvpd;
	const uint8_t *pr_rec, *pr_end, *sm;
	size_t lxvpd_size, pr_size;
	const uint16_t *mf = NULL;
	char record[5] = "PR00";
	uint8_t mf_sz, sm_sz;
	bool found = false;

	record[2] += chip_id;
	record[3] += index;
	record[4] = 0;

	/* Get LX VPD pointer */
	lxvpd = dt_prop_get_def_size(node, "ibm,io-vpd", NULL, &lxvpd_size);
	if (!lxvpd) {
		printf("LXVPD: LX VPD not found for %s in %p\n",
		       record, phb->dt_node);
		return;
	}

	pr_rec = vpd_find_record(lxvpd, lxvpd_size, record, &pr_size);
	if (!pr_rec) {
		printf("LXVPD: %s record not found in LX VPD in %p\n",
		       record, phb->dt_node);
		return;
	}
	pr_end = pr_rec + pr_size;

	prlog(PR_TRACE, "LXVPD: %s record for PHB%d is %ld bytes\n",
	      record, phb->opal_id, pr_size);

	/* As long as there's still something in the PRxy record... */
	while(pr_rec < pr_end) {
		pr_size = pr_end - pr_rec;

		/* Find the next MF keyword */
		mf = vpd_find_keyword(pr_rec, pr_size, "MF", &mf_sz);
		/* And the corresponding SM */
		sm = vpd_find_keyword(pr_rec, pr_size, "SM", &sm_sz);
		if (!mf || !sm) {
			if (!found)
				printf("LXVPD: Slot Map keyword %s not found\n",
				       record);
			return;
		}
		prlog(PR_TRACE, "LXVPD: Found 0x%04x map...\n", *mf);

		switch (*mf) {
		case 0x1004:
			lxvpd_parse_1004_map(phb, sm + 1, sm_sz - 1);
			found = true;
			break;
		case 0x1005:
			lxvpd_parse_1005_map(phb, sm + 1, sm_sz - 1);
			found = true;
			break;
			/* Add support for 0x1006 maps ... */
		}
		pr_rec = sm + sm_sz;
	}
}

