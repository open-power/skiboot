/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright 2021 IBM Corp.
 */

#include <phys-map.h>
#include <pau.h>
#include <pau-regs.h>

struct pau_dev *pau_next_dev(struct pau *pau, struct pau_dev *dev,
			       enum pau_dev_type type)
{
	uint32_t i = 0;

	if (dev)
		i = dev->index + 1;

	for (; i < pau->links; i++) {
		dev = &pau->devices[i];

		if (dev->type == type || type == PAU_DEV_TYPE_ANY)
			return dev;
	}

	return NULL;
}

static void pau_dt_create_link(struct dt_node *pau, uint32_t pau_index,
			       uint32_t dev_index)
{
	struct dt_node *link;
	uint32_t phy_lane_mask = 0, pau_unit = 0;
	uint32_t op_unit = 0, odl_index = 0;

	link = dt_new_addr(pau, "link", dev_index);

	dt_add_property_string(link, "compatible", "ibm,pau-link");
	dt_add_property_cells(link, "reg", dev_index);
	dt_add_property_cells(link, "ibm,pau-link-index", dev_index);

	/* pau_index	Interface Link - OPxA/B
	 * 0		OPT0 -- PAU0
	 *		OPT1 -- no PAU, SMP only
	 *		OPT2 -- no PAU, SMP only
	 * 1		OPT3 -- PAU3
	 * 2		OPT4 -- PAU4 by default, but can be muxed to use PAU5
	 * 3		OPT5 -- PAU5 by default, but can be muxed to use PAU4
	 * 4		OPT6 -- PAU6 by default, but can be muxed to use PAU7
	 * 5		OPT7 -- PAU7 by default, but can be muxed to use PAU6
	 */
	switch (pau_index) {
	case 0:
		/* OP0A - OP0B */
		pau_unit = 0;
		op_unit = 0;
		break;
	case 1:
		/* OP3A - OP3B */
		pau_unit = 3;
		op_unit = 3;
		break;
	case 2:
		/* OP4A - OP4B or OP5A - OP5B (TO DO) */
		pau_unit = 4;
		op_unit = 4;
		break;
	case 3:
		/* OP5A - OP5B or OP4A - OP4B (TO DO) */
		pau_unit = 5;
		op_unit = 5;
		break;
	case 4:
		/* OP6A - OP6B or OP7A - OP7B (TO DO) */
		pau_unit = 6;
		op_unit = 6;
		break;
	case 5:
		/* OP7A - OP7B or OP6A - OP6B (TO DO) */
		pau_unit = 7;
		op_unit = 7;
		break;
	default:
		return;
	}

	/* ODL0 is hooked up to OTL0 */
	if (dev_index == 0) {
		odl_index = 0;
		phy_lane_mask = PPC_BITMASK32(0, 3);
		phy_lane_mask |= PPC_BITMASK32(5, 8);
	} else if (dev_index == 1) {
		odl_index = 1;
		phy_lane_mask = PPC_BITMASK32(9, 12);
		phy_lane_mask |= PPC_BITMASK32(14, 17);
	}

	dt_add_property_cells(link, "ibm,odl-index", odl_index);
	dt_add_property_cells(link, "ibm,pau-unit", pau_unit);
	dt_add_property_cells(link, "ibm,op-unit", op_unit);
	dt_add_property_cells(link, "ibm,pau-lane-mask", phy_lane_mask);
	dt_add_property_cells(link, "ibm,phb-index", pau_get_phb_index(pau_index, dev_index));
}

static void pau_dt_create_pau(struct dt_node *xscom, uint32_t pau_index)
{
	const uint32_t pau_base[] = { 0x10010800, 0x11010800,
				      0x12010800, 0x12011000,
				      0x13010800, 0x13011000};
	struct dt_node *pau;
	uint32_t links;

	assert(pau_index < PAU_NBR);
	pau = dt_new_addr(xscom, "pau", pau_base[pau_index]);

	dt_add_property_cells(pau, "#size-cells", 0);
	dt_add_property_cells(pau, "#address-cells", 1);
	dt_add_property_cells(pau, "reg", pau_base[pau_index], 0x2c);
	dt_add_property_string(pau, "compatible", "ibm,power10-pau");
	dt_add_property_cells(pau, "ibm,pau-index", pau_index);

	links = PAU_LINKS_OPENCAPI_PER_PAU;
	for (uint32_t i = 0; i < links; i++)
		pau_dt_create_link(pau, pau_index, i);
}

static bool pau_dt_create(void)
{
	struct dt_node *xscom;

	/* P10 chips only */
	if (proc_gen < proc_gen_p10)
		return false;

	dt_for_each_compatible(dt_root, xscom, "ibm,xscom")
		for (uint32_t i = 0; i < PAU_NBR; i++)
			pau_dt_create_pau(xscom, i);

	return true;
}

static struct pau *pau_create(struct dt_node *dn)
{
	struct pau *pau;
	struct dt_node *link;
	struct pau_dev *dev;
	char *path;
	uint32_t i;

	pau = zalloc(sizeof(*pau));
	assert(pau);

	init_lock(&pau->lock);

	pau->dt_node = dn;
	pau->index = dt_prop_get_u32(dn, "ibm,pau-index");
	pau->xscom_base = dt_get_address(dn, 0, NULL);

	pau->chip_id = dt_get_chip_id(dn);
	assert(get_chip(pau->chip_id));

	pau->links = PAU_LINKS_OPENCAPI_PER_PAU;
	dt_for_each_compatible(dn, link, "ibm,pau-link") {
		i = dt_prop_get_u32(link, "ibm,pau-link-index");
		assert(i < PAU_LINKS_OPENCAPI_PER_PAU);

		dev = &pau->devices[i];
		dev->index = i;
		dev->pau = pau;
		dev->dn = link;
		dev->odl_index = dt_prop_get_u32(link, "ibm,odl-index");
		dev->op_unit = dt_prop_get_u32(link, "ibm,op-unit");
		dev->phy_lane_mask = dt_prop_get_u32(link, "ibm,pau-lane-mask");
	};

	path = dt_get_path(dn);
	PAUINF(pau, "Found %s\n", path);
	PAUINF(pau, "SCOM base: 0x%llx\n", pau->xscom_base);
	free(path);

	return pau;
}

static void pau_device_detect_fixup(struct pau_dev *dev)
{
	struct dt_node *dn = dev->dn;

	if (dev->type == PAU_DEV_TYPE_OPENCAPI) {
		PAUDEVDBG(dev, "Link type opencapi\n");
		dt_add_property_strings(dn, "ibm,pau-link-type", "opencapi");
		return;
	}

	PAUDEVDBG(dev, "Link type unknown\n");
	dt_add_property_strings(dn, "ibm,pau-link-type", "unknown");
}

static void pau_init(struct pau *pau)
{
	struct pau_dev *dev;

	platform.pau_device_detect(pau);
	pau_for_each_dev(dev, pau)
		pau_device_detect_fixup(dev);

}

void probe_pau(void)
{
	struct dt_node *dn;
	struct pau *pau;

	/* This can be removed when/if we decide to use HDAT instead */
	if (!pau_dt_create())
		return;

	if (!platform.pau_device_detect) {
		prlog(PR_INFO, "PAU: Platform does not support PAU\n");
		return;
	}

	dt_for_each_compatible(dt_root, dn, "ibm,power10-pau") {
		pau = pau_create(dn);
		pau_init(pau);
	}
}
