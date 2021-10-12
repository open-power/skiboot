// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020 IBM Corp.
 */

#include <interrupts.h>
#include <pci-slot.h>
#include <phys-map.h>
#include <pau.h>
#include <pau-regs.h>

/* Number of PEs supported */
#define PAU_MAX_PE_NUM		16
#define PAU_RESERVED_PE_NUM	15

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

static void pau_opencapi_assign_bars(struct pau *pau)
{
	struct pau_dev *dev;
	uint64_t addr, size, val;

	/* Global MMIO bar (per pau)
	 * 16M aligned address -> 0x1000000 (bit 24)
	 */
	phys_map_get(pau->chip_id, PAU_REGS, pau->index, &addr, &size);
	val = SETFIELD(PAU_MMIO_BAR_ADDR, 0ull, addr >> 24);
	val |= PAU_MMIO_BAR_ENABLE;
	pau_write(pau, PAU_MMIO_BAR, val);

	PAUINF(pau, "MMIO base: 0x%016llx (%lldMB)\n", addr, size >> 20);
	pau->regs[0] = addr;
	pau->regs[1] = size;

	/* NTL bar (per device)
	 * 64K aligned address -> 0x10000 (bit 16)
	 */
	pau_for_each_dev(dev, pau) {
		if (dev->type == PAU_DEV_TYPE_UNKNOWN)
			continue;

		phys_map_get(pau->chip_id, PAU_OCAPI_MMIO,
			     pau_dev_index(dev, PAU_LINKS_OPENCAPI_PER_PAU),
			     &addr, &size);

		val = SETFIELD(PAU_NTL_BAR_ADDR, 0ull, addr >> 16);
		val = SETFIELD(PAU_NTL_BAR_SIZE, val, ilog2(size >> 16));
		pau_write(pau, PAU_NTL_BAR(dev->index), val);

		val = SETFIELD(PAU_CTL_MISC_MMIOPA_CONFIG_BAR_ADDR, 0ull, addr >> 16);
		val = SETFIELD(PAU_CTL_MISC_MMIOPA_CONFIG_BAR_SIZE, val, ilog2(size >> 16));
		pau_write(pau, PAU_CTL_MISC_MMIOPA_CONFIG(dev->index), val);

		dev->ntl_bar.addr = addr;
		dev->ntl_bar.size = size;
	}

	/* GENID bar (logically divided per device)
	 * 512K aligned address -> 0x80000 (bit 19)
	 */
	phys_map_get(pau->chip_id, PAU_GENID, pau->index, &addr, &size);
	val = SETFIELD(PAU_GENID_BAR_ADDR, 0ull, addr >> 19);
	pau_write(pau, PAU_GENID_BAR, val);

	pau_for_each_dev(dev, pau) {
		if (dev->type == PAU_DEV_TYPE_UNKNOWN)
			continue;

		dev->genid_bar.size = size;
		/* +320K = Bricks 0-4 Config Addr/Data registers */
		dev->genid_bar.cfg = addr + 0x50000;
	}
}

static void pau_opencapi_create_phb_slot(struct pau_dev *dev)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(&dev->phb, NULL);
	if (!slot) {
		/**
		 * @fwts-label OCAPICannotCreatePHBSlot
		 * @fwts-advice Firmware probably ran out of memory creating
		 * PAU slot. OpenCAPI functionality could be broken.
		 */
		PAUDEVERR(dev, "Cannot create PHB slot\n");
	}
}

static int64_t pau_opencapi_pcicfg_check(struct pau_dev *dev,
					 uint32_t offset,
					 uint32_t size)
{
	if (!dev || offset > 0xfff || (offset & (size - 1)))
		return OPAL_PARAMETER;

	return OPAL_SUCCESS;
}

static int64_t pau_opencapi_pcicfg_read(struct phb *phb, uint32_t bdfn,
					uint32_t offset, uint32_t size,
					void *data)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	uint64_t cfg_addr, genid_base;
	int64_t rc;

	rc = pau_opencapi_pcicfg_check(dev, offset, size);
	if (rc)
		return rc;

	/* Config Address for Brick 0 – Offset 0
	 * Config Address for Brick 1 – Offset 256
	 */
	genid_base = dev->genid_bar.cfg + (dev->index << 8);

	cfg_addr = PAU_CTL_MISC_CFG_ADDR_ENABLE;
	cfg_addr = SETFIELD(PAU_CTL_MISC_CFG_ADDR_BUS_NBR |
			    PAU_CTL_MISC_CFG_ADDR_DEVICE_NBR |
			    PAU_CTL_MISC_CFG_ADDR_FUNCTION_NBR,
			    cfg_addr, bdfn);
	cfg_addr = SETFIELD(PAU_CTL_MISC_CFG_ADDR_REGISTER_NBR,
			    cfg_addr, offset & ~3u);

	out_be64((uint64_t *)genid_base, cfg_addr);
	sync();

	switch (size) {
	case 1:
		*((uint8_t *)data) =
			in_8((uint8_t *)(genid_base + 128 + (offset & 3)));
		break;
	case 2:
		*((uint16_t *)data) =
			in_le16((uint16_t *)(genid_base + 128 + (offset & 2)));
		break;
	case 4:
		*((uint32_t *)data) = in_le32((uint32_t *)(genid_base + 128));
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

#define PAU_OPENCAPI_PCI_CFG_READ(size, type)					\
static int64_t pau_opencapi_pcicfg_read##size(struct phb *phb, uint32_t bdfn,	\
					      uint32_t offset, type * data)	\
{										\
	/* Initialize data in case of error */					\
	*data = (type)0xffffffff;						\
	return pau_opencapi_pcicfg_read(phb, bdfn, offset, sizeof(type), data);	\
}

static int64_t pau_opencapi_pcicfg_write(struct phb *phb, uint32_t bdfn,
					 uint32_t offset, uint32_t size,
					 uint32_t data)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	uint64_t genid_base, cfg_addr;
	int64_t rc;

	rc = pau_opencapi_pcicfg_check(dev, offset, size);
	if (rc)
		return rc;

	/* Config Address for Brick 0 – Offset 0
	 * Config Address for Brick 1 – Offset 256
	 */
	genid_base = dev->genid_bar.cfg + (dev->index << 8);

	cfg_addr = PAU_CTL_MISC_CFG_ADDR_ENABLE;
	cfg_addr = SETFIELD(PAU_CTL_MISC_CFG_ADDR_BUS_NBR |
			    PAU_CTL_MISC_CFG_ADDR_DEVICE_NBR |
			    PAU_CTL_MISC_CFG_ADDR_FUNCTION_NBR,
			    cfg_addr, bdfn);
	cfg_addr = SETFIELD(PAU_CTL_MISC_CFG_ADDR_REGISTER_NBR,
			    cfg_addr, offset & ~3u);

	out_be64((uint64_t *)genid_base, cfg_addr);
	sync();

	switch (size) {
	case 1:
		out_8((uint8_t *)(genid_base + 128 + (offset & 3)), data);
		break;
	case 2:
		out_le16((uint16_t *)(genid_base + 128 + (offset & 2)), data);
		break;
	case 4:
		out_le32((uint32_t *)(genid_base + 128), data);
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

#define PAU_OPENCAPI_PCI_CFG_WRITE(size, type)					\
static int64_t pau_opencapi_pcicfg_write##size(struct phb *phb, uint32_t bdfn,	\
						uint32_t offset, type data)	\
{										\
	return pau_opencapi_pcicfg_write(phb, bdfn, offset, sizeof(type), data);\
}

PAU_OPENCAPI_PCI_CFG_READ(8, u8)
PAU_OPENCAPI_PCI_CFG_READ(16, u16)
PAU_OPENCAPI_PCI_CFG_READ(32, u32)
PAU_OPENCAPI_PCI_CFG_WRITE(8, u8)
PAU_OPENCAPI_PCI_CFG_WRITE(16, u16)
PAU_OPENCAPI_PCI_CFG_WRITE(32, u32)

static const struct phb_ops pau_opencapi_ops = {
	.cfg_read8		= pau_opencapi_pcicfg_read8,
	.cfg_read16		= pau_opencapi_pcicfg_read16,
	.cfg_read32		= pau_opencapi_pcicfg_read32,
	.cfg_write8		= pau_opencapi_pcicfg_write8,
	.cfg_write16		= pau_opencapi_pcicfg_write16,
	.cfg_write32		= pau_opencapi_pcicfg_write32,
};

static void pau_opencapi_create_phb(struct pau_dev *dev)
{
	struct phb *phb = &dev->phb;
	uint64_t mm_win[2];

	mm_win[0] = dev->ntl_bar.addr;
	mm_win[1] = dev->ntl_bar.size;

	phb->phb_type = phb_type_pau_opencapi;
	phb->scan_map = 0;

	phb->ops = &pau_opencapi_ops;
	phb->dt_node = dt_new_addr(dt_root, "pciex", mm_win[0]);
	assert(phb->dt_node);

	pci_register_phb(phb, pau_get_opal_id(dev->pau->chip_id,
					      pau_get_phb_index(dev->pau->index, dev->index)));
	pau_opencapi_create_phb_slot(dev);
}

static void pau_opencapi_dt_add_mmio_window(struct pau_dev *dev)
{
	struct dt_node *dn = dev->phb.dt_node;
	uint64_t mm_win[2];

	mm_win[0] = dev->ntl_bar.addr;
	mm_win[1] = dev->ntl_bar.size;
	PAUDEVDBG(dev, "Setting AFU MMIO window to %016llx  %016llx\n",
			mm_win[0], mm_win[1]);

	dt_add_property(dn, "reg", mm_win, sizeof(mm_win));
	dt_add_property(dn, "ibm,mmio-window", mm_win, sizeof(mm_win));
	dt_add_property_cells(dn, "ranges", 0x02000000,
			      hi32(mm_win[0]), lo32(mm_win[0]),
			      hi32(mm_win[0]), lo32(mm_win[0]),
			      hi32(mm_win[1]), lo32(mm_win[1]));
}

static void pau_opencapi_dt_add_props(struct pau_dev *dev)
{
	struct dt_node *dn = dev->phb.dt_node;
	struct pau *pau = dev->pau;

	dt_add_property_strings(dn,
				"compatible",
				"ibm,power10-pau-opencapi-pciex",
				"ibm,ioda3-pau-opencapi-phb",
				"ibm,ioda2-npu2-opencapi-phb");

	dt_add_property_cells(dn, "#address-cells", 3);
	dt_add_property_cells(dn, "#size-cells", 2);
	dt_add_property_cells(dn, "#interrupt-cells", 1);
	dt_add_property_cells(dn, "bus-range", 0, 0xff);
	dt_add_property_cells(dn, "clock-frequency", 0x200, 0);
	dt_add_property_cells(dn, "interrupt-parent", get_ics_phandle());

	dt_add_property_strings(dn, "device_type", "pciex");
	dt_add_property_cells(dn, "ibm,pau-index", pau->index);
	dt_add_property_cells(dn, "ibm,chip-id", pau->chip_id);
	dt_add_property_cells(dn, "ibm,xscom-base", pau->xscom_base);
	dt_add_property_cells(dn, "ibm,npcq", pau->dt_node->phandle);
	dt_add_property_cells(dn, "ibm,links", 1);
	dt_add_property_cells(dn, "ibm,phb-diag-data-size", 0);
	dt_add_property_cells(dn, "ibm,opal-num-pes", PAU_MAX_PE_NUM);
	dt_add_property_cells(dn, "ibm,opal-reserved-pe", PAU_RESERVED_PE_NUM);

	pau_opencapi_dt_add_mmio_window(dev);
}

static void pau_opencapi_init_hw(struct pau *pau)
{
	struct pau_dev *dev = NULL;

	pau_opencapi_assign_bars(pau);

	/* Create phb */
	pau_for_each_opencapi_dev(dev, pau) {
		pau_opencapi_create_phb(dev);
		pau_opencapi_dt_add_props(dev);
	}
}

static void pau_opencapi_init(struct pau *pau)
{
	if (!pau_next_dev(pau, NULL, PAU_DEV_TYPE_OPENCAPI))
		return;

	assert(platform.ocapi);

	pau_opencapi_init_hw(pau);

	disable_fast_reboot("OpenCAPI device enabled");
}

static void pau_init(struct pau *pau)
{
	struct pau_dev *dev;

	platform.pau_device_detect(pau);
	pau_for_each_dev(dev, pau)
		pau_device_detect_fixup(dev);

	pau_opencapi_init(pau);
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
