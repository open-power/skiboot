/* Copyright 2013-2018 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <skiboot.h>
#include <xscom.h>
#include <pci.h>
#include <npu2.h>
#include <npu2-regs.h>
#include <bitutils.h>
#include <nvram.h>

enum npu2_dev_type npu2_dt_link_dev_type(struct dt_node *link)
{
	const char *link_type = dt_prop_get(link, "ibm,npu-link-type") ?:
		"unknown";
	if (streq(link_type, "nvlink")) {
		return NPU2_DEV_TYPE_NVLINK;
	} else if (streq(link_type, "opencapi")) {
		return NPU2_DEV_TYPE_OPENCAPI;
	} else {
		return NPU2_DEV_TYPE_UNKNOWN;
	}
}

/*
 * We use the indirect method because it uses the same addresses as
 * the MMIO offsets (NPU RING)
 */
static void npu2_scom_set_addr(uint64_t gcid, uint64_t scom_base,
			       uint64_t addr, uint64_t size)
{
	addr = SETFIELD(NPU2_MISC_DA_ADDR, 0ull, addr);
	addr = SETFIELD(NPU2_MISC_DA_LEN, addr, size);
	xscom_write(gcid, scom_base + NPU2_MISC_SCOM_IND_SCOM_ADDR, addr);
}

void npu2_scom_write(uint64_t gcid, uint64_t scom_base,
		     uint64_t reg, uint64_t size,
		     uint64_t val)
{
	npu2_scom_set_addr(gcid, scom_base, reg, size);
	xscom_write(gcid, scom_base + NPU2_MISC_SCOM_IND_SCOM_DATA, val);
}

uint64_t npu2_scom_read(uint64_t gcid, uint64_t scom_base,
			uint64_t reg, uint64_t size)
{
	uint64_t val;

	npu2_scom_set_addr(gcid, scom_base, reg, size);
	xscom_read(gcid, scom_base + NPU2_MISC_SCOM_IND_SCOM_DATA, &val);

	return val;
}

void npu2_write_4b(struct npu2 *p, uint64_t reg, uint32_t val)
{
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_4B,
			(uint64_t)val << 32);
}

uint32_t npu2_read_4b(struct npu2 *p, uint64_t reg)
{
	return npu2_scom_read(p->chip_id, p->xscom_base, reg,
			      NPU2_MISC_DA_LEN_4B) >> 32;
}

void npu2_write(struct npu2 *p, uint64_t reg, uint64_t val)
{
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_8B, val);
}

uint64_t npu2_read(struct npu2 *p, uint64_t reg)
{
	return npu2_scom_read(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_8B);
}

void npu2_write_mask(struct npu2 *p, uint64_t reg, uint64_t val, uint64_t mask)
{
	uint64_t new_val;

	new_val = npu2_read(p, reg);
	new_val &= ~mask;
	new_val |= val & mask;
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_8B, new_val);
}

void npu2_write_mask_4b(struct npu2 *p, uint64_t reg, uint32_t val, uint32_t mask)
{
	uint32_t new_val;

	new_val = npu2_read_4b(p, reg);
	new_val &= ~mask;
	new_val |= val & mask;
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_4B,
			(uint64_t)new_val << 32);
}

static struct npu2 *setup_npu(struct dt_node *dn)
{
	struct npu2 *npu;
	struct npu2_dev *dev;
	struct dt_node *np;
	uint32_t num_links;
	void *npumem;
	char *path;
	int gcid;
	struct proc_chip *chip;
	int i = 0;

	/* Retrieve chip ID */
	path = dt_get_path(dn);
	gcid = dt_get_chip_id(dn);
	chip = get_chip(gcid);
	assert(chip);

	num_links = dt_prop_get_u32(dn, "ibm,npu-links");
	npumem = zalloc(sizeof(struct npu2) + num_links *
			sizeof(struct npu2_dev));
	assert(npumem);
	npu = npumem;

	npu->dt_node = dn;
	npu->index = dt_prop_get_u32(dn, "ibm,npu-index");
	npu->chip_id = gcid;
	npu->xscom_base = dt_get_address(dn, 0, NULL);
	npu->phb_index = dt_prop_get_u32(dn, "ibm,phb-index");
	npu->devices = npumem + sizeof(struct npu2);

	dt_for_each_compatible(dn, np, "ibm,npu-link") {
		assert(i < num_links);
		dev = &npu->devices[i];
		dev->link_index = dt_prop_get_u32(np, "ibm,npu-link-index");
		/* May be overridden by platform presence detection */
		dev->brick_index = dev->link_index;
		dev->type = npu2_dt_link_dev_type(np);
		dev->npu = npu;
		dev->dt_node = np;
		dev->pl_xscom_base = dt_prop_get_u64(np, "ibm,npu-phy");
		dev->lane_mask = dt_prop_get_u32(np, "ibm,npu-lane-mask");
		dev->link_speed = dt_prop_get_u64(np, "ibm,link-speed");
		i++;
	};
	npu->total_devices = i;

	prlog(PR_INFO, "NPU: Chip %d Found NPU2#%d (%d links) at %s\n",
	      npu->chip_id, npu->index, npu->total_devices, path);
	prlog(PR_INFO, "   SCOM Base:  %08llx\n", npu->xscom_base);
	free(path);
	return npu;
}

static void setup_devices(struct npu2 *npu)
{
	bool nvlink_detected = false, ocapi_detected = false;
	struct npu2_dev *dev;

	/*
	 * TODO: In future, we'll do brick configuration here to support mixed
	 * setups.
	 */
	for (int i = 0; i < npu->total_devices; i++) {
		dev = &npu->devices[i];
		switch (dev->type) {
		case NPU2_DEV_TYPE_NVLINK:
			nvlink_detected = true;
			break;
		case NPU2_DEV_TYPE_OPENCAPI:
			ocapi_detected = true;
			break;
		default:
			prlog(PR_INFO, "NPU: Link %d device not present\n",
			      npu->devices[i].link_index);
		}
	}

	if (nvlink_detected && ocapi_detected) {
		prlog(PR_ERR, "NPU: NVLink and OpenCAPI devices on same chip not supported, aborting NPU init\n");
		return;
	}

	if (nvlink_detected)
		npu2_nvlink_init_npu(npu);
	else if (ocapi_detected)
		npu2_opencapi_init_npu(npu);
}

void probe_npu2(void)
{
	struct proc_chip *chip = next_chip(NULL);
	struct npu2 *npu;
	struct dt_node *np;
	const char *zcal;

	/* Abort if we're running on DD1 */
	if (chip &&
	    (chip->type == PROC_CHIP_P9_NIMBUS ||
	     chip->type == PROC_CHIP_P9_CUMULUS) &&
	    (chip->ec_level & 0xf0) == 0x10) {
		prlog(PR_INFO, "NPU2: DD1 not supported\n");
		return;
	}

	/* Check for a zcal override */
	zcal = nvram_query("nv_zcal_override");
	if (zcal) {
		nv_zcal_nominal = atoi(zcal);
		prlog(PR_WARNING, "NPU2: Using ZCAL impedance override = %d\n", nv_zcal_nominal);
	}

	dt_for_each_compatible(dt_root, np, "ibm,power9-npu") {
	        npu = setup_npu(np);
		setup_devices(npu);
	}
}
