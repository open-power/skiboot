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
