/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define pr_fmt(fmt)	"DUMP: " fmt

#include <device.h>
#include <mem-map.h>
#include <mem_region.h>
#include <mem_region-malloc.h>
#include <opal.h>
#include <opal-dump.h>
#include <opal-internal.h>
#include <skiboot.h>

#include <ccan/endian/endian.h>

#include "hdata/spira.h"

/* Actual address of MDST and MDDT table */
#define MDST_TABLE_BASE		(SKIBOOT_BASE + MDST_TABLE_OFF)
#define MDDT_TABLE_BASE		(SKIBOOT_BASE + MDDT_TABLE_OFF)

static struct spira_ntuple *ntuple_mdst;
static struct spira_ntuple *ntuple_mddt;
static struct spira_ntuple *ntuple_mdrt;

static struct mpipl_metadata    *mpipl_metadata;

static int opal_mpipl_add_entry(u8 region, u64 src, u64 dest, u64 size)
{
	int i, max_cnt;
	struct mdst_table *mdst;
	struct mddt_table *mddt;

	max_cnt = MDST_TABLE_SIZE / sizeof(struct mdst_table);
	if (ntuple_mdst->act_cnt >= max_cnt) {
		prlog(PR_DEBUG, "MDST table is full\n");
		return OPAL_RESOURCE;
	}

	max_cnt = MDDT_TABLE_SIZE / sizeof(struct mddt_table);
	if (ntuple_mdst->act_cnt >= max_cnt) {
		prlog(PR_DEBUG, "MDDT table is full\n");
		return OPAL_RESOURCE;
	}

	/* Use relocated memory address */
	mdst = (void *)(MDST_TABLE_BASE);
	mddt = (void *)(MDDT_TABLE_BASE);

	/* Check for duplicate entry */
	for (i = 0; i < ntuple_mdst->act_cnt; i++) {
		if (mdst->addr == (src | HRMOR_BIT)) {
			prlog(PR_DEBUG,
			      "Duplicate source address : 0x%llx", src);
			return OPAL_PARAMETER;
		}
		mdst++;
	}
	for (i = 0; i < ntuple_mddt->act_cnt; i++) {
		if (mddt->addr == (dest | HRMOR_BIT)) {
			prlog(PR_DEBUG,
			      "Duplicate destination address : 0x%llx", dest);
			return OPAL_PARAMETER;
		}
		mddt++;
	}

	/* Add OPAL source address to MDST entry */
	mdst->addr = src | HRMOR_BIT;
	mdst->data_region = region;
	mdst->size = size;
	ntuple_mdst->act_cnt++;

	/* Add OPAL destination address to MDDT entry */
	mddt->addr = dest | HRMOR_BIT;
	mddt->data_region = region;
	mddt->size = size;
	ntuple_mddt->act_cnt++;

	prlog(PR_TRACE, "Added new entry. src : 0x%llx, dest : 0x%llx,"
	      " size : 0x%llx\n", src, dest, size);
	return OPAL_SUCCESS;
}

/* Remove entry from source (MDST) table */
static int opal_mpipl_remove_entry_mdst(bool remove_all, u8 region, u64 src)
{
	bool found = false;
	int i, j;
	struct mdst_table *tmp_mdst;
	struct mdst_table *mdst = (void *)(MDST_TABLE_BASE);

	for (i = 0; i < ntuple_mdst->act_cnt;) {
		if (mdst->data_region != region) {
			mdst++;
			i++;
			continue;
		}

		if (remove_all != true && mdst->addr != (src | HRMOR_BIT)) {
			mdst++;
			i++;
			continue;
		}

		tmp_mdst = mdst;
		memset(tmp_mdst, 0, sizeof(struct mdst_table));

		for (j = i; j < ntuple_mdst->act_cnt - 1; j++) {
			memcpy((void *)tmp_mdst,
			       (void *)(tmp_mdst + 1), sizeof(struct mdst_table));
			tmp_mdst++;
			memset(tmp_mdst, 0, sizeof(struct mdst_table));
		}

		ntuple_mdst->act_cnt--;

		if (remove_all == false) {
			found = true;
			break;
		}
	}  /* end - for loop */

	if (remove_all == false && found == false) {
		prlog(PR_DEBUG,
		      "Source address [0x%llx] not found in MDST table\n", src);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

/* Remove entry from destination (MDDT) table */
static int opal_mpipl_remove_entry_mddt(bool remove_all, u8 region, u64 dest)
{
	bool found = false;
	int i, j;
	struct mddt_table *tmp_mddt;
	struct mddt_table *mddt = (void *)(MDDT_TABLE_BASE);

	for (i = 0; i < ntuple_mddt->act_cnt;) {
		if (mddt->data_region != region) {
			mddt++;
			i++;
			continue;
		}

		if (remove_all != true && mddt->addr != (dest | HRMOR_BIT)) {
			mddt++;
			i++;
			continue;
		}

		tmp_mddt = mddt;
		memset(tmp_mddt, 0, sizeof(struct mddt_table));

		for (j = i; j < ntuple_mddt->act_cnt - 1; j++) {
			memcpy((void *)tmp_mddt,
			       (void *)(tmp_mddt + 1), sizeof(struct mddt_table));
			tmp_mddt++;
			memset(tmp_mddt, 0, sizeof(struct mddt_table));
		}

		ntuple_mddt->act_cnt--;

		if (remove_all == false) {
			found = true;
			break;
		}
	}  /* end - for loop */

	if (remove_all == false && found == false) {
		prlog(PR_DEBUG,
		      "Dest address [0x%llx] not found in MDDT table\n", dest);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

/* Register for OPAL dump.  */
static void opal_mpipl_register(void)
{
	u64 opal_dest, opal_size;

	/* Get OPAL runtime size */
	if (!dt_find_property(opal_node, "opal-runtime-size")) {
		prlog(PR_DEBUG, "Could not get OPAL runtime size\n");
		return;
	}
	opal_size = dt_prop_get_u64(opal_node, "opal-runtime-size");
	if (!opal_size) {
		prlog(PR_DEBUG, "OPAL runtime size is zero\n");
		return;
	}

	/* Calculate and reserve OPAL dump destination memory */
	opal_dest = SKIBOOT_BASE + opal_size;
	mem_reserve_fw("ibm,firmware-dump", opal_dest, opal_size);

	/* Add OPAL reservation detail to MDST/MDDT table */
	opal_mpipl_add_entry(DUMP_REGION_OPAL_MEMORY,
			     SKIBOOT_BASE, opal_dest, opal_size);
}

static int payload_mpipl_register(u64 src, u64 dest, u64 size)
{
	if (!opal_addr_valid((void *)src)) {
		prlog(PR_DEBUG, "Invalid source address [0x%llx]\n", src);
		return OPAL_PARAMETER;
	}

	if (!opal_addr_valid((void *)dest)) {
		prlog(PR_DEBUG, "Invalid dest address [0x%llx]\n", dest);
		return OPAL_PARAMETER;
	}

	if (size <= 0) {
		prlog(PR_DEBUG, "Invalid size [0x%llx]\n", size);
		return OPAL_PARAMETER;
	}

	return opal_mpipl_add_entry(DUMP_REGION_KERNEL, src, dest, size);
}

static int payload_mpipl_unregister(u64 src, u64 dest)
{
	int rc;

	/* Remove src from MDST table */
	rc = opal_mpipl_remove_entry_mdst(false, DUMP_REGION_KERNEL, src);
	if (rc)
		return rc;

	/* Remove dest from MDDT table */
	rc = opal_mpipl_remove_entry_mddt(false, DUMP_REGION_KERNEL, dest);
	return rc;
}

static int payload_mpipl_unregister_all(void)
{
	opal_mpipl_remove_entry_mdst(true, DUMP_REGION_KERNEL, 0);
	opal_mpipl_remove_entry_mddt(true, DUMP_REGION_KERNEL, 0);

	return OPAL_SUCCESS;
}

static int64_t opal_mpipl_update(enum opal_mpipl_ops ops,
				 u64 src, u64 dest, u64 size)
{
	int rc;

	switch (ops) {
	case OPAL_MPIPL_ADD_RANGE:
		rc = payload_mpipl_register(src, dest, size);
		if (!rc)
			prlog(PR_NOTICE, "Payload registered for MPIPL\n");
		break;
	case OPAL_MPIPL_REMOVE_RANGE:
		rc = payload_mpipl_unregister(src, dest);
		if (!rc) {
			prlog(PR_NOTICE, "Payload removed entry from MPIPL."
			      "[src : 0x%llx, dest : 0x%llx]\n", src, dest);
		}
		break;
	case OPAL_MPIPL_REMOVE_ALL:
		rc = payload_mpipl_unregister_all();
		if (!rc)
			prlog(PR_NOTICE, "Payload unregistered for MPIPL\n");
		break;
	case OPAL_MPIPL_FREE_PRESERVED_MEMORY:
		/* Clear MDRT table */
		memset((void *)MDRT_TABLE_BASE, 0, MDRT_TABLE_SIZE);
		/* Set MDRT count to max allocated count */
		ntuple_mdrt->act_cnt = MDRT_TABLE_SIZE / sizeof(struct mdrt_table);
		rc = OPAL_SUCCESS;
		prlog(PR_NOTICE, "Payload Invalidated MPIPL\n");
		break;
	default:
		prlog(PR_DEBUG, "Unsupported MPIPL update operation : 0x%x\n", ops);
		rc = OPAL_PARAMETER;
		break;
	}

	return rc;
}

void opal_mpipl_init(void)
{
	void *mdst_base = (void *)MDST_TABLE_BASE;
	void *mddt_base = (void *)MDDT_TABLE_BASE;
	struct dt_node *dump_node;

	dump_node = dt_find_by_path(opal_node, "dump");
	if (!dump_node)
		return;

	/* Get MDST and MDDT ntuple from SPIRAH */
	ntuple_mdst = &(spirah.ntuples.mdump_src);
	ntuple_mddt = &(spirah.ntuples.mdump_dst);
	ntuple_mdrt = &(spirah.ntuples.mdump_res);

	/* Get metadata area pointer */
	mpipl_metadata = (void *)(DUMP_METADATA_AREA_BASE);

	/* Clear OPAL metadata area */
	if (sizeof(struct mpipl_metadata) > DUMP_METADATA_AREA_SIZE) {
		prlog(PR_ERR, "INSUFFICIENT OPAL METADATA AREA\n");
		prlog(PR_ERR, "INCREASE OPAL MEDTADATA AREA SIZE\n");
		assert(false);
	}
	memset(mpipl_metadata, 0, sizeof(struct mpipl_metadata));

	/* Clear MDST and MDDT table */
	memset(mdst_base, 0, MDST_TABLE_SIZE);
	ntuple_mdst->act_cnt = 0;
	memset(mddt_base, 0, MDDT_TABLE_SIZE);
	ntuple_mddt->act_cnt = 0;

	opal_mpipl_register();

	/* OPAL API for MPIPL update */
	opal_register(OPAL_MPIPL_UPDATE, opal_mpipl_update, 4);
}
