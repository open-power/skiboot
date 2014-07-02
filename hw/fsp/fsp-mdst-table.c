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
 * Sapphire dump design:
 *   - During initialization we setup Memory Dump Source Table (MDST) table
 *     which contains address, size pair.
 *   - We send MDST table update notification to FSP via MBOX command.
 *   - During Sapphire checkstop:
 *     - FSP retrieves HWDUMP.
 *     - FSP retrieves CEC memory based on MDST table.
 *   - Once Sapphire reboot FSP sends new dump avialable notification via HDAT
 */

#include <fsp.h>
#include <psi.h>
#include <opal.h>
#include <lock.h>
#include <skiboot.h>
#include <fsp-elog.h>
#include <fsp-mdst-table.h>

/*
 * Sapphire dump size
 *   This is the maximum memory that FSP can retrieve during checkstop.
 *
 * Note:
 *   Presently we are hardcoding this parameter. Eventually we need
 *   new System parameter so that we can get max size dynamically.
 */
#define MAX_SAPPHIRE_DUMP_SIZE	0x1000000

DEFINE_LOG_ENTRY(OPAL_RC_DUMP_MDST_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_DUMP,
		 OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT,
		 OPAL_NA, NULL);

DEFINE_LOG_ENTRY(OPAL_RC_DUMP_MDST_UPDATE, OPAL_PLATFORM_ERR_EVT, OPAL_DUMP,
		 OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA, NULL);


static struct dump_mdst_table *mdst_table;

static int cur_mdst_entry;
static int max_mdst_entry;
static int cur_dump_size;
/*
 * Presently both sizes are same.. But if someday FSP gives more space
 * than our TCE mapping then we need this validation..
 *
 * Also once FSP implements MAX_SAPPHIRE_DUMP_SIZE system param, we can
 * move this validation to separate function.
 */
static int max_dump_size = MIN(MAX_SAPPHIRE_DUMP_SIZE, PSI_DMA_HYP_DUMP_SIZE);

/* Protect MDST table entries */
static struct lock mdst_lock = LOCK_UNLOCKED;

/* Not supported on P7 */
static inline bool fsp_mdst_supported(void)
{
	return proc_gen >= proc_gen_p8;
}

static void update_mdst_table_complete(struct fsp_msg *msg)
{
	uint8_t status = (msg->resp->word1 >> 8) & 0xff;

	if (status)
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_UPDATE),
				 "MDST: MDST table update failed: 0x%x\n",
				 status);
	else
		printf("MDST: Table updated.\n");

	fsp_freemsg(msg);
}

/* Send MDST table to FSP */
static int64_t fsp_update_mdst_table(void)
{
	struct fsp_msg *msg;
	int rc = OPAL_SUCCESS;

	if (cur_mdst_entry <= 0) {
		printf("MDST: Table is empty\n");
		return OPAL_INTERNAL_ERROR;
	}

	lock(&mdst_lock);
	msg = fsp_mkmsg(FSP_CMD_HYP_MDST_TABLE, 4, 0,
			PSI_DMA_MDST_TABLE,
			sizeof(*mdst_table) * cur_mdst_entry,
			sizeof(*mdst_table));
	unlock(&mdst_lock);

	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_UPDATE),
				 "MDST: Message allocation failed.!\n");
		rc = OPAL_INTERNAL_ERROR;
	} else if (fsp_queue_msg(msg, update_mdst_table_complete)) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_UPDATE),
				 "MDST: Failed to queue MDST table message.\n");
		fsp_freemsg(msg);
		rc = OPAL_INTERNAL_ERROR;
	}
	return rc;
}

/* Add entry to MDST table */
static int __mdst_table_add_entry(void *addr, uint32_t type, uint32_t size)
{
	int rc = OPAL_INTERNAL_ERROR;

	lock(&mdst_lock);

	if (!mdst_table)
		goto out;

	if (cur_mdst_entry >= max_mdst_entry) {
		printf("MDST: Table is full.\n");
		goto out;
	}

	/* Make sure we don't cross dump size limit */
	if (cur_dump_size + size > max_dump_size) {
		printf("MDST: %d is crossing max dump size (%d) limit.\n",
		       cur_dump_size + size, max_dump_size);
		goto out;
	}

	/* TCE mapping */
	fsp_tce_map(PSI_DMA_HYP_DUMP + cur_dump_size, addr, ALIGN_UP(size, TCE_PSIZE));

	/* Add entry to MDST table */
	mdst_table[cur_mdst_entry].addr = PSI_DMA_HYP_DUMP + cur_dump_size;
	mdst_table[cur_mdst_entry].type = type;
	mdst_table[cur_mdst_entry].size = size;

	/* Update MDST count and dump size */
	cur_mdst_entry++;
	cur_dump_size += ALIGN_UP(size, TCE_PSIZE);

	printf("MDST: Addr = 0x%llx [size : %d bytes] added to MDST table.\n",
	       (uint64_t)addr, size);

	rc = OPAL_SUCCESS;

out:
	unlock(&mdst_lock);
	return rc;
}

static int mdst_table_add_entries(void)
{
	int rc;

	/* Add console buffer */
	rc = __mdst_table_add_entry((void *)INMEM_CON_START,
				    DUMP_SECTION_CONSOLE, INMEM_CON_LEN);
	if (rc)
		return rc;

	/* Add HBRT buffer */
	rc = __mdst_table_add_entry((void *)HBRT_CON_START,
				    DUMP_SECTION_HBRT_LOG, HBRT_CON_LEN);

	return rc;
}

/* TCE mapping */
static inline void mdst_table_tce_map(void)
{
	fsp_tce_map(PSI_DMA_MDST_TABLE, mdst_table, PSI_DMA_MDST_TABLE_SIZE);
}

/* Initialize MDST table */
static int mdst_table_init(void)
{
	max_mdst_entry = PSI_DMA_MDST_TABLE_SIZE / sizeof(*mdst_table);
	printf("MDST: Max entries in MDST table : %d\n", max_mdst_entry);

	mdst_table = memalign(TCE_PSIZE, PSI_DMA_MDST_TABLE_SIZE);
	if (!mdst_table) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_INIT),
			 "MDST: Failed to allocate memory for MDST table.\n");
		return -ENOMEM;
	}

	memset(mdst_table, 0, PSI_DMA_MDST_TABLE_SIZE);
	mdst_table_tce_map();

	return OPAL_SUCCESS;
}

/*
 * Handle FSP R/R event.
 */
static bool fsp_mdst_update_rr(uint32_t cmd_sub_mod,
			       struct fsp_msg *msg __unused)
{
	switch (cmd_sub_mod) {
	case FSP_RESET_START:
		return true;
	case FSP_RELOAD_COMPLETE: /* Send MDST to FSP */
		fsp_update_mdst_table();
		return true;
	}
	return false;
}

static struct fsp_client fsp_mdst_client_rr = {
	.message = fsp_mdst_update_rr,
};

/* Initialize MDST table and send notification to FSP */
void fsp_mdst_table_init(void)
{
	if (!fsp_present())
		return;

	if (!fsp_mdst_supported())
		return;

	/* Initiate MDST */
	if (mdst_table_init() != OPAL_SUCCESS)
		return;

	/*
	 * Ignore return code from mdst_table_add_entries so that
	 * we can atleast capture partial dump.
	 */
	mdst_table_add_entries();
	fsp_update_mdst_table();

	/* Register for Class AA (FSP R/R) */
	fsp_register_client(&fsp_mdst_client_rr, FSP_MCLASS_RR_EVENT);
}
