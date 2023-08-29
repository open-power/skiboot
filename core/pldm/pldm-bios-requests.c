// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <opal.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libpldm/bios.h>
#include <libpldm/bios_table.h>
#include "pldm.h"

/*
 * PLDM_BIOS_STRING_TABLE = 0
 * pldmtool bios GetBIOSTable -t 0
 * pldmtool: Tx: 08 01 80 03 01 00 00 00 00 01 00
 *    ...
 *    "60": "hb_lid_ids",
 *    ...
 */
static void *bios_string_table;
static size_t bios_string_length;

/*
 * PLDM_BIOS_ATTR_TABLE = 1
 * pldmtool bios GetBIOSTable -t 1
 * pldmtool: Tx: 08 01 80 03 01 00 00 00 00 01 01
 *
 * {
 *   "AttributeHandle": 8,
 *   "AttributeNameHandle": "60(hb_lid_ids)",
 *   "AttributeType": "BIOSString",
 *   "StringType": "0x01",
 *   "MinimumStringLength": 0,
 *   "MaximumStringLength": 1024,
 *   "DefaultStringLength": 0,
 *   "DefaultString": ""
 * },
 */
static void *bios_attr_table;
static size_t bios_attr_length;

/*
 * PLDM_BIOS_ATTR_VAL_TABLE = 2
 * pldmtool bios GetBIOSTable -t 2
 * pldmtool: Tx: 08 01 80 03 01 00 00 00 00 01 02
 *
 * {
 *   "AttributeHandle": 8,
 *   "AttributeType": "BIOSString",
 *   "CurrentStringLength": 616,
 *   "CurrentString": "ATTR_PERM=81e00663,ATTR_TMP=81e00664, ...
 *                   NVRAM=81e0066b,...,pnor.toc=NA"
 * }, ...
 */
static void *bios_val_table;
static size_t bios_val_length;

static bool bios_ready;

static void bios_init_complete(bool success)
{
	/* Read not successful, error out and free the buffer */
	if (!success) {
		bios_ready = false;

		if (bios_string_table != NULL) {
			free(bios_string_table);
			bios_string_length = 0;
		}
		if (bios_attr_table != NULL) {
			free(bios_attr_table);
			bios_attr_length = 0;
		}
		if (bios_val_table != NULL) {
			free(bios_val_table);
			bios_val_length = 0;
		}
		return;
	}

	/* Mark ready */
	bios_ready = true;
}

/*
 * Send/receive a PLDM GetBIOSTable request message
 */
static int get_bios_table_req(enum pldm_bios_table_types table_type,
			      void **bios_table, size_t *bios_length)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_bios_table_req);
	size_t response_len, payload_len, bios_table_offset;
	uint8_t completion_code, transfer_flag;
	struct pldm_tx_data *tx = NULL;
	uint32_t next_transfer_handle;
	int rc = OPAL_SUCCESS;
	void *response_msg;

	struct pldm_get_bios_table_req bios_table_req = {
		.transfer_handle = 0, /* (0 if transfer op is FIRSTPART) */
		.transfer_op_flag = PLDM_GET_FIRSTPART,
		.table_type = table_type
	};

	prlog(PR_DEBUG, "%s - table type: %d\n", __func__, table_type);

	/* Encode the bios table request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;

	rc = encode_get_bios_table_req(
				DEFAULT_INSTANCE_ID,
				bios_table_req.transfer_handle,
				bios_table_req.transfer_op_flag,
				bios_table_req.table_type,
				(struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetBIOSTableReq Error, type: %d, rc: %d\n",
			      table_type, rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Send and get the response message bytes */
	rc = pldm_requester_queue_and_wait(tx, &response_msg, &response_len);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: GetBIOSTableReq, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	/* Decode the message */
	payload_len = response_len - sizeof(struct pldm_msg_hdr);
	rc = decode_get_bios_table_resp(
				response_msg,
				payload_len,
				&completion_code,
				&next_transfer_handle,
				&transfer_flag,
				&bios_table_offset);
	if (rc != PLDM_SUCCESS || completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode GetBIOSTableResp Error, rc: %d, cc: %d\n",
			      rc, completion_code);
		rc = OPAL_PARAMETER;
		goto out;
	}

	/* we do not support multipart transfer */
	if ((next_transfer_handle != PLDM_GET_NEXTPART) ||
	    (transfer_flag != PLDM_START_AND_END)) {
		prlog(PR_ERR, "Transfert GetBIOSTable not complete "
			      "transfer_hndl: %d, transfer_flag: %d\n",
			      next_transfer_handle,
			      transfer_flag);
	}

	*bios_length = payload_len - bios_table_offset;
	*bios_table = zalloc(*bios_length);
	if (!bios_table) {
		prlog(PR_ERR, "failed to allocate bios table (size: 0x%lx)\n",
			      *bios_length);
		rc = OPAL_NO_MEM;
		goto out;
	}

	memcpy(*bios_table,
	       ((struct pldm_msg *)response_msg)->payload + bios_table_offset,
	       *bios_length);

out:
	free(tx);
	free(response_msg);
	return rc;
}

int pldm_bios_init(void)
{
	int rc;

	/* BIOS String Table is a BIOS table that contains all the BIOS
	 * strings including attribute names, and pre-configured strings
	 * used in representing the values of the attributes.
	 * Each string in the BIOS String Table has an associated unique
	 * handle.
	 */
	rc = get_bios_table_req(PLDM_BIOS_STRING_TABLE,
				&bios_string_table, &bios_string_length);
	if (rc)
		goto err;

	/* BIOS Attribute Table is a BIOS table that contains attribute
	 * name handles, attribute types, type-specific metadata,
	 * type-specific possible values (if any), and default values.
	 */
	rc = get_bios_table_req(PLDM_BIOS_ATTR_TABLE,
				&bios_attr_table, &bios_attr_length);
	if (rc)
		goto err;

	/* BIOS Attribute Value Table is a BIOS table that contains all
	 * the current values of the BIOS attributes and settings.
	 * Each entry in this table contains the attribute handle, the
	 * attribute type, and current values.
	 */
	rc = get_bios_table_req(PLDM_BIOS_ATTR_VAL_TABLE,
				&bios_val_table, &bios_val_length);
	if (rc)
		goto err;

	bios_init_complete(true);
	prlog(PR_DEBUG, "%s - done\n", __func__);

	return OPAL_SUCCESS;

err:
	bios_init_complete(false);
	return rc;
}
