// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <cpu.h>
#include <opal.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libpldm/fru.h>
#include "pldm.h"

static void *fru_record_table;
static size_t fru_record_length;

static bool fru_ready;

static void fru_init_complete(bool success)
{
	/* Read not successful, error out and free the buffer */
	if (!success) {
		fru_ready = false;

		if (fru_record_table != NULL) {
			free(fru_record_table);
			fru_record_length = 0;
		}
		return;
	}

	/* Mark ready */
	fru_ready = true;
}

static int get_fru_record_table_req(void **record_table_data,
				    size_t *record_table_length)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_fru_record_table_req);
	uint8_t transfer_flag, completion_code;
	size_t response_len, payload_len;
	struct pldm_tx_data *tx = NULL;
	uint32_t next_transfer_handle;
	uint8_t *table_data;
	size_t table_length;
	void *response_msg;
	int rc = OPAL_SUCCESS;

	struct pldm_get_fru_record_table_req fru_record_table_req = {
		.data_transfer_handle = 0, /* (0 if operation op is FIRSTPART) */
		.transfer_operation_flag = PLDM_GET_FIRSTPART,
	};
	payload_len = sizeof(struct pldm_get_fru_record_table_req);

	/* Encode the file table request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;

	rc = encode_get_fru_record_table_req(
			DEFAULT_INSTANCE_ID,
			fru_record_table_req.data_transfer_handle,
			fru_record_table_req.transfer_operation_flag,
			(struct pldm_msg *)tx->data,
			payload_len);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetFruRecordTableReq Error, rc: %d\n", rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Send and get the response message bytes */
	rc = pldm_requester_queue_and_wait(tx, &response_msg, &response_len);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: GetFruRecordTableReq, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	/* Decode the message */
	payload_len = response_len - sizeof(struct pldm_msg_hdr);
	table_data = zalloc(payload_len);
	if (!table_data) {
		free(tx);
		return OPAL_NO_MEM;
	}

	rc = decode_get_fru_record_table_resp(
				response_msg,
				payload_len,
				&completion_code,
				&next_transfer_handle,
				&transfer_flag,
				table_data,
				&table_length);
	if (rc != PLDM_SUCCESS || completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode GetFruRecordTableReq Error, rc: %d, cc: %d\n",
			      rc, completion_code);
		rc = OPAL_PARAMETER;
		goto out;
	}

	/* we do not support multipart transfer */
	if ((next_transfer_handle != PLDM_GET_NEXTPART) ||
	    (transfer_flag != PLDM_START_AND_END)) {
		prlog(PR_ERR, "Transfert GetFruRecordTableReq not complete, "
			      "transfer_hndl: %d, transfer_flag: %d\n",
			      next_transfer_handle,
			      transfer_flag);
		rc = OPAL_PARAMETER;
		goto out;
	}

	*record_table_length = table_length;
	*record_table_data = zalloc(table_length);
	if (!record_table_data)
		rc = OPAL_NO_MEM;
	else
		memcpy(*record_table_data, table_data, table_length);

out:
	free(tx);
	free(table_data);
	free(response_msg);
	return rc;
}

int pldm_fru_init(void)
{
	int rc;

	/* get fru record table */
	rc = get_fru_record_table_req(&fru_record_table,
				      &fru_record_length);
	if (rc)
		goto err;

	fru_init_complete(true);
	prlog(PR_DEBUG, "%s - done\n", __func__);

	return OPAL_SUCCESS;

err:
	fru_init_complete(false);
	return rc;
}
