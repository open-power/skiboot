// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <opal.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libpldm/file_io.h>
#include "pldm.h"

/* list of lid files available */
static void *file_attr_table;
static size_t file_attr_length;

static bool file_io_ready;

static void file_io_init_complete(bool success)
{
	/* Read not successful, error out and free the buffer */
	if (!success) {
		file_io_ready = false;

		if (file_attr_table != NULL) {
			free(file_attr_table);
			file_attr_length = 0;
		}
		return;
	}

	/* Mark ready */
	file_io_ready = true;
}

/*
 * Send/receive a PLDM GetFileTable request message.
 * The file table contains the list of files available and
 * their attributes.
 *
 * Ex:
 * {
 *   "FileHandle": "11",
 *   "FileNameLength": 12,
 *   "FileName": "81e0066b.lid",
 *   "FileSize": 589824,
 *   "FileTraits": 6
 * },
 */
static int get_file_table_req(void)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_file_table_req);
	size_t response_len, payload_len;
	uint8_t file_table_data_start_offset;
	uint8_t transfer_flag, completion_code;
	struct pldm_tx_data *tx = NULL;
	uint32_t next_transfer_handle;
	void *response_msg;
	int rc = OPAL_SUCCESS;

	struct pldm_get_file_table_req file_table_req = {
		.transfer_handle = 0, /* (0 if operation op is FIRSTPART) */
		.operation_flag = PLDM_GET_FIRSTPART,
		.table_type = PLDM_FILE_ATTRIBUTE_TABLE,
	};

	prlog(PR_DEBUG, "%s - GetFileReq\n", __func__);

	/* Encode the file table request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;

	rc = encode_get_file_table_req(
			DEFAULT_INSTANCE_ID,
			file_table_req.transfer_handle,
			file_table_req.operation_flag,
			file_table_req.table_type,
			(struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetFileReq Error, rc: %d\n", rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Send and get the response message bytes */
	rc = pldm_requester_queue_and_wait(tx,
					   &response_msg, &response_len);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: GetFileReq, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	/* Decode the message */
	payload_len = response_len - sizeof(struct pldm_msg_hdr);
	rc = decode_get_file_table_resp(
				response_msg,
				payload_len,
				&completion_code,
				&next_transfer_handle,
				&transfer_flag,
				&file_table_data_start_offset,
				&file_attr_length);
	if (rc != PLDM_SUCCESS || completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode GetFileResp Error, rc: %d, cc: %d\n",
			      rc, completion_code);
		rc = OPAL_PARAMETER;
		goto out;
	}

	/* we do not support multipart transfer */
	if ((next_transfer_handle != PLDM_GET_NEXTPART) ||
	    (transfer_flag != PLDM_START_AND_END)) {
		prlog(PR_ERR, "Transfert GetFileResp not complete, "
			      "transfer_hndl: %d, transfer_flag: %d\n",
			      next_transfer_handle,
			      transfer_flag);
	}

	file_attr_table = zalloc(file_attr_length);
	if (!file_attr_table) {
		rc = OPAL_NO_MEM;
		goto out;
	}

	memcpy(file_attr_table,
	       ((struct pldm_msg *)response_msg)->payload +
	       file_table_data_start_offset,
	       file_attr_length);

out:
	free(tx);
	free(response_msg);
	return rc;
}

int pldm_file_io_init(void)
{
	int rc;

	/* PLDM GetFileTable request */
	rc = get_file_table_req();
	if (rc)
		goto err;

	file_io_init_complete(true);
	prlog(PR_DEBUG, "%s - done\n", __func__);

	return OPAL_SUCCESS;

err:
	file_io_init_complete(false);
	return rc;
}
