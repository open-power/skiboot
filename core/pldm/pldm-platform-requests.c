// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <cpu.h>
#include <opal.h>
#include <stdio.h>
#include <string.h>
#include <timebase.h>
#include <inttypes.h>
#include <libpldm/entity.h>
#include <libpldm/pdr.h>
#include <libpldm/state_set.h>
#include <libpldm/platform.h>
#include "pldm.h"

#define NO_MORE_PDR_HANDLES 0

static pldm_pdr *pdrs_repo;
static bool pdr_ready;

struct pldm_pdrs {
	struct pldm_tx_data *tx;
	uint32_t record_hndl;
	bool done;
	int rc;
};

struct pldm_pdrs *pdrs;

static void pdr_init_complete(bool success)
{
	/* Read not successful, error out and free the buffer */
	if (!success) {
		pdr_ready = false;

		if (pdrs_repo)
			pldm_pdr_destroy(pdrs_repo);
		return;
	}

	/* Mark ready */
	pdr_ready = true;
}

/*
 * Search the matching record and return the effecter id.
 * PDR type = PLDM_STATE_EFFECTER_PDR
 */
static int find_effecter_id_by_state_set_Id(uint16_t entity_type,
					    uint16_t state_set_id,
					    uint16_t *effecter_id,
					    uint16_t terminus_handle)
{
	struct state_effecter_possible_states *possible_states;
	struct pldm_state_effecter_pdr *state_effecter_pdr;
	const pldm_pdr_record *record = NULL;
	uint8_t *outData = NULL;
	uint32_t size;

	do {
		/* Find (first) PDR record by PLDM_STATE_EFFECTER_PDR type
		 * if record not NULL, then search will begin from this
		 * record's next record
		 */
		record = pldm_pdr_find_record_by_type(
				pdrs_repo, /* PDR repo handle */
				PLDM_STATE_EFFECTER_PDR,
				record, /* PDR record handle */
				&outData, &size);

		if (record) {
			state_effecter_pdr = (struct pldm_state_effecter_pdr *) outData;

			*effecter_id = le16_to_cpu(state_effecter_pdr->effecter_id);

			possible_states = (struct state_effecter_possible_states *)
				state_effecter_pdr->possible_states;

			if ((le16_to_cpu(state_effecter_pdr->entity_type) == entity_type) &&
			    (le16_to_cpu(state_effecter_pdr->terminus_handle) == terminus_handle) &&
			    (le16_to_cpu(possible_states->state_set_id) == state_set_id))
				return OPAL_SUCCESS;
		}

	} while (record);

	return OPAL_PARAMETER;
}

struct set_effecter_state_response {
	uint8_t completion_code;
};

/*
 * Create and send a PLDM request message for SetStateEffecterStates.
 */
static int set_state_effecter_states_req(uint16_t effecter_id,
					 set_effecter_state_field *field,
					 bool no_timeout)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_set_state_effecter_states_req);
	struct set_effecter_state_response response;
	size_t response_len, payload_len;
	struct pldm_tx_data *tx = NULL;
	void *response_msg;
	int rc;

	struct pldm_set_state_effecter_states_req states_req = {
		.effecter_id = effecter_id,
		.comp_effecter_count = 1
	};

	/* Encode the state effecter states request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;

	rc = encode_set_state_effecter_states_req(
			DEFAULT_INSTANCE_ID,
			states_req.effecter_id,
			states_req.comp_effecter_count,
			field,
			(struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode SetStateEffecter Error, rc: %d\n",
			      rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Send and get the response message bytes.
	 * It may happen that for some commands, the responder does not
	 * have time to respond.
	 */
	if (no_timeout) {
		rc = pldm_mctp_message_tx(tx);
		if (rc)
			prlog(PR_ERR, "Failed to send SetStateEffecter request, rc = %d\n", rc);
		free(tx);
		return rc;
	}

	/* Send and get the response message bytes */
	rc = pldm_requester_queue_and_wait(tx, &response_msg, &response_len);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: SetStateEffecter, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	/* Decode the message */
	payload_len = response_len - sizeof(struct pldm_msg_hdr);

	rc = decode_set_state_effecter_states_resp(
				response_msg,
				payload_len,
				&response.completion_code);
	if (rc != PLDM_SUCCESS || response.completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode SetStateEffecter Error, rc: %d, cc: %d\n",
			      rc, response.completion_code);
		free(tx);
		free(response_msg);
		return OPAL_PARAMETER;
	}

	free(tx);
	free(response_msg);
	return OPAL_SUCCESS;
}

/*
 * entity_type:  System Firmware
 * state_set:    Software Termination Status(129)
 * states:       Graceful Restart Requested(6)
 */
int pldm_platform_restart(void)
{
	set_effecter_state_field field;
	uint16_t effecter_id;
	int rc;

	if (!pdr_ready)
		return OPAL_HARDWARE;

	rc = find_effecter_id_by_state_set_Id(
				PLDM_ENTITY_SYS_FIRMWARE,
				PLDM_STATE_SET_SW_TERMINATION_STATUS,
				&effecter_id, BMC_TID);
	if (rc) {
		prlog(PR_ERR, "%s - effecter id not found\n", __func__);
		return rc;
	}

	field.set_request = PLDM_REQUEST_SET;
	field.effecter_state = PLDM_SW_TERM_GRACEFUL_RESTART_REQUESTED;

	prlog(PR_INFO, "sending system firmware Graceful Restart request (effecter_id: %d)\n",
			effecter_id);

	return set_state_effecter_states_req(effecter_id, &field, true);
}

struct get_pdr_response {
	uint8_t completion_code;
	uint32_t next_record_hndl;
	uint32_t next_data_transfer_hndl;
	uint8_t transfer_flag;
	uint16_t resp_cnt;
	uint8_t *record_data;
	size_t record_data_length;
	uint8_t transfer_crc;
};

static int encode_and_queue_get_pdr_req(struct pldm_pdrs *pdrs);

static void get_pdr_req_complete(struct pldm_rx_data *rx,
				 void *data)
{
	struct pldm_pdrs *pdrs = (struct pldm_pdrs *)data;
	uint32_t record_hndl = pdrs->record_hndl;
	struct get_pdr_response response;
	size_t payload_len;
	int rc, i;

	prlog(PR_DEBUG, "%s - record_hndl: %d\n", __func__, record_hndl);

	if (rx == NULL) {
		pdrs->rc = OPAL_PARAMETER;
		pdrs->done = true;
	}

	/* Decode the message twice; the first time, the payload buffer
	 * will be null so that the decoder will simply tell us how big
	 * the buffer should be. Then we create a suitable payload
	 * buffer and call the decoder again, this time with the real
	 * buffer so that it can fill it with data from the message.
	 *
	 * transfer_crc is not used in case of PLDM_START_AND_END.
	 */
	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);
	response.record_data_length = 0;
	response.record_data = NULL;

	for (i = 0; i < 2; i++) {
		rc = decode_get_pdr_resp(
				rx->msg, payload_len,
				&response.completion_code,
				&response.next_record_hndl,
				&response.next_data_transfer_hndl,
				&response.transfer_flag,
				&response.resp_cnt,
				response.record_data,
				response.record_data_length,
				&response.transfer_crc);

		if (rc != PLDM_SUCCESS || response.completion_code != PLDM_SUCCESS) {
			/* Message decoding failed */
			prlog(PR_ERR, "Decode GetPDRResp Error (rc: %d, cc: %d)\n",
				      rc, response.completion_code);

			/* BMC is not ready, try again. This behavior can be
			 * encountered when the BMC reboots and the host is
			 * still operational.
			 * The host receives a GET VERSION request indicating
			 * that we must rehcrage the pdrs.
			 */
			if (response.completion_code == PLDM_ERROR_NOT_READY) {
				time_wait_ms(500);
				encode_and_queue_get_pdr_req(pdrs);
				return;
			}

			pdrs->rc = OPAL_PARAMETER;
			pdrs->done = true;
			return;
		}

		if (response.record_data == NULL) {
			response.record_data_length = response.resp_cnt;
			response.record_data = zalloc(response.resp_cnt);
			if (!response.record_data) {
				prlog(PR_ERR, "failed to allocate record data (size: 0x%lx)\n", response.record_data_length);
				pdrs->rc = OPAL_NO_MEM;
				pdrs->done = true;
				return;
			}
		}
	}

	/* we do not support multipart transfer */
	if (response.transfer_flag != PLDM_START_AND_END)
		prlog(PR_ERR, "Transfert GetPDRResp not complete, transfer_flag: %d\n",
			      response.transfer_flag);

	prlog(PR_DEBUG, "%s - record_hndl: %d, next_record_hndl: %d, resp_cnt: %d\n",
			__func__, record_hndl,
			response.next_record_hndl,
			response.resp_cnt);

	/* Add a PDR record to a PDR repository.
	 * Use HOST_TID as terminus handle
	 */
	pldm_pdr_add(pdrs_repo,
		     response.record_data,
		     response.resp_cnt,
		     record_hndl,
		     false,
		     HOST_TID);

	free(response.record_data);

	if (response.next_record_hndl != NO_MORE_PDR_HANDLES) {
		pdrs->record_hndl = response.next_record_hndl;
		encode_and_queue_get_pdr_req(pdrs);
	} else {
		/* We have to indicate the end of the initialization when we
		 * reload the pdrs in background
		 */
		pdr_init_complete(true);
		pdrs->done = true;
		pdrs->rc = OPAL_SUCCESS;
		prlog(PR_DEBUG, "%s - done\n", __func__);
	}
}

/*
 * Send/receive a PLDM GetPDR stateEffecter request message
 * Get platform descriptor records.
 *
 * pldmtool platform GetPDR -t stateEffecter
 * ...
 * {
 * "nextRecordHandle": 138,
 * "responseCount": 30,
 * "recordHandle": 137,
 * "PDRHeaderVersion": 1,
 * "PDRType": "State Effecter PDR",
 * "recordChangeNumber": 0,
 * "dataLength": 20,
 * "PLDMTerminusHandle": 1,
 * "effecterID": 43,
 * "entityType": "[Physical] System chassis (main enclosure)",
 * ...
 * "Off-Soft Graceful(9)"
 * }
 * ...
 */
static int encode_and_queue_get_pdr_req(struct pldm_pdrs *pdrs)
{
	uint32_t record_hndl = pdrs->record_hndl;
	int rc;

	struct pldm_get_pdr_req pdr_req = {
		.record_handle = record_hndl, /* record change number (0 for first request) */
		.data_transfer_handle = 0, /* (0 if transfer op is FIRSTPART) */
		.transfer_op_flag = PLDM_GET_FIRSTPART, /* transfer op flag */
		.request_count = SHRT_MAX, /* Don't limit the size of the PDR */
		.record_change_number = 0 /* record change number (0 for first request) */
	};

	prlog(PR_DEBUG, "%s - record_hndl: %d\n", __func__, record_hndl);

	/* Encode the get_PDR request */
	rc = encode_get_pdr_req(DEFAULT_INSTANCE_ID,
				pdr_req.record_handle,
				pdr_req.data_transfer_handle,
				pdr_req.transfer_op_flag,
				pdr_req.request_count,
				pdr_req.record_change_number,
				(struct pldm_msg *)pdrs->tx->data,
				PLDM_GET_PDR_REQ_BYTES);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetPDRReq Error, rc: %d\n", rc);
		pdrs->done = true;
		pdrs->rc = OPAL_PARAMETER;
		return OPAL_PARAMETER;
	}

	/* Queue the first getpdr request */
	rc = pldm_requester_queue(pdrs->tx, get_pdr_req_complete, pdrs);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: GetPDRReq, rc: %d\n", rc);
		pdrs->done = true;
		pdrs->rc = OPAL_PARAMETER;
	}

	return rc;
}

static int pldm_platform_load_pdrs(void)
{
	/* destroy current repo and mark repo not ready */
	pdr_init_complete(false);

	/* make a new PDR repository */
	pdrs_repo = pldm_pdr_init();

	/* collect all PDrs into a PDR Repository */
	pdrs->record_hndl = 0;
	pdrs->done = false;
	return encode_and_queue_get_pdr_req(pdrs);
}

static int pdrs_init(void)
{
	int rc;

	rc = pldm_platform_load_pdrs();
	if (rc)
		return rc;

	/* wait for the end of pdrs received */
	for (;;) {
		if (pdrs->done)
			break;

		time_wait_ms(5);
	}
	return pdrs->rc;
}

int pldm_platform_init(void)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_pdr_req);
	int rc;

	pdrs = zalloc(sizeof(struct pldm_pdrs));
	if (!pdrs) {
		prlog(PR_ERR, "failed to allocate pdrs\n");
		return OPAL_NO_MEM;
	}

	pdrs->tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!pdrs->tx)
		return OPAL_NO_MEM;
	pdrs->tx->data_size = data_size;

	/* retrieve all PDRs */
	rc = pdrs_init();
	if (rc)
		goto err;

	pdr_init_complete(true);
	prlog(PR_DEBUG, "%s - done\n", __func__);

	return OPAL_SUCCESS;

err:
	prlog(PR_ERR, "%s - failed to initialize pdrs, rc: %d\n", __func__, rc);
	pdr_init_complete(false);
	free(pdrs->tx);
	free(pdrs);
	return rc;
}

void pldm_platform_exit(void)
{
	if (pdr_ready)
		pldm_pdr_destroy(pdrs_repo);

	if (pdrs) {
		free(pdrs->tx);
		free(pdrs);
	}
}
