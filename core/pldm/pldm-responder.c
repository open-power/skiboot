// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <bitmap.h>
#include <cpu.h>
#include <opal.h>
#include <stdio.h>
#include <string.h>
#include <debug_descriptor.h>
#include <libpldm/platform.h>
#include <libpldm/utils.h>
#include "pldm.h"

struct pldm_type {
	const char *name;
	int pldm_type_id;
	ver32_t version;

	struct list_head commands;
	struct list_node link;
};

struct pldm_cmd {
	const char *name;
	int pldm_cmd_id;

	int (*handler)(const struct pldm_rx_data *rx);

	struct list_node link; /* link in the msg type's command list */
};

/*
 * Send a response with just a completion code and no payload
 */
static int cc_resp(const struct pldm_rx_data *rx, uint8_t type,
			uint8_t command, uint8_t cc)
{
	size_t data_size = PLDM_MSG_SIZE(uint8_t);
	struct pldm_tx_data *tx;
	int rc;

	/* Encode the cc response */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	encode_cc_only_resp(rx->hdrinf.instance,
			    type,
			    command,
			    cc,
			    (struct pldm_msg *)tx->data);

	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send response message containing only cc, "
			      "rc = %d, cc = %d\n", rc, cc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

/*
 * PLDM Type / Command wrangling.
 */
LIST_HEAD(pldm_type_list);

static const struct pldm_type *find_type(int type_id)
{
	struct pldm_type *iter;

	list_for_each(&pldm_type_list, iter, link) {
		if (iter->pldm_type_id == type_id)
			return iter;
	}

	return NULL;
}

static const struct pldm_cmd *find_cmd(const struct pldm_type *type, int cmd)
{
	struct pldm_cmd *iter;

	list_for_each(&type->commands, iter, link)
		if (iter->pldm_cmd_id == cmd)
			return iter;

	return NULL;
}

static void add_type(struct pldm_type *new_type)
{
	assert(new_type->pldm_type_id < 32); /* limited by GetPLDMTypes */
	assert(!find_type(new_type->pldm_type_id));

	list_head_init(&new_type->commands);
	list_add_tail(&pldm_type_list, &new_type->link);

	prlog(PR_DEBUG, "Registered type %s (%d)\n",
	      new_type->name, new_type->pldm_type_id);
}

static void add_cmd(struct pldm_type *type, struct pldm_cmd *new_cmd)
{
	assert(new_cmd->pldm_cmd_id < 256); /* limited by GetPLDMCommands */
	assert(new_cmd->handler);
	assert(!find_cmd(type, new_cmd->pldm_cmd_id));

	list_add_tail(&type->commands, &new_cmd->link);
	prlog(PR_DEBUG, "Registered command %s (%d) under %s\n",
		new_cmd->name, new_cmd->pldm_cmd_id, type->name);
}

/*
 * PLDM Base commands support
 */
static struct pldm_type pldm_base_type = {
	.name = "base",
	.pldm_type_id = PLDM_BASE,
	.version = { 0xF1, 0xF0, 0xF0, 0x00 },
};

/*
 * GetTID command (0x02)
 * The GetTID command is used to retrieve the present Terminus ID (TID)
 * setting for a PLDM Terminus.
 */
static int base_get_tid_handler(const struct pldm_rx_data *rx)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_tid_resp);
	struct pldm_tx_data *tx;
	int rc;

	/* create a PLDM response message for GetTID */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_tid_resp(rx->hdrinf.instance,
				 PLDM_SUCCESS,
				 HOST_TID,
				 (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetTID Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetTID response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_base_get_tid = {
	.name = "PLDM_GET_TID",
	.pldm_cmd_id = PLDM_GET_TID,
	.handler = base_get_tid_handler,
};

/*
 * GetPLDMTypes (0x04)
 * The GetPLDMTypes command can be used to discover the PLDM type
 * capabilities supported by a PLDM terminus and to get a list of the
 * PLDM types that are supported.
 */
static int base_get_types_handler(const struct pldm_rx_data *rx)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_types_resp);
	bitmap_elem_t type_map[BITMAP_ELEMS(PLDM_MAX_TYPES)];
	struct pldm_tx_data *tx;
	struct pldm_type *iter;
	int rc;

	/* build the supported type list from the registered type
	 * handlers
	 */
	memset(type_map, 0, sizeof(type_map));
	list_for_each(&pldm_type_list, iter, link)
		bitmap_set_bit(type_map, iter->pldm_type_id);

	for (int i = 0; i < BITMAP_ELEMS(PLDM_MAX_TYPES); i++)
		type_map[i] = cpu_to_le64(type_map[i]);

	/* create a PLDM response message for GetPLDMTypes */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_types_resp(rx->hdrinf.instance,
				   PLDM_SUCCESS,
				   (bitfield8_t *)type_map,
				   (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetPLDMTypes Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetPLDMTypes response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_base_get_types = {
	.name = "PLDM_GET_PLDM_TYPES",
	.pldm_cmd_id = PLDM_GET_PLDM_TYPES,
	.handler = base_get_types_handler,
};

/*
 * Extended error codes defined for the Base command set.
 */
#define INVALID_DATA_TRANSFER_HANDLE           0x80
#define INVALID_TRANSFER_OPERATION_FLAG        0x81
#define INVALID_PLDM_TYPE_IN_REQUEST_DATA      0x83
#define INVALID_PLDM_VERSION_IN_REQUEST_DATA   0x84

/*
 * GetPLDMCommands (0x05)
 * The GetPLDMCommands command can be used to discover the PLDM command
 * capabilities supported by aPLDM terminus for a specific PLDM Type and
 * version as a responder.
 */
static int base_get_commands_handler(const struct pldm_rx_data *rx)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_commands_resp);
	bitmap_elem_t cmd_map[BITMAP_ELEMS(PLDM_MAX_CMDS_PER_TYPE)];
	const struct pldm_type *type;
	const struct pldm_cmd *iter;
	struct pldm_tx_data *tx;
	size_t payload_len;
	ver32_t version;
	uint8_t type_id;
	int rc;

	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);
	rc = decode_get_commands_req(rx->msg, payload_len,
				     &type_id, &version);
	if (rc) {
		prlog(PR_ERR, "Failed to decode GetPLDMCommands request, rc = %d", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	type = find_type(type_id);
	if (!type) {
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			INVALID_PLDM_TYPE_IN_REQUEST_DATA);
		return OPAL_PARAMETER;
	}

	if (memcmp(&type->version, &version, sizeof(version))) {
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			INVALID_PLDM_VERSION_IN_REQUEST_DATA);
		return OPAL_PARAMETER;
	}

	/* build the supported type list from the registered type
	 * handlers
	 */
	memset(cmd_map, 0, sizeof(cmd_map));
	list_for_each(&type->commands, iter, link)
		bitmap_set_bit(cmd_map, iter->pldm_cmd_id);

	/* fix the endian */
	for (int i = 0; i < BITMAP_ELEMS(PLDM_MAX_CMDS_PER_TYPE); i++)
		cmd_map[i] = cpu_to_le64(cmd_map[i]);

	/* create a PLDM response message for GetPLDMCommands */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_commands_resp(rx->hdrinf.instance,
				      PLDM_SUCCESS,
				      (bitfield8_t *)cmd_map,
				      (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetPLDMCommands Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* send PLDM message over MCTP */
	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetPLDMCommands response, rc = %d\n", rc);
		return OPAL_HARDWARE;
		free(tx);
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_base_get_commands = {
	.name = "PLDM_GET_PLDM_COMMANDS",
	.pldm_cmd_id = PLDM_GET_PLDM_COMMANDS,
	.handler = base_get_commands_handler,
};

/*
 * GetPLDMVersion (0x03)
 * The GetPLDMVersion command can be used to retrieve the PLDM base
 * specification versions that the PLDM terminus supports, as well as
 * the PLDM Type specification versions supported for each PLDM Type.
 */
static int base_get_version_handler(const struct pldm_rx_data *rx)
{
	uint32_t version_data[2];
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_version_resp) + sizeof(version_data);
	const struct pldm_type *type;
	struct pldm_tx_data *tx;
	uint8_t type_id, opflag;
	uint32_t xfer_handle;
	size_t payload_len;
	int rc;

	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);
	rc = decode_get_version_req(rx->msg, payload_len,
				    &xfer_handle,
				    &opflag,
				    &type_id);
	if (rc) {
		prlog(PR_ERR, "Failed to decode GetPLDMVersion request, rc = %d", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	/* reject multipart requests */
	if (opflag != PLDM_GET_FIRSTPART) {
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			INVALID_TRANSFER_OPERATION_FLAG);
		return OPAL_PARAMETER;
	}

	type = find_type(type_id);
	if (!type) {
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			INVALID_PLDM_TYPE_IN_REQUEST_DATA);
		return OPAL_PARAMETER;
	}

	/* pack a scratch buffer with our version(s) and CRC32 the lot */
	memcpy(&version_data[0], &type->version, 4);

	version_data[1] = cpu_to_le32(crc32(&type->version, 4));

	/* create a PLDM response for GetPLDMVersion */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_version_resp(rx->hdrinf.instance,
				     PLDM_SUCCESS,
				     0x0, /* no handle */
				     PLDM_START_AND_END,
				     (ver32_t *) version_data,
				     sizeof(version_data),
				     (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetPLDMVersion Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* send PLDM message over MCTP */
	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetPLDMVersion response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_base_get_version = {
	.name = "PLDM_GET_PLDM_VERSION",
	.pldm_cmd_id = PLDM_GET_PLDM_VERSION,
	.handler = base_get_version_handler,
};

/*
 * PLDM Platform commands support
 */
static struct pldm_type pldm_platform_type = {
	.name = "platform",
	.pldm_type_id = PLDM_PLATFORM,
};

#define MIN_WATCHDOG_TIMEOUT_SEC 15

/*
 * SetEventReceiver (0x04)
 * The SetEventReceiver command is used to set the address of the Event
 * Receiver into a terminus that generates event messages. It is also
 * used to globally enable or disable whether event messages are
 * generated from the terminus.
 */
static int platform_set_event_receiver_handler(const struct pldm_rx_data *rx)
{
	uint8_t event_message_global_enable, transport_protocol_type;
	uint8_t event_receiver_address_info, cc = PLDM_SUCCESS;
	uint16_t heartbeat_timer;
	int rc = OPAL_SUCCESS;

	/* decode SetEventReceiver request data */
	rc = decode_set_event_receiver_req(
				rx->msg,
				PLDM_SET_EVENT_RECEIVER_REQ_BYTES,
				&event_message_global_enable,
				&transport_protocol_type,
				&event_receiver_address_info,
				&heartbeat_timer);
	if (rc) {
		prlog(PR_ERR, "Failed to decode SetEventReceiver request, rc = %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	/* invoke the appropriate callback handler */
	prlog(PR_DEBUG, "%s - event_message_global_enable: %d, "
			"transport_protocol_type: %d "
			"event_receiver_address_info: %d "
			"heartbeat_timer: %d\n",
			__func__,
			event_message_global_enable,
			transport_protocol_type,
			event_receiver_address_info,
			heartbeat_timer);

	if (event_message_global_enable !=
		PLDM_EVENT_MESSAGE_GLOBAL_ENABLE_ASYNC_KEEP_ALIVE) {

		prlog(PR_ERR, "%s - invalid value for message global enable received: %d\n",
			      __func__, event_message_global_enable);
		cc = PLDM_PLATFORM_ENABLE_METHOD_NOT_SUPPORTED;
	}

	if (heartbeat_timer < MIN_WATCHDOG_TIMEOUT_SEC) {
		prlog(PR_ERR, "%s - BMC requested watchdog timeout that's too small: %d\n",
			      __func__, heartbeat_timer);
		cc = PLDM_PLATFORM_HEARTBEAT_FREQUENCY_TOO_HIGH;
	} else {
		/* set the internal watchdog period to what BMC indicated */
		watchdog_period_sec = heartbeat_timer;
	}

	/* send the response to BMC */
	cc_resp(rx, PLDM_PLATFORM, PLDM_SET_EVENT_RECEIVER, cc);

	/* no error happened above, so arm the watchdog and set the default timeout */
	if (cc == PLDM_SUCCESS)
		watchdog_armed = true;

	return rc;
}

static struct pldm_cmd pldm_platform_set_event_receiver = {
	.name = "PLDM_SET_EVENT_RECEIVER",
	.pldm_cmd_id = PLDM_SET_EVENT_RECEIVER,
	.handler = platform_set_event_receiver_handler,
};

int pldm_responder_handle_request(struct pldm_rx_data *rx)
{
	const struct pldm_type *type;
	const struct pldm_cmd *cmd;

	prlog(PR_INFO, "Receive PLDM request from BMC, type: 0x%x, command: 0x%x\n",
			rx->hdrinf.pldm_type, rx->hdrinf.command);

	type = find_type(rx->hdrinf.pldm_type);
	if (!type) {
		prlog(PR_ERR, "Type not supported, type: 0x%x\n",
			      rx->hdrinf.pldm_type);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			PLDM_ERROR_INVALID_PLDM_TYPE);
		return OPAL_UNSUPPORTED;
	}

	cmd = find_cmd(type, rx->hdrinf.command);
	if (!cmd) {
		prlog(PR_ERR, "Command not supported, type: 0x%x, command: 0x%x\n",
			      rx->hdrinf.pldm_type, rx->hdrinf.command);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			PLDM_ERROR_UNSUPPORTED_PLDM_CMD);
		return OPAL_UNSUPPORTED;
	}

	return cmd->handler(rx);
}

int pldm_responder_init(void)
{
	/* Register mandatory commands we'll respond to - DSP0240 */
	add_type(&pldm_base_type);
	add_cmd(&pldm_base_type, &pldm_base_get_tid);
	add_cmd(&pldm_base_type, &pldm_base_get_types);
	add_cmd(&pldm_base_type, &pldm_base_get_commands);
	add_cmd(&pldm_base_type, &pldm_base_get_version);

	/* Register platform commands we'll respond to - DSP0248 */
	add_type(&pldm_platform_type);
	add_cmd(&pldm_platform_type, &pldm_platform_set_event_receiver);

	return OPAL_SUCCESS;
}
