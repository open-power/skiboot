// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <bitmap.h>
#include <cpu.h>
#include <opal.h>
#include <stdio.h>
#include <string.h>
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

	return OPAL_SUCCESS;
}
