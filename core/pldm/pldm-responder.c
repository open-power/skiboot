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

/*
 * PLDM Base commands support
 */
static struct pldm_type pldm_base_type = {
	.name = "base",
	.pldm_type_id = PLDM_BASE,
	.version = { 0xF1, 0xF0, 0xF0, 0x00 },
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

	return OPAL_SUCCESS;
}
