// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <cpu.h>
#include <opal.h>
#include <stdio.h>
#include <string.h>
#include "pldm.h"

/*
 * PLDM over MCTP (DSP0241)
 *
 * First byte of the MCTP message is the message Type = PLDM
 *    PLDM = 0x01 (000_0001b)
 *
 * Next bytes of the MCTP message (MCTP message body) contain the
 * PLDM message (The base PLDM message fields are defined in DSP0240)
 */

int pldm_mctp_message_tx(struct pldm_tx_data *tx)
{
	tx->mctp_msg_type = MCTP_MSG_TYPE_PLDM;

	return ast_mctp_message_tx(tx->tag_owner, tx->msg_tag,
				   &tx->mctp_msg_type,
				   tx->data_size + sizeof(tx->mctp_msg_type));
}

int pldm_mctp_message_rx(uint8_t eid, bool tag_owner, uint8_t msg_tag,
			 const uint8_t *buf, int len)
{
	struct pldm_rx_data *rx;
	int rc = 0;

	rx = zalloc(sizeof(struct pldm_rx_data));
	if (!rx) {
		prlog(PR_ERR, "failed to allocate rx message\n");
		return OPAL_NO_MEM;
	}

	rx->msg = (struct pldm_msg *)buf;
	rx->source_eid = eid;
	rx->msg_len = len;
	rx->tag_owner = tag_owner;
	rx->msg_tag = msg_tag;

	/* Additional header information */
	if (unpack_pldm_header(&rx->msg->hdr, &rx->hdrinf)) {
		prlog(PR_ERR, "%s: unable to decode header\n", __func__);
		rc = OPAL_EMPTY;
		goto out;
	}

out:
	free(rx);
	return rc;
}

int pldm_mctp_init(void)
{
	int nbr_elt = 1, rc = OPAL_SUCCESS;

	int (*pldm_config[])(void) = {
		ast_mctp_init,		/* MCTP Binding */
	};

	const char *pldm_config_error[] = {
		"Failed to bind MCTP",
	};

	prlog(PR_NOTICE, "%s - Getting PLDM data\n", __func__);

	for (int i = 0; i < nbr_elt; i++) {
		rc = pldm_config[i]();
		if (rc) {
			prlog(PR_ERR, "%s\n", pldm_config_error[i]);
			goto out;
		}
	}

out:
	prlog(PR_NOTICE, "%s - done, rc: %d\n", __func__, rc);
	return rc;
}

void pldm_mctp_exit(void)
{
	ast_mctp_exit();
}
