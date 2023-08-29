/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright 2022 IBM Corp.
 */

#ifndef __COREPLDM_H__
#define __COREPLDM_H__

#include <ast.h>
#include <base.h>
#include <pldm.h>

struct pldm_tx_data {
	/* Contains an message header and payload of an MCTP packet.
	 * Size of data[]
	 */
	size_t data_size;

	/* Holds data related to the routing of an MCTP packet */
	bool tag_owner;
	uint8_t msg_tag;

	/* This byte is situated just before the message body */
	uint8_t mctp_msg_type;

	/* The message payload (e.g. PLDM message) */
	uint8_t data[1];
};

struct pldm_rx_data {
	struct pldm_header_info hdrinf; /* parsed message header */

	struct pldm_msg *msg;
	int msg_len;
	int source_eid;
	bool tag_owner;
	uint8_t msg_tag;
};

int pldm_mctp_message_tx(struct pldm_tx_data *tx);

int pldm_mctp_message_rx(uint8_t eid, bool tag_owner, uint8_t msg_tag,
			 const uint8_t *buf, int len);

#endif /* __COREPLDM_H__ */
