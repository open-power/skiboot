/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright 2022 IBM Corp.
 */

#ifndef __COREPLDM_H__
#define __COREPLDM_H__

#include <ast.h>
#include <base.h>
#include <utils.h>
#include <pldm.h>

#define PLDM_MSG_SIZE(x) (sizeof(struct pldm_msg_hdr) + sizeof(x))

/* For all of the encode functions just pass in a default ID (0x00) */
#define DEFAULT_INSTANCE_ID 0

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

/* Responder support */
int pldm_responder_handle_request(struct pldm_rx_data *rx);
int pldm_responder_init(void);

/* Requester support */
int pldm_file_io_init(void);

int pldm_fru_get_bmc_version(void *bv, int len);
int pldm_fru_init(void);

int pldm_bios_find_lid_by_attr_name(const char *name, char **lid);
int pldm_bios_get_lids_id(char **lid_ids_string);
int pldm_bios_init(void);

uint8_t pldm_base_get_bmc_tid(void);
int pldm_base_get_tid_req(void);

int pldm_platform_init(void);
void pldm_platform_exit(void);

int pldm_requester_handle_response(struct pldm_rx_data *rx);
int pldm_requester_queue(struct pldm_tx_data *tx,
			 void (*complete)(struct pldm_rx_data *rx, void *data),
			 void *complete_data);
int pldm_requester_queue_and_wait(struct pldm_tx_data *tx,
				  void **msg, size_t *msg_size);
int pldm_requester_init(void);

#endif /* __COREPLDM_H__ */
