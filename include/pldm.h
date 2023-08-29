/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright 2022 IBM Corp.
 */

#ifndef __PLDM_H__
#define __PLDM_H__

/**
 * Handle PLDM messages received from MCTP
 */
int pldm_mctp_message_rx(uint8_t eid, bool tag_owner, uint8_t msg_tag,
			 const uint8_t *buf, int len);

/**
 * PLDM over MCTP initialization
 */
int pldm_mctp_init(void);

/**
 * PLDM over MCTP stop
 */
void pldm_mctp_exit(void);

/**
 * Send a system firmware Graceful Restart request
 */
int pldm_platform_restart(void);

#endif /* __PLDM_H__ */
