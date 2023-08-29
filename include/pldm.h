/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright 2022 IBM Corp.
 */

#ifndef __PLDM_H__
#define __PLDM_H__

#include <skiboot.h>

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
 * Send a system chassis Off-Soft Graceful request
 */
int pldm_platform_power_off(void);

/**
 * Send a system firmware Graceful Restart request
 */
int pldm_platform_restart(void);

/**
 * Update the firmware version device-tree field
 */
int pldm_fru_dt_add_bmc_version(void);

/**
 * Convert lid ids data to pnor structure
 */
int pldm_lid_files_init(struct blocklevel_device **bl);

#endif /* __PLDM_H__ */