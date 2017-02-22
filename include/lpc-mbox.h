/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __LPC_MBOX_H
#define __LPC_MBOX_H

#include <opal.h>
#include <ccan/endian/endian.h>

/* Not 16 because the last two are interrupt based status regs */
#define BMC_MBOX_DATA_REGS 14
#define BMC_MBOX_ARGS_REGS 11

#define MBOX_C_RESET_STATE 0x01
#define MBOX_C_GET_MBOX_INFO 0x02
#define MBOX_C_GET_FLASH_INFO 0x03
#define MBOX_C_CREATE_READ_WINDOW 0x04
#define MBOX_C_CLOSE_WINDOW 0x05
#define MBOX_C_CREATE_WRITE_WINDOW 0x06
#define MBOX_C_MARK_WRITE_DIRTY 0x07
#define MBOX_C_WRITE_FLUSH 0x08
#define MBOX_C_BMC_EVENT_ACK 0x09

#define MBOX_R_SUCCESS 0x01
#define MBOX_R_PARAM_ERROR 0x02
#define MBOX_R_WRITE_ERROR 0x03
#define MBOX_R_SYSTEM_ERROR 0x04
#define MBOX_R_TIMEOUT 0x05

/* Default poll interval before interrupts are working */
#define MBOX_DEFAULT_POLL_MS	200

struct bmc_mbox_msg {
	uint8_t command;
	uint8_t seq;
	uint8_t args[BMC_MBOX_ARGS_REGS];
	uint8_t response;
	uint8_t host;
	uint8_t bmc;
};

int bmc_mbox_enqueue(struct bmc_mbox_msg *msg);
int bmc_mbox_register_callback(void (*callback)(struct bmc_mbox_msg *msg, void *priv),
		void *drv_data);
#endif /* __LPC_MBOX_H */
