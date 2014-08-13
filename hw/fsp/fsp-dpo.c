/* Copyright 2013-2014 IBM Corp.
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
/*
 * Handle FSP DPO (Delayed Power Off) event notification
 */
#include <skiboot.h>
#include <console.h>
#include <fsp.h>
#include <device.h>
#include <stdio.h>
#include <opal.h>
#include <opal-msg.h>

#define PREFIX "FSPDPO: "

static bool fsp_dpo_pending = false;

/* Process FSP DPO init message */
static void fsp_process_dpo(struct fsp_msg *msg)
{
	u32 cmd = FSP_RSP_INIT_DPO;
	int rc;

	/* DPO message does not have the correct signatures */
	if ((msg->data.bytes[0] != 0xf4) || (msg->data.bytes[1] != 0x20)) {
		printf("DPO: Message signatures did not match\n");
		cmd |= FSP_STATUS_INVALID_CMD;
		fsp_queue_msg(fsp_mkmsg(cmd, 0), fsp_freemsg);
		return;
	}

	/* Sapphire is already in "DPO pending" state */
	if (fsp_dpo_pending) {
		printf("DPO: Sapphire is already in DPO pending state\n");
		cmd |= FSP_STATUS_INVALID_DPOSTATE;
		fsp_queue_msg(fsp_mkmsg(cmd, 0), fsp_freemsg);
		return;
	}

	/* Inform the host about DPO */
	rc = opal_queue_msg(OPAL_MSG_DPO, NULL, NULL);
	if (rc) {
		printf("DPO: OPAL message queuing failed\n");
		return;
	}

	/* Acknowledge the FSP on DPO */
	fsp_queue_msg(fsp_mkmsg(cmd, 0), fsp_freemsg);
	fsp_dpo_pending = true;
	/*
	 * Sapphire is now in DPO pending state. After first detecting DPO
	 * condition from Sapphire, the host will have 45 minutes to prepare
	 * the system for shutdown. The host must take all necessary actions
	 * required in that regard and at the end shutdown itself. The host
	 * shutdown sequence eventually will make the call OPAL_CEC_POWER_DOWN
	 * which in turn ask the FSP to shutdown the CEC. If the FSP does not
	 * receive the cec power down command from Sapphire within 45 minutes,
	 * it will assume that the host and the Sapphire has processed the DPO
	 * sequence successfully and hence force power off the system.
	 */
}

/* Handle DPO sub-command from FSP */
static bool fsp_dpo_message(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	if (cmd_sub_mod == FSP_CMD_INIT_DPO) {
		printf(PREFIX "SP initiated Delayed Power Off (DPO)\n");
		fsp_process_dpo(msg);
	}
	return false;
}

static struct fsp_client fsp_dpo_client = {
	.message = fsp_dpo_message,
};

void fsp_dpo_init(void)
{
	fsp_register_client(&fsp_dpo_client, FSP_MCLASS_SERVICE);
	printf(PREFIX "FSP DPO support initialized\n");
}
