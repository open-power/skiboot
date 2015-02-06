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
#include <timebase.h>
#include <opal.h>
#include <opal-api.h>
#include <opal-msg.h>

#define PREFIX "FSPDPO: "

#define DPO_CMD_SGN_BYTE0	0xf4 /* Byte[0] signature */
#define DPO_CMD_SGN_BYTE1	0x20 /* Byte[1] signature */
#define DPO_TIMEOUT		2700 /* 45 minutes in seconds */

static bool fsp_dpo_pending = false;
unsigned long fsp_dpo_init_tb = 0;

/*
 * OPAL DPO interface
 *
 * Returns zero if DPO is not active, positive value indicating number
 * of seconds remaining for a forced system shutdown. This will enable
 * the host to schedule for shutdown voluntarily before timeout occurs.
 */
static int64_t fsp_opal_get_dpo_status(int64_t *dpo_timeout)
{
	if (fsp_dpo_init_tb && fsp_dpo_pending) {
		*dpo_timeout = DPO_TIMEOUT - tb_to_secs(mftb() - fsp_dpo_init_tb);
		return OPAL_SUCCESS;
	} else {
		*dpo_timeout = 0;
		return OPAL_WRONG_STATE;
	}
}

/* Process FSP DPO init message */
static void fsp_process_dpo(struct fsp_msg *msg)
{
	struct fsp_msg *resp;
	u32 cmd = FSP_RSP_INIT_DPO;
	int rc;

	/* DPO message does not have the correct signatures */
	if ((msg->data.bytes[0] != DPO_CMD_SGN_BYTE0)
			|| (msg->data.bytes[1] != DPO_CMD_SGN_BYTE1)) {
		prlog(PR_ERR, PREFIX "Message signatures did not match\n");
		cmd |= FSP_STATUS_INVALID_CMD;
		resp = fsp_mkmsg(cmd, 0);
		if (resp == NULL) {
			prerror(PREFIX "%s : Message allocation failed\n",
				__func__);
			return;
		}
		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror(PREFIX "%s : Failed to queue response "
				"message\n", __func__);
		}
		return;
	}

	/* Sapphire is already in "DPO pending" state */
	if (fsp_dpo_pending) {
		prlog(PR_ERR, PREFIX "OPAL is already in DPO pending state\n");
		cmd |= FSP_STATUS_INVALID_DPOSTATE;
		resp = fsp_mkmsg(cmd, 0);
		if (resp == NULL) {
			prerror(PREFIX "%s : Message allocation failed\n",
				__func__);
			return;
		}
		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror(PREFIX "%s : Failed to queue response "
				"message\n", __func__);
		}
		return;
	}

	/* Record the DPO init time */
	fsp_dpo_init_tb = mftb();

	/* Inform the host about DPO */
	rc = opal_queue_msg(OPAL_MSG_DPO, NULL, NULL);
	if (rc) {
		prlog(PR_ERR, PREFIX "OPAL message queuing failed\n");
		cmd |= FSP_STATUS_GENERIC_ERROR;
		resp = fsp_mkmsg(cmd, 0);
		if (resp == NULL) {
			prerror(PREFIX "%s : Message allocation failed\n",
				__func__);
			return;
		}
		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror(PREFIX "%s : Failed to queue response "
				"message\n", __func__);
		}
		return;
	}

	/* Acknowledge the FSP on DPO */
	resp = fsp_mkmsg(cmd, 0);
	if (resp == NULL) {
		prerror(PREFIX "%s : Message allocation failed\n", __func__);
		return;
	}
	if (fsp_queue_msg(resp, fsp_freemsg)) {
		fsp_freemsg(resp);
		prerror(PREFIX "%s : Failed to queue response message\n",
			__func__);
	}

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
		prlog(PR_TRACE, PREFIX "SP initiated Delayed Power Off (DPO)\n");
		fsp_process_dpo(msg);
		return true;
	}
	return false;
}

static struct fsp_client fsp_dpo_client = {
	.message = fsp_dpo_message,
};

void fsp_dpo_init(void)
{
	fsp_register_client(&fsp_dpo_client, FSP_MCLASS_SERVICE);
	opal_register(OPAL_GET_DPO_STATUS, fsp_opal_get_dpo_status, 1);
	prlog(PR_TRACE, PREFIX "FSP DPO support initialized\n");
}
