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
 * Handle FSP EPOW (Environmental and Power Warning) events notification
 */
#include <skiboot.h>
#include <console.h>
#include <fsp.h>
#include <device.h>
#include <stdio.h>
#include <spcn.h>
#include <opal.h>
#include <opal-msg.h>

#include "fsp-epow.h"

#define PREFIX "EPOW: "

/*
 * System EPOW status
 *
 * This value is exported to the host. Each individual element in this array
 * [0..(OPAL_SYSEPOW_MAX -1)] contains detailed status (in it's bit positions)
 * corresponding to a particular defined EPOW sub class. For example.
 *
 * epow_status[OPAL_SYSEPOW_POWER] will reflect whether the system has one or
 * more of power subsystem specific EPOW events like OPAL_SYSPOWER_UPS,
 * OPAL_SYSPOWER_CHNG, OPAL_SYSPOWER_FAIL or OPAL_SYSPOWER_INCL.
 */
int16_t epow_status[OPAL_SYSEPOW_MAX];

/* EPOW lock */
static struct lock epow_lock = LOCK_UNLOCKED;

/* Process FSP sent SPCN based information */
static void epow_process_base_event(u8 *epow)
{
	/*
	 * FIXME: As of now, SPCN_FAULT_LOG event is not being used
	 * as it does not map to any generic defined OPAL EPOW event.
	 */
	if (epow[3] & SPCN_CNF_CHNG) {
		/*
		 * The frequency of the SPCN_CNF_CHNG message is very
		 * high on POWER7 and POWER8 systems which will fill
		 * up the Sapphire log buffer. SPCN configuration
		 * change does not take down the system, hence the
		 * logging of these type of messages can be avoided to
		 * save precious log buffer space.
		 */
		epow_status[OPAL_SYSEPOW_POWER] |= OPAL_SYSPOWER_CHNG;
	}

	if (epow[3] & SPCN_POWR_FAIL) {
		printf(PREFIX "FSP message with SPCN_POWR_FAIL\n");
		epow_status[OPAL_SYSEPOW_POWER] |= OPAL_SYSPOWER_FAIL;
	}

	if (epow[3] & SPCN_INCL_POWR) {
		printf(PREFIX "FSP message with SPCN_INCL_POWR\n");
		epow_status[OPAL_SYSEPOW_POWER] |= OPAL_SYSPOWER_INCL;
	}
}

/* Process FSP sent EPOW based information */
static void epow_process_ex1_event(u8 *epow)
{
	if (epow[4] == EPOW_ON_UPS) {
		printf(PREFIX "FSP message with EPOW_ON_UPS\n");
		epow_status[OPAL_SYSEPOW_POWER] |= OPAL_SYSPOWER_UPS;
	}

	if (epow[4] == EPOW_TMP_AMB) {
		printf(PREFIX "FSP message with EPOW_TMP_AMB\n");
		epow_status[OPAL_SYSEPOW_TEMP] |= OPAL_SYSTEMP_AMB;
	}

	if (epow[4] == EPOW_TMP_INT) {
		printf(PREFIX "FSP message with EPOW_TMP_INT\n");
		epow_status[OPAL_SYSEPOW_TEMP] |= OPAL_SYSTEMP_INT;
	}
}

/* Update the system EPOW status */
static void fsp_epow_update(u8 *epow, int epow_type)
{
	int16_t old_epow_status[OPAL_SYSEPOW_MAX];
	bool epow_changed = false;
	int rc;

	lock(&epow_lock);

	/* Copy over and clear system EPOW status */
	memcpy(old_epow_status, epow_status, sizeof(old_epow_status));
	memset(epow_status, 0, sizeof(epow_status));
	switch(epow_type) {
	case EPOW_NORMAL:
		epow_process_base_event(epow);
		/* FIXME: IPL mode information present but not used */
		break;
	case EPOW_EX1:
		epow_process_base_event(epow);
		epow_process_ex1_event(epow);
		/* FIXME: IPL mode information present but not used */
		/* FIXME: Key position information present but not used */
		break;
	case EPOW_EX2:
		/*FIXME: IPL mode information present but not used */
		/*FIXME: Key position information present but not used */
		break;
	default:
		printf(PREFIX "Unkown EPOW event notification\n");
		break;
	}
	unlock(&epow_lock);

	if (epow_status != old_epow_status)
		epow_changed = true;

	/* Send OPAL message notification */
	if (epow_changed) {
		rc = opal_queue_msg(OPAL_MSG_EPOW, NULL, NULL);
		if (rc) {
			printf(PREFIX "OPAL EPOW message queuing failed\n");
			return;
		}
	}
}

/* Process captured EPOW event notification */
static void fsp_process_epow(struct fsp_msg *msg, int epow_type)
{
	u8 epow[8];

	/* Basic EPOW signature */
	if (msg->data.bytes[0] != 0xF2) {
		printf(PREFIX "Signature mismatch\n");
		return;
	}

	/* Common to all EPOW event types */
	epow[0] = msg->data.bytes[0];
	epow[1] = msg->data.bytes[1];
	epow[2] = msg->data.bytes[2];
	epow[3] = msg->data.bytes[3];

	/*
	 * After receiving the FSP async message, HV needs to
	 * ask for the detailed panel status through corresponding
	 * mbox command. HV need not use the received details status
	 * as it does not have any thing more or new than what came
	 * along with the original FSP async message. But requesting
	 * for the detailed panel status exclussively is necessary as
	 * it forms a kind of handshaking with the FSP. Without this
	 * step, FSP wont be sending any new panel status messages.
	 */
	switch(epow_type) {
	case EPOW_NORMAL:
		fsp_queue_msg(fsp_mkmsg(FSP_CMD_STATUS_REQ, 0), fsp_freemsg);
		break;
	case EPOW_EX1:
		/* EPOW_EX1 specific extra event data */
		epow[4] = msg->data.bytes[4];
		fsp_queue_msg(fsp_mkmsg(FSP_CMD_STATUS_EX1_REQ, 0), fsp_freemsg);
		break;
	case EPOW_EX2:
		fsp_queue_msg(fsp_mkmsg(FSP_CMD_STATUS_EX2_REQ, 0), fsp_freemsg);
		break;
	default:
		printf(PREFIX "Unkown EPOW event notification\n");
		return;
	}
	fsp_epow_update(epow, epow_type);
}

/*
 * EPOW OPAL interface
 *
 * The host requests for the system EPOW status through this
 * OPAl call, where it passes a buffer with a give length.
 * Sapphire fills the buffer with updated system EPOW status
 * and then updates the length variable back to reflect the
 * number of EPOW sub classes it has updated the buffer with.
 */
static int64_t fsp_opal_get_epow_status(int16_t *out_epow,
						int16_t *length)
{
	int i;
	int n_epow_class;

	/*
	 * There can be situations where the host and the Sapphire versions
	 * dont match with eact other and hence the expected system EPOW status
	 * details. Newer hosts might be expecting status for more number of EPOW
	 * sub classes which Sapphire may not know about and older hosts might be
	 * expecting status for EPOW sub classes which is a subset of what
	 * Sapphire really knows about. Both these situations are handled here.
	 *
	 * (A) Host version >= Sapphire version
	 *
	 * Sapphire sends out EPOW status for sub classes it knows about
	 * and keeps the status. Updates the length variable for the host.
	 *
	 * (B) Host version < Sapphire version
	 *
	 * Sapphire sends out EPOW status for sub classes host knows about
	 * and can interpret correctly.
	 */
	if (*length >= OPAL_SYSEPOW_MAX) {
		n_epow_class = OPAL_SYSEPOW_MAX;
		*length = OPAL_SYSEPOW_MAX;
	} else {
		n_epow_class = *length;
	}

	/* Transfer EPOW Status */
	for (i = 0; i < n_epow_class; i++)
		out_epow[i] = epow_status[i];

	return OPAL_SUCCESS;
}

/* Handle EPOW sub-commands from FSP */
static bool fsp_epow_message(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	switch(cmd_sub_mod) {
	case FSP_CMD_PANELSTATUS:
		fsp_process_epow(msg, EPOW_NORMAL);
		return true;
	case FSP_CMD_PANELSTATUS_EX1:
		fsp_process_epow(msg, EPOW_EX1);
		return true;
	case FSP_CMD_PANELSTATUS_EX2:
		fsp_process_epow(msg, EPOW_EX2);
		return true;
	}
	return false;
}

static struct fsp_client fsp_epow_client = {
	.message = fsp_epow_message,
};

void fsp_epow_init(void)
{
	struct dt_node *np;

	fsp_register_client(&fsp_epow_client, FSP_MCLASS_SERVICE);
	opal_register(OPAL_GET_EPOW_STATUS, fsp_opal_get_epow_status, 2);
	np = dt_new(opal_node, "epow");
	dt_add_property_strings(np, "compatible", "ibm,opal-v3-epow");
	dt_add_property_strings(np, "epow-classes", "power", "temperature", "cooling");
	printf(PREFIX "FSP EPOW support initialized\n");
}
