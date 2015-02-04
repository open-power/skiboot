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

#include <skiboot.h>
#include <stdlib.h>
#include <string.h>
#include <ipmi.h>
#include <device.h>
#include <opal.h>
#include <lock.h>
#include <errorlog.h>
#include <pel.h>

/* As far as I can tell the size of PEL record is unbounded (due to
 * the possible presence of the user defined section). We chose this
 * size because it's what FSP uses, but we could probably reduce
 * it. */
#define MAX_PEL_SIZE 0x10000

#define ESEL_HDR_SIZE 7

static void ipmi_elog_error(struct ipmi_msg *msg)
{
	if (msg->cc == IPMI_LOST_ARBITRATION_ERR)
		/* Retry due to SEL erase */
		ipmi_queue_msg(msg);
	else
		opal_elog_complete(msg->user_data, false);

	ipmi_free_msg(msg);
}

/* Goes through the required steps to add a complete eSEL:
 *
 *  1. Get a reservation
 *  2. Partially add data to the SEL
 *
 * Because a reservation is needed we need to ensure eSEL's are added
 * as a single transaction as concurrent/interleaved adds would cancel
 * the reservation. We guarantee this by always adding our messages to
 * the head of the transmission queue, blocking any other messages
 * being sent until we have completed sending this message.
 *
 * There is still a very small chance that we will accidentally
 * interleave a message if there is another one waiting at the head of
 * the ipmi queue and another cpu calls the ipmi poller before we
 * complete. However this should just cause a resevation cancelled
 * error which we have to deal with anyway (eg. because there may be a
 * SEL erase in progress) so it shouldn't cause any problems.
 */
static void ipmi_elog_poll(struct ipmi_msg *msg)
{
	static char pel_buf[MAX_PEL_SIZE];
	static size_t pel_size;
	static int index = 0;
	static unsigned int reservation_id = 0;
	static unsigned int record_id = 0;
	struct errorlog *elog_buf = (struct errorlog *) msg->user_data;
	size_t req_size;

	if (msg->cmd == IPMI_CMD(IPMI_RESERVE_SEL)) {
		reservation_id = msg->data[0];
		reservation_id |= msg->data[1] << 8;
		if (!reservation_id) {
			/* According to specification we should never
			 * get here, but just in case we do we cancel
			 * sending the message. */
			prerror("Invalid reservation id");
			opal_elog_complete(elog_buf, false);
			ipmi_free_msg(msg);
			return;
		}

		pel_size = create_pel_log(elog_buf, pel_buf, MAX_PEL_SIZE);
		index = 0;
		record_id = 0;
	} else {
		record_id = msg->data[0];
		record_id |= msg->data[1] << 8;
	}

	/* Start or continue the IPMI_PARTIAL_ADD_SEL */
	if (index >= pel_size) {
		/* We're all done. Invalidate the resevation id to
		 * ensure we get an error if we cut in on another eSEL
		 * message. */
		reservation_id = 0;
		index = 0;
		opal_elog_complete(elog_buf, true);
		ipmi_free_msg(msg);
		return;
	}

	if ((pel_size - index) < (IPMI_MAX_REQ_SIZE - ESEL_HDR_SIZE)) {
		/* Last data to send */
		msg->data[6] = 1;
		req_size = pel_size - index + ESEL_HDR_SIZE;
	} else {
		msg->data[6] = 0;
		req_size = IPMI_MAX_REQ_SIZE;
	}

	ipmi_init_msg(msg, IPMI_DEFAULT_INTERFACE, IPMI_PARTIAL_ADD_ESEL,
		      ipmi_elog_poll, elog_buf, req_size, 2);

	msg->data[0] = reservation_id & 0xff;
	msg->data[1] = (reservation_id >> 8) & 0xff;
	msg->data[2] = record_id & 0xff;
	msg->data[3] = (record_id >> 8) & 0xff;
	msg->data[4] = index & 0xff;
	msg->data[5] = (index >> 8) & 0xff;

	memcpy(&msg->data[ESEL_HDR_SIZE], &pel_buf[index], msg->req_size - ESEL_HDR_SIZE);
	index += msg->req_size - ESEL_HDR_SIZE;

	ipmi_queue_msg_head(msg);
	return;
}

int ipmi_elog_commit(struct errorlog *elog_buf)
{
	struct ipmi_msg *msg;

	/* We pass a large request size in to mkmsg so that we have a
	 * large enough allocation to reuse the message to pass the
	 * PEL data via a series of partial add commands.  */
	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_RESERVE_SEL, ipmi_elog_poll,
			 elog_buf, NULL, IPMI_MAX_REQ_SIZE, 2);
	if (!msg) {
		opal_elog_complete(elog_buf, false);
		return OPAL_RESOURCE;
	}
	msg->error = ipmi_elog_error;

	msg->req_size = 0;
	ipmi_queue_msg(msg);

	return 0;
}
