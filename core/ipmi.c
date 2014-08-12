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

#include <stdio.h>
#include <bt.h>
#include <ipmi.h>
#include <opal.h>

static void ipmi_cmd_done(struct ipmi_msg *msg)
{
	if (msg->cc != IPMI_CC_NO_ERROR) {
		prerror("IPMI: Got error response 0x%02x\n", msg->cc);
		goto out;
	}

	switch (msg->netfn) {
	case IPMI_NETFN_CHASSIS_RESPONSE:
		break;
	default:
		prerror("IPMI: Invalid IPMI function code in response\n");
	}

out:
	free(msg);
}

int64_t ipmi_opal_chassis_request(uint64_t request)
{
	struct ipmi_msg *msg = zalloc(sizeof(struct ipmi_msg));

	if (!msg)
		return OPAL_HARDWARE;

	msg->cmd = request;
	msg->netfn = IPMI_NETFN_CHASSIS_REQUEST;
	msg->req_data = NULL;
	msg->req_data_len = 0;
	msg->resp_data = NULL;
	msg->resp_data_len = 0;

	prlog(PR_INFO, "IPMI: sending chassis request %llu\n", request);

	return bt_add_ipmi_msg_wait(msg);
}

void ipmi_init(void)
{
	bt_init(ipmi_cmd_done);
}
