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
#include <device.h>

static struct ipmi_backend *ipmi_backend = NULL;

void ipmi_free_msg(struct ipmi_msg *msg)
{
	msg->backend->free_msg(msg);
}

struct ipmi_msg *ipmi_mkmsg_simple(uint32_t code, void *req_data, size_t req_size)
{
	return ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, code, ipmi_free_msg, NULL,
			  req_data, req_size, 0);
}

struct ipmi_msg *ipmi_mkmsg(int interface, uint32_t code,
			    void (*complete)(struct ipmi_msg *),
			    void *user_data, void *req_data, size_t req_size,
			    size_t resp_size)
{
	struct ipmi_msg *msg;

	/* We don't actually support multiple interfaces at the moment. */
	assert(interface == IPMI_DEFAULT_INTERFACE);

	msg = ipmi_backend->alloc_msg(req_size, resp_size);
	if (!msg)
		return NULL;

	msg->backend = ipmi_backend;
	msg->cmd = IPMI_CMD(code);
	msg->netfn = IPMI_NETFN(code);
	msg->req_size = req_size;
	msg->resp_size = resp_size;
	msg->complete = complete;
	msg->user_data = user_data;

	if (req_data)
		memcpy(msg->data, req_data, req_size);

	return msg;
}

int ipmi_queue_msg(struct ipmi_msg *msg)
{
	/* Here we could choose which interface to use if we want to support
	   multiple interfaces. */

	/* We should also store the original message cmd/netfn here if we wish
	   to validate it when we get the response. */

	return msg->backend->queue_msg(msg);
}

void ipmi_cmd_done(struct ipmi_msg *msg)
{
	if (msg->cc != IPMI_CC_NO_ERROR) {
		prerror("IPMI: Got error response 0x%02x\n", msg->cc);

		if (msg->error)
			msg->error(msg);
	} else if (msg->complete)
		msg->complete(msg);

	/* At this point the message has should have been freed by the
	   completion functions. */
	msg = NULL;
}

void ipmi_register_backend(struct ipmi_backend *backend)
{
	/* We only support one backend at the moment */
	assert(backend->alloc_msg);
	assert(backend->free_msg);
	assert(backend->queue_msg);
	assert(backend->dequeue_msg);
	ipmi_backend = backend;
}

bool ipmi_present(void)
{
	return ipmi_backend != NULL;
}
