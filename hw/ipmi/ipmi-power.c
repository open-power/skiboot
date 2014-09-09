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

#include <stdlib.h>
#include <ipmi.h>
#include <opal.h>

int64_t ipmi_opal_chassis_control(uint64_t request)
{
	struct ipmi_msg *msg;
	uint8_t chassis_control = request;

	if (chassis_control > IPMI_CHASSIS_SOFT_SHUTDOWN)
		return OPAL_PARAMETER;


	msg = ipmi_mkmsg_simple(IPMI_CHASSIS_CONTROL, &chassis_control,
				sizeof(chassis_control));
	if (!msg)
		return OPAL_HARDWARE;


	prlog(PR_INFO, "IPMI: sending chassis control request %llu\n",
			request);

	return ipmi_queue_msg(msg);
}
