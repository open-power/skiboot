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
#include <time.h>
#include <time-utils.h>

/* Sane default (2014/01/01) */
static time_t time = 1388494800;

static void ipmi_process_storage_resp(struct ipmi_msg *msg)
{
	uint32_t new_time;

	switch (msg->cmd) {
	case IPMI_GET_SEL_TIME_CMD:
		/*
		 * I couldn't find any mention of endianess in the IPMI spec,
		 * but ipmitool seemed to assume little endian?
		 */
		memcpy(&new_time, msg->data, 4);
		time = le32_to_cpu(new_time);
		break;

	case IPMI_SET_SEL_TIME_CMD:
		/* Nothing to do in this case */
		break;

	default:
		printf("Unsupported/invalid IPMI storage command\n");
	}
}

static int64_t ipmi_get_sel_time(void)
{
	struct ipmi_msg *msg;
	static uint32_t time_result;

	msg = bt_alloc_ipmi_msg(0, 4);
	if (!msg)
		return OPAL_HARDWARE;

	msg->cmd = IPMI_GET_SEL_TIME_CMD;
	msg->netfn = IPMI_NETFN_STORAGE_REQUEST;

	if (bt_add_ipmi_msg_wait(msg))
		return -1;

	memcpy(&time_result, msg->data, sizeof(time_result));

	return time_result;
}

static int64_t ipmi_set_sel_time(uint32_t tv)
{
	struct ipmi_msg *msg;

	msg = bt_alloc_ipmi_msg(sizeof(tv), 0);
	if (!msg)
		return OPAL_HARDWARE;

	msg->cmd = IPMI_SET_SEL_TIME_CMD;
	msg->netfn = IPMI_NETFN_STORAGE_REQUEST;
	memcpy(msg->data, &tv, sizeof(tv));

	return bt_add_ipmi_msg_wait(msg);
}

static int64_t ipmi_opal_rtc_read(uint32_t *y_m_d,
				 uint64_t *h_m_s_m)
{
	struct tm tm;

	if (ipmi_get_sel_time() < 0)
		return OPAL_HARDWARE;

	gmtime_r(&time, &tm);
	tm_to_datetime(&tm, y_m_d, h_m_s_m);
	return OPAL_SUCCESS;
}

static int64_t ipmi_opal_rtc_write(uint32_t year_month_day,
				  uint64_t hour_minute_second_millisecond)
{
	time_t t;
	struct tm tm;

	datetime_to_tm(year_month_day, hour_minute_second_millisecond, &tm);
	t = mktime(&tm);
	t = cpu_to_le32(t);
	if (ipmi_set_sel_time(t))
		return OPAL_HARDWARE;

	return OPAL_SUCCESS;
}

static void ipmi_rtc_init(void)
{
	struct dt_node *np = dt_new(opal_node, "rtc");
	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");

	opal_register(OPAL_RTC_READ, ipmi_opal_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, ipmi_opal_rtc_write, 2);
}

static void ipmi_cmd_done(struct ipmi_msg *msg)
{
	if (msg->cc != IPMI_CC_NO_ERROR) {
		prerror("IPMI: Got error response 0x%02x\n", msg->cc);
		goto out;
	}

	switch (msg->netfn) {
	case IPMI_NETFN_STORAGE_RESPONSE:
		ipmi_process_storage_resp(msg);
		break;

	case IPMI_NETFN_CHASSIS_RESPONSE:
		break;
	default:
		prerror("IPMI: Invalid IPMI function code in response\n");
	}

out:
	bt_free_ipmi_msg(msg);
}

int64_t ipmi_opal_chassis_control(uint64_t request)
{
	struct ipmi_msg *msg;
	uint8_t chassis_control = request;

	msg = bt_alloc_ipmi_msg(sizeof(chassis_control), 0);
	if (!msg)
		return OPAL_HARDWARE;

	if (request > IPMI_CHASSIS_SOFT_SHUTDOWN)
		return OPAL_PARAMETER;

	msg->cmd = IPMI_CHASSIS_CONTROL_CMD;
	msg->netfn = IPMI_NETFN_CHASSIS_REQUEST;
	msg->data[0] = chassis_control;

	prlog(PR_INFO, "IPMI: sending chassis control request %llu\n",
			request);

	return bt_add_ipmi_msg_wait(msg);
}

void ipmi_init(void)
{
	bt_init(ipmi_cmd_done);

	ipmi_rtc_init();
}
