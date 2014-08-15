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
#include <time.h>
#include <time-utils.h>

static time_t time = 0;

static void ipmi_process_storage_resp(struct ipmi_msg *msg)
{
	uint32_t new_time;

	switch (msg->cmd) {
	case IPMI_GET_SEL_TIME_CMD:
		/*
		 * I couldn't find any mention of endianess in the IPMI spec,
		 * but ipmitool seemed to assume little endian?
		 */
		memcpy(&new_time, msg->resp_data, 4);
		time = le32_to_cpu(new_time);
		break;

	case IPMI_SET_SEL_TIME_CMD:
		/* Nothing to do in this case */
		break;

	default:
		printf("Unsupported/invalid IPMI storage command\n");
	}
}

static uint32_t time_result;
static int64_t ipmi_get_sel_time(void)
{
	struct ipmi_msg *msg = malloc(sizeof(struct ipmi_msg));

	if (!msg)
		return OPAL_HARDWARE;

	msg->cmd = IPMI_GET_SEL_TIME_CMD;
	msg->netfn = IPMI_NETFN_STORAGE_REQUEST;
	msg->req_data = NULL;
	msg->req_data_len = 0;
	msg->resp_data = (uint8_t *) &time_result;
	msg->resp_data_len = 4;
	if (bt_add_ipmi_msg_wait(msg))
		return -1;

	return time_result;
}

static int64_t ipmi_set_sel_time(uint32_t tv)
{
	struct ipmi_msg *msg = malloc(sizeof(struct ipmi_msg));

	if (!msg)
		return OPAL_HARDWARE;

	msg->cmd = IPMI_SET_SEL_TIME_CMD;
	msg->netfn = IPMI_NETFN_STORAGE_REQUEST;
	msg->req_data = (uint8_t *) &tv;
	msg->req_data_len = 4;
	msg->resp_data = NULL;
	msg->resp_data_len = 0;

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
	free(msg);
}

static uint8_t chassis_control;
int64_t ipmi_opal_chassis_control(uint64_t request)
{
	struct ipmi_msg *msg = zalloc(sizeof(struct ipmi_msg));

	if (!msg)
		return OPAL_HARDWARE;

	if (request > IPMI_CHASSIS_SOFT_SHUTDOWN)
		return OPAL_PARAMETER;

	chassis_control = request;

	msg->cmd = IPMI_CHASSIS_CONTROL_CMD;
	msg->netfn = IPMI_NETFN_CHASSIS_REQUEST;
	msg->req_data = (uint8_t *)&chassis_control;
	msg->req_data_len = sizeof(chassis_control);
	msg->resp_data = NULL;
	msg->resp_data_len = 0;

	prlog(PR_INFO, "IPMI: sending chassis control request %llu\n",
			request);

	return bt_add_ipmi_msg_wait(msg);
}

void ipmi_init(void)
{
	bt_init(ipmi_cmd_done);
	opal_register(OPAL_RTC_READ, ipmi_opal_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, ipmi_opal_rtc_write, 2);
}
