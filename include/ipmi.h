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

#ifndef __IPMI_H
#define __IPMI_H

#include <stdint.h>

/*
 * IPMI codes as defined by the standard.
 */
#define IPMI_NETFN_APP_REQUEST		0x06
#define IPMI_NETFN_APP_RESPONSE		0x07
#define IPMI_GET_DEVICE_ID_CMD		0x01
#define IPMI_COLD_RESET_CMD		0x02
#define IPMI_WARM_RESET_CMD		0x03
#define IPMI_CLEAR_MSG_FLAGS_CMD	0x30
#define IPMI_GET_DEVICE_GUID_CMD	0x08
#define IPMI_GET_MSG_FLAGS_CMD		0x31
#define IPMI_SEND_MSG_CMD		0x34
#define IPMI_GET_MSG_CMD		0x33
#define IPMI_SET_BMC_GLOBAL_ENABLES_CMD	0x2e
#define IPMI_GET_BMC_GLOBAL_ENABLES_CMD	0x2f
#define IPMI_READ_EVENT_MSG_BUFFER_CMD	0x35
#define IPMI_GET_CHANNEL_INFO_CMD	0x42

/*
 * 28. Chassis Commands
 */
#define IPMI_CHASSIS_GET_CAP_CMD		0x00
#define IPMI_CHASSIS_GET_STATUS_CMD		0x01
#define IPMI_CHASSIS_CONTROL_CMD		0x02
#define IPMI_CHASSIS_RESET_CMD			0x03
#define IPMI_CHASSIS_IDENTIFY_CMD		0x04
#define IPMI_CHASSIS_SET_PANEL_BUTTON_EN_CMD	0x05
#define IPMI_CHASSIS_SET_CAP_CMD		0x06
#define IPMI_CHASSIS_SET_PWR_RESTORE_CMD	0x07
#define IPMI_CHASSIS_SET_PWR_CYCLE_CMD		0x08
#define IPMI_CHASSIS_GET_SYS_RESTART_CAUSE_CMD	0x09
#define IPMI_CHASSIS_SET_SYS_BOOT_OPT_CMD	0x0a
#define IPMI_CHASSIS_GET_SYS_BOOT_OPT_CMD	0x0b
#define IPMI_CHASSIS_GET_POH_COUNTER_CMD	0x0f

#define IPMI_NETFN_CHASSIS_REQUEST		0x00
#define IPMI_NETFN_CHASSIS_RESPONSE		0x01

/* 28.3. Chassis Control Command */
#define   IPMI_CHASSIS_PWR_DOWN 		0x00
#define   IPMI_CHASSIS_PWR_UP			0x01
#define   IPMI_CHASSIS_PWR_CYCLE		0x02
#define   IPMI_CHASSIS_HARD_RESET		0x03
#define   IPMI_CHASSIS_PULSE_DIAG		0x04
#define   IPMI_CHASSIS_SOFT_SHUTDOWN		0x05

#define IPMI_NETFN_STORAGE_REQUEST	0x0a
#define IPMI_NETFN_STORAGE_RESPONSE	0x0b
#define   IPMI_GET_SEL_INFO_CMD		0x40
#define   IPMI_GET_SEL_TIME_CMD		0x48
#define   IPMI_SET_SEL_TIME_CMD		0x49

/*
 * IPMI response codes.
 */
#define IPMI_CC_NO_ERROR		0x00
#define IPMI_NODE_BUSY_ERR		0xc0
#define IPMI_INVALID_COMMAND_ERR	0xc1
#define IPMI_TIMEOUT_ERR		0xc3
#define IPMI_ERR_MSG_TRUNCATED		0xc6
#define IPMI_REQ_LEN_INVALID_ERR	0xc7
#define IPMI_REQ_LEN_EXCEEDED_ERR	0xc8
#define IPMI_NOT_IN_MY_STATE_ERR	0xd5	/* IPMI 2.0 */
#define IPMI_LOST_ARBITRATION_ERR	0x81
#define IPMI_BUS_ERR			0x82
#define IPMI_NAK_ON_WRITE_ERR		0x83
#define IPMI_ERR_UNSPECIFIED		0xff

struct ipmi_msg {
	uint8_t netfn;
	uint8_t cmd;
	uint8_t cc;
	uint8_t req_data_len;
	uint8_t resp_data_len;
	uint8_t *data;
};

/* Initialise the IPMI interface */
void ipmi_init(void);

/* Change the power state of the P8 */
int64_t ipmi_opal_chassis_control(uint64_t request);

#endif
