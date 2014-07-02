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
 */


#ifndef __SPCN_H
#define __SPCN_H


/* SPCN commands */
#define SPCN_CMD_PRS			0x42 /* Power Resource Status */
#define SPCN_CMD_SET			0x66 /* Set Environmental Thresholds */

/* SPCN command address modes */
#define SPCN_ADDR_MODE_CEC_NODE		0x0000d000 /* CEC node single destination */
#define SPCN_ADDR_MODE_ALL_SLAVES	0x0000f000 /* Address all slaves in all racks */
#define SPCN_ADDR_MODE_RACK_NODES	0x00000000 /* Address rack node in all racks */

/* SPCN PRS command modifiers */
#define SPCN_MOD_PRS_STATUS_FIRST	0x01 /* Power Resource Status (First 1KB) */
#define SPCN_MOD_PRS_STATUS_SUBS	0x02 /* Subsequent set of 1KB PRS entries */
#define SPCN_MOD_PRS_LED_DATA_FIRST	0x51 /* LED data entry (First 1KB) */
#define SPCN_MOD_PRS_LED_DATA_SUB	0x52 /* Subsequent LED data entries */

/* SPCN SET command modifiers */
#define SPCN_MOD_SET_LED_CTL_LOC_CODE	0x07 /* Control LED with location code */
#define SPCN_MOD_SET_IDENTIFY_OFF_ENC	0x08 /* Turn off identify LEDs in CEC */
#define SPCN_MOD_SET_IDENTIFY_OFF_NODE	0x0B /* Turn off identify LEDs in Node */

/* SPCN SENSOR command modifiers */
#define SPCN_MOD_SENSOR_PARAM_FIRST	0x10 /* First 1K sensor parameters */
#define SPCN_MOD_SENSOR_PARAM_SUBS	0x11 /* Subsequent sensor parameters */
#define SPCN_MOD_SENSOR_DATA_FIRST	0x12 /* First 1K sensor data */
#define SPCN_MOD_SENSOR_DATA_SUBS	0x13 /* Subsequent sensor data blocks */
#define SPCN_MOD_PROC_JUNC_TEMP		0x14 /* Process junction temperatures */
#define SPCN_MOD_SENSOR_POWER		0x1c /* System power consumption */
#define SPCN_MOD_LAST			0xff

/*
 * Modifiers 0x53 and 0x54 are used by LEDS at standby. So HV does not come into
 * the picture here. Do we need those?
 */

/* Supported SPCN response codes */
#define LOGICAL_IND_STATE_MASK		0x10 /* If set, control fault state */
#define ACTIVE_LED_STATE_MASK		0x01 /* If set, switch on the LED */
#define SPCN_LED_IDENTIFY_MASK		0x80 /* Set identify indicator */
#define SPCN_LED_FAULT_MASK		0x40 /* Set fault indicator */
#define SPCN_LED_TRANS_MASK		0x20 /* LED is in transition */
#define SPCN_CLR_LED_STATE		0x00 /* Reset identify indicator */

/* SPCN command response status codes */
enum spcn_rsp_status {
	SPCN_RSP_STATUS_SUCCESS		= 0x01, /* Command successful */
	SPCN_RSP_STATUS_COND_SUCCESS	= 0x02, /* Command successful, but additional entries exist */
	SPCN_RSP_STATUS_INVALID_RACK	= 0x15, /* Invalid rack command */
	SPCN_RSP_STATUS_INVALID_SLAVE	= 0x16, /* Invalid slave command */
	SPCN_RSP_STATUS_INVALID_MOD	= 0x18, /* Invalid modifier */
	SPCN_RSP_STATUS_STATE_PROHIBIT	= 0x21, /* Present state prohibits */
	SPCN_RSP_STATUS_UNKNOWN		= 0xff, /* Default state */
};

/* Sensor FRCs (Frame resource class) */
enum {
	SENSOR_FRC_POWER_CTRL = 0x02,
	SENSOR_FRC_POWER_SUPPLY,
	SENSOR_FRC_REGULATOR,
	SENSOR_FRC_COOLING_FAN,
	SENSOR_FRC_COOLING_CTRL,
	SENSOR_FRC_BATTERY_CHRG,
	SENSOR_FRC_BATTERY_PACK,
	SENSOR_FRC_AMB_TEMP,
	SENSOR_FRC_TEMP,
	SENSOR_FRC_VRM,
	SENSOR_FRC_RISER_CARD,
	SENSOR_FRC_IO_BP,
};

#endif /* __SPCN_H */
