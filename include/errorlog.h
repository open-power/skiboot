/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __ERRORLOG_H
#define __ERRORLOG_H

/* Classification of error/events type reported on OPAL */
/* Platform Events/Errors: Report Machine Check Interrupt */
#define OPAL_PLATFORM_ERR_EVT		0x01
/* INPUT_OUTPUT: Report all I/O related events/errors */
#define OPAL_INPUT_OUTPUT_ERR_EVT	0x02
/* RESOURCE_DEALLOC: Hotplug events and errors */
#define OPAL_RESOURCE_DEALLOC_ERR_EVT	0x03
/* MISC: Miscellanous error */
#define OPAL_MISC_ERR_EVT		0x04

/* OPAL Subsystem IDs listed for reporting events/errors */
#define OPAL_PROCESSOR_SUBSYSTEM	0x10
#define OPAL_MEMORY_SUBSYSTEM		0x20
#define OPAL_IO_SUBSYSTEM		0x30
#define OPAL_IO_DEVICES			0x40
#define OPAL_CEC_HARDWARE		0x50
#define OPAL_POWER_COOLING		0x60
#define OPAL_MISC_SUBSYSTEM		0x70
#define OPAL_SURVEILLANCE_ERR		0x7A
#define OPAL_PLATFORM_FIRMWARE		0x80
#define OPAL_SOFTWARE			0x90
#define OPAL_EXTERNAL_ENV		0xA0

/*
 * During reporting an event/error the following represents
 * how serious the logged event/error is. (Severity)
 */
#define OPAL_INFO						0x00
#define OPAL_RECOVERED_ERR_GENERAL				0x10

/* 0x2X series is to denote set of Predictive Error */
/* 0x20 Generic predictive error */
#define OPAL_PREDICTIVE_ERR_GENERAL				0x20
/* 0x21 Predictive error, degraded performance */
#define OPAL_PREDICTIVE_ERR_DEGRADED_PERF			0x21
/* 0x22 Predictive error, fault may be corrected after reboot */
#define OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT		0x22
/*
 * 0x23 Predictive error, fault may be corrected after reboot,
 * degraded performance
 */
#define OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_BOOT_DEGRADE_PERF	0x23
/* 0x24 Predictive error, loss of redundancy */
#define OPAL_PREDICTIVE_ERR_LOSS_OF_REDUNDANCY			0x24

/* 0x4X series for Unrecoverable Error */
/* 0x40 Generic Unrecoverable error */
#define OPAL_UNRECOVERABLE_ERR_GENERAL				0x40
/* 0x41 Unrecoverable error bypassed with degraded performance */
#define OPAL_UNRECOVERABLE_ERR_DEGRADE_PERF			0x41
/* 0x44 Unrecoverable error bypassed with loss of redundancy */
#define OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY			0x44
/* 0x45 Unrecoverable error bypassed with loss of redundancy and performance */
#define OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY_PERF		0x45
/* 0x48 Unrecoverable error bypassed with loss of function */
#define OPAL_UNRECOVERABLE_ERR_LOSS_OF_FUNCTION			0x48
/* 0x50 In case of PANIC	*/
#define OPAL_ERROR_PANIC					0x50

/*
 * OPAL Event Sub-type
 * This field provides additional information on the non-error
 * event type
 */
#define OPAL_NA						0x00
#define OPAL_MISCELLANEOUS_INFO_ONLY			0x01
#define OPAL_PREV_REPORTED_ERR_RECTIFIED		0x10
#define OPAL_SYS_RESOURCES_DECONFIG_BY_USER		0x20
#define OPAL_SYS_RESOURCE_DECONFIG_PRIOR_ERR		0x21
#define OPAL_RESOURCE_DEALLOC_EVENT_NOTIFY		0x22
#define OPAL_CONCURRENT_MAINTENANCE_EVENT		0x40
#define OPAL_CAPACITY_UPGRADE_EVENT			0x60
#define OPAL_RESOURCE_SPARING_EVENT			0x70
#define OPAL_DYNAMIC_RECONFIG_EVENT			0x80
#define OPAL_NORMAL_SYS_PLATFORM_SHUTDOWN		0xD0
#define OPAL_ABNORMAL_POWER_OFF				0xE0

/* Max user dump size is 14K	*/
#define OPAL_LOG_MAX_DUMP	14336

/* Multiple user data sections */
struct __attribute__((__packed__))elog_user_data_section {
	uint32_t tag;
	uint16_t size;
	uint16_t component_id;
	char data_dump[1];
};

/*
 * All the information regarding an error/event to be reported
 * needs to populate this structure using pre-defined interfaces
 * only
 */
struct __attribute__((__packed__)) errorlog {

	uint16_t component_id;
	uint8_t error_event_type;
	uint8_t subsystem_id;

	uint8_t event_severity;
	uint8_t event_subtype;
	uint8_t user_section_count;
	uint8_t elog_origin;

	uint32_t user_section_size;
	uint32_t reason_code;
	uint32_t additional_info[4];

	uint32_t plid;
	uint32_t log_size;
	uint64_t elog_timeout;

	char user_data_dump[OPAL_LOG_MAX_DUMP];
	struct list_node link;
};
#endif /* __ERRORLOG_H */
