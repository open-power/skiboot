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
/**
 * @file opal-internal.h
 * @brief OPAL related internal definitions
 *
 */

#ifndef __OPAL_INTERNAL_H
#define __OPAL_INTERNAL_H

#include <skiboot.h>

struct opal_table_entry {
	void    *func;
	uint32_t token;
	uint32_t nargs;
};

#define opal_call(__tok, __func, __nargs) \
static struct opal_table_entry __e_##__func __used __section(".opal_table") = \
{ .func = __func, .token = __tok, \
  .nargs = __nargs + 0 * sizeof(__func( __test_args##__nargs )) }

/* Make sure function takes args they claim.  Look away now... */
#define __test_args0
#define __test_args1 0
#define __test_args2 0,0
#define __test_args3 0,0,0
#define __test_args4 0,0,0,0
#define __test_args5 0,0,0,0,0
#define __test_args6 0,0,0,0,0,0
#define __test_args7 0,0,0,0,0,0,0

extern struct opal_table_entry __opal_table_start[];
extern struct opal_table_entry __opal_table_end[];

extern uint64_t opal_pending_events;

extern struct dt_node *opal_node;

extern void opal_table_init(void);
extern void opal_update_pending_evt(uint64_t evt_mask, uint64_t evt_values);
extern void add_opal_node(void);

#define opal_register(token, func, nargs) \
	__opal_reister((token) + 0*sizeof(func(__test_args##nargs)), \
			(func), (nargs))
extern void __opal_register(uint64_t token, void *func, unsigned num_args);

/** @defgroup POLLER Poller
 * Warning: no locking at the moment, do at init time only
 * XXX TODO: Add the big RCU-ish "opal API lock" to protect us here
 * which will also be used for other things such as runtime updates
 * @ingroup OPAL_INTERNAL POLLER
 * @{ */
/** Function Doc */
extern void opal_add_poller(void (*poller)(void *data), void *data);
/** Function Doc */
extern void opal_del_poller(void (*poller)(void *data));
/** @} */

/** @defgroup NOTIFIER Host Sync Notifier
 * Warning: no locking, only call that from the init processor
 * @ingroup OPAL_INTERNAL NOTIFIER
 * @{ */
/** Function Doc */
extern void opal_add_host_sync_notifier(bool (*notify)(void *data), void *data);
/** Function Doc */
extern void opal_del_host_sync_notifier(bool (*notify)(void *data));
/** @} */


/** @ingroup OPAL_INTERNAL
 *  @defgroup ERR_TYPE Classification of error/events type reported on OPAL
 * OPAL error/event type classification
 * @ingroup OPAL_INTERNAL ERR_TYPE
 * @{ */
/** Platform Events/Errors: Report Machine Check Interrupt */
#define OPAL_PLATFORM_ERR_EVT         0x01
/** INPUT_OUTPUT: Report all I/O related events/errors */
#define OPAL_INPUT_OUTPUT_ERR_EVT     0x02
/** RESOURCE_DEALLOC: Hotplug events and errors */
#define OPAL_RESOURCE_DEALLOC_ERR_EVT 0x03
/** MISC: Miscellanous error */
#define OPAL_MISC_ERR_EVT             0x04
/** @} */

/**
 * @ingroup OPAL_INTERNAL
 * @defgroup ERR_ID OPAL Subsystem IDs listed for reporting events/errors
 * @ingroup ERR_ID OPAL_INTERNAL
 * @{ */
#define OPAL_PROCESSOR_SUBSYSTEM 0x10
#define OPAL_MEMORY_SUBSYSTEM    0x20
#define OPAL_IO_SUBSYSTEM        0x30
#define OPAL_IO_DEVICES          0x40
#define OPAL_CEC_HARDWARE        0x50
#define OPAL_POWER_COOLING       0x60
#define OPAL_MISC_SUBSYSTEM      0x70
#define OPAL_SURVEILLANCE_ERR    0x7A
#define OPAL_PLATFORM_FIRMWARE   0x80
#define OPAL_SOFTWARE            0x90
#define OPAL_EXTERNAL_ENV        0xA0
/** @} */

/**
 * @ingroup OPAL_INTERNAL
 * @defgroup ERR_SEV OPAL Error Severity
 * During reporting an event/error the following represents how
 * serious the logged event/error is. (Severity)
 * @ingroup OPAL_INTERNAL ERR_SEV
 * @{ */
#define OPAL_INFO                  0x00
#define OPAL_RECOVERED_ERR_GENERAL 0x10
/** @} */

/**
 * @ingroup ERR_SEV OPAL_INTERNAL
 * @defgroup ERR_SEV_2 Predictive Error defines
 * @ingroup ERR_SEV_2 ERR_SEV OPAL_INTERNAL
 * @{ */
/** 0x20 Generic predictive error */
#define OPAL_PREDICTIVE_ERR_GENERAL                         0x20
/** 0x21 Predictive error, degraded performance */
#define OPAL_PREDICTIVE_ERR_DEGRADED_PERF                   0x21
/** 0x22 Predictive error, fault may be corrected after reboot */
#define OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT            0x22
/**
 * 0x23 Predictive error, fault may be corrected after reboot,
 * degraded performance
 */
#define OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_BOOT_DEGRADE_PERF 0x23
/** 0x24 Predictive error, loss of redundancy */
#define OPAL_PREDICTIVE_ERR_LOSS_OF_REDUNDANCY              0x24
/** @} */

/** @ingroup ERR_SEV OPAL_INTERNAL
 * @defgroup ERR_SEV_4 Unrecoverable Error defines
 * @ingroup ERR_SEV_4 ERR_SEV OPAL_INTERNAL
 * @{ */
/** 0x40 Generic Unrecoverable error */
#define OPAL_UNRECOVERABLE_ERR_GENERAL                      0x40
/** 0x41 Unrecoverable error bypassed with degraded performance */
#define OPAL_UNRECOVERABLE_ERR_DEGRADE_PERF                 0x41
/** 0x44 Unrecoverable error bypassed with loss of redundancy */
#define OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY              0x44
/** 0x45 Unrecoverable error bypassed with loss of redundancy and performance */
#define OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY_PERF         0x45
/** 0x48 Unrecoverable error bypassed with loss of function */
#define OPAL_UNRECOVERABLE_ERR_LOSS_OF_FUNCTION             0x48
/** 0x50 In case of PANIC */
#define OPAL_ERROR_PANIC                                    0x50
/** @} */

/**
 * @ingroup OPAL_INTERNAL
 * @defgroup OPAL_EVENT_SUB_TYPE Event Sub-Type
 * This field provides additional information on the non-error
 * event type
 * @ingroup OPAL_EVENT_SUB_TYPE OPAL_INTERNAL
 * @{ */
#define OPAL_NA                              0x00
#define OPAL_MISCELLANEOUS_INFO_ONLY         0x01
#define OPAL_PREV_REPORTED_ERR_RECTIFIED     0x10
#define OPAL_SYS_RESOURCES_DECONFIG_BY_USER  0x20
#define OPAL_SYS_RESOURCE_DECONFIG_PRIOR_ERR 0x21
#define OPAL_RESOURCE_DEALLOC_EVENT_NOTIFY   0x22
#define OPAL_CONCURRENT_MAINTENANCE_EVENT    0x40
#define OPAL_CAPACITY_UPGRADE_EVENT          0x60
#define OPAL_RESOURCE_SPARING_EVENT          0x70
#define OPAL_DYNAMIC_RECONFIG_EVENT          0x80
#define OPAL_NORMAL_SYS_PLATFORM_SHUTDOWN    0xD0
#define OPAL_ABNORMAL_POWER_OFF              0xE0
/** @} */

/** @ingroup OPAL_INTERNAL
 * Max user dump size is 14K */
#define OPAL_LOG_MAX_DUMP 14336

/**
 * @struct opal_user_data_section
 * @ingroup OPAL_INTERNAL
 * Multiple user data sections
 */
struct opal_user_data_section {
	uint32_t tag;
	uint16_t size;
	uint16_t component_id;
	char data_dump[1];
} __attribute__((__packed__));

/**
 * @struct opal_errorlog
 * @ingroup OPAL_INTERNAL
 * All the information regarding an error/event to be reported
 * needs to populate this structure using pre-defined interfaces
 * only
 */
struct opal_errorlog {

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

	char user_data_dump[OPAL_LOG_MAX_DUMP];
	struct list_node link;
} __attribute__((__packed__));

#endif /* __ASSEMBLY__ */

#endif /* __OPAL_INTERNAL_H */
