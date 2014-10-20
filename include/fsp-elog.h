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
#include <opal.h>
#include <errorlog.h>
#include <pel.h>
#ifndef __ELOG_H
#define __ELOG_H

#define ELOG_TYPE_PEL			0
#define MAX_RETRIES			3

/* Following variables are used to indicate state of the
 * head log entry which is being fetched from FSP/OPAL and
 * these variables are not overwritten until next log is
 * retrieved from FSP/OPAL.
 */
enum elog_head_state {
	ELOG_STATE_FETCHING,    /*In the process of reading log from FSP. */
	ELOG_STATE_FETCHED_INFO,/* Indicates reading log info is completed */
	ELOG_STATE_FETCHED_DATA,/* Indicates reading log is completed */
	ELOG_STATE_NONE,        /* Indicates to fetch next log */
	ELOG_STATE_REJECTED,    /* resend all pending logs to linux */
};

/* Component IDs */
/* In PEL error log format, Creator ID is hypervisor
 * But we can have various component ID to distinguish
 * which component in hypervisor is reporting the error
 * This is 2 bytes long,
 *	first byte corresponds to Component IDs
 *	Second byte is reserved for the Reason code.
 * Component ID is mapped to readable 4-digit ascii
 * character name in FSP and displayed.
 */
/* SAPPHIRE components */
#define OPAL_CODEUPDATE			0x4355	/* CU */
#define OPAL_CONSOLE			0x434E	/* CN */
#define OPAL_CEC			0x4345	/* CE */
#define OPAL_CHIP			0x4348	/* CH */
#define OPAL_ELOG			0x454C	/* EL */
#define OPAL_NVRAM			0x4E56	/* NV */
#define OPAL_RTC			0x5254	/* RT */
#define OPAL_SURVEILLANCE		0x5355	/* SU */
#define OPAL_SYSPARAM			0x5350	/* SP */
#define OPAL_LPC			0x4C50	/* LP */
#define OPAL_UART			0x5541	/* UA */
#define OPAL_OCC			0x4F43	/* OC */
#define OPAL_OP_PANEL			0x4F50	/* OP */
#define OPAL_PHB3			0x5048	/* PH */
#define OPAL_PSI			0x5053	/* PS */
#define OPAL_VPD			0x5650	/* VP */
#define OPAL_XSCOM			0x5853	/* XS */
#define OPAL_PCI			0x5043	/* PC */
#define OPAL_MISC			0x4D49	/* MI */
#define OPAL_ATTN			0x4154	/* AT */
#define OPAL_MEM_ERR			0x4D45	/* ME */
#define OPAL_CENTAUR			0x4354	/* CT */
#define OPAL_MFSI			0x4D46	/* MF */
#define OPAL_DUMP			0x4455	/* DU */
#define OPAL_LED			0x4C45	/* LE */
#define OPAL_SENSOR			0x5345	/* SE */
#define OPAL_SLW			0x534C	/* SL */
#define OPAL_FSP			0x4650	/* FP */

/* SAPPHIRE SRC componenet ID*/
#define OPAL_CU				0x1000
#define OPAL_CN				0x2000
#define OPAL_CE				0x3000
#define OPAL_CH				0x4000
#define OPAL_EL				0x5000
#define OPAL_NV				0x6000
#define OPAL_RT				0x7000
#define OPAL_SU				0x8000
#define OPAL_SP				0x9000
#define OPAL_LP				0xa000
#define OPAL_UA				0xb000
#define OPAL_OC				0xc000
#define OPAL_OP				0xd000
#define OPAL_PH				0xe000
#define OPAL_PS				0xf000
#define OPAL_VP				0x1000
#define OPAL_XS				0x1100
#define OPAL_PC				0x1200
#define OPAL_MI				0x1300
#define OPAL_AT				0x1400
#define OPAL_ME				0x1500
#define OPAL_CT				0x1600
#define OPAL_MF				0x1700
#define OPAL_DU				0x1800
#define OPAL_LE				0x1900
#define OPAL_SE				0x2000
#define OPAL_SL				0x2100
#define OPAL_FP				0x2200

enum opal_reasoncode {
/* code update */
	OPAL_RC_CU_FLASH        = OPAL_CU | 0x10,
	OPAL_RC_CU_INIT         = OPAL_CU | 0x11,
	OPAL_RC_CU_SG_LIST      = OPAL_CU | 0x12,
	OPAL_RC_CU_COMMIT	= OPAL_CU | 0x13,
	OPAL_RC_CU_MSG		= OPAL_CU | 0x14,
	OPAL_RC_CU_NOTIFY       = OPAL_CU | 0x15,
	OPAL_RC_CU_MARKER_LID	= OPAL_CU | 0x16,
/* NVRAM */
	OPAL_RC_NVRAM_INIT      = OPAL_NV | 0x10,
	OPAL_RC_NVRAM_OPEN	= OPAL_NV | 0x11,
	OPAL_RC_NVRAM_SIZE      = OPAL_NV | 0x12,
	OPAL_RC_NVRAM_WRITE     = OPAL_NV | 0x13,
	OPAL_RC_NVRAM_READ      = OPAL_NV | 0x14,
/* CENTAUR */
	OPAL_RC_CENTAUR_INIT    = OPAL_CT | 0x10,
	OPAL_RC_CENTAUR_RW_ERR  = OPAL_CT | 0x11,
/* MFSI */
	OPAL_RC_MFSI_RW_ERR     = OPAL_MF | 0x10,
/* UART */
	OPAL_RC_UART_INIT       = OPAL_UA | 0x10,
/* OCC */
	OPAL_RC_OCC_RESET       = OPAL_OC | 0x10,
	OPAL_RC_OCC_LOAD        = OPAL_OC | 0x11,
	OPAL_RC_OCC_PSTATE_INIT = OPAL_OC | 0x12,
	OPAL_RC_OCC_TIMEOUT	= OPAL_OC | 0x13,
/* RTC	*/
	OPAL_RC_RTC_READ	= OPAL_RT | 0x10,
	OPAL_RC_RTC_TOD		= OPAL_RT | 0x11,
/* SURVEILLANCE */
	OPAL_RC_SURVE_INIT      = OPAL_SU | 0x10,
	OPAL_RC_SURVE_STATUS	= OPAL_SU | 0x11,
	OPAL_RC_SURVE_ACK	= OPAL_SU | 0x12,
/* SYSPARAM */
	OPAL_RC_SYSPARM_INIT    = OPAL_SP | 0x10,
	OPAL_RC_SYSPARM_MSG     = OPAL_SP | 0x11,
/* LPC */
	OPAL_RC_LPC_READ        = OPAL_LP | 0x10,
	OPAL_RC_LPC_WRITE       = OPAL_LP | 0x11,
/* OP_PANEL */
	OPAL_RC_PANEL_WRITE     = OPAL_OP | 0x10,
/* PSI */
	OPAL_RC_PSI_INIT        = OPAL_PS | 0x10,
	OPAL_RC_PSI_IRQ_RESET   = OPAL_PS | 0x11,
/* XSCOM */
	OPAL_RC_XSCOM_RW		= OPAL_XS | 0x10,
	OPAL_RC_XSCOM_INDIRECT_RW	= OPAL_XS | 0x11,
	OPAL_RC_XSCOM_RESET		= OPAL_XS | 0x12,
/* PCI */
	OPAL_RC_PCI_INIT_SLOT   = OPAL_PC | 0x10,
	OPAL_RC_PCI_ADD_SLOT    = OPAL_PC | 0x11,
	OPAL_RC_PCI_SCAN        = OPAL_PC | 0x12,
	OPAL_RC_PCI_RESET_PHB   = OPAL_PC | 0x10,
/* ATTN */
	OPAL_RC_ATTN		= OPAL_AT | 0x10,
/* MEM_ERR */
	OPAL_RC_MEM_ERR_RES	= OPAL_ME | 0x10,
	OPAL_RC_MEM_ERR_DEALLOC	= OPAL_ME | 0x11,
/* DUMP */
	OPAL_RC_DUMP_INIT	= OPAL_DU | 0x10,
	OPAL_RC_DUMP_LIST	= OPAL_DU | 0x11,
	OPAL_RC_DUMP_ACK	= OPAL_DU | 0x12,
	OPAL_RC_DUMP_MDST_INIT	= OPAL_DU | 0x13,
	OPAL_RC_DUMP_MDST_UPDATE= OPAL_DU | 0x14,
	OPAL_RC_DUMP_MDST_ADD	= OPAL_DU | 0x15,
	OPAL_RC_DUMP_MDST_REMOVE= OPAL_DU | 0x16,
/* LED	*/
	OPAL_RC_LED_SPCN	= OPAL_LE | 0x10,
	OPAL_RC_LED_BUFF	= OPAL_LE | 0x11,
	OPAL_RC_LED_LC		= OPAL_LE | 0x12,
	OPAL_RC_LED_STATE	= OPAL_LE | 0x13,
	OPAL_RC_LED_SUPPORT	= OPAL_LE | 0x14,
/* SENSOR */
	OPAL_RC_SENSOR_INIT	= OPAL_SE | 0x10,
	OPAL_RC_SENSOR_READ	= OPAL_SE | 0x11,
	OPAL_RC_SENSOR_ASYNC_COMPLETE
				= OPAL_SE | 0x12,
/* SLW */
	OPAL_RC_SLW_INIT	= OPAL_SL | 0x10,
	OPAL_RC_SLW_SET		= OPAL_SL | 0x11,
	OPAL_RC_SLW_GET		= OPAL_SL | 0x12,
	OPAL_RC_SLW_REG		= OPAL_SL | 0x13,
/* FSP	*/
	OPAL_RC_FSP_POLL_TIMEOUT
				= OPAL_FP | 0x10,
};

struct opal_err_info {
	uint32_t reason_code;
	uint8_t err_type;
	uint16_t cmp_id;
	uint8_t subsystem;
	uint8_t sev;
	uint8_t event_subtype;
	void (*call_out)(struct errorlog *buf, void *data, uint16_t size);
};

#define DEFINE_LOG_ENTRY(reason, type, id, subsys,			\
severity, subtype, callout_func) struct opal_err_info err_##reason =	\
{ .reason_code = reason, .err_type = type, .cmp_id = id,		\
.subsystem = subsys, .sev = severity, .event_subtype = subtype,		\
.call_out = callout_func }

/* Generate src from opal reason code (src_comp) */
#define generate_src_from_comp(src_comp)  (OPAL_SRC_TYPE_ERROR << 24 | \
				OPAL_FAILING_SUBSYSTEM << 16 | src_comp)

#define e_info(reason_code) err_##reason_code

struct errorlog *opal_elog_create(struct opal_err_info *e_info);

int opal_elog_update_user_dump(struct errorlog *buf, unsigned char *data,
						uint32_t tag, uint16_t size);

int elog_fsp_commit(struct errorlog *buf);

bool opal_elog_info(uint64_t *opal_elog_id, uint64_t *opal_elog_size);

bool opal_elog_read(uint64_t *buffer, uint64_t opal_elog_size,
						uint64_t opal_elog_id);

bool opal_elog_ack(uint64_t ack_id);

void opal_resend_pending_logs(void);

/* This is wrapper around the error log function, which creates
 * and commits the error to FSP.
 * Used for simple error logging
 */
void log_simple_error(struct opal_err_info *e_info, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
void log_error(struct opal_err_info *e_info, void *data, uint16_t size,
		const char *fmt, ...) __attribute__ ((format (printf, 4, 5)));

#endif /* __ELOG_H */
