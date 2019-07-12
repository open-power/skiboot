// SPDX-License-Identifier: Apache-2.0
/*
 * When everything is terrible, tell the FSP as much as possible as to why
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <errorlog.h>
#include <ipmi.h>
#include <pel.h>
#include <platform.h>
#include <processor.h>
#include <sbe-p9.h>
#include <skiboot.h>
#include <stack.h>
#include <timebase.h>

/* Use same attention SRC for BMC based machine */
DEFINE_LOG_ENTRY(OPAL_RC_ATTN, OPAL_PLATFORM_ERR_EVT,
		 OPAL_ATTN, OPAL_PLATFORM_FIRMWARE,
		 OPAL_ERROR_PANIC, OPAL_ABNORMAL_POWER_OFF);

/* Maximum buffer size to capture backtrace and other useful information */
#define IPMI_TI_BUFFER_SIZE	(IPMI_MAX_PEL_SIZE - PEL_MIN_SIZE)
static char ti_buffer[IPMI_TI_BUFFER_SIZE];

#define STACK_BUF_ENTRIES       20
static struct bt_entry bt_buf[STACK_BUF_ENTRIES];

/* Log eSEL event with OPAL backtrace */
static void ipmi_log_terminate_event(const char *msg)
{
	struct bt_metadata metadata;
	unsigned int ti_len;
	unsigned int ti_size;
	struct errorlog *elog_buf;

	/* Fill OPAL version */
	ti_len = snprintf(ti_buffer, IPMI_TI_BUFFER_SIZE,
			  "OPAL version : %s\n", version);

	/* File information */
	ti_len += snprintf(ti_buffer + ti_len, IPMI_TI_BUFFER_SIZE - ti_len,
			   "File info : %s\n", msg);
	ti_size = IPMI_TI_BUFFER_SIZE - ti_len;

	/* Backtrace */
	backtrace_create(bt_buf, STACK_BUF_ENTRIES, &metadata);
	metadata.token = OPAL_LAST + 1;
	backtrace_print(bt_buf, &metadata, ti_buffer + ti_len, &ti_size, true);

	/* Create eSEL event and commit */
	elog_buf = opal_elog_create(&e_info(OPAL_RC_ATTN), 0);
	log_append_data(elog_buf, (char *)&ti_buffer, ti_len + ti_size);
	log_commit(elog_buf);
}

void __attribute__((noreturn)) ipmi_terminate(const char *msg)
{
	/* Log eSEL event */
	if (ipmi_present())
		ipmi_log_terminate_event(msg);

	/*
	 * If mpipl is supported then trigger SBE interrupt
	 * to initiate mpipl
	 */
	p9_sbe_terminate();

	/* Terminate called before initializing IPMI (early abort) */
	if (!ipmi_present()) {
		if (platform.cec_reboot)
			platform.cec_reboot();
		goto out;
	}

	/* Reboot call */
	if (platform.cec_reboot)
		platform.cec_reboot();

out:
	while (1)
		time_wait_ms(100);
}
