// SPDX-License-Identifier: Apache-2.0
/* Copyright 2013-2019 IBM Corp. */

#ifndef __DEBUG_DESCRIPTOR_H
#define __DEBUG_DESCRIPTOR_H

#define OPAL_BOOT_COMPLETE 0x1
/* Debug descriptor. This structure is pointed to by the word at offset
 * 0x80 in the sapphire binary
 */
struct debug_descriptor {
	u8	eye_catcher[8];	/* "OPALdbug" */
#define DEBUG_DESC_VERSION	1
	u32	version;
	u8	console_log_levels;	/* high 4 bits in memory,
					 * low 4 bits driver (e.g. uart). */
	u8	state_flags; /* various state flags - OPAL_BOOT_COMPLETE etc */
	u16	reserved2;
	u32	reserved[2];

	/* Memory console */
	u64	memcons_phys;
	u32	memcons_tce;
	u32	memcons_obuf_tce;
	u32	memcons_ibuf_tce;

	/* Traces */
	u64	trace_mask;
	u32	num_traces;
#define DEBUG_DESC_MAX_TRACES	256
	u64	trace_phys[DEBUG_DESC_MAX_TRACES];
	u32	trace_size[DEBUG_DESC_MAX_TRACES];
	u32	trace_tce[DEBUG_DESC_MAX_TRACES];
	u16	trace_pir[DEBUG_DESC_MAX_TRACES];
};
extern struct debug_descriptor debug_descriptor;

static inline bool opal_booting(void)
{
	return !(debug_descriptor.state_flags & OPAL_BOOT_COMPLETE);
}

#endif
