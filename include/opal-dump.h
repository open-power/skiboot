// SPDX-License-Identifier: Apache-2.0
/* Copyright 2013-2015 IBM Corp. */

#ifndef __OPAL_DUMP_H
#define __OPAL_DUMP_H

/*
 * Dump region ids
 *
 * 0x01 - 0x7F : OPAL
 * 0x80 - 0xFF : Kernel
 *
 */
#define DUMP_REGION_OPAL_START		0x01
#define DUMP_REGION_OPAL_END		0x7F
#define DUMP_REGION_HOST_START		OPAL_DUMP_REGION_HOST_START
#define DUMP_REGION_HOST_END		OPAL_DUMP_REGION_HOST_END

#define DUMP_REGION_CONSOLE	0x01
#define DUMP_REGION_HBRT_LOG	0x02

/*
 * Sapphire Memory Dump Source Table
 *
 * Format of this table is same as Memory Dump Source Table (MDST)
 * defined in HDAT spec.
 */
struct mdst_table {
	__be64	addr;
	__be32	type; /* DUMP_REGION_* */
	__be32	size;
};

#endif	/* __OPAL_DUMP_H */
