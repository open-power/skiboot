// SPDX-License-Identifier: Apache-2.0
/* Copyright 2013-2015 IBM Corp. */

#ifndef __OPAL_DUMP_H
#define __OPAL_DUMP_H

/*
 * Dump region ids
 *
 * 0x01 - 0x3F : OPAL
 * 0x40 - 0x7F : Reserved for future use
 * 0x80 - 0xFF : Kernel
 *
 */
#define DUMP_REGION_OPAL_START		0x01
#define DUMP_REGION_OPAL_END		0x3F
#define DUMP_REGION_HOST_START		OPAL_DUMP_REGION_HOST_START
#define DUMP_REGION_HOST_END		OPAL_DUMP_REGION_HOST_END

#define DUMP_REGION_CONSOLE	0x01
#define DUMP_REGION_HBRT_LOG	0x02

/* Mainstore memory to be captured by FSP SYSDUMP */
#define DUMP_TYPE_SYSDUMP		0xF5
/* Mainstore memory to preserve during IPL */
#define DUMP_TYPE_MPIPL			0x00

/*
 *  Memory Dump Source Table
 *
 * Format of this table is same as Memory Dump Source Table (MDST)
 * defined in HDAT spec.
 */
struct mdst_table {
	__be64	addr;
	uint8_t	data_region;	/* DUMP_REGION_* */
	uint8_t dump_type;	/* DUMP_TYPE_* */
	__be16	reserved;
	__be32	size;
} __packed;

#endif	/* __OPAL_DUMP_H */
