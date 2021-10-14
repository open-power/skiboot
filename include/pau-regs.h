/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright 2021 IBM Corp.
 */

#ifndef __PAU_REGS_H
#define __PAU_REGS_H

/* PAU FIR registers */
#define PAU_FIR(n)				(0x400 + (n) * 0x40)
#define PAU_FIR_MASK(n)				(0x403 + (n) * 0x40)
#define PAU_FIR_ACTION0(n)			(0x406 + (n) * 0x40)
#define PAU_FIR_ACTION1(n)			(0x407 + (n) * 0x40)
#define PAU_FIR_MAX				3

/* PAU RING: Indirect address/data port */
#define PAU_MISC_SCOM_IND_SCOM_ADDR		0x33e
#define   PAU_MISC_DA_ADDR			PPC_BITMASK(0, 23)
#define   PAU_MISC_DA_LEN			PPC_BITMASK(24, 25)
#define     PAU_MISC_DA_LEN_4B			2
#define     PAU_MISC_DA_LEN_8B			3
#define PAU_MISC_SCOM_IND_SCOM_DATA		0x33f

/* PAU RING: Indirect register blocks */
#define PAU_BLOCK(nib0, nib1)			((nib0) << 20 | (nib1) << 16)
#define PAU_REG_BLOCK(reg)			((reg) & 0xff0000)
#define PAU_REG_OFFSET(reg)			((reg) & 0xffff)

#define PAU_BLOCK_CQ_SM(n)			PAU_BLOCK(4, (n))

#endif /* __PAU_REGS_H */
