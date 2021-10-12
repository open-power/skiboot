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
#define PAU_BLOCK_CQ_CTL			PAU_BLOCK(4, 4)

/*
 * CQ_SM block registers
 *
 * Definitions here use PAU_BLOCK_CQ_SM(0), but when pau_write() is given
 * one of these, it will do corresponding writes to every CQ_SM block.
 */
#define PAU_MCP_MISC_CFG0			(PAU_BLOCK_CQ_SM(0) + 0x000)
#define   PAU_MCP_MISC_CFG0_MA_MCRESP_OPT_WRP	PPC_BIT(9)
#define   PAU_MCP_MISC_CFG0_ENABLE_PBUS		PPC_BIT(26)
#define PAU_SNP_MISC_CFG0			(PAU_BLOCK_CQ_SM(0) + 0x180)
#define   PAU_SNP_MISC_CFG0_ENABLE_PBUS		PPC_BIT(2)
#define PAU_NTL_BAR(brk)			(PAU_BLOCK_CQ_SM(0) + 0x1b8 + (brk) * 8)
#define   PAU_NTL_BAR_ADDR			PPC_BITMASK(3, 35)
#define   PAU_NTL_BAR_SIZE			PPC_BITMASK(39, 43)
#define PAU_MMIO_BAR				(PAU_BLOCK_CQ_SM(0) + 0x1e0)
#define   PAU_MMIO_BAR_ENABLE			PPC_BIT(0)
#define   PAU_MMIO_BAR_ADDR			PPC_BITMASK(3, 27)
#define PAU_GENID_BAR				(PAU_BLOCK_CQ_SM(0) + 0x1e8)
#define   PAU_GENID_BAR_ADDR			PPC_BITMASK(3, 32)

/* CQ_CTL block registers */
#define PAU_CTL_MISC_MMIOPA_CONFIG(brk)		(PAU_BLOCK_CQ_CTL + 0x098 + (brk) * 8)
#define   PAU_CTL_MISC_MMIOPA_CONFIG_BAR_ADDR	PPC_BITMASK(1, 35)
#define   PAU_CTL_MISC_MMIOPA_CONFIG_BAR_SIZE	PPC_BITMASK(39, 43)

#endif /* __PAU_REGS_H */
