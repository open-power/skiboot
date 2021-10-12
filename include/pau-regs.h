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
#define PAU_BLOCK_CQ_DAT			PAU_BLOCK(4, 5)
#define PAU_BLOCK_XSL				PAU_BLOCK(4, 0xE)
#define PAU_BLOCK_PAU_XTS			PAU_BLOCK(7, 1)
#define PAU_BLOCK_PAU_MISC			PAU_BLOCK(7, 2)

/*
 * CQ_SM block registers
 *
 * Definitions here use PAU_BLOCK_CQ_SM(0), but when pau_write() is given
 * one of these, it will do corresponding writes to every CQ_SM block.
 */
#define PAU_MCP_MISC_CFG0			(PAU_BLOCK_CQ_SM(0) + 0x000)
#define   PAU_MCP_MISC_CFG0_MA_MCRESP_OPT_WRP	PPC_BIT(9)
#define   PAU_MCP_MISC_CFG0_ENABLE_PBUS		PPC_BIT(26)
#define   PAU_MCP_MISC_CFG0_OCAPI_MODE		PPC_BITMASK(44, 48)
#define PAU_SNP_MISC_CFG0			(PAU_BLOCK_CQ_SM(0) + 0x180)
#define   PAU_SNP_MISC_CFG0_ENABLE_PBUS		PPC_BIT(2)
#define   PAU_SNP_MISC_CFG0_OCAPI_MODE		PPC_BITMASK(32, 36)
#define   PAU_SNP_MISC_CFG0_OCAPI_C2		PPC_BITMASK(45, 49)
#define PAU_NTL_BAR(brk)			(PAU_BLOCK_CQ_SM(0) + 0x1b8 + (brk) * 8)
#define   PAU_NTL_BAR_ENABLE			PPC_BIT(0)
#define   PAU_NTL_BAR_ADDR			PPC_BITMASK(3, 35)
#define   PAU_NTL_BAR_SIZE			PPC_BITMASK(39, 43)
#define PAU_MMIO_BAR				(PAU_BLOCK_CQ_SM(0) + 0x1e0)
#define   PAU_MMIO_BAR_ENABLE			PPC_BIT(0)
#define   PAU_MMIO_BAR_ADDR			PPC_BITMASK(3, 27)
#define PAU_GENID_BAR				(PAU_BLOCK_CQ_SM(0) + 0x1e8)
#define   PAU_GENID_BAR_ENABLE			PPC_BIT(0)
#define   PAU_GENID_BAR_ADDR			PPC_BITMASK(3, 32)
#define PAU_MISC_MACHINE_ALLOC			(PAU_BLOCK_CQ_SM(0) + 0x268)
#define   PAU_MISC_MACHINE_ALLOC_ENABLE		PPC_BIT(0)

/* CQ_CTL block registers */
#define PAU_CTL_MISC_CFG2			(PAU_BLOCK_CQ_CTL + 0x010)
#define   PAU_CTL_MISC_CFG2_OCAPI_MODE		PPC_BITMASK(0, 4)
#define   PAU_CTL_MISC_CFG2_OCAPI_4		PPC_BITMASK(10, 14)
#define   PAU_CTL_MISC_CFG2_OCAPI_C2		PPC_BITMASK(15, 19)
#define   PAU_CTL_MISC_CFG2_OCAPI_AMO		PPC_BITMASK(20, 24)
#define   PAU_CTL_MISC_CFG2_OCAPI_MEM_OS_BIT	PPC_BITMASK(25, 29)
#define PAU_CTL_MISC_STATUS(brk)		(PAU_BLOCK_CQ_CTL + 0x060 + (brk) * 8)
#define   PAU_CTL_MISC_STATUS_AM_FENCED(brk)	(PPC_BITMASK(41, 42) << ((brk)*32))
#define PAU_CTL_MISC_MMIOPA_CONFIG(brk)		(PAU_BLOCK_CQ_CTL + 0x098 + (brk) * 8)
#define   PAU_CTL_MISC_MMIOPA_CONFIG_BAR_ADDR	PPC_BITMASK(1, 35)
#define   PAU_CTL_MISC_MMIOPA_CONFIG_BAR_SIZE	PPC_BITMASK(39, 43)
#define PAU_CTL_MISC_FENCE_CTRL(brk)		(PAU_BLOCK_CQ_CTL + 0x108 + (brk) * 8)
#define   PAU_CTL_MISC_FENCE_REQUEST		PPC_BITMASK(0, 1)
#define PAU_CTL_MISC_CFG_ADDR(brk)		(PAU_BLOCK_CQ_CTL + 0x250 + (brk) * 8)
#define   PAU_CTL_MISC_CFG_ADDR_ENABLE		PPC_BIT(0)
#define   PAU_CTL_MISC_CFG_ADDR_STATUS		PPC_BITMASK(1, 3)
#define   PAU_CTL_MISC_CFG_ADDR_BUS_NBR		PPC_BITMASK(4, 11)
#define   PAU_CTL_MISC_CFG_ADDR_DEVICE_NBR	PPC_BITMASK(12, 16)
#define   PAU_CTL_MISC_CFG_ADDR_FUNCTION_NBR	PPC_BITMASK(17, 19)
#define   PAU_CTL_MISC_CFG_ADDR_REGISTER_NBR	PPC_BITMASK(20, 31)
#define   PAU_CTL_MISC_CFG_ADDR_TYPE		PPC_BIT(32)

/* CQ_DAT block registers */
#define PAU_DAT_MISC_CFG1			(PAU_BLOCK_CQ_DAT + 0x008)
#define   PAU_DAT_MISC_CFG1_OCAPI_MODE		PPC_BITMASK(40, 44)

/* XSL block registers */
#define PAU_XSL_WRAP_CFG			(PAU_BLOCK_XSL + 0x100)
#define   PAU_XSL_WRAP_CFG_CLOCK_ENABLE		PPC_BIT(0)

/* XTS block registers */
#define PAU_XTS_CFG				(PAU_BLOCK_PAU_XTS + 0x020)
#define   PAU_XTS_CFG_OPENCAPI			PPC_BIT(15)
#define PAU_XTS_CFG2				(PAU_BLOCK_PAU_XTS + 0x028)
#define   PAU_XTS_CFG2_XSL2_ENA			PPC_BIT(55)

/* MISC block registers */
#define PAU_MISC_OPTICAL_IO_CONFIG		(PAU_BLOCK_PAU_MISC + 0x018)
#define   PAU_MISC_OPTICAL_IO_CONFIG_OTL	PPC_BITMASK(2, 3)
#define PAU_MISC_HOLD				(PAU_BLOCK_PAU_MISC + 0x020)
#define   PAU_MISC_HOLD_NDL_STALL		PPC_BITMASK(0, 3)
#define PAU_MISC_CONFIG				(PAU_BLOCK_PAU_MISC + 0x030)
#define   PAU_MISC_CONFIG_OC_MODE		PPC_BIT(16)

#endif /* __PAU_REGS_H */
