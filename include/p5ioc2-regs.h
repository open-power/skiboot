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

#ifndef __P5IOC2_REGS_H
#define __P5IOC2_REGS_H

/*
 * IO HUB registers
 *
 * Most (all) of those registers support an AND access
 * at address + 0x1000 and an OR access at address + 0x2000
 */
#define P5IOC2_REG_AND		0x1000
#define P5IOC2_REG_OR		0x2000

/* Internal BARs */
#define P5IOC2_BAR0		0x0100
#define P5IOC2_BAR1		0x0108
#define P5IOC2_BAR2		0x0110
#define P5IOC2_BAR3		0x0118
#define P5IOC2_BAR4		0x0120
#define P5IOC2_BAR5		0x0128
#define P5IOC2_BAR6		0x0130
#define P5IOC2_BAR7		0x0138
#define P5IOC2_BARM0		0x0180
#define P5IOC2_BARM1		0x0188
#define P5IOC2_BARM2		0x0190
#define P5IOC2_BARM3		0x0198
#define P5IOC2_BARM4		0x01a0
#define P5IOC2_BARM5		0x01a8
#define P5IOC2_BARM6		0x01b0
#define P5IOC2_BARM7		0x01b8
#define P5IOC2_BAR(n)		(0x100 + ((n) << 3))
#define P5IOC2_BARM(n)		(0x180 + ((n) << 3))

/* Routing table */
#define P5IOC2_TxRTE(x,n)	(0x200 + ((x) << 7) + ((n) << 3))
#define   P5IOC2_TxRTE_VALID	PPC_BIT(47)

/* BUID routing table */
#define P5IOC2_BUIDRTE(n)	(0x600 + ((n) << 3))
#define   P5IOC2_BUIDRTE_VALID	PPC_BIT(47)
#define   P5IOC2_BUIDRTE_RR_EOI	PPC_BIT(48)
#define   P5IOC2_BUIDRTE_RR_RET	PPC_BIT(49)

/* Others */
#define P5IOC2_FIRMC		0x0008  /* FIR Mask Checkstop */
#define P5IOC2_CTL		0x0030	/* Control register part 1 */
#define P5IOC2_CTL2		0x00c8	/* Control register part 2 */
#define P5IOC2_DIRA		0x0090  /* Cache dir. address */
#define P5IOC2_DIRD		0x0098  /* Cache dir. data */
#define P5IOC2_IBASE		0x0048	/* Interrupt base address */
#define P5IOC2_IRBM		0x00d8  /* Interrupt re-issue broadcast mask */
#define P5IOC2_SID		0x0038  /* P5IOC2 ID register */
#define   P5IOC2_SID_BUID_BASE	PPC_BITMASK(14,22)
#define   P5IOC2_SID_BUID_MASK	PPC_BITMASK(27,30)
#define P5IOC2_SBUID 		0x00f8  /* P5IOC2 HUB BUID */

/* XIPM area */
#define P5IOC2_BUCO		0x40008
#define P5IOC2_MIIP		0x40000
#define P5IOC2_XINM		0x40010

/* Xin/Xout area */
#define P5IOC2_XIXO		0xf0030
#define   P5IOC2_XIXO_ENH_TCE	PPC_BIT(0)

/*
 * Calgary registers
 *
 * CA0 is PCI-X and CA1 is PCIE, though the type can be discovered
 * from registers so we'll simply let it do so
 */

#define CA_CCR				0x108
#define CA_DEVBUID			0x118
#define   CA_DEVBUID_MASK		PPC_BITMASK32(7,15)
#define CA_TAR0				0x580
#define   CA_TAR_HUBID			PPC_BITMASK(0,5)
#define   CA_TAR_ALTHUBID		PPC_BITMASK(6,11)
#define   CA_TAR_TCE_ADDR		PPC_BITMASK(16,48)
#define   CA_TAR_VALID			PPC_BIT(60)
#define   CA_TAR_NUM_TCE		PPC_BITMASK(61,63)
#define CA_TAR1				0x588
#define CA_TAR2				0x590
#define CA_TAR3				0x598
#define CA_TARn(n)			(0x580 + ((n) << 3))

#define CA_PHBID0			0x650
#define   CA_PHBID_PHB_ENABLE		PPC_BIT32(0)
#define   CA_PHBID_ADDRSPACE_ENABLE	PPC_BIT32(1)
#define   CA_PHBID_PHB_TYPE		PPC_BITMASK32(4,7)
#define     CA_PHBTYPE_PCIX1_0	0
#define     CA_PHBTYPE_PCIX2_0	1
#define     CA_PHBTYPE_PCIE_G1	4
#define     CA_PHBTYPE_PCIE_G2	5
/* PCI-X bits */
#define   CA_PHBID_XMODE_EMBEDDED	PPC_BIT32(8)
#define   CA_PHBID_XBUS_64BIT		PPC_BIT32(9)
#define   CA_PHBID_XBUS_266MHZ		PPC_BIT32(10)
/* PCI-E bits */
#define   CA_PHBID_EWIDTH		PPC_BITMASK32(8,10)
#define     CA_PHB_EWIDTH_X4	0
#define     CA_PHB_EWIDTH_X8	1
#define     CA_PHB_EWIDTH_X16	2
#define CA_PHBID1			0x658
#define CA_PHBID2			0x660
#define CA_PHBID3			0x668
#define CA_PHBIDn(n)			(0x650 + ((n) << 3))

/* PHB n reg base inside CA */
#define CA_PHBn_REGS(n)			(0x8000 + ((n) << 12))

/*
 * P5IOC2 PHB registers
 */
#define CAP_BUID			0x100
#define   CAP_BUID_MASK			PPC_BITMASK32(7,15)
#define CAP_MSIBASE			0x108 /* Undocumented ! */
#define CAP_DMACSR			0x110
#define CAP_PLSSR			0x120
#define CAP_PCADR			0x140
#define   CAP_PCADR_ENABLE		PPC_BIT32(0)
#define   CAP_PCADR_FUNC		PPC_BITMASK32(21,23)
#define   CAP_PCADR_BDFN		PPC_BITMASK32(8,23) /* bus,dev,func */
#define   CAP_PCADR_EXTOFF		PPC_BITMASK32(4,7)
#define CAP_PCDAT			0x130
#define CAP_PCFGRW			0x160
#define   CAP_PCFGRW_ERR_RECOV_EN	PPC_BIT32(1)
#define   CAP_PCFGRW_TCE_EN		PPC_BIT32(2)
#define   CAP_PCFGRW_FREEZE_EN		PPC_BIT32(3)
#define   CAP_PCFGRW_MMIO_FROZEN	PPC_BIT32(4)
#define   CAP_PCFGRW_DMA_FROZEN		PPC_BIT32(5)
#define   CAP_PCFGRW_ENHANCED_CFG_EN	PPC_BIT32(6)
#define   CAP_PCFGRW_DAC_DISABLE	PPC_BIT32(7)
#define   CAP_PCFGRW_2ND_MEM_SPACE_EN	PPC_BIT32(9)
#define   CAP_PCFGRW_MASK_PLSSR_IRQ	PPC_BIT32(10)
#define   CAP_PCFGRW_MASK_CSR_IRQ	PPC_BIT32(11)
#define   CAP_PCFGRW_IO_SPACE_DIABLE	PPC_BIT32(12)
#define   CAP_PCFGRW_SZ_MASK_IS_LIMIT	PPC_BIT32(13)
#define   CAP_PCFGRW_MSI_EN		PPC_BIT32(14)
#define CAP_IOAD_L			0x170
#define CAP_IOAD_H			0x180
#define CAP_MEM1_L			0x190
#define CAP_MEM1_H			0x1a0
#define CAP_IOSZ			0x1b0
#define CAP_MSZ1			0x1c0
#define CAP_MEM_ST			0x1d0
#define CAP_IO_ST			0x1e0
#define CAP_AER				0x200
#define CAP_BPR				0x210
#define CAP_CRR				0x270
#define   CAP_CRR_RESET1		PPC_BIT32(0)
#define   CAP_CRR_RESET2		PPC_BIT32(1)
#define CAP_XIVR0			0x400
#define   CAP_XIVR_PRIO			0x000000ff
#define   CAP_XIVR_SERVER		0x0000ff00
#define CAP_XIVRn(n)			(0x400 + ((n) << 4))
#define CAP_MVE0			0x500
#define   CAP_MVE_VALID			PPC_BIT32(0)
#define   CAP_MVE_TBL_OFF		PPC_BITMASK32(13,15)
#define   CAP_MVE_NUM_INT		PPC_BITMASK32(18,19)
#define CAP_MVE1			0x510
#define CAP_MODE0			0x880
#define CAP_MODE1			0x890
#define CAP_MODE2			0x8a0
#define CAP_MODE3			0x8b0

/*
 * SHPC Registers
 */
#define SHPC_LOGICAL_SLOT		0xb40
#define SHPC_LOGICAL_SLOT_STATE		0x00000003
#define   SHPC_SLOT_STATE_POWER_ONLY	1
#define   SHPC_SLOT_STATE_ENABLED	2
#define   SHPC_SLOT_STATE_DISABLED	3
#define SHPC_LOGICAL_SLOT_PRSNT		0x000000c00
#define   SHPC_SLOT_PRSTN_7_5W		0
#define   SHPC_SLOT_PRSTN_25W		1
#define   SHPC_SLOT_STATE_15W		2
#define   SHPC_SLOT_STATE_EMPTY		3

/* UTL registers */
#define UTL_SYS_BUS_CONTROL		0xc00
#define UTL_STATUS			0xc04
#define UTL_SYS_BUS_AGENT_STATUS	0xc08
#define UTL_SYS_BUS_AGENT_ERR_EN	0xc0c
#define UTL_SYS_BUS_AGENT_IRQ_EN	0xc10
#define UTL_SYS_BUS_BURST_SZ_CONF	0xc20
#define UTL_REVISION_ID			0xc24
#define UTL_TX_NON_POST_DEBUG_STAT1	0xc30
#define UTL_TX_NON_POST_DEBUG_STAT2	0xc34
#define UTL_GBIF_READ_REQ_DEBUG		0xc38
#define UTL_GBIF_WRITE_REQ_DEBUG	0xc3c
#define UTL_GBIF_TX_COMP_DEBUG		0xc40
#define UTL_GBIF_RX_COMP_DEBUG		0xc44
#define UTL_OUT_POST_HDR_BUF_ALLOC	0xc60
#define UTL_OUT_POST_DAT_BUF_ALLOC	0xc68
#define UTL_IN_POST_HDR_BUF_ALLOC	0xc70
#define UTL_IN_POST_DAT_BUF_ALLOC	0xc78
#define UTL_OUT_NP_BUF_ALLOC		0xc80
#define UTL_IN_NP_BUF_ALLOC		0xc88
#define UTL_PCIE_TAGS_ALLOC		0xc90
#define UTL_GBIF_READ_TAGS_ALLOC	0xc98
#define UTL_PCIE_PORT_CONTROL		0xca0
#define UTL_PCIE_PORT_STATUS		0xca4
#define UTL_PCIE_PORT_ERR_EN		0xca8
#define UTL_PCIE_PORT_IRQ_EN		0xcac
#define UTL_RC_STATUS			0xcb0
#define UTL_RC_ERR_EN			0xcb4
#define UTL_RC_IRQ_EN			0xcb8
#define UTL_PCI_PM_CONTROL		0xcc8
#define UTL_PCIE_PORT_ID		0xccc
#define UTL_TLP_DEBUG			0xcd0
#define UTL_VC_CTL_DEBUG		0xcd4
#define UTL_NP_BUFFER_DEBUG		0xcd8
#define UTL_POSTED_BUFFER_DEBUG		0xcdc
#define UTL_TX_FIFO_DEBUG		0xce0
#define UTL_TLP_COMPL_DEBUG		0xce4

#endif /* __P5IOC2_REGS_H */
