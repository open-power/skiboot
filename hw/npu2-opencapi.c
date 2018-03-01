/* Copyright 2013-2018 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Support for OpenCAPI on POWER9 NPUs
 *
 * This file provides support for OpenCAPI as implemented on POWER9.
 *
 * At present, we initialise the NPU separately from the NVLink code in npu2.c.
 * As such, we don't currently support mixed NVLink and OpenCAPI configurations
 * on the same NPU for machines such as Witherspoon.
 *
 * Procedure references in this file are to the POWER9 OpenCAPI NPU Workbook
 * (IBM internal document).
 *
 * TODO:
 *   - Support for mixed NVLink and OpenCAPI on the same NPU
 *   - Support for link ganging (one AFU using multiple links)
 *   - Link reset and error handling
 *   - Presence detection
 *   - Consume HDAT NPU information
 *   - LPC Memory support
 */

#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <timebase.h>
#include <pci.h>
#include <pci-cfg.h>
#include <pci-slot.h>
#include <interrupts.h>
#include <opal.h>
#include <opal-api.h>
#include <npu2.h>
#include <npu2-regs.h>
#include <phys-map.h>
#include <xive.h>
#include <i2c.h>

#define NPU_IRQ_LEVELS		35

static inline uint64_t index_to_stack(uint64_t index) {
	switch (index) {
	case 2:
	case 3:
		return NPU2_STACK_STCK_1;
		break;
	case 4:
	case 5:
		return NPU2_STACK_STCK_2;
		break;
	default:
		assert(false);
	}
}

static inline uint64_t index_to_stacku(uint64_t index) {
	switch (index) {
	case 2:
	case 3:
		return NPU2_STACK_STCK_1U;
		break;
	case 4:
	case 5:
		return NPU2_STACK_STCK_2U;
		break;
	default:
		assert(false);
	}
}

static inline uint64_t index_to_block(uint64_t index) {
	switch (index) {
	case 2:
	case 4:
		return NPU2_BLOCK_OTL0;
		break;
	case 3:
	case 5:
		return NPU2_BLOCK_OTL1;
		break;
	default:
		assert(false);
	}
}

/* Procedure 13.1.3.1 - select OCAPI vs NVLink for bricks 2-3/4-5 */

static void set_transport_mux_controls(uint32_t gcid, uint32_t scom_base,
				       int index, enum npu2_dev_type type)
{
	/* Step 1 - Set Transport MUX controls to select correct OTL or NTL */
	uint64_t reg;
	uint64_t field;

	/* TODO: Rework this to select for NVLink too */
	assert(type == NPU2_DEV_TYPE_OPENCAPI);

	prlog(PR_DEBUG, "OCAPI: %s: Setting transport mux controls\n", __func__);

	/* Optical IO Transport Mux Config for Bricks 0-2 and 4-5 */
	reg = npu2_scom_read(gcid, scom_base, NPU2_MISC_OPTICAL_IO_CFG0,
			     NPU2_MISC_DA_LEN_8B);
	switch (index) {
	case 0:
	case 1:
		/* not valid for OpenCAPI */
		assert(false);
		break;
	case 2:	 /* OTL1.0 */
		field = GETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_NDLMUX_BRK0TO2, reg);
		field &= ~0b100;
		reg = SETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_NDLMUX_BRK0TO2, reg,
			       field);
		field = GETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_OCMUX_BRK0TO1, reg);
		field |= 0b10;
		reg = SETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_OCMUX_BRK0TO1, reg,
			       field);
		break;
	case 3:	 /* OTL1.1 */
		field = GETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_NDLMUX_BRK0TO2, reg);
		field &= ~0b010;
		reg = SETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_NDLMUX_BRK0TO2, reg,
			       field);
		field = GETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_OCMUX_BRK0TO1, reg);
		field |= 0b01;
		reg = SETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_OCMUX_BRK0TO1, reg,
			       field);
		break;
	case 4:	 /* OTL2.0 */
		field = GETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_OCMUX_BRK4TO5, reg);
		field |= 0b10;
		reg = SETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_OCMUX_BRK4TO5, reg,
			       field);
		break;
	case 5:	 /* OTL2.1 */
		field = GETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_OCMUX_BRK4TO5, reg);
		field |= 0b01;
		reg = SETFIELD(NPU2_MISC_OPTICAL_IO_CFG0_OCMUX_BRK4TO5, reg,
			       field);
		break;
	default:
		assert(false);
	}
	npu2_scom_write(gcid, scom_base, NPU2_MISC_OPTICAL_IO_CFG0,
			NPU2_MISC_DA_LEN_8B, reg);

	/*
	 * PowerBus Optical Miscellaneous Config Register - select
	 * OpenCAPI for b4/5 and A-Link for b3
	 */
	xscom_read(gcid, PU_IOE_PB_MISC_CFG, &reg);
	switch (index) {
	case 0:
	case 1:
	case 2:
	case 3:
		break;
	case 4:
		reg = SETFIELD(PU_IOE_PB_MISC_CFG_SEL_04_NPU_NOT_PB, reg, 1);
		break;
	case 5:
		reg = SETFIELD(PU_IOE_PB_MISC_CFG_SEL_05_NPU_NOT_PB, reg, 1);
		break;
	}
	xscom_write(gcid, PU_IOE_PB_MISC_CFG, reg);
}

static void enable_odl_phy_mux(uint32_t gcid, int index)
{
	uint64_t reg;
	uint64_t phy_config_scom;
	prlog(PR_DEBUG, "OCAPI: %s: Enabling ODL to PHY MUXes\n", __func__);
	/* Step 2 - Enable MUXes for ODL to PHY connection */
	switch (index) {
	case 2:
	case 3:
		phy_config_scom = OBUS_LL0_IOOL_PHY_CONFIG;
		break;
	case 4:
	case 5:
		phy_config_scom = OBUS_LL3_IOOL_PHY_CONFIG;
		break;
	default:
		assert(false);
	}

	/* PowerBus OLL PHY Training Config Register */
	xscom_read(gcid, phy_config_scom, &reg);

	/* Enable ODLs to use shared PHYs */
	reg |= OBUS_IOOL_PHY_CONFIG_ODL0_ENABLED;
	reg |= OBUS_IOOL_PHY_CONFIG_ODL1_ENABLED;

	/*
	 * Based on the platform, we may have to activate an extra mux
	 * to connect the ODL to the right set of lanes.
	 *
	 * FIXME: to be checked once we have merged with nvlink
	 * code. Need to verify that it's a platform parameter and not
	 * slot-dependent
	 */
	if (platform.ocapi->odl_phy_swap)
		reg |= OBUS_IOOL_PHY_CONFIG_ODL_PHY_SWAP;
	else
		reg &= ~OBUS_IOOL_PHY_CONFIG_ODL_PHY_SWAP;

	/* Disable A-Link link layers */
	reg &= ~OBUS_IOOL_PHY_CONFIG_LINK0_OLL_ENABLED;
	reg &= ~OBUS_IOOL_PHY_CONFIG_LINK1_OLL_ENABLED;

	/* Disable NV-Link link layers */
	reg &= ~OBUS_IOOL_PHY_CONFIG_NV0_NPU_ENABLED;
	reg &= ~OBUS_IOOL_PHY_CONFIG_NV1_NPU_ENABLED;
	reg &= ~OBUS_IOOL_PHY_CONFIG_NV2_NPU_ENABLED;
	xscom_write(gcid, phy_config_scom, reg);
}

static void disable_alink_fp(uint32_t gcid)
{
	uint64_t reg = 0;

	prlog(PR_DEBUG, "OCAPI: %s: Disabling A-Link framer/parsers\n", __func__);
	/* Step 3 - Disable A-Link framers/parsers */
	/* TODO: Confirm if needed on OPAL system */

	reg |= PU_IOE_PB_FP_CFG_FP0_FMR_DISABLE;
	reg |= PU_IOE_PB_FP_CFG_FP0_PRS_DISABLE;
	reg |= PU_IOE_PB_FP_CFG_FP1_FMR_DISABLE;
	reg |= PU_IOE_PB_FP_CFG_FP1_PRS_DISABLE;
	xscom_write(gcid, PU_IOE_PB_FP01_CFG, reg);
	xscom_write(gcid, PU_IOE_PB_FP23_CFG, reg);
	xscom_write(gcid, PU_IOE_PB_FP45_CFG, reg);
	xscom_write(gcid, PU_IOE_PB_FP67_CFG, reg);
}

static void enable_xsl_clocks(uint32_t gcid, uint32_t scom_base, int index)
{
	/* Step 5 - Enable Clocks in XSL */

	prlog(PR_DEBUG, "OCAPI: %s: Enable clocks in XSL\n", __func__);

	npu2_scom_write(gcid, scom_base, NPU2_REG_OFFSET(index_to_stack(index),
							 NPU2_BLOCK_XSL,
							 NPU2_XSL_WRAP_CFG),
			NPU2_MISC_DA_LEN_8B, NPU2_XSL_WRAP_CFG_XSLO_CLOCK_ENABLE);
}

#define CQ_CTL_STATUS_TIMEOUT	10 /* milliseconds */

static int set_fence_control(uint32_t gcid, uint32_t scom_base,
			     int index, uint8_t status)
{
	int stack, block;
	uint64_t reg, status_field;
	uint8_t status_val;
	uint64_t fence_control;
	uint64_t timeout = mftb() + msecs_to_tb(CQ_CTL_STATUS_TIMEOUT);

	stack = index_to_stack(index);
	block = index_to_block(index);

	fence_control = NPU2_REG_OFFSET(stack, NPU2_BLOCK_CTL,
					block == NPU2_BLOCK_OTL0 ?
					NPU2_CQ_CTL_FENCE_CONTROL_0 :
					NPU2_CQ_CTL_FENCE_CONTROL_1);

	reg = SETFIELD(NPU2_CQ_CTL_FENCE_CONTROL_REQUEST_FENCE, 0ull, status);
	npu2_scom_write(gcid, scom_base, fence_control,
			NPU2_MISC_DA_LEN_8B, reg);

	/* Wait for fence status to update */
	if (index_to_block(index) == NPU2_BLOCK_OTL0)
		status_field = NPU2_CQ_CTL_STATUS_BRK0_AM_FENCED;
	else
		status_field = NPU2_CQ_CTL_STATUS_BRK1_AM_FENCED;

	do {
		reg = npu2_scom_read(gcid, scom_base,
				     NPU2_REG_OFFSET(index_to_stack(index),
						     NPU2_BLOCK_CTL,
						     NPU2_CQ_CTL_STATUS),
				     NPU2_MISC_DA_LEN_8B);
		status_val = GETFIELD(status_field, reg);
		if (status_val == status)
			return OPAL_SUCCESS;
		time_wait_ms(1);
	} while (tb_compare(mftb(), timeout) == TB_ABEFOREB);

	/**
	 * @fwts-label OCAPIFenceStatusTimeout
	 * @fwts-advice The NPU fence status did not update as expected. This
	 * could be the result of a firmware or hardware bug. OpenCAPI
	 * functionality could be broken.
	 */
	prlog(PR_ERR,
	      "OCAPI: Fence status for brick %d stuck: expected 0x%x, got 0x%x\n",
	      index, status, status_val);
	return OPAL_HARDWARE;
}

static void set_npcq_config(uint32_t gcid, uint32_t scom_base, int index)
{
	uint64_t reg, stack, block;

	prlog(PR_DEBUG, "OCAPI: %s: Set NPCQ Config\n", __func__);
	/* Step 6 - Set NPCQ configuration */
	/* CQ_CTL Misc Config Register #0 */
	stack = index_to_stack(index);
	block = index_to_block(index);

	/* Enable OTL */
	npu2_scom_write(gcid, scom_base, NPU2_OTL_CONFIG0(stack, block),
			NPU2_MISC_DA_LEN_8B, NPU2_OTL_CONFIG0_EN);
	set_fence_control(gcid, scom_base, index, 0b01);
	reg = npu2_scom_read(gcid, scom_base,
			     NPU2_REG_OFFSET(stack, NPU2_BLOCK_CTL,
					     NPU2_CQ_CTL_MISC_CFG),
			     NPU2_MISC_DA_LEN_8B);
	/* Set OCAPI mode */
	reg |= NPU2_CQ_CTL_MISC_CFG_CONFIG_OCAPI_MODE;
	if (block == NPU2_BLOCK_OTL0)
		reg |= NPU2_CQ_CTL_MISC_CFG_CONFIG_OTL0_ENABLE;
	else
		reg |= NPU2_CQ_CTL_MISC_CFG_CONFIG_OTL1_ENABLE;
	npu2_scom_write(gcid, scom_base,
			NPU2_REG_OFFSET(stack, NPU2_BLOCK_CTL,
					NPU2_CQ_CTL_MISC_CFG),
			NPU2_MISC_DA_LEN_8B, reg);

	/* NPU Fenced */
	set_fence_control(gcid, scom_base, index, 0b11);

	/* NPU Half Fenced */
	set_fence_control(gcid, scom_base, index, 0b10);

	/* CQ_DAT Misc Config Register #1 */
	reg = npu2_scom_read(gcid, scom_base,
			     NPU2_REG_OFFSET(stack, NPU2_BLOCK_DAT,
					     NPU2_CQ_DAT_MISC_CFG),
			     NPU2_MISC_DA_LEN_8B);
	/* Set OCAPI mode for bricks 2-5 */
	reg |= NPU2_CQ_DAT_MISC_CFG_CONFIG_OCAPI_MODE;
	npu2_scom_write(gcid, scom_base,
			NPU2_REG_OFFSET(stack, NPU2_BLOCK_DAT,
					NPU2_CQ_DAT_MISC_CFG),
			NPU2_MISC_DA_LEN_8B, reg);

	/* CQ_SM Misc Config Register #0 */
	for (block = NPU2_BLOCK_SM_0; block <= NPU2_BLOCK_SM_3; block++) {
		reg = npu2_scom_read(gcid, scom_base,
				     NPU2_REG_OFFSET(stack, block,
						     NPU2_CQ_SM_MISC_CFG0),
				     NPU2_MISC_DA_LEN_8B);
		/* Set OCAPI mode for bricks 2-5 */
		reg |= NPU2_CQ_SM_MISC_CFG0_CONFIG_OCAPI_MODE;
		npu2_scom_write(gcid, scom_base,
				NPU2_REG_OFFSET(stack, block,
						NPU2_CQ_SM_MISC_CFG0),
				NPU2_MISC_DA_LEN_8B, reg);
	}
}

static void enable_xsl_xts_interfaces(uint32_t gcid, uint32_t scom_base, int index)
{
	uint64_t reg;

	prlog(PR_DEBUG, "OCAPI: %s: Enable XSL-XTS Interfaces\n", __func__);
	/* Step 7 - Enable XSL-XTS interfaces */
	/* XTS Config Register - Enable XSL-XTS interface */
	reg = npu2_scom_read(gcid, scom_base, NPU2_XTS_CFG, NPU2_MISC_DA_LEN_8B);
	reg |= NPU2_XTS_CFG_OPENCAPI;
	npu2_scom_write(gcid, scom_base, NPU2_XTS_CFG, NPU2_MISC_DA_LEN_8B, reg);

	/* XTS Config2 Register - Enable XSL1/2 */
	reg = npu2_scom_read(gcid, scom_base, NPU2_XTS_CFG2, NPU2_MISC_DA_LEN_8B);
	switch (index_to_stack(index)) {
	case NPU2_STACK_STCK_1:
		reg |= NPU2_XTS_CFG2_XSL1_ENA;
		break;
	case NPU2_STACK_STCK_2:
		reg |= NPU2_XTS_CFG2_XSL2_ENA;
		break;
	}
	npu2_scom_write(gcid, scom_base, NPU2_XTS_CFG2, NPU2_MISC_DA_LEN_8B, reg);
}

static void enable_sm_allocation(uint32_t gcid, uint32_t scom_base, int index)
{
	uint64_t reg, block;
	int stack = index_to_stack(index);

	prlog(PR_DEBUG, "OCAPI: %s: Enable State Machine Allocation\n", __func__);
	/* Step 8 - Enable state-machine allocation */
	/* Low-Water Marks Registers - Enable state machine allocation */
	for (block = NPU2_BLOCK_SM_0; block <= NPU2_BLOCK_SM_3; block++) {
		reg = npu2_scom_read(gcid, scom_base,
				     NPU2_REG_OFFSET(stack, block,
						     NPU2_LOW_WATER_MARKS),
				     NPU2_MISC_DA_LEN_8B);
		reg |= NPU2_LOW_WATER_MARKS_ENABLE_MACHINE_ALLOC;
		npu2_scom_write(gcid, scom_base,
				NPU2_REG_OFFSET(stack, block,
						NPU2_LOW_WATER_MARKS),
				NPU2_MISC_DA_LEN_8B, reg);
	}
}

static void enable_pb_snooping(uint32_t gcid, uint32_t scom_base, int index)
{
	uint64_t reg, block;
	int stack = index_to_stack(index);

	prlog(PR_DEBUG, "OCAPI: %s: Enable PowerBus snooping\n", __func__);
	/* Step 9 - Enable PowerBus snooping */
	/* CQ_SM Misc Config Register #0 - Enable PowerBus snooping */
	for (block = NPU2_BLOCK_SM_0; block <= NPU2_BLOCK_SM_3; block++) {
		reg = npu2_scom_read(gcid, scom_base,
				     NPU2_REG_OFFSET(stack, block,
						     NPU2_CQ_SM_MISC_CFG0),
				     NPU2_MISC_DA_LEN_8B);
		reg |= NPU2_CQ_SM_MISC_CFG0_CONFIG_ENABLE_PBUS;
		npu2_scom_write(gcid, scom_base,
				NPU2_REG_OFFSET(stack, block,
						NPU2_CQ_SM_MISC_CFG0),
				NPU2_MISC_DA_LEN_8B, reg);
	}
}

static void brick_config(uint32_t gcid, uint32_t scom_base, int index)
{
	/*
	 * We assume at this point that the PowerBus Hotplug Mode Control
	 * register is correctly set by Hostboot
	 */
	set_transport_mux_controls(gcid, scom_base, index,
				   NPU2_DEV_TYPE_OPENCAPI);
	enable_odl_phy_mux(gcid, index);
	disable_alink_fp(gcid);
	enable_xsl_clocks(gcid, scom_base, index);
	set_npcq_config(gcid, scom_base, index);
	enable_xsl_xts_interfaces(gcid, scom_base, index);
	enable_sm_allocation(gcid, scom_base, index);
	enable_pb_snooping(gcid, scom_base, index);
}

/* Procedure 13.1.3.5 - TL Configuration */
static void tl_config(uint32_t gcid, uint32_t scom_base, uint64_t index)
{
	uint64_t reg;
	uint64_t stack = index_to_stack(index);
	uint64_t block = index_to_block(index);

	prlog(PR_DEBUG, "OCAPI: %s: TL Configuration\n", __func__);
	/* OTL Config 0 Register */
	reg = 0;
	/* OTL Enable */
	reg |= NPU2_OTL_CONFIG0_EN;
	/* Block PE Handle from ERAT Index */
	reg |= NPU2_OTL_CONFIG0_BLOCK_PE_HANDLE;
	/* OTL Brick ID */
	reg = SETFIELD(NPU2_OTL_CONFIG0_BRICKID, reg, index - 2);
	/* ERAT Hash 0 */
	reg = SETFIELD(NPU2_OTL_CONFIG0_ERAT_HASH_0, reg, 0b011001);
	/* ERAT Hash 1 */
	reg = SETFIELD(NPU2_OTL_CONFIG0_ERAT_HASH_1, reg, 0b000111);
	/* ERAT Hash 2 */
	reg = SETFIELD(NPU2_OTL_CONFIG0_ERAT_HASH_2, reg, 0b101100);
	/* ERAT Hash 3 */
	reg = SETFIELD(NPU2_OTL_CONFIG0_ERAT_HASH_3, reg, 0b100110);
	npu2_scom_write(gcid, scom_base, NPU2_OTL_CONFIG0(stack, block),
			NPU2_MISC_DA_LEN_8B, reg);

	/* OTL Config 1 Register */
	reg = 0;
	/*
	 * We leave Template 1-3 bits at 0 to force template 0 as required
	 * for unknown devices.
	 *
	 * Template 0 Transmit Rate is set to most conservative setting which
	 * will always be supported. Other Template Transmit rates are left
	 * unset and will be set later by OS.
	 */
	reg = SETFIELD(NPU2_OTL_CONFIG1_TX_TEMP0_RATE, reg, 0b1111);
	/* Extra wait cycles TXI-TXO */
	reg = SETFIELD(NPU2_OTL_CONFIG1_TX_DRDY_WAIT, reg, 0b001);
	/* Minimum Frequency to Return TLX Credits to AFU */
	reg = SETFIELD(NPU2_OTL_CONFIG1_TX_CRET_FREQ, reg, 0b001);
	/* Frequency to add age to Transmit Requests */
	reg = SETFIELD(NPU2_OTL_CONFIG1_TX_AGE_FREQ, reg, 0b11000);
	/* Response High Priority Threshold */
	reg = SETFIELD(NPU2_OTL_CONFIG1_TX_RS2_HPWAIT, reg, 0b011011);
	/* 4-slot Request High Priority Threshold */
	reg = SETFIELD(NPU2_OTL_CONFIG1_TX_RQ4_HPWAIT, reg, 0b011011);
	/* 6-slot Request High Priority */
	reg = SETFIELD(NPU2_OTL_CONFIG1_TX_RQ6_HPWAIT, reg, 0b011011);
	/* Stop the OCAPI Link on Uncorrectable Error
	 * TODO: Confirm final value - disabled for debug */

	npu2_scom_write(gcid, scom_base, NPU2_OTL_CONFIG1(stack, block),
			NPU2_MISC_DA_LEN_8B, reg);

	/* TLX Credit Configuration Register */
	reg = 0;
	/* VC0/VC3/DCP0/DCP1 credits to send to AFU */
	reg = SETFIELD(NPU2_OTL_TLX_CREDITS_VC0_CREDITS, reg, 0x40);
	reg = SETFIELD(NPU2_OTL_TLX_CREDITS_VC3_CREDITS, reg, 0x40);
	reg = SETFIELD(NPU2_OTL_TLX_CREDITS_DCP0_CREDITS, reg, 0x80);
	reg = SETFIELD(NPU2_OTL_TLX_CREDITS_DCP1_CREDITS, reg, 0x80);
	npu2_scom_write(gcid, scom_base, NPU2_OTL_TLX_CREDITS(stack, block),
			NPU2_MISC_DA_LEN_8B, reg);
}

/* Detect Nimbus DD2.0 and DD2.01 */
static int get_nimbus_level(void)
{
	struct proc_chip *chip = next_chip(NULL);

	if (chip && chip->type == PROC_CHIP_P9_NIMBUS)
		return chip->ec_level & 0xff;
	return -1;
}

/* Procedure 13.1.3.6 - Address Translation Configuration */
static void address_translation_config(uint32_t gcid, uint32_t scom_base,
				       uint64_t index)
{
	int chip_level;
	uint64_t reg;
	uint64_t stack = index_to_stack(index);

	prlog(PR_DEBUG, "OCAPI: %s: Address Translation Configuration\n", __func__);
	/* PSL_SCNTL_A0 Register */
	/*
	 * ERAT shared between multiple AFUs
	 *
	 * The workbook has this bit around the wrong way from the hardware.
	 *
	 * TODO: handle correctly with link ganging
	 */
	reg = npu2_scom_read(gcid, scom_base,
			     NPU2_REG_OFFSET(stack, NPU2_BLOCK_XSL,
					     NPU2_XSL_PSL_SCNTL_A0),
			     NPU2_MISC_DA_LEN_8B);
	reg |= NPU2_XSL_PSL_SCNTL_A0_MULTI_AFU_DIAL;
	npu2_scom_write(gcid, scom_base,
			NPU2_REG_OFFSET(stack, NPU2_BLOCK_XSL,
					NPU2_XSL_PSL_SCNTL_A0),
			NPU2_MISC_DA_LEN_8B, reg);

	chip_level = get_nimbus_level();
	if (chip_level == 0x20) {
		/*
		 * Errata HW408041 (section 15.1.10 of NPU workbook)
		 * "RA mismatch when both tlbie and checkout response
		 * are seen in same cycle"
		 */
		/* XSL_GP Register - Bloom Filter Disable */
		reg = npu2_scom_read(gcid, scom_base,
				NPU2_REG_OFFSET(stack, NPU2_BLOCK_XSL, NPU2_XSL_GP),
				NPU2_MISC_DA_LEN_8B);
		/* To update XSL_GP, we must first write a magic value to it */
		npu2_scom_write(gcid, scom_base,
				NPU2_REG_OFFSET(stack, NPU2_BLOCK_XSL, NPU2_XSL_GP),
				NPU2_MISC_DA_LEN_8B, 0x0523790323000000);
		reg &= ~NPU2_XSL_GP_BLOOM_FILTER_ENABLE;
		npu2_scom_write(gcid, scom_base,
				NPU2_REG_OFFSET(stack, NPU2_BLOCK_XSL, NPU2_XSL_GP),
				NPU2_MISC_DA_LEN_8B, reg);
	}

	if (chip_level == 0x20 || chip_level == 0x21) {
		/*
		 * DD2.0/2.1 EOA Bug. Fixed in DD2.2
		 */
		reg = 0x32F8000000000001;
		npu2_scom_write(gcid, scom_base,
				NPU2_REG_OFFSET(stack, NPU2_BLOCK_XSL,
						NPU2_XSL_DEF),
				NPU2_MISC_DA_LEN_8B, reg);
	}
}

/* TODO: Merge this with NVLink implementation - we don't use the npu2_bar
 * wrapper for the PHY BARs yet */
static void write_bar(uint32_t gcid, uint32_t scom_base, uint64_t reg,
		      uint64_t addr, uint64_t size)
{
	uint64_t val;
	int block;
	switch (NPU2_REG(reg)) {
	case NPU2_PHY_BAR:
		val = SETFIELD(NPU2_PHY_BAR_ADDR, 0ul, addr >> 21);
		val = SETFIELD(NPU2_PHY_BAR_ENABLE, val, 1);
		break;
	case NPU2_NTL0_BAR:
	case NPU2_NTL1_BAR:
		val = SETFIELD(NPU2_NTL_BAR_ADDR, 0ul, addr >> 16);
		val = SETFIELD(NPU2_NTL_BAR_SIZE, val, ilog2(size >> 16));
		val = SETFIELD(NPU2_NTL_BAR_ENABLE, val, 1);
		break;
	case NPU2_GENID_BAR:
		val = SETFIELD(NPU2_GENID_BAR_ADDR, 0ul, addr >> 16);
		val = SETFIELD(NPU2_GENID_BAR_ENABLE, val, 1);
		break;
	default:
		val = 0ul;
	}

	for (block = NPU2_BLOCK_SM_0; block <= NPU2_BLOCK_SM_3; block++) {
		npu2_scom_write(gcid, scom_base, NPU2_REG_OFFSET(0, block, reg),
				NPU2_MISC_DA_LEN_8B, val);
		prlog(PR_DEBUG, "OCAPI: Setting BAR %llx to %llx\n",
		      NPU2_REG_OFFSET(0, block, reg), val);
	}
}

static void setup_global_mmio_bar(uint32_t gcid, uint32_t scom_base,
				  uint64_t reg[])
{
	uint64_t addr, size;

	prlog(PR_DEBUG, "OCAPI: patching up PHY0 bar, %s\n", __func__);
	phys_map_get(gcid, NPU_PHY, 0, &addr, &size);
	write_bar(gcid, scom_base,
		  NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_PHY_BAR),
		addr, size);
	prlog(PR_DEBUG, "OCAPI: patching up PHY1 bar, %s\n", __func__);
	phys_map_get(gcid, NPU_PHY, 1, &addr, &size);
	write_bar(gcid, scom_base,
		  NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_PHY_BAR),
		addr, size);

	prlog(PR_DEBUG, "OCAPI: setup global mmio, %s\n", __func__);
	phys_map_get(gcid, NPU_REGS, 0, &addr, &size);
	write_bar(gcid, scom_base,
		  NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_PHY_BAR),
		addr, size);
	reg[0] = addr;
	reg[1] = size;
}

static void mask_nvlink_fir(struct npu2 *p)
{
	uint64_t reg;

	/*
	 * From section 13.1.3.10 of the NPU workbook: "the NV-Link
	 * Datalink Layer Stall and NoStall signals are used for a
	 * different purpose when the link is configured for
	 * OpenCAPI. Therefore, the corresponding bits in NPU FIR
	 * Register 1 must be masked and configured to NOT cause the
	 * NPU to go into Freeze or Fence mode or send an Interrupt."
	 *
	 * FIXME: will need to revisit when mixing nvlink with
	 * opencapi. Assumes an opencapi-only setup on both PHYs for
	 * now.
	 */

	/* Mask FIRs */
	xscom_read(p->chip_id, p->xscom_base + NPU2_MISC_FIR_MASK1, &reg);
	reg = SETFIELD(PPC_BITMASK(0, 11), reg, 0xFFF);
	xscom_write(p->chip_id, p->xscom_base + NPU2_MISC_FIR_MASK1, reg);

	/* freeze disable */
	reg = npu2_scom_read(p->chip_id, p->xscom_base,
			NPU2_MISC_FREEZE_ENABLE1, NPU2_MISC_DA_LEN_8B);
	reg = SETFIELD(PPC_BITMASK(0, 11), reg, 0);
	npu2_scom_write(p->chip_id, p->xscom_base,
			NPU2_MISC_FREEZE_ENABLE1, NPU2_MISC_DA_LEN_8B, reg);

	/* fence disable */
	reg = npu2_scom_read(p->chip_id, p->xscom_base,
			NPU2_MISC_FENCE_ENABLE1, NPU2_MISC_DA_LEN_8B);
	reg = SETFIELD(PPC_BITMASK(0, 11), reg, 0);
	npu2_scom_write(p->chip_id, p->xscom_base,
			NPU2_MISC_FENCE_ENABLE1, NPU2_MISC_DA_LEN_8B, reg);

	/* irq disable */
	reg = npu2_scom_read(p->chip_id, p->xscom_base,
			NPU2_MISC_IRQ_ENABLE1, NPU2_MISC_DA_LEN_8B);
	reg = SETFIELD(PPC_BITMASK(0, 11), reg, 0);
	npu2_scom_write(p->chip_id, p->xscom_base,
			NPU2_MISC_IRQ_ENABLE1, NPU2_MISC_DA_LEN_8B, reg);
}

static int setup_irq(struct npu2 *p)
{
	uint64_t reg, mmio_addr;
	uint32_t base;

	base = xive_alloc_ipi_irqs(p->chip_id, NPU_IRQ_LEVELS, 64);
	if (base == XIVE_IRQ_ERROR) {
		/**
		 * @fwts-label OCAPIIRQAllocationFailed
		 * @fwts-advice OpenCAPI IRQ setup failed. This is probably
		 * a firmware bug. OpenCAPI functionality will be broken.
		 */
		prlog(PR_ERR, "OCAPI: Couldn't allocate interrupts for NPU\n");
		return -1;
	}
	p->irq_base = base;

	xive_register_ipi_source(base, NPU_IRQ_LEVELS, NULL, NULL);
	mmio_addr = (uint64_t ) xive_get_trigger_port(base);
	prlog(PR_DEBUG, "OCAPI: NPU base irq %d @%llx\n", base, mmio_addr);
	reg = (mmio_addr & NPU2_MISC_IRQ_BASE_MASK) << 13;
	npu2_scom_write(p->chip_id, p->xscom_base, NPU2_MISC_IRQ_BASE,
			NPU2_MISC_DA_LEN_8B, reg);
	/*
	 * setup page size = 64k
	 *
	 * OS type is set to AIX: opal also runs with 2 pages per interrupt,
	 * so to cover the max offset for 35 levels of interrupt, we need
	 * bits 41 to 46, which is what the AIX setting does. There's no
	 * other meaning for that AIX setting.
	 */
	reg = npu2_scom_read(p->chip_id, p->xscom_base, NPU2_MISC_CFG,
			NPU2_MISC_DA_LEN_8B);
	reg |= NPU2_MISC_CFG_IPI_PS;
	reg &= ~NPU2_MISC_CFG_IPI_OS;
	npu2_scom_write(p->chip_id, p->xscom_base, NPU2_MISC_CFG,
			NPU2_MISC_DA_LEN_8B, reg);

	/* enable translation interrupts for all bricks */
	reg = npu2_scom_read(p->chip_id, p->xscom_base, NPU2_MISC_IRQ_ENABLE2,
			     NPU2_MISC_DA_LEN_8B);
	reg |= PPC_BIT(0) | PPC_BIT(1) | PPC_BIT(2) | PPC_BIT(3);
	npu2_scom_write(p->chip_id, p->xscom_base, NPU2_MISC_IRQ_ENABLE2,
			NPU2_MISC_DA_LEN_8B, reg);

	mask_nvlink_fir(p);
	return 0;
}

static void npu2_opencapi_probe(struct dt_node *dn)
{
	struct dt_node *link;
	char *path;
	uint32_t gcid, index, links, scom_base;
	uint64_t reg[2];
	uint64_t dev_index;
	struct npu2 *n;
	int rc;

	path = dt_get_path(dn);
	gcid = dt_get_chip_id(dn);
	index = dt_prop_get_u32(dn, "ibm,npu-index");
	links = dt_prop_get_u32(dn, "ibm,npu-links");

	/* Don't try to init when we have an NVLink link */
	dt_for_each_compatible(dn, link, "ibm,npu-link") {
		prlog(PR_DEBUG, "OCAPI: NPU%d: NVLink link found, skipping\n",
		      index);
		return;
	}

	prlog(PR_INFO, "OCAPI: Chip %d Found OpenCAPI NPU%d (%d links) at %s\n",
	      gcid, index, links, path);
	free(path);

	/* TODO: Test OpenCAPI with fast reboot and make it work */
	disable_fast_reboot("OpenCAPI device enabled");

	scom_base = dt_get_address(dn, 0, NULL);
	prlog(PR_INFO, "OCAPI:	 SCOM Base:  %08x\n", scom_base);

	setup_global_mmio_bar(gcid, scom_base, reg);

	n = zalloc(sizeof(struct npu2) + links * sizeof(struct npu2_dev));
	n->devices = (struct npu2_dev *)(n + 1);
	n->chip_id = gcid;
	n->xscom_base = scom_base;
	n->regs = (void *)reg[0];
	n->dt_node = dn;

	dt_for_each_compatible(dn, link, "ibm,npu-link-opencapi") {
		dev_index = dt_prop_get_u32(link, "ibm,npu-link-index");
		prlog(PR_INFO, "OCAPI: Configuring link index %lld\n",
		      dev_index);

		/* Procedure 13.1.3.1 - Select OCAPI vs NVLink */
		brick_config(gcid, scom_base, dev_index);

		/* Procedure 13.1.3.5 - Transaction Layer Configuration */
		tl_config(gcid, scom_base, dev_index);

		/* Procedure 13.1.3.6 - Address Translation Configuration */
		address_translation_config(gcid, scom_base, dev_index);
	}

	/* Procedure 13.1.3.10 - Interrupt Configuration */
	rc = setup_irq(n);
	if (rc)
		goto failed;

	return;
failed:
	free(n);
}

void probe_npu2_opencapi(void)
{
	struct dt_node *np_npu;

	dt_for_each_compatible(dt_root, np_npu, "ibm,power9-npu")
		npu2_opencapi_probe(np_npu);
}
