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
#include <skiboot.h>
#include <opal.h>
#include <opal-api.h>
#include <opal-msg.h>
#include <processor.h>
#include <chiptod.h>
#include <lock.h>
#include <xscom.h>
#include <capp.h>
#include <pci.h>
#include <cpu.h>
#include <chip.h>

/*
 * HMER register layout:
 * +===+==========+============================+========+===================+
 * |Bit|Name      |Description                 |PowerKVM|Action             |
 * |   |          |                            |HMI     |                   |
 * |   |          |                            |enabled |                   |
 * |   |          |                            |for this|                   |
 * |   |          |                            |bit ?   |                   |
 * +===+==========+============================+========+===================+
 * |0  |malfunctio|A processor core in the     |Yes     |Raise attn from    |
 * |   |n_allert  |system has checkstopped     |        |sapphire resulting |
 * |   |          |(failed recovery) and has   |        |xstop              |
 * |   |          |requested a CP Sparing      |        |                   |
 * |   |          |to occur. This is           |        |                   |
 * |   |          |broadcasted to every        |        |                   |
 * |   |          |processor in the system     |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |1  |Reserved  |reserved                    |n/a     |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |2  |proc_recv_|Processor recovery occurred |Yes     |Log message and    |
 * |   |done      |error-bit in fir not masked |        |continue working.  |
 * |   |          |(see bit 11)                |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |3  |proc_recv_|Processor went through      |Yes     |Log message and    |
 * |   |error_mask|recovery for an error which |        |continue working.  |
 * |   |ed        |is actually masked for      |        |                   |
 * |   |          |reporting                   |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |4  |          |Timer facility experienced  |Yes     |Raise attn from    |
 * |   |tfac_error|an error.                   |        |sapphire resulting |
 * |   |          |TB, DEC, HDEC, PURR or SPURR|        |xstop              |
 * |   |          |may be corrupted (details in|        |                   |
 * |   |          |TFMR)                       |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |5  |          |TFMR SPR itself is          |Yes     |Raise attn from    |
 * |   |tfmr_parit|corrupted.                  |        |sapphire resulting |
 * |   |y_error   |Entire timing facility may  |        |xstop              |
 * |   |          |be compromised.             |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |6  |ha_overflo| UPS (Uniterrupted Power    |No      |N/A                |
 * |   |w_warning |System) Overflow indication |        |                   |
 * |   |          |indicating that the UPS     |        |                   |
 * |   |          |DirtyAddrTable has          |        |                   |
 * |   |          |reached a limit where it    |        |                   |
 * |   |          |requires PHYP unload support|        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |7  |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |8  |xscom_fail|An XSCOM operation caused by|No      |We handle it by    |
 * |   |          |a cache inhibited load/store|        |manually reading   |
 * |   |          |from this thread failed. A  |        |HMER register.     |
 * |   |          |trap register is            |        |                   |
 * |   |          |available.                  |        |                   |
 * |   |          |                            |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |9  |xscom_done|An XSCOM operation caused by|No      |We handle it by    |
 * |   |          |a cache inhibited load/store|        |manually reading   |
 * |   |          |from this thread completed. |        |HMER register.     |
 * |   |          |If hypervisor               |        |                   |
 * |   |          |intends to use this bit, it |        |                   |
 * |   |          |is responsible for clearing |        |                   |
 * |   |          |it before performing the    |        |                   |
 * |   |          |xscom operation.            |        |                   |
 * |   |          |NOTE: this bit should always|        |                   |
 * |   |          |be masked in HMEER          |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |10 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |11 |proc_recv_|Processor recovery occurred |y       |Log message and    |
 * |   |again     |again before bit2 or bit3   |        |continue working.  |
 * |   |          |was cleared                 |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |12-|reserved  |was temperature sensor      |n/a     |n/a                |
 * |15 |          |passed the critical point on|        |                   |
 * |   |          |the way up                  |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |16 |          |SCOM has set a reserved FIR |No      |n/a                |
 * |   |scom_fir_h|bit to cause recovery       |        |                   |
 * |   |m         |                            |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |17 |trig_fir_h|Debug trigger has set a     |No      |n/a                |
 * |   |mi        |reserved FIR bit to cause   |        |                   |
 * |   |          |recovery                    |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |18 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |19 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |20 |hyp_resour|A hypervisor resource error |y       |Raise attn from    |
 * |   |ce_err    |occurred: data parity error |        |sapphire resulting |
 * |   |          |on, SPRC0:3; SPR_Modereg or |        |xstop.             |
 * |   |          |HMEER.                      |        |                   |
 * |   |          |Note: this bit will cause an|        |                   |
 * |   |          |check_stop when (HV=1, PR=0 |        |                   |
 * |   |          |and EE=0)                   |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |21-|          |if bit 8 is active, the     |No      |We handle it by    |
 * |23 |xscom_stat|reason will be detailed in  |        |Manually reading   |
 * |   |us        |these bits. see chapter 11.1|        |HMER register.     |
 * |   |          |This bits are information   |        |                   |
 * |   |          |only and always masked      |        |                   |
 * |   |          |(mask = '0')                |        |                   |
 * |   |          |If hypervisor intends to use|        |                   |
 * |   |          |this bit, it is responsible |        |                   |
 * |   |          |for clearing it before      |        |                   |
 * |   |          |performing the xscom        |        |                   |
 * |   |          |operation.                  |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |24-|Not       |Not implemented             |n/a     |n/a                |
 * |63 |implemente|                            |        |                   |
 * |   |d         |                            |        |                   |
 * +-- +----------+----------------------------+--------+-------------------+
 *
 * Above HMER bits can be enabled/disabled by modifying
 * SPR_HMEER_HMI_ENABLE_MASK #define in include/processor.h
 * If you modify support for any of the bits listed above, please make sure
 * you change the above table to refelct that.
 *
 * NOTE: Per Dave Larson, never enable 8,9,21-23
 */

/* xscom addresses for core FIR (Fault Isolation Register) */
#define CORE_FIR		0x10013100
#define NX_STATUS_REG		0x02013040 /* NX status register */
#define NX_DMA_ENGINE_FIR	0x02013100 /* DMA & Engine FIR Data Register */
#define NX_PBI_FIR		0x02013080 /* PowerBus Interface FIR Register */

/*
 * Bit 54 from NX status register is set to 1 when HMI interrupt is triggered
 * due to NX checksop.
 */
#define NX_HMI_ACTIVE		PPC_BIT(54)

static const struct core_xstop_bit_info {
	uint8_t bit;		/* CORE FIR bit number */
	enum OpalHMI_CoreXstopReason reason;
} xstop_bits[] = {
	{ 3, CORE_CHECKSTOP_IFU_REGFILE },
	{ 5, CORE_CHECKSTOP_IFU_LOGIC },
	{ 8, CORE_CHECKSTOP_PC_DURING_RECOV },
	{ 10, CORE_CHECKSTOP_ISU_REGFILE },
	{ 12, CORE_CHECKSTOP_ISU_LOGIC },
	{ 21, CORE_CHECKSTOP_FXU_LOGIC },
	{ 25, CORE_CHECKSTOP_VSU_LOGIC },
	{ 26, CORE_CHECKSTOP_PC_RECOV_IN_MAINT_MODE },
	{ 32, CORE_CHECKSTOP_LSU_REGFILE },
	{ 36, CORE_CHECKSTOP_PC_FWD_PROGRESS },
	{ 38, CORE_CHECKSTOP_LSU_LOGIC },
	{ 45, CORE_CHECKSTOP_PC_LOGIC },
	{ 48, CORE_CHECKSTOP_PC_HYP_RESOURCE },
	{ 52, CORE_CHECKSTOP_PC_HANG_RECOV_FAILED },
	{ 54, CORE_CHECKSTOP_PC_AMBI_HANG_DETECTED },
	{ 60, CORE_CHECKSTOP_PC_DEBUG_TRIG_ERR_INJ },
	{ 63, CORE_CHECKSTOP_PC_SPRD_HYP_ERR_INJ },
};

static const struct nx_xstop_bit_info {
	uint8_t bit;		/* NX FIR bit number */
	enum OpalHMI_NestAccelXstopReason reason;
} nx_dma_xstop_bits[] = {
	{ 1, NX_CHECKSTOP_SHM_INVAL_STATE_ERR },
	{ 15, NX_CHECKSTOP_DMA_INVAL_STATE_ERR_1 },
	{ 16, NX_CHECKSTOP_DMA_INVAL_STATE_ERR_2 },
	{ 20, NX_CHECKSTOP_DMA_CH0_INVAL_STATE_ERR },
	{ 21, NX_CHECKSTOP_DMA_CH1_INVAL_STATE_ERR },
	{ 22, NX_CHECKSTOP_DMA_CH2_INVAL_STATE_ERR },
	{ 23, NX_CHECKSTOP_DMA_CH3_INVAL_STATE_ERR },
	{ 24, NX_CHECKSTOP_DMA_CH4_INVAL_STATE_ERR },
	{ 25, NX_CHECKSTOP_DMA_CH5_INVAL_STATE_ERR },
	{ 26, NX_CHECKSTOP_DMA_CH6_INVAL_STATE_ERR },
	{ 27, NX_CHECKSTOP_DMA_CH7_INVAL_STATE_ERR },
	{ 31, NX_CHECKSTOP_DMA_CRB_UE },
	{ 32, NX_CHECKSTOP_DMA_CRB_SUE },
};

static const struct nx_xstop_bit_info nx_pbi_xstop_bits[] = {
	{ 12, NX_CHECKSTOP_PBI_ISN_UE },
};

static struct lock hmi_lock = LOCK_UNLOCKED;

static int queue_hmi_event(struct OpalHMIEvent *hmi_evt, int recover)
{
	uint64_t *hmi_data;

	/* Don't queue up event if recover == -1 */
	if (recover == -1)
		return 0;

	/* set disposition */
	if (recover == 1)
		hmi_evt->disposition = OpalHMI_DISPOSITION_RECOVERED;
	else if (recover == 0)
		hmi_evt->disposition = OpalHMI_DISPOSITION_NOT_RECOVERED;

	/*
	 * V2 of struct OpalHMIEvent is of (4 * 64 bits) size and well packed
	 * structure. Hence use uint64_t pointer to pass entire structure
	 * using 4 params in generic message format.
	 */
	hmi_data = (uint64_t *)hmi_evt;

	/* queue up for delivery to host. */
	return opal_queue_msg(OPAL_MSG_HMI_EVT, NULL, NULL,
				hmi_data[0], hmi_data[1], hmi_data[2],
				hmi_data[3]);
}

static int is_capp_recoverable(int chip_id)
{
	uint64_t reg;
	xscom_read(chip_id, CAPP_ERR_STATUS_CTRL, &reg);
	return (reg & PPC_BIT(0)) != 0;
}

static int handle_capp_recoverable(int chip_id)
{
	struct dt_node *np;
	u64 phb_id;
	u32 dt_chip_id;
	struct phb *phb;
	u32 phb_index;

	dt_for_each_compatible(dt_root, np, "ibm,power8-pciex") {
		dt_chip_id = dt_prop_get_u32(np, "ibm,chip-id");
		phb_index = dt_prop_get_u32(np, "ibm,phb-index");
		phb_id = dt_prop_get_u64(np, "ibm,opal-phbid");

		if ((phb_index == 0) && (chip_id == dt_chip_id)) {
			phb = pci_get_phb(phb_id);
			phb->ops->lock(phb);
			phb->ops->set_capp_recovery(phb);
			phb->ops->unlock(phb);
			return 1;
		}
	}
	return 0;
}

static int decode_one_malfunction(int flat_chip_id, struct OpalHMIEvent *hmi_evt)
{
	hmi_evt->severity = OpalHMI_SEV_FATAL;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;

	if (is_capp_recoverable(flat_chip_id)) {
		if (handle_capp_recoverable(flat_chip_id) == 0)
			return 0;

		hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
		hmi_evt->type = OpalHMI_ERROR_CAPP_RECOVERY;
		return 1;
	}
	/* TODO check other FIRs */
	return 0;
}

static bool decode_core_fir(struct cpu_thread *cpu,
				struct OpalHMIEvent *hmi_evt)
{
	uint64_t core_fir;
	uint32_t core_id;
	int i;
	bool found = false;

	/* Sanity check */
	if (!cpu || !hmi_evt)
		return false;

	core_id = pir_to_core_id(cpu->pir);

	/* Get CORE FIR register value. */
	if (xscom_read(cpu->chip_id, XSCOM_ADDR_P8_EX(core_id, CORE_FIR),
							&core_fir) != 0) {
		prerror("HMI: XSCOM error reading CORE FIR\n");
		return false;
	}

	prlog(PR_INFO, "HMI: CHIP ID: %x, CORE ID: %x, FIR: %016llx\n",
			cpu->chip_id, core_id, core_fir);

	/* Check CORE FIR bits and populate HMI event with error info. */
	for (i = 0; i < ARRAY_SIZE(xstop_bits); i++) {
		if (core_fir & PPC_BIT(xstop_bits[i].bit)) {
			found = true;
			hmi_evt->u.xstop_error.xstop_reason
						|= xstop_bits[i].reason;
		}
	}
	return found;
}

static void find_core_checkstop_reason(struct OpalHMIEvent *hmi_evt,
					int *event_generated)
{
	struct cpu_thread *cpu;

	/* Initialize HMI event */
	hmi_evt->severity = OpalHMI_SEV_FATAL;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_CORE;

	/*
	 * Check CORE FIRs and find the reason for core checkstop.
	 * Send a separate HMI event for each core that has checkstopped.
	 */
	for_each_cpu(cpu) {
		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		/* Only check on primaries (ie. core), not threads */
		if (cpu->is_secondary)
			continue;

		/* Initialize xstop_error fields. */
		hmi_evt->u.xstop_error.xstop_reason = 0;
		hmi_evt->u.xstop_error.u.pir = cpu->pir;

		if (decode_core_fir(cpu, hmi_evt)) {
			queue_hmi_event(hmi_evt, 0);
			*event_generated = 1;
		}
	}
}

static void find_nx_checkstop_reason(int flat_chip_id,
			struct OpalHMIEvent *hmi_evt, int *event_generated)
{
	uint64_t nx_status;
	uint64_t nx_dma_fir;
	uint64_t nx_pbi_fir;
	int i;

	/* Get NX status register value. */
	if (xscom_read(flat_chip_id, NX_STATUS_REG, &nx_status) != 0) {
		prerror("HMI: XSCOM error reading NX_STATUS_REG\n");
		return;
	}

	/* Check if NX has driven an HMI interrupt. */
	if (!(nx_status & NX_HMI_ACTIVE))
		return;

	/* Initialize HMI event */
	hmi_evt->severity = OpalHMI_SEV_FATAL;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_NX;
	hmi_evt->u.xstop_error.u.chip_id = flat_chip_id;

	/* Get DMA & Engine FIR data register value. */
	if (xscom_read(flat_chip_id, NX_DMA_ENGINE_FIR, &nx_dma_fir) != 0) {
		prerror("HMI: XSCOM error reading NX_DMA_ENGINE_FIR\n");
		return;
	}

	/* Get PowerBus Interface FIR data register value. */
	if (xscom_read(flat_chip_id, NX_PBI_FIR, &nx_pbi_fir) != 0) {
		prerror("HMI: XSCOM error reading NX_DMA_ENGINE_FIR\n");
		return;
	}

	/* Find NX checkstop reason and populate HMI event with error info. */
	for (i = 0; i < ARRAY_SIZE(nx_dma_xstop_bits); i++)
		if (nx_dma_fir & PPC_BIT(nx_dma_xstop_bits[i].bit))
			hmi_evt->u.xstop_error.xstop_reason
						|= nx_dma_xstop_bits[i].reason;

	for (i = 0; i < ARRAY_SIZE(nx_pbi_xstop_bits); i++)
		if (nx_pbi_fir & PPC_BIT(nx_pbi_xstop_bits[i].bit))
			hmi_evt->u.xstop_error.xstop_reason
						|= nx_pbi_xstop_bits[i].reason;

	/* Send an HMI event. */
	queue_hmi_event(hmi_evt, 0);
	*event_generated = 1;
}

static int decode_malfunction(struct OpalHMIEvent *hmi_evt)
{
	int i;
	int recover = -1;
	uint64_t malf_alert;
	int event_generated = 0;

	xscom_read(this_cpu()->chip_id, 0x2020011, &malf_alert);

	for (i = 0; i < 64; i++)
		if (malf_alert & PPC_BIT(i)) {
			recover = decode_one_malfunction(i, hmi_evt);
			xscom_write(this_cpu()->chip_id, 0x02020011, ~PPC_BIT(i));
			if (recover) {
				queue_hmi_event(hmi_evt, recover);
				event_generated = 1;
			}

			find_nx_checkstop_reason(i, hmi_evt, &event_generated);
		}

	if (recover != -1) {
		find_core_checkstop_reason(hmi_evt, &event_generated);

		/*
		 * In case, if we fail to find checkstop reason send an
		 * unknown HMI event.
		 */
		if (!event_generated) {
			hmi_evt->u.xstop_error.xstop_type =
						CHECKSTOP_TYPE_UNKNOWN;
			hmi_evt->u.xstop_error.xstop_reason = 0;
		}
	}

	return recover;
}

int handle_hmi_exception(uint64_t hmer, struct OpalHMIEvent *hmi_evt)
{
	int recover = 1;
	uint64_t tfmr;

	printf("HMI: Received HMI interrupt: HMER = 0x%016llx\n", hmer);
	if (hmi_evt)
		hmi_evt->hmer = hmer;
	if (hmer & SPR_HMER_PROC_RECV_DONE) {
		hmer &= ~SPR_HMER_PROC_RECV_DONE;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE;
			queue_hmi_event(hmi_evt, recover);
		}
		printf("HMI: Processor recovery Done.\n");
	}
	if (hmer & SPR_HMER_PROC_RECV_ERROR_MASKED) {
		hmer &= ~SPR_HMER_PROC_RECV_ERROR_MASKED;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_MASKED;
			queue_hmi_event(hmi_evt, recover);
		}
		printf("HMI: Processor recovery Done (masked).\n");
	}
	if (hmer & SPR_HMER_PROC_RECV_AGAIN) {
		hmer &= ~SPR_HMER_PROC_RECV_AGAIN;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE_AGAIN;
			queue_hmi_event(hmi_evt, recover);
		}
		printf("HMI: Processor recovery occurred again before"
			"bit2 was cleared\n");
	}
	/* Assert if we see malfunction alert, we can not continue. */
	if (hmer & SPR_HMER_MALFUNCTION_ALERT) {
		hmer &= ~SPR_HMER_MALFUNCTION_ALERT;
		recover = 0;

		if (hmi_evt) {
			recover = decode_malfunction(hmi_evt);
			queue_hmi_event(hmi_evt, recover);
		}
	}

	/* Assert if we see Hypervisor resource error, we can not continue. */
	if (hmer & SPR_HMER_HYP_RESOURCE_ERR) {
		hmer &= ~SPR_HMER_HYP_RESOURCE_ERR;
		recover = 0;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_FATAL;
			hmi_evt->type = OpalHMI_ERROR_HYP_RESOURCE;
			queue_hmi_event(hmi_evt, recover);
		}
	}

	/*
	 * Assert for now for all TOD errors. In future we need to decode
	 * TFMR and take corrective action wherever required.
	 */
	if (hmer & SPR_HMER_TFAC_ERROR) {
		tfmr = mfspr(SPR_TFMR);		/* save original TFMR */
		hmer &= ~SPR_HMER_TFAC_ERROR;
		recover = chiptod_recover_tb_errors();
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_ERROR_SYNC;
			hmi_evt->type = OpalHMI_ERROR_TFAC;
			hmi_evt->tfmr = tfmr;
			queue_hmi_event(hmi_evt, recover);
		}
	}
	if (hmer & SPR_HMER_TFMR_PARITY_ERROR) {
		tfmr = mfspr(SPR_TFMR);		/* save original TFMR */
		hmer &= ~SPR_HMER_TFMR_PARITY_ERROR;
		recover = 0;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_FATAL;
			hmi_evt->type = OpalHMI_ERROR_TFMR_PARITY;
			hmi_evt->tfmr = tfmr;
			queue_hmi_event(hmi_evt, recover);
		}
	}

	/*
	 * HMER bits are sticky, once set to 1 they remain set to 1 until
	 * they are set to 0. Reset the error source bit to 0, otherwise
	 * we keep getting HMI interrupt again and again.
	 */
	mtspr(SPR_HMER, hmer);
	return recover;
}

static int64_t opal_handle_hmi(void)
{
	uint64_t hmer;
	int rc = OPAL_SUCCESS;
	struct OpalHMIEvent hmi_evt;

	/*
	 * Compiled time check to see size of OpalHMIEvent do not exceed
	 * that of struct opal_msg.
	 */
	BUILD_ASSERT(sizeof(struct opal_msg) >= sizeof(struct OpalHMIEvent));

	memset(&hmi_evt, 0, sizeof(struct OpalHMIEvent));
	hmi_evt.version = OpalHMIEvt_V2;

	lock(&hmi_lock);
	hmer = mfspr(SPR_HMER);		/* Get HMER register value */
	handle_hmi_exception(hmer, &hmi_evt);
	unlock(&hmi_lock);

	return rc;
}
opal_call(OPAL_HANDLE_HMI, opal_handle_hmi, 0);
