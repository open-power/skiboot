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
#include <stack.h>
#include <opal.h>
#include <processor.h>
#include <cpu.h>

static uint64_t client_mc_address;

extern uint8_t exc_primary_start;
extern uint8_t exc_primary_end;

extern uint32_t exc_primary_patch_branch;

extern uint8_t exc_secondary_start;
extern uint8_t exc_secondary_end;

extern uint32_t exc_secondary_patch_stack;
extern uint32_t exc_secondary_patch_mfsrr0;
extern uint32_t exc_secondary_patch_mfsrr1;
extern uint32_t exc_secondary_patch_type;
extern uint32_t exc_secondary_patch_mtsrr0;
extern uint32_t exc_secondary_patch_mtsrr1;
extern uint32_t exc_secondary_patch_rfid;

struct lock hmi_lock = LOCK_UNLOCKED;

#define SRR1_MC_LOADSTORE(srr1)		((srr1) & PPC_BIT(42))

#define SRR1_MC_IFETCH(srr1)		((srr1) & PPC_BITMASK(43,45))
#define SRR1_MC_IFETCH_UE		(0x1 << PPC_BITLSHIFT(45))
#define SRR1_MC_IFETCH_SLB_PARITY	(0x2 << PPC_BITLSHIFT(45))
#define SRR1_MC_IFETCH_SLB_MULTIHIT	(0x3 << PPC_BITLSHIFT(45))
#define SRR1_MC_IFETCH_SLB_BOTH		(0x4 << PPC_BITLSHIFT(45))
#define SRR1_MC_IFETCH_TLB_MULTIHIT	(0x5 << PPC_BITLSHIFT(45))
#define SRR1_MC_IFETCH_UE_TLB_RELOAD	(0x6 << PPC_BITLSHIFT(45))
#define SRR1_MC_IFETCH_UE_IFU_INTERNAL	(0x7 << PPC_BITLSHIFT(45))

#define DSISR_MC_UE			(PPC_BIT(48))
#define DSISR_MC_UE_TABLEWALK		(PPC_BIT(49))
#define DSISR_MC_ERAT_MULTIHIT		(PPC_BIT(52))
#define DSISR_MC_TLB_MULTIHIT_MFTLB	(PPC_BIT(53))
#define DSISR_MC_TLB_MULTIHIT_MFSLB	(PPC_BIT(55))
#define DSISR_MC_TLB_MULTIHIT		(PPC_BIT(53) | PPC_BIT(55))
#define DSISR_MC_SLB_MULTIHIT		(PPC_BIT(56))
#define DSISR_MC_SLB_MULTIHIT_PARITY	(PPC_BIT(57))

static void mce_set_ierror(struct opal_machine_check_event *mce, uint64_t srr1)
{
	switch (SRR1_MC_IFETCH(srr1)) {
	case SRR1_MC_IFETCH_SLB_PARITY:
		mce->error_type = OpalMCE_ERROR_TYPE_SLB;
		mce->u.slb_error.slb_error_type = OpalMCE_SLB_ERROR_PARITY;
		break;

	case SRR1_MC_IFETCH_SLB_MULTIHIT:
		mce->error_type = OpalMCE_ERROR_TYPE_SLB;
		mce->u.slb_error.slb_error_type = OpalMCE_SLB_ERROR_MULTIHIT;
		break;

	case SRR1_MC_IFETCH_SLB_BOTH:
		mce->error_type = OpalMCE_ERROR_TYPE_SLB;
		mce->u.slb_error.slb_error_type =
				OpalMCE_SLB_ERROR_INDETERMINATE;
		break;

	case SRR1_MC_IFETCH_TLB_MULTIHIT:
		mce->error_type = OpalMCE_ERROR_TYPE_TLB;
		mce->u.tlb_error.tlb_error_type = OpalMCE_TLB_ERROR_MULTIHIT;
		break;

	case SRR1_MC_IFETCH_UE:
	case SRR1_MC_IFETCH_UE_IFU_INTERNAL:
		mce->error_type = OpalMCE_ERROR_TYPE_UE;
		mce->u.ue_error.ue_error_type = OpalMCE_UE_ERROR_IFETCH;
		break;

	case SRR1_MC_IFETCH_UE_TLB_RELOAD:
		mce->error_type = OpalMCE_ERROR_TYPE_UE;
		mce->u.ue_error.ue_error_type =
				OpalMCE_UE_ERROR_PAGE_TABLE_WALK_IFETCH;
		break;
	}

}

static void mce_set_derror(struct opal_machine_check_event *mce, uint64_t dsisr)
{
	if (dsisr & DSISR_MC_UE) {
		mce->error_type = OpalMCE_ERROR_TYPE_UE;
		mce->u.ue_error.ue_error_type = OpalMCE_UE_ERROR_LOAD_STORE;

	} else if (dsisr & DSISR_MC_UE_TABLEWALK) {
		mce->error_type = OpalMCE_ERROR_TYPE_UE;
		mce->u.ue_error.ue_error_type =
				OpalMCE_UE_ERROR_PAGE_TABLE_WALK_LOAD_STORE;

	} else if (dsisr & DSISR_MC_ERAT_MULTIHIT) {
		mce->error_type = OpalMCE_ERROR_TYPE_ERAT;
		mce->u.erat_error.erat_error_type =
					OpalMCE_ERAT_ERROR_MULTIHIT;

	} else if (dsisr & DSISR_MC_TLB_MULTIHIT) {
		mce->error_type = OpalMCE_ERROR_TYPE_TLB;
		mce->u.tlb_error.tlb_error_type =
					OpalMCE_TLB_ERROR_MULTIHIT;

	} else if (dsisr & DSISR_MC_SLB_MULTIHIT) {
		mce->error_type = OpalMCE_ERROR_TYPE_SLB;
		mce->u.slb_error.slb_error_type =
					OpalMCE_SLB_ERROR_MULTIHIT;

	} else if (dsisr & DSISR_MC_SLB_MULTIHIT_PARITY) {
		mce->error_type = OpalMCE_ERROR_TYPE_SLB;
		mce->u.slb_error.slb_error_type =
					OpalMCE_SLB_ERROR_INDETERMINATE;
	}
}

/* Called from head.S, thus no prototype */
void handle_machine_check(struct stack_frame *stack);

void handle_machine_check(struct stack_frame *stack)
{
	struct opal_machine_check_event *mce;
	uint64_t srr1, addr;

	mce = &this_cpu()->mc_event;

	/* This will occur if we get another MC between the time that
	 * we re-set MSR_ME, and the OS clears this flag.
	 *
	 * However, the alternative is keeping MSR_ME cleared, and letting
	 * the OS re-set it (after clearing the flag). However, we
	 * risk a checkstop, and an opal assert() is the better option.
	 */
	assert(!mce->in_use);

	mce->in_use = 1;

	/* Populate generic machine check info */
	mce->version = OpalMCE_V1;
	mce->srr0 = stack->srr0;
	mce->srr1 = stack->srr1;
	mce->gpr3 = stack->gpr[3];

	mce->initiator = OpalMCE_INITIATOR_CPU;
	mce->disposition = OpalMCE_DISPOSITION_NOT_RECOVERED;
	mce->severity = OpalMCE_SEV_ERROR_SYNC;

	srr1 = stack->srr1;

	/* Populate the mce error_type and type-specific error_type from either
	 * SRR1 or DSISR, depending whether this was a load/store or ifetch
	 * exception */
	if (SRR1_MC_LOADSTORE(srr1)) {
		mce_set_derror(mce, srr1);
		addr = stack->srr0;
	} else {
		mce_set_ierror(mce, mfspr(SPR_DSISR));
		addr = mfspr(SPR_DAR);
	}

	if (mce->error_type == OpalMCE_ERROR_TYPE_TLB) {
		mce->u.tlb_error.effective_address_provided = true;
		mce->u.tlb_error.effective_address = addr;

	} else if (mce->error_type == OpalMCE_ERROR_TYPE_SLB) {
		mce->u.slb_error.effective_address_provided = true;
		mce->u.slb_error.effective_address = addr;

	} else if (mce->error_type == OpalMCE_ERROR_TYPE_ERAT) {
		mce->u.erat_error.effective_address_provided = true;
		mce->u.erat_error.effective_address = addr;

	} else if (mce->error_type == OpalMCE_ERROR_TYPE_UE) {
		mce->u.ue_error.effective_address_provided = true;
		mce->u.ue_error.effective_address = addr;
	}

	/* Setup stack to rfi into the OS' handler, with ME re-enabled. */
	stack->gpr[3] = (uint64_t)mce;
	stack->srr0 = client_mc_address;
	stack->srr1 = mfmsr() | MSR_ME;
}

#define REG		"%016llx"
#define REGS_PER_LINE	4
#define LAST_VOLATILE	13

static void dump_regs(struct stack_frame *stack, uint64_t hmer)
{
	int i;
	uint64_t tfmr;

	if (hmer & SPR_HMER_MALFUNCTION_ALERT)
		printf("HMI: malfunction Alert\n");
	if (hmer & SPR_HMER_HYP_RESOURCE_ERR)
		printf("HMI: Hypervisor resource error.\n");
	if (hmer & SPR_HMER_TFAC_ERROR) {
		tfmr = mfspr(SPR_TFMR);
		printf("HMI: TFAC error: SPRN_TFMR = 0x%016llx\n", tfmr);
	}
	if (hmer & SPR_HMER_TFMR_PARITY_ERROR) {
		tfmr = mfspr(SPR_TFMR);
		printf("HMI: TFMR parity error: SPRN_TFMR = 0x%016llx\n", tfmr);
	}
	printf("TRAP: %04llx\n", stack->type);
	printf("SRR0: "REG" SRR1: "REG"\n", stack->srr0, stack->srr1);
	printf("CFAR: "REG" LR: "REG" CTR: "REG"\n",
		stack->cfar, stack->lr, stack->ctr);
	printf("  CR: %08x  XER: %08x\n", stack->cr, stack->xer);

	for (i = 0;  i < 32;  i++) {
		if ((i % REGS_PER_LINE) == 0)
			printf("\nGPR%02d: ", i);
		printf(REG " ", stack->gpr[i]);
		if (i == LAST_VOLATILE)
			break;
	}
	printf("\n");
}

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

/* make compiler happy with a prototype */
void handle_hmi(struct stack_frame *stack);

void handle_hmi(struct stack_frame *stack)
{
	uint64_t hmer, orig_hmer;
	bool assert = false;

	orig_hmer = hmer = mfspr(SPR_HMER);
	printf("HMI: Received HMI interrupt: HMER = 0x%016llx\n", hmer);
	if (hmer & (SPR_HMER_PROC_RECV_DONE
			| SPR_HMER_PROC_RECV_ERROR_MASKED)) {
		hmer &= ~(SPR_HMER_PROC_RECV_DONE
			| SPR_HMER_PROC_RECV_ERROR_MASKED);
		printf("HMI: Processor recovery Done.\n");
	}
	if (hmer & SPR_HMER_PROC_RECV_AGAIN) {
		hmer &= ~SPR_HMER_PROC_RECV_AGAIN;
		printf("HMI: Processor recovery occurred again before"
			"bit2 was cleared\n");
	}
	/* Assert if we see malfunction alert, we can not continue. */
	if (hmer & SPR_HMER_MALFUNCTION_ALERT) {
		hmer &= ~SPR_HMER_MALFUNCTION_ALERT;
		assert = true;
	}

	/* Assert if we see Hypervisor resource error, we can not continue. */
	if (hmer & SPR_HMER_HYP_RESOURCE_ERR) {
		hmer &= ~SPR_HMER_HYP_RESOURCE_ERR;
		assert = true;
	}

	/*
	 * Assert for now for all TOD errors. In future we need to decode
	 * TFMR and take corrective action wherever required.
	 */
	if (hmer & (SPR_HMER_TFAC_ERROR | SPR_HMER_TFMR_PARITY_ERROR)) {
		hmer &= ~(SPR_HMER_TFAC_ERROR | SPR_HMER_TFMR_PARITY_ERROR);
		assert = true;
	}

	/*
	 * HMER bits are sticky, once set to 1 they remain set to 1 until
	 * they are set to 0. Reset the error source bit to 0, otherwise
	 * we keep getting HMI interrupt again and again.
	 */
	mtspr(SPR_HMER, hmer);
	if (!assert)
		return;

	/*
	 * Raise attn to crash.
	 *
	 * We get HMI on all threads at the same time. Using locks to avoid
	 * printf messages jumbled up.
	 */
	lock(&hmi_lock);
	dump_regs(stack, orig_hmer);
	/* Should we unlock? We are going down anyway. */
	unlock(&hmi_lock);
	assert(false);
}

/* Called from head.S, thus no prototype */
void exception_entry(struct stack_frame *stack);

void exception_entry(struct stack_frame *stack)
{
	switch(stack->type) {
	case STACK_ENTRY_MCHECK:
		handle_machine_check(stack);
		break;
	case STACK_ENTRY_HMI:
		handle_hmi(stack);
		/* XXX TODO : Implement machine check */
		break;
	case STACK_ENTRY_SOFTPATCH:
		/* XXX TODO : Implement softpatch ? */
		break;
	}
}

static int64_t patch_exception(uint64_t vector, uint64_t glue, bool hv)
{
	uint64_t iaddr;

	/* Copy over primary exception handler */
	memcpy((void *)vector, &exc_primary_start,
	       &exc_primary_end - &exc_primary_start);

	/* Patch branch instruction in primary handler */
	iaddr = vector + exc_primary_patch_branch;
	*(uint32_t *)iaddr |= (glue - iaddr) & 0x03fffffc;

	/* Copy over secondary exception handler */
	memcpy((void *)glue, &exc_secondary_start,
	       &exc_secondary_end - &exc_secondary_start);

	/* Patch-in the vector number */
	*(uint32_t *)(glue + exc_secondary_patch_type) |= vector;

	/*
	 * If machine check, patch GET_STACK to get to the MC stack
	 * instead of the normal stack.
	 *
	 * To simplify the arithmetic involved I make assumptions
	 * on the fact that the base of all CPU stacks is 64k aligned
	 * and that our stack size is < 32k, which means that the
	 * "addi" instruction used in GET_STACK() is always using a
	 * small (<32k) positive offset, which we can then easily
	 * fixup with a simple addition
	 */
	BUILD_ASSERT(STACK_SIZE < 0x8000);
	BUILD_ASSERT(!(CPU_STACKS_BASE & 0xffff));

	if (vector == 0x200) {
		/*
		 * The addi we try to patch is the 3rd instruction
		 * of GET_STACK(). If you change the macro, you must
		 * update this code
		 */
		iaddr = glue + exc_secondary_patch_stack + 8;
		*(uint32_t *)iaddr += MC_STACK_SIZE;
	}

	/* Standard exception ? All done */
	if (!hv)
		goto flush;

	/* HV exception, change the SRR's to HSRRs and rfid to hrfid
	 *
	 * The magic is that mfspr/mtspr of SRR can be turned into the
	 * equivalent HSRR version by OR'ing 0x4800. For rfid to hrfid
	 * we OR 0x200.
	 */
	*(uint32_t *)(glue + exc_secondary_patch_mfsrr0) |= 0x4800;
	*(uint32_t *)(glue + exc_secondary_patch_mfsrr1) |= 0x4800;
	*(uint32_t *)(glue + exc_secondary_patch_mtsrr0) |= 0x4800;
	*(uint32_t *)(glue + exc_secondary_patch_mtsrr1) |= 0x4800;
	*(uint32_t *)(glue + exc_secondary_patch_rfid) |= 0x200;

 flush:
	/* On P7 and later all we need is : */
	sync_icache();

	return OPAL_SUCCESS;
}

static int64_t opal_register_exc_handler(uint64_t opal_exception,
					 uint64_t handler_address,
					 uint64_t glue_cache_line)
{
	switch(opal_exception) {
	case OPAL_MACHINE_CHECK_HANDLER:
		client_mc_address = handler_address;
		return patch_exception(0x200, glue_cache_line, false);
	case OPAL_HYPERVISOR_MAINTENANCE_HANDLER:
		return patch_exception(0xe60, glue_cache_line, true);
#if 0 /* We let Linux handle softpatch */
	case OPAL_SOFTPATCH_HANDLER:
		return patch_exception(0x1500, glue_cache_line, true);
#endif
	default:
		break;
	}
	return OPAL_PARAMETER;
}
opal_call(OPAL_REGISTER_OPAL_EXCEPTION_HANDLER, opal_register_exc_handler, 3);

