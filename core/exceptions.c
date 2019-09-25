// SPDX-License-Identifier: Apache-2.0
/*
 * Deal with exceptions when in OPAL.
 *
 * Copyright 2013-2014 IBM Corp.
 */

#include <skiboot.h>
#include <stack.h>
#include <opal.h>
#include <processor.h>
#include <cpu.h>

#define REG		"%016llx"
#define REG32		"%08x"
#define REGS_PER_LINE	4

static void dump_regs(struct stack_frame *stack)
{
	unsigned int i;

	prerror("CFAR : "REG" MSR  : "REG"\n", stack->cfar, stack->msr);
	prerror("SRR0 : "REG" SRR1 : "REG"\n", stack->srr0, stack->srr1);
	prerror("HSRR0: "REG" HSRR1: "REG"\n", stack->hsrr0, stack->hsrr1);
	prerror("DSISR: "REG32"         DAR  : "REG"\n", stack->dsisr, stack->dar);
	prerror("LR   : "REG" CTR  : "REG"\n", stack->lr, stack->ctr);
	prerror("CR   : "REG32"         XER  : "REG32"\n", stack->cr, stack->xer);
	for (i = 0;  i < 16;  i++)
		prerror("GPR%02d: "REG" GPR%02d: "REG"\n",
		       i, stack->gpr[i], i + 16, stack->gpr[i + 16]);
}

#define EXCEPTION_MAX_STR 320

void exception_entry(struct stack_frame *stack)
{
	bool fatal = false;
	bool hv;
	uint64_t nip;
	uint64_t msr;
	char buf[EXCEPTION_MAX_STR];
	size_t l;

	switch (stack->type) {
	case 0x500:
	case 0x980:
	case 0xe00:
	case 0xe20:
	case 0xe40:
	case 0xe60:
	case 0xe80:
	case 0xea0:
	case 0xf80:
		hv = true;
		break;
	default:
		hv = false;
		break;
	}

	if (hv) {
		nip = stack->hsrr0;
		msr = stack->hsrr1;
	} else {
		nip = stack->srr0;
		msr = stack->srr1;
	}

	if (!(msr & MSR_RI))
		fatal = true;

	l = 0;
	switch (stack->type) {
	case 0x100:
		prerror("***********************************************\n");
		if (fatal) {
			l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
				"Fatal System Reset at "REG"   ", nip);
		} else {
			l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
				"System Reset at "REG"   ", nip);
		}
		break;

	case 0x200:
		fatal = true;
		prerror("***********************************************\n");
		l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
			"Fatal MCE at "REG"   ", nip);
		break;

	case 0x700: {
		struct trap_table_entry *tte;

		fatal = true;
		prerror("***********************************************\n");
		for (tte = __trap_table_start; tte < __trap_table_end; tte++) {
			if (tte->address == nip) {
				prerror("< %s >\n", tte->message);
				prerror("    .\n");
				prerror("     .\n");
				prerror("      .\n");
				prerror("        OO__)\n");
				prerror("       <\"__/\n");
				prerror("        ^ ^\n");
				break;
			}
		}
		l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
			"Fatal TRAP at "REG"   ", nip);
		l += snprintf_symbol(buf + l, EXCEPTION_MAX_STR - l, nip);
		l += snprintf(buf + l, EXCEPTION_MAX_STR - l, "  MSR "REG, msr);
		prerror("%s\n", buf);
		dump_regs(stack);
		backtrace();
		if (platform.terminate)
			platform.terminate(buf);
		for (;;) ;
		break; }

	default:
		fatal = true;
		prerror("***********************************************\n");
		l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
			"Fatal Exception 0x%llx at "REG"  ", stack->type, nip);
		break;
	}
	l += snprintf_symbol(buf + l, EXCEPTION_MAX_STR - l, nip);
	l += snprintf(buf + l, EXCEPTION_MAX_STR - l, "  MSR "REG, msr);
	prerror("%s\n", buf);
	dump_regs(stack);
	backtrace();
	if (fatal) {
		if (platform.terminate)
			platform.terminate(buf);
		for (;;) ;
	}

	if (hv) {
		/* Set up for SRR return */
		stack->srr0 = nip;
		stack->srr1 = msr;
	}
}

void exception_entry_pm_sreset(void)
{
	char buf[EXCEPTION_MAX_STR];
	size_t l;

	prerror("***********************************************\n");
	l = 0;
	l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
		"System Reset in sleep");
	prerror("%s\n", buf);
	backtrace();
}

void __noreturn exception_entry_pm_mce(void)
{
	char buf[EXCEPTION_MAX_STR];
	size_t l;

	prerror("***********************************************\n");
	l = 0;
	l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
		"Fatal MCE in sleep");
	prerror("%s\n", buf);
	prerror("SRR0 : "REG" SRR1 : "REG"\n",
			(uint64_t)mfspr(SPR_SRR0), (uint64_t)mfspr(SPR_SRR1));
	prerror("DSISR: "REG32"         DAR  : "REG"\n",
			(uint32_t)mfspr(SPR_DSISR), (uint64_t)mfspr(SPR_DAR));
	abort();
}

static int64_t opal_register_exc_handler(uint64_t opal_exception __unused,
					 uint64_t handler_address __unused,
					 uint64_t glue_cache_line __unused)
{
	/* This interface is deprecated */
	return OPAL_UNSUPPORTED;
}
opal_call(OPAL_REGISTER_OPAL_EXCEPTION_HANDLER, opal_register_exc_handler, 3);

