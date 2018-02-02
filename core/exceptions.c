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

#define REG		"%016llx"
#define REG32		"%08x"
#define REGS_PER_LINE	4

static void dump_regs(struct stack_frame *stack)
{
	unsigned int i;

	prerror("CFAR : "REG"\n", stack->cfar);
	prerror("SRR0 : "REG" SRR1 : "REG"\n", stack->srr0, stack->srr1);
	prerror("HSRR0: "REG" HSRR1: "REG"\n", stack->hsrr0, stack->hsrr1);
	prerror("DSISR: "REG32"         DAR  : "REG"\n", stack->dsisr, stack->dar);
	prerror("LR   : "REG" CTR  : "REG"\n", stack->lr, stack->ctr);
	prerror("CR   : "REG32"         XER  : "REG32"\n", stack->cr, stack->xer);
	for (i = 0;  i < 16;  i++)
		prerror("GPR%02d: "REG" GPR%02d: "REG"\n",
		       i, stack->gpr[i], i + 16, stack->gpr[i + 16]);
}

/* Called from head.S, thus no prototype */
void exception_entry(struct stack_frame *stack) __noreturn;

void exception_entry(struct stack_frame *stack)
{
	const size_t max = 320;
	char buf[max];
	size_t l;

	prerror("***********************************************\n");
	if (stack->type == 0x200) {
		l = 0;
		l += snprintf(buf + l, max - l, "Fatal MCE at "REG"   ", stack->srr0);
		l += snprintf_symbol(buf + l, max - l, stack->srr0);
		prerror("%s\n", buf);
	} else {
		uint64_t nip;
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
			nip = stack->hsrr0;
			break;
		default:
			nip = stack->srr0;
			break;
		}
		l = 0;
		l += snprintf(buf + l, max - l, "Fatal Exception 0x%llx at "REG"   ", stack->type, nip);
		l += snprintf_symbol(buf + l, max - l, nip);
		prerror("%s\n", buf);
	}
	dump_regs(stack);
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

