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
#include <opal-api.h>
#include <processor.h>
#include <cpu.h>

#define REG		"%016llx"
#define REGS_PER_LINE	4

static void dump_regs(struct stack_frame *stack)
{
	unsigned int i;

	printf("SRR0 : "REG" SRR1 : "REG"\n", stack->srr0, stack->srr1);
	printf("HSRR0: "REG" HSRR1: "REG"\n", stack->srr0, stack->srr1);
	printf("CFAR : "REG" LR   : "REG" CTR: "REG"\n",
		stack->cfar, stack->lr, stack->ctr);
	printf("  CR: %08x  XER: %08x\n", stack->cr, stack->xer);

	for (i = 0;  i < 32;  i++) {
		if ((i % REGS_PER_LINE) == 0)
			printf("\nGPR%02d: ", i);
		printf(REG " ", stack->gpr[i]);
	}
	printf("\n");
}

/* Called from head.S, thus no prototype */
void exception_entry(struct stack_frame *stack) __noreturn;

void exception_entry(struct stack_frame *stack)
{
	prerror("Unexpected exception %llx !\n", stack->type);
	dump_regs(stack);
	backtrace();
	_abort();
}

static int64_t opal_register_exc_handler(uint64_t opal_exception __unused,
					 uint64_t handler_address __unused,
					 uint64_t glue_cache_line __unused)
{
	/* This interface is deprecated */
	return OPAL_UNSUPPORTED;
}
opal_call(OPAL_REGISTER_OPAL_EXCEPTION_HANDLER, opal_register_exc_handler, 3);

