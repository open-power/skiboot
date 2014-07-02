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
#include <processor.h>
#include <cpu.h>

void backtrace(void)
{
	unsigned int pir = mfspr(SPR_PIR);
	unsigned long *sp;
	unsigned long *bottom, *top;

	/* Check if there's a __builtin_something instead */
	asm("mr %0,1" : "=r" (sp));

	bottom = cpu_stack_bottom(pir);
	top = cpu_stack_top(pir);

	/* XXX Handle SMP */
	fprintf(stderr, "CPU %08x Backtrace:\n", pir);
	while(sp > bottom && sp < top) {
		fprintf(stderr, " S: %016lx R: %016lx\n",
			(unsigned long)sp, sp[2]);
		sp = (unsigned long *)sp[0];
	}
}
