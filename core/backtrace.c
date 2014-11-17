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

/* Upto 10 frames each of length 40 bytes + header = 440 bytes */
#define STACK_BUF_SZ		440
static char backtrace_buffer[STACK_BUF_SZ];

/* Dumps backtrace to buffer */
void __nomcount __backtrace(char *bt_buf, int bt_buf_len)
{
	unsigned int pir = mfspr(SPR_PIR);
	unsigned long *sp;
	unsigned long *bottom, *top;
	char *buf;
	int len = 0;

	/* Check if there's a __builtin_something instead */
	asm("mr %0,1" : "=r" (sp));

	bottom = cpu_stack_bottom(pir);
	top = cpu_stack_top(pir);

	if (!bt_buf || !bt_buf_len)
		return;

	buf = bt_buf;
	len += snprintf(buf, bt_buf_len, "CPU %08x Backtrace:\n", pir);
	/* XXX Handle SMP */
	while (sp > bottom && sp < top) {
		len += snprintf(buf + len, bt_buf_len - len, " S: %016lx "
				"R: %016lx\n", (unsigned long)sp, sp[2]);
		sp = (unsigned long *)sp[0];
	}
}

void backtrace(void)
{
	memset(backtrace_buffer, 0, STACK_BUF_SZ);
	__backtrace(backtrace_buffer, STACK_BUF_SZ);

	fputs(backtrace_buffer, stderr);
}
