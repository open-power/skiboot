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
#include <stack.h>

#define STACK_BUF_ENTRIES	20
static struct bt_entry bt_buf[STACK_BUF_ENTRIES];

extern uint32_t _stext, _etext;

/* Dumps backtrace to buffer */
void __nomcount __backtrace(struct bt_entry *entries, unsigned int *count)
{
	unsigned int room = *count;
	unsigned int i = 1; /* Start at level 1 */

	*count = 0;
	while(room) {
		unsigned long pc,
			fp = (unsigned long)__builtin_frame_address(i);
		if (!fp)
			break;
		pc = (unsigned long)__builtin_return_address(i);
		entries->sp = fp;
		entries->pc = pc;
		entries++;
		*count = (*count) + 1;
		room--;
	}
}

void __print_backtrace(unsigned int pir,
		       struct bt_entry *entries, unsigned int count,
		       char *out_buf, unsigned int *len)
{
	int i, l = 0, max;
	char *buf = out_buf;
	unsigned long bottom, top, tbot, ttop;
	char mark;

	if (len)
		max = *len - 1;
	else
		max = INT_MAX;

	bottom = cpu_stack_bottom(pir);
	top = cpu_stack_top(pir);
	tbot = (unsigned long)&_stext;
	ttop = (unsigned long)&_etext;

	if (buf)
		l += snprintf(buf, max, "CPU %04x Backtrace:\n", pir);
	else
		l += printf("CPU %04x Backtrace:\n", pir);
	for (i = 0; i < count && l < max; i++) {
		if (entries->sp < bottom || entries->sp > top)
			mark = '!';
		else if (entries->pc < tbot || entries->pc > ttop)
			mark = '*';
		else
			mark = ' ';
		if (buf)
			l += snprintf(buf + l, max - l,
				      " S: %016lx R: %016lx %c\n",
				      entries->sp, entries->pc, mark);
		else
			l += printf(" S: %016lx R: %016lx %c\n",
				    entries->sp, entries->pc, mark);
		entries++;
	}
	if (buf)
		buf[l++] = 0;
	else
		l++;
	if (len)
		*len = l;
}

void backtrace(void)
{
	unsigned int ents = STACK_BUF_ENTRIES;

	__backtrace(bt_buf, &ents);
	__print_backtrace(mfspr(SPR_PIR), bt_buf, ents, NULL, NULL);
}
