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
#include <lock.h>
#include <fsp.h>
#include <processor.h>
#include <cpu.h>
#include <stack.h>

unsigned long __stack_chk_guard = 0xdeadf00dbaad300d;

void __noreturn assert_fail(const char *msg)
{
	prlog(PR_EMERG, "Assert fail: %s\n", msg);
	abort();
}

void __noreturn abort(void)
{
	static bool in_abort = false;
	unsigned long hid0;

	if (in_abort)
		for (;;) ;
	in_abort = true;

	bust_locks = true;

	op_display(OP_FATAL, OP_MOD_CORE, 0x6666);
	
	prlog(PR_EMERG, "Aborting!\n");
	backtrace();

	/* XXX FIXME: We should fsp_poll for a while to ensure any pending
	 * console writes have made it out, but until we have decent PSI
	 * link handling we must not do it forever. Polling can prevent the
	 * FSP from bringing the PSI link up and it can get stuck in a
	 * reboot loop.
	 */

	hid0 = mfspr(SPR_HID0);
	hid0 |= SPR_HID0_ENABLE_ATTN;
	set_hid0(hid0);
	trigger_attn();
	for (;;) ;
}

char __attrconst tohex(uint8_t nibble)
{
	static const char __tohex[] = {'0','1','2','3','4','5','6','7','8','9',
				       'A','B','C','D','E','F'};
	if (nibble > 0xf)
		return '?';
	return __tohex[nibble];
}

void __noreturn __nomcount __stack_chk_fail(void);
void __noreturn __nomcount __stack_chk_fail(void)
{
	prlog(PR_EMERG, "Stack corruption detected !\n");
	abort();
}

#ifdef STACK_CHECK_ENABLED

void __nomcount __mcount_stack_check(uint64_t sp, uint64_t lr);
void __nomcount __mcount_stack_check(uint64_t sp, uint64_t lr)
{
	struct cpu_thread *c = this_cpu();
	uint64_t base = (uint64_t)c;
	uint64_t bot = base + sizeof(struct cpu_thread);
	int64_t mark = sp - bot;
	uint64_t top = base + NORMAL_STACK_SIZE;

	/*
	 * Don't re-enter on this CPU or don't enter at all if somebody
	 * has spotted an overflow
	 */
	if (c->in_mcount)
		return;
	c->in_mcount = true;

	/* Capture lowest stack for this thread */
	if (mark < c->stack_bot_mark) {
		c->stack_bot_mark = mark;
		c->stack_bot_pc = lr;
		c->stack_bot_tok = c->current_token;
	}

	/* Stack is within bounds ? check for warning and bail */
	if (sp >= (bot + STACK_SAFETY_GAP) && sp < top) {
		if (mark < STACK_WARNING_GAP) {
			prlog(PR_EMERG, "CPU %04x Stack usage danger !"
			      " pc=%08llx sp=%08llx (gap=%lld) token=%lld\n",
			      c->pir, lr, sp, mark, c->current_token);
			backtrace();
		}
		c->in_mcount = false;
		return;
	}
	
	prlog(PR_EMERG, "CPU %04x Stack overflow detected !"
	      " pc=%08llx sp=%08llx (gap=%lld) token=%lld\n",
	      c->pir, lr, sp, mark, c->current_token);
	abort();
}

static int64_t lowest_stack_mark = LONG_MAX;
static struct lock stack_check_lock = LOCK_UNLOCKED;

void check_stacks(void)
{
	struct cpu_thread *c;
	uint64_t lmark, lpc, ltok;
	int found = -1;

	for_each_cpu(c) {
		if (!c->stack_bot_mark ||
		    c->stack_bot_mark >= lowest_stack_mark)
			continue;
		lock(&stack_check_lock);
		if (c->stack_bot_mark >= lowest_stack_mark) {
			unlock(&stack_check_lock);
			continue;
		}
		lmark = lowest_stack_mark = c->stack_bot_mark;
		lpc = c->stack_bot_pc;
		ltok = c->stack_bot_tok;
		found = c->pir;
		unlock(&stack_check_lock);
	}
	if (found >= 0)
		prlog(PR_NOTICE, "CPU %04x lowest stack mark %lld bytes left"
		      " pc=%08llx token=%lld\n", found, lmark, lpc, ltok);
}

#endif /* STACK_CHECK_ENABLED */
