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

void abort(void)
{
	static bool in_abort = false;
	unsigned long hid0;

	if (in_abort)
		for (;;) ;
	in_abort = true;

	bust_locks = true;

	op_display(OP_FATAL, OP_MOD_CORE, 0x6666);
	
	fputs("Aborting!\n", stderr);
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
