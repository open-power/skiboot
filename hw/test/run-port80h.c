/* Copyright 2018 IBM Corp.
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

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <assert.h>

#define __LPC_H

uint8_t port80;

static inline void lpc_outb(uint8_t data, uint32_t addr)
{
	assert(addr == 0x80);
	port80 = data;
}

#include "op-panel.h"

void op_display_lpc(enum op_severity s, enum op_module m, uint16_t c);

#include "../lpc-port80h.c"
#include "../../core/test/stubs.c"

int main(void)
{
	op_display_lpc(OP_LOG, OP_MOD_INIT, 0x00);
	assert(port80 == 0x80);
	op_display_lpc(OP_WARN, OP_MOD_INIT, 0x00);
	assert(port80 == 0x82);
	op_display_lpc(OP_ERROR, OP_MOD_INIT, 0x00);
	assert(port80 == 0x81);
	op_display_lpc(OP_FATAL, OP_MOD_INIT, 0x00);
	assert(port80 == 0x83);
	op_display_lpc(OP_FATAL, OP_MOD_INIT, 0x0f);
	assert(port80 == 0xBF);
	op_display_lpc(OP_LOG, OP_MOD_INIT, 0x0f);
	assert(port80 == 0xBC);
	op_display_lpc(OP_FATAL, OP_MOD_CORE, 0x6666);
	assert(port80 == 0xBF);
	op_display_lpc(OP_LOG, OP_MOD_INIT, 0x01);
	assert(port80 == 0x84);
	op_display_lpc(OP_LOG, OP_MOD_CPU, 0x05);
	assert(port80 == 0xC4);
	op_display_lpc(OP_LOG, OP_MOD_LOCK, 0x07);
	assert(port80 == 0xDC);
	op_display_lpc(OP_FATAL, OP_MOD_LOCK, 0x07);
	assert(port80 == 0xDF);
	op_display_lpc(OP_FATAL, OP_MOD_MEM, 0x07);
	assert(port80 == 0xEF);
	op_display_lpc(OP_WARN, OP_MOD_MEM, 0x02);
	assert(port80 == 0xEA);
	op_display_lpc(OP_WARN, OP_MOD_CHIPTOD, 0x02);
	assert(port80 == 0xFA);

	/*
	 * We can't assert that OP_MOD_FSP is invalid as we'd end up
	 * trying to set port80 in the assert parth
	 */
	op_display_lpc(OP_LOG, OP_MOD_FSP, 0x00);
	assert(port80 == 0x80);
	op_display_lpc(OP_LOG, OP_MOD_FSPCON, 0x00);
	assert(port80 == 0x80);
	return 0;
}
