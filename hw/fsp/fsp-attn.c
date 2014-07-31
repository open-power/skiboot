/* Copyright 2013-2014 IBM Corp.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
* implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#include <fsp.h>
#include <skiboot.h>
#include <fsp-elog.h>
#include <fsp-attn.h>
#include <hdata/spira.h>

#define TI_CMD_VALID	0x1	/* Command valid */
#define TI_CMD		0xA1	/* Terminate Immediate command */
#define TI_DATA_LEN	0x0400	/* Data length */
/* Controls dump actions
 *	- Non-destructive hardware dump (bit 0)
 *	- memory dump (bit 1)
 *	- Destructive hardware dump (bit 2)
 */
#define TI_DMP_CTL	0x6
/* Dump type
 * 0 - Abbreviated hardware dump
 * 1 - Complete hardware dump
 * 2 - No hardware dump
 */
#define TI_DUMP_TYPE	0x1
#define TI_FORMAT	0x02	/* SRC format */
#define TI_SRC_FLAGS	0x0	/* SRC flags */
#define TI_ASCII_WORDS	0x0	/* Number of ASCII words */

/* HEX words: Number of hex words of data added, up to 8 total
 * this value is one more.
 */
#define TI_HEX_WORDS	0x02
/* SRC length : 8 byte header, 8 hex words of data and
 * 32 byte ASCII SRC
 */
#define TI_SRC_LEN	0x48

/* Generate src from assert function's address
 * First byte in the SRC used for source opal src_type
 * Next 3 bytes used for assert function call address
 */
#define generate_attn_src(addr)	(OPAL_SRC_TYPE_ERROR << 24 | (addr & 0xffffff))

static struct ti_attn *ti_attn;

/* Initialises SP attention area with default values */
static void init_sp_attn_area(void)
{
	/* We are just enabling attention area 1 */
	ti_attn = (struct ti_attn *)&cpu_ctl_sp_attn_area1;

	/* Attention component checks Attn area 2  first, if its NULL
	 * it will check for Attn area 1.
	 */
	memset(&cpu_ctl_sp_attn_area1, 0, sizeof(struct sp_attn_area));
	memset(&cpu_ctl_sp_attn_area2, 0, sizeof(struct sp_attn_area));

	ti_attn->cmd_valid = TI_CMD_VALID;
	ti_attn->attn_cmd = TI_CMD;
	ti_attn->data_len = CPU_TO_BE16(TI_DATA_LEN);
	/* Dump control byte not used as of now */
	ti_attn->dump_ctrl =TI_DMP_CTL;
	ti_attn->dump_type = CPU_TO_BE16(TI_DUMP_TYPE);

	/* SRC format */
	ti_attn->src_fmt = TI_FORMAT;
	/* SRC flags */
	ti_attn->src_flags = TI_SRC_FLAGS;
	/* #ASCII words */
	ti_attn->ascii_cnt = TI_ASCII_WORDS;
	/* #HEX words */
	ti_attn->hex_cnt = TI_HEX_WORDS;
	ti_attn->src_len = CPU_TO_BE16(TI_SRC_LEN);
}

/* Updates src in sp attention area
 */
void update_sp_attn_area(const char *msg)
{
	if (!fsp_present())
		return;

	sprintf(ti_attn->src, "%X",
			(uint32_t)generate_attn_src((uint64_t)__builtin_return_address(0)));

	ti_attn->msg_len = strlen(msg);
	sprintf(ti_attn->msg, "%s", msg);
}

/* Intialises SP attention area */
void fsp_attn_init(void)
{
	if (!fsp_present())
		return;

	init_sp_attn_area();
}
