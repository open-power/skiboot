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
#include <fsp.h>
#include <lock.h>
#include <opal.h>
#include <opal-api.h>
#include <device.h>
#include <processor.h>
#include <opal-msg.h>
#include <errorlog.h>

DEFINE_LOG_ENTRY(OPAL_RC_PANEL_WRITE, OPAL_PLATFORM_ERR_EVT, OPAL_OP_PANEL,
		 OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA, NULL);

static struct fsp_msg op_msg_resp;
static struct fsp_msg op_msg = {
	.resp = &op_msg_resp,
};
static struct fsp_msg *op_req;
static uint64_t op_async_token;
static struct lock op_lock = LOCK_UNLOCKED;

void op_display(enum op_severity sev, enum op_module mod, uint16_t code)
{
	uint32_t w0 = sev << 16 | mod;
	uint32_t w1;
	bool clean_lock;

	if (!fsp_present())
		return;

	w1 =  tohex((code >> 12) & 0xf) << 24;
	w1 |= tohex((code >>  8) & 0xf) << 16;
	w1 |= tohex((code >>  4) & 0xf) <<  8;
	w1 |= tohex((code      ) & 0xf);

	/*
	 * We use lock_recursive to detect recursion. We avoid sending
	 * the message if that happens as this could be a case of a
	 * locking error in the FSP driver for example
	 */
	clean_lock = lock_recursive(&op_lock);
	if (!clean_lock)
		return;

	/* We don't use mkmsg, we use a preallocated msg to avoid
	 * going down the malloc path etc... since this can be called
	 * in case of fatal errors
	 */
	fsp_fillmsg(&op_msg, FSP_CMD_DISP_SRC_DIRECT, 3, 1, w0, w1);

	if (sev == OP_FATAL) {
		if(fsp_queue_msg(&op_msg, NULL))
			prerror("Failed to queue FSP message for OP PANEL\n");
	} else {
		fsp_sync_msg(&op_msg, false);
	}

	unlock(&op_lock);
}

void op_panel_disable_src_echo(void)
{
	if (!fsp_present())
		return;

	lock(&op_lock);
	fsp_fillmsg(&op_msg, FSP_CMD_DIS_SRC_ECHO, 0);
	fsp_sync_msg(&op_msg, false);
	unlock(&op_lock);
}

void op_panel_clear_src(void)
{
	if (!fsp_present())
		return;

	lock(&op_lock);
	fsp_fillmsg(&op_msg, FSP_CMD_CLEAR_SRC, 0);
	fsp_sync_msg(&op_msg, false);
	unlock(&op_lock);
}

/* opal_write_oppanel - Write to the physical op panel.
 *
 * Pass in an array of oppanel_line_t structs defining the ASCII characters
 * to display on each line of the oppanel. If there are two lines on the
 * physical panel, and you only want to write to the first line, you only
 * need to pass in one line. If you only want to write to the second line,
 * you need to pass in both lines, and set the line_len of the first line
 * to zero.
 *
 * This command is asynchronous. If OPAL_SUCCESS is returned, then the
 * operation was initiated successfully. Subsequent calls will return
 * OPAL_BUSY until the current operation is complete.
 */
struct op_src {
	uint8_t version;
#define OP_SRC_VERSION	2
	uint8_t	flags;
	uint8_t reserved;
	uint8_t	hex_word_cnt;
	uint16_t reserved2;
	uint16_t total_size;
	uint32_t word2; /* SRC format in low byte */
	uint32_t word3;
	uint32_t word4;
	uint32_t word5;
	uint32_t word6;
	uint32_t word7;
	uint32_t word8;
	uint32_t word9;
#define OP_SRC_ASCII_LEN 32
	uint8_t	ascii[OP_SRC_ASCII_LEN]; /* Word 11 */
} __packed __align(4);

/* Page align for the sake of TCE mapping */
static struct op_src op_src __align(0x1000);

static void __op_panel_write_complete(struct fsp_msg *msg)
{
	fsp_tce_unmap(PSI_DMA_OP_PANEL_MISC, 0x1000);
	lwsync();
	op_req = NULL;
	fsp_freemsg(msg);
}

static void op_panel_write_complete(struct fsp_msg *msg)
{
	uint8_t rc = (msg->resp->word1 >> 8) & 0xff;

	if (rc)
		prerror("OPPANEL: Error 0x%02x in display command\n", rc);

	__op_panel_write_complete(msg);

	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL, 1, op_async_token);
}

static int64_t __opal_write_oppanel(oppanel_line_t *lines, uint64_t num_lines,
				    uint64_t async_token)
{
	int64_t rc = OPAL_ASYNC_COMPLETION;
	int len;
	int i;

	if (num_lines < 1 || num_lines > 2)
		return OPAL_PARAMETER;

	lock(&op_lock);

	/* Only one in flight */
	if (op_req) {
		rc = OPAL_BUSY_EVENT;
		goto bail;
	}

	op_req = fsp_allocmsg(true);
	if (!op_req) {
		rc = OPAL_NO_MEM;
		goto bail;
	}

	op_async_token = async_token;

	memset(&op_src, 0, sizeof(op_src));

	op_src.version = OP_SRC_VERSION;
	op_src.flags = 0;
	op_src.reserved = 0;
	op_src.hex_word_cnt = 1; /* header word only */
	op_src.reserved2 = 0;
	op_src.total_size = sizeof(op_src);
	op_src.word2 = 0; /* should be unneeded */

	len = lines[0].line_len > 16 ? 16 : lines[0].line_len;

	memset(op_src.ascii + len, ' ', 16-len);
	memcpy(op_src.ascii, lines[0].line, len);
	if (num_lines > 1) {
		len = lines[1].line_len > 16 ? 16 : lines[1].line_len;
		memcpy(op_src.ascii + 16, lines[1].line, len);
		memset(op_src.ascii + 16 + len, ' ', 16-len);
	}

	for (i = 0; i < sizeof(op_src.ascii); i++) {
		/*
		 * So, there's this interesting thing if you send
		 * HTML/Javascript through the Operator Panel.
		 * You get to inject it into the ASM web ui!
		 * So we filter out anything suspect here,
		 * at least for the time being.
		 *
		 * Allowed characters:
		 *  . / 0-9 : a-z A-Z SPACE
		 */
		if (! ((op_src.ascii[i] >= '.' && op_src.ascii[i] <= ':') ||
		       (op_src.ascii[i] >= 'a' && op_src.ascii[i] <= 'z') ||
		       (op_src.ascii[i] >= 'A' && op_src.ascii[i] <= 'Z') ||
		       op_src.ascii[i] == ' ')) {
			op_src.ascii[i] = '.';
		}
	}

	fsp_tce_map(PSI_DMA_OP_PANEL_MISC, &op_src, 0x1000);

	fsp_fillmsg(op_req, FSP_CMD_DISP_SRC_INDIR, 3, 0,
		    PSI_DMA_OP_PANEL_MISC, sizeof(struct op_src));
	rc = fsp_queue_msg(op_req, op_panel_write_complete);
	if (rc) {
		__op_panel_write_complete(op_req);
		rc = OPAL_INTERNAL_ERROR;
	}
 bail:
	unlock(&op_lock);
	log_simple_error(&e_info(OPAL_RC_PANEL_WRITE),
			"FSP: Error updating Op Panel: %lld\n", rc);
	return rc;
}

static int64_t opal_write_oppanel_async(uint64_t async_token,
					oppanel_line_t *lines,
					uint64_t num_lines)
{
	return __opal_write_oppanel(lines, num_lines, async_token);
}

void fsp_oppanel_init(void)
{
	struct dt_node *oppanel;

	if (!fsp_present())
		return;

	opal_register(OPAL_WRITE_OPPANEL_ASYNC, opal_write_oppanel_async, 3);

	oppanel = dt_new(opal_node, "oppanel");
	dt_add_property_cells(oppanel, "#length", 16);
	dt_add_property_cells(oppanel, "#lines", 2);
	dt_add_property_string(oppanel, "compatible", "ibm,opal-oppanel");
}
