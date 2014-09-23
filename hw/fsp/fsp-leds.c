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


/*
 * LED location code and indicator handling
 */
#include <skiboot.h>
#include <processor.h>
#include <io.h>
#include <fsp.h>
#include <console.h>
#include <timebase.h>
#include <device.h>
#include <stdio.h>
#include <spcn.h>
#include <timebase.h>
#include <hdata/spira.h>
#include <hdata/hdata.h>
#include <fsp-elog.h>

#include "fsp-leds.h"

/* Debug prefix */
#define PREFIX		"FSPLED: "

#define buf_write(p, type, val)  do { *(type *)(p) = val;\
					p += sizeof(type); } while(0)
#define buf_read(p, type, addr)  do { *addr = *(type *)(p);\
					p += sizeof(type); } while(0)

/* SPCN replay threshold */
#define SPCN_REPLAY_THRESHOLD 2

/* Sapphire LED support */
static bool led_support;

/*
 *  PSI mapped buffer for LED data
 *
 * Mapped once and never unmapped. Used for fetching all
 * available LED information and creating the list. Also
 * used for setting individual LED state.
 *
 */
static void *led_buffer;

/* Maintain list of all LEDs
 *
 * The contents here will be used to cater requests from FSP
 * async commands and HV initiated OPAL calls.
 */
static struct list_head  cec_ledq;		/* CEC LED list */
static struct list_head	 encl_ledq;	/* Enclosure LED list */

/* LED lock */
static struct lock led_lock = LOCK_UNLOCKED;

/* Last SPCN command */
static u32 last_spcn_cmd;
static int replay = 0;


static void fsp_leds_query_spcn(void);
static void fsp_read_leds_data_complete(struct fsp_msg *msg);

DEFINE_LOG_ENTRY(OPAL_RC_LED_SPCN, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA, NULL);

DEFINE_LOG_ENTRY(OPAL_RC_LED_BUFF, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA, NULL);

DEFINE_LOG_ENTRY(OPAL_RC_LED_LC, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_INFO, OPAL_NA, NULL);

DEFINE_LOG_ENTRY(OPAL_RC_LED_STATE, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA, NULL);

DEFINE_LOG_ENTRY(OPAL_RC_LED_SUPPORT, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_INFO, OPAL_NA, NULL);

/* Find descendent LED record with CEC location code in CEC list */
static struct fsp_led_data * fsp_find_cec_led(char * loc_code)
{
	struct fsp_led_data *led, *next;

	list_for_each_safe(&cec_ledq, led, next, link) {
		if (strcmp(led->loc_code, loc_code))
			continue;
		return led;
	}
	return NULL;
}

/* Find encl LED record with ENCL location code in ENCL list */
static struct fsp_led_data * fsp_find_encl_led(char * loc_code)
{
	struct fsp_led_data *led, *next;

	list_for_each_safe(&encl_ledq, led, next, link) {
		if (strcmp(led->loc_code, loc_code))
			continue;
		return led;
	}
	return NULL;
}

/* Find encl LED record with CEC location code in CEC list */
static struct fsp_led_data * fsp_find_encl_cec_led(char *loc_code)
{
	struct fsp_led_data *led, *next;

	list_for_each_safe(&cec_ledq, led, next, link) {
		if (strstr(led->loc_code, "-"))
			continue;
		if (!strstr(loc_code, led->loc_code))
			continue;
		return led;
	}
	return NULL;
}

/* Find encl LED record with CEC location code in ENCL list */
static struct fsp_led_data * fsp_find_encl_encl_led(char *loc_code)
{
	struct fsp_led_data *led, *next;

	list_for_each_safe(&encl_ledq, led, next, link) {
		if (!strstr(loc_code, led->loc_code))
			continue;
		return led;
	}
	return NULL;
}

/* Compute the ENCL LED status in CEC list */
static void compute_encl_status_cec(struct fsp_led_data *encl_led)
{
	struct fsp_led_data *led, *next;

	encl_led->status &= ~SPCN_LED_IDENTIFY_MASK;
	encl_led->status &= ~SPCN_LED_FAULT_MASK;

	list_for_each_safe(&cec_ledq, led, next, link) {
		if (!strstr(led->loc_code, encl_led->loc_code))
			continue;

		/* Dont count the enclsure LED itself */
		if (!strcmp(led->loc_code, encl_led->loc_code))
			continue;

		if (led->status & SPCN_LED_IDENTIFY_MASK)
			encl_led->status |= SPCN_LED_IDENTIFY_MASK;

		if (led->status & SPCN_LED_FAULT_MASK)
			encl_led->status |= SPCN_LED_FAULT_MASK;
	}
}

/* Is a enclosure LED */
static bool is_enclosure_led(char *loc_code)
{
	if (strstr(loc_code, "-"))
		return false;
	if (!fsp_find_cec_led(loc_code) || !fsp_find_encl_led(loc_code))
		return false;
	return true;
}

/*
 * Update both the local LED lists to reflect upon led state changes
 * occured with the recent SPCN command. Subsequent LED requests will
 * be served with these updates changed to the list.
 */
static void update_led_list(char *loc_code, u32 led_state)
{
	struct fsp_led_data *led = NULL, *encl_led = NULL, *encl_cec_led = NULL;
	bool is_encl_led = is_enclosure_led(loc_code);

	if (is_encl_led)
		goto enclosure;

	/* Descendant LED in CEC list */
	led = fsp_find_cec_led(loc_code);
	if (!led) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
			"LED: Could not find descendent LED in CEC LC=%s\n",
			loc_code);
		return;
	}
	led->status = led_state;

enclosure:
	/* Enclosure LED in CEC list */
	encl_cec_led = fsp_find_encl_cec_led(loc_code);
	if (!encl_cec_led) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
			"LED: Could not find enclosure LED in CEC LC=%s\n",
			loc_code);
		return;
	}

	/* Enclosure LED in ENCL list */
	encl_led = fsp_find_encl_encl_led(loc_code);
	if (!encl_led) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
			"LED: Could not find enclosure LED in ENCL LC=%s\n",
			loc_code);
		return;
	}

	/* Compute descendent rolled up status */
	compute_encl_status_cec(encl_cec_led);

	/* Check whether exclussive bits set */
	if (encl_cec_led->excl_bit & FSP_LED_EXCL_FAULT)
		encl_cec_led->status |= SPCN_LED_FAULT_MASK;

	if (encl_cec_led->excl_bit & FSP_LED_EXCL_IDENTIFY)
		encl_cec_led->status |= SPCN_LED_IDENTIFY_MASK;

	/* Copy over */
	encl_led->status = encl_cec_led->status;
	encl_led->excl_bit = encl_cec_led->excl_bit;
}

static void fsp_spcn_set_led_completion(struct fsp_msg *msg)
{
	bool fail;
	u16 ckpt_status;
	char loc_code[LOC_CODE_SIZE + 1];
	struct fsp_msg *resp = msg->resp;
	u32 cmd = FSP_RSP_SET_LED_STATE;
	u8 status = resp->word1 & 0xff00;

	/*
	 * LED state update request came as part of FSP async message
	 * FSP_CMD_SET_LED_STATE, hence need to send response message.
	 */
	fail = (status == FSP_STATUS_INVALID_DATA) ||
		(status == FSP_STATUS_DMA_ERROR) ||
		(status == FSP_STATUS_SPCN_ERROR);

	/* SPCN command failed: Identify the command and roll back changes */
	if (fail) {
		log_simple_error(&e_info(OPAL_RC_LED_SPCN),
			"LED: Last SPCN command failed, status=%02x\n",
			status);
		cmd |= FSP_STATUS_GENERIC_ERROR;

		/* Identify the failed command */
		memset(loc_code, 0, sizeof(loc_code));
		strncpy(loc_code,
			((struct fsp_led_data *)(msg->user_data))->loc_code,
			LOC_CODE_SIZE);
		ckpt_status = ((struct fsp_led_data *)(msg->user_data))
			->ckpt_status;

		/* Rollback the changes */
		update_led_list(loc_code, ckpt_status);
	}
	fsp_queue_msg(fsp_mkmsg(cmd, 0), fsp_freemsg);
}

/*
 * Set the state of the LED pointed by the location code
 *
 * LED command:		FAULT state or IDENTIFY state
 * LED state  :		OFF (reset) or ON (set)
 *
 * SPCN TCE mapped buffer entries for setting LED state
 *
 * struct spcn_led_data {
 *	u8	lc_len;
 *	u16	state;
 *	char	lc_code[LOC_CODE_SIZE];
 *};
 */
static int fsp_msg_set_led_state(char *loc_code, bool command, bool state)
{
	struct spcn_led_data sled;
	struct fsp_msg *msg = NULL;
	struct fsp_led_data *led = NULL;
	void *buf = led_buffer;
	u16 data_len = 0;
	u32 cmd_hdr = 0;
	int rc = 0;

	sled.lc_len = strlen(loc_code);
	strncpy(sled.lc_code, loc_code, sled.lc_len);

	/* Location code length + Location code + LED control */
	data_len = LOC_CODE_LEN + sled.lc_len + LED_CONTROL_LEN;
	cmd_hdr =  SPCN_MOD_SET_LED_CTL_LOC_CODE << 24 | SPCN_CMD_SET << 16 |
		data_len;

	/* Fetch the current state of LED */
	led = fsp_find_cec_led(loc_code);

	/* LED not present */
	if (led == NULL) {
		u32 cmd = 0;
		int rc = -1;

		cmd = FSP_RSP_SET_LED_STATE | FSP_STATUS_INVALID_LC;
		fsp_queue_msg(fsp_mkmsg(cmd, 0), fsp_freemsg);
		return rc;
	}

	/*
	 * Checkpoint the status here, will use it if the SPCN
	 * command eventually fails.
	 */
	led->ckpt_status = led->status;
	sled.state = led->status;

	/* Update the exclussive LED bits  */
	if (is_enclosure_led(loc_code)) {
		if (command == LED_COMMAND_FAULT) {
			if (state == LED_STATE_ON)
				led->excl_bit |= FSP_LED_EXCL_FAULT;
			if (state == LED_STATE_OFF)
				led->excl_bit &= ~FSP_LED_EXCL_FAULT;
		}

		if (command == LED_COMMAND_IDENTIFY) {
			if (state == LED_STATE_ON)
				led->excl_bit |= FSP_LED_EXCL_IDENTIFY;
			if (state == LED_STATE_OFF)
				led->excl_bit &= ~FSP_LED_EXCL_IDENTIFY;
		}
	}

	/* LED FAULT commad */
	if (command == LED_COMMAND_FAULT) {
		if (state == LED_STATE_ON)
			sled.state |= SPCN_LED_FAULT_MASK;
		if (state == LED_STATE_OFF)
			sled.state &= ~SPCN_LED_FAULT_MASK;
	}

	/* LED IDENTIFY command */
	if (command == LED_COMMAND_IDENTIFY){
		if (state == LED_STATE_ON)
			sled.state |= SPCN_LED_IDENTIFY_MASK;
		if (state == LED_STATE_OFF)
			sled.state &= ~SPCN_LED_IDENTIFY_MASK;
	}

	/* Write into SPCN TCE buffer */
	buf_write(buf, u8, sled.lc_len);	 /* Location code length */
	strncpy(buf, sled.lc_code, sled.lc_len); /* Location code */
	buf += sled.lc_len;
	buf_write(buf, u16, sled.state);	/* LED state */

	msg = fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
			SPCN_ADDR_MODE_CEC_NODE, cmd_hdr, 0, PSI_DMA_LED_BUF);
	/*
	 * Update the local lists based on the attempted SPCN command to
	 * set/reset an individual led (CEC or ENCL).
	 */
	lock(&led_lock);
	update_led_list(loc_code, sled.state);
	msg->user_data = led;
	unlock(&led_lock);

	rc = fsp_queue_msg(msg, fsp_spcn_set_led_completion);
	return rc;
}

/*
 * Write single location code information into the TCE outbound buffer
 *
 * Data layout
 *
 * 2 bytes - Length of location code structure
 * 4 bytes - CCIN in ASCII
 * 1 byte  - Resource status flag
 * 1 byte  - Indicator state
 * 1 byte  - Raw loc code length
 * 1 byte  - Loc code field size
 * Field size byte - Null terminated ASCII string padded to 4 byte boundary
 *
 */
static u32 fsp_push_data_to_tce(struct fsp_led_data *led, u8 *out_data,
				u32 total_size)
{
	struct fsp_loc_code_data lcode;

	/* CCIN value is irrelevant */
	lcode.ccin = 0x0;

	lcode.status = FSP_IND_NOT_IMPLMNTD;

	if (led->parms & SPCN_LED_IDENTIFY_MASK)
		lcode.status = FSP_IND_IMPLMNTD;

	/* LED indicator status */
	lcode.ind_state = FSP_IND_INACTIVE;
	if (led->status & SPCN_LED_IDENTIFY_MASK)
                lcode.ind_state |= FSP_IND_IDENTIFY_ACTV;
	if (led->status & SPCN_LED_FAULT_MASK)
                lcode.ind_state |= FSP_IND_FAULT_ACTV;

	/* Location code */
	memset(lcode.loc_code, 0, LOC_CODE_SIZE);
	lcode.raw_len = strlen(led->loc_code);
	strncpy(lcode.loc_code, led->loc_code, lcode.raw_len);
	lcode.fld_sz = sizeof(lcode.loc_code);

	/* Rest of the structure */
	lcode.size = sizeof(lcode);
	lcode.status &= 0x0f;

	/*
	 * Check for outbound buffer overflow. If there are still
	 * more LEDs to be sent across to FSP, dont send, ignore.
	 */
	if ((total_size + lcode.size) > PSI_DMA_LOC_COD_BUF_SZ)
		return 0;

	/* Copy over to the buffer */
	memcpy(out_data, &lcode, sizeof(lcode));

	return lcode.size;
}

/*
 * Send out LED information structure pointed by "loc_code"
 * to FSP through the PSI DMA mapping. Buffer layout structure
 * must be followed.
 */
static void fsp_ret_loc_code_list(u16 req_type, char *loc_code)
{
	struct fsp_led_data *led, *next;

	u8 *data;			/* Start of TCE mapped buffer */
	u8 *out_data;			/* Start of location code data */
	u32 bytes_sent = 0, total_size = 0;
	u16 header_size = 0, flags = 0;

	/* Init the addresses */
	data = (u8 *) PSI_DMA_LOC_COD_BUF;
	out_data = NULL;

	/* Unmapping through FSP_CMD_RET_LOC_BUFFER command */
	fsp_tce_map(PSI_DMA_LOC_COD_BUF, (void*)data, PSI_DMA_LOC_COD_BUF_SZ);
	out_data = data + 8;

	/* CEC LED list */
	list_for_each_safe(&cec_ledq, led, next, link) {
		/*
		 * When the request type is system wide led list
		 * i.e GET_LC_CMPLT_SYS, send the entire contents
		 * of the CEC list including both all descendents
		 * and all of their enclosures.
		 */

		if (req_type == GET_LC_ENCLOSURES)
			break;

		if (req_type == GET_LC_ENCL_DESCENDANTS) {
			if (strstr(led->loc_code, loc_code) == NULL)
				continue;
		}

		if (req_type == GET_LC_SINGLE_LOC_CODE) {
			if (strcmp(led->loc_code, loc_code))
				continue;
		}

		/* Push the data into TCE buffer */
		bytes_sent = 0;
		bytes_sent = fsp_push_data_to_tce(led, out_data, total_size);

	        /* Advance the TCE pointer */
		out_data += bytes_sent;
		total_size += bytes_sent;
	}

	/* Enclosure LED list */
	if (req_type == GET_LC_ENCLOSURES) {
		list_for_each_safe(&encl_ledq, led, next, link) {

			/* Push the data into TCE buffer */
			bytes_sent = 0;
			bytes_sent = fsp_push_data_to_tce(led,
							  out_data, total_size);

			/* Advance the TCE pointer */
			out_data += bytes_sent;
			total_size += bytes_sent;
		}
	}

	/* Count from 'data' instead of 'data_out' */
	total_size += 8;
	memcpy(data, &total_size, sizeof(total_size));

	header_size = OUTBUF_HEADER_SIZE;
	memcpy(data + sizeof(total_size), &header_size, sizeof(header_size));

	if (req_type == GET_LC_ENCL_DESCENDANTS)
		flags = 0x8000;

	memcpy(data +  sizeof(total_size) + sizeof(header_size), &flags,
	       sizeof(flags));
	fsp_queue_msg(fsp_mkmsg(FSP_RSP_GET_LED_LIST,
				3, 0, PSI_DMA_LOC_COD_BUF, total_size),
		      fsp_freemsg);
}

/*
 * FSP async command: FSP_CMD_GET_LED_LIST
 *
 * (1) FSP sends the list of location codes through inbound buffer
 * (2) HV sends the status of those location codes through outbound buffer
 *
 * Inbound buffer data layout (loc code request structure)
 *
 * 2 bytes - Length of entire structure
 * 2 bytes - Request type
 * 1 byte - Raw length of location code
 * 1 byte - Location code field size
 * `Field size` bytes - NULL terminated ASCII location code string
 */
void fsp_get_led_list(struct fsp_msg *msg)
{
	struct fsp_loc_code_req req;
	u32 tce_token = msg->data.words[1];
	void *buf;

	/* Parse inbound buffer */
	buf = fsp_inbound_buf_from_tce(tce_token);
	if (!buf) {
		fsp_queue_msg(fsp_mkmsg(FSP_RSP_GET_LED_LIST |
					FSP_STATUS_INVALID_DATA,
					0), fsp_freemsg);
		return;
	}
	memcpy(&req, buf, sizeof(req));

	prlog(PR_TRACE, PREFIX "Request for loc code list type 0x%04x LC=%s\n",
	       req.req_type, req.loc_code);

	fsp_ret_loc_code_list(req.req_type, req.loc_code);
}

/*
 * FSP async command: FSP_CMD_RET_LOC_BUFFER
 *
 * With this command FSP returns ownership of the outbound buffer
 * used by Sapphire to pass the indicator list previous time. That
 * way FSP tells Sapphire that it has consumed all the data present
 * on the outbound buffer and Sapphire can reuse it for next request.
 */
void fsp_free_led_list_buf(struct fsp_msg *msg)
{
	u32 tce_token = msg->data.words[1];
	u32 cmd = FSP_RSP_RET_LED_BUFFER;

	/* Token does not point to outbound buffer */
	if (tce_token != PSI_DMA_LOC_COD_BUF) {
		log_simple_error(&e_info(OPAL_RC_LED_BUFF),
			"LED: Invalid tce token from FSP\n");
		cmd |=  FSP_STATUS_GENERIC_ERROR;
		fsp_queue_msg(fsp_mkmsg(cmd, 0), fsp_freemsg);
		return;
	}

	/* Unmap the location code DMA buffer */
	fsp_tce_unmap(PSI_DMA_LOC_COD_BUF, PSI_DMA_LOC_COD_BUF_SZ);

	/* Respond the FSP */
	fsp_queue_msg(fsp_mkmsg(cmd, 0), fsp_freemsg);
}

static void fsp_ret_led_state(char *loc_code)
{
	struct fsp_led_data *led, *next;
	u8 ind_state = 0;

	list_for_each_safe(&cec_ledq, led, next, link) {
		if (strcmp(loc_code, led->loc_code))
			continue;

		/* Found the location code */
		if (led->status & SPCN_LED_IDENTIFY_MASK)
			ind_state |= FSP_IND_IDENTIFY_ACTV;
		if (led->status & SPCN_LED_FAULT_MASK)
			ind_state |= FSP_IND_FAULT_ACTV;
		fsp_queue_msg(fsp_mkmsg(FSP_RSP_GET_LED_STATE, 1, ind_state),
			      fsp_freemsg);
		return;
	}

	/* Location code not found */
	log_simple_error(&e_info(OPAL_RC_LED_LC),
		"LED: Could not find the location code LC=%s\n", loc_code);

	fsp_queue_msg(fsp_mkmsg(FSP_RSP_GET_LED_STATE |
				FSP_STATUS_INVALID_LC, 1, 0xff), fsp_freemsg);
}

/*
 * FSP async command: FSP_CMD_GET_LED_STATE
 *
 * With this command FSP query the state for any given LED
 */
void fsp_get_led_state(struct fsp_msg *msg)
{
	struct fsp_get_ind_state_req req;
	u32 tce_token = msg->data.words[1];
	void *buf;

	/* Parse the inbound buffer */
	buf = fsp_inbound_buf_from_tce(tce_token);
	if (!buf) {
		fsp_queue_msg(fsp_mkmsg(FSP_RSP_GET_LED_STATE |
					FSP_STATUS_INVALID_DATA, 0),
			      fsp_freemsg);
		return;
	}
	memcpy(&req, buf, sizeof(req));

	prlog(PR_TRACE, "%s: tce=0x%08x buf=%p rq.sz=%d rq.lc_len=%d"
	      " rq.fld_sz=%d LC: %02x %02x %02x %02x....\n", __func__,
	      tce_token, buf, req.size, req.lc_len, req.fld_sz,
	      req.loc_code[0], req.loc_code[1],
	      req.loc_code[2], req.loc_code[3]);

	/* Bound check */
	if (req.lc_len >= LOC_CODE_SIZE) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
			"LED: Loc code too large in %s: %d bytes\n",
			__func__, req.lc_len);
		req.lc_len = LOC_CODE_SIZE - 1;
	}
	/* Ensure NULL termination */
	req.loc_code[req.lc_len] = 0;

	/* Do the deed */
	fsp_ret_led_state(req.loc_code);
}

/*
 * FSP async command: FSP_CMD_SET_LED_STATE
 *
 * With this command FSP sets/resets the state for any given LED
 */
void fsp_set_led_state(struct fsp_msg *msg)
{
	struct fsp_set_ind_state_req req;
	struct fsp_led_data *led, *next;
	u32 tce_token = msg->data.words[1];
	bool command, state;
	void *buf;

	/* Parse the inbound buffer */
	buf = fsp_inbound_buf_from_tce(tce_token);
	if (!buf) {
		fsp_queue_msg(fsp_mkmsg(FSP_RSP_SET_LED_STATE |
					FSP_STATUS_INVALID_DATA,
					0), fsp_freemsg);
		return;
	}
	memcpy(&req, buf, sizeof(req));

	prlog(PR_TRACE, "%s: tce=0x%08x buf=%p rq.sz=%d rq.typ=0x%04x"
	      " rq.lc_len=%d rq.fld_sz=%d LC: %02x %02x %02x %02x....\n",
	      __func__, tce_token, buf, req.size, req.lc_len, req.fld_sz,
	      req.req_type,
	      req.loc_code[0], req.loc_code[1],
	      req.loc_code[2], req.loc_code[3]);

	/* Bound check */
	if (req.lc_len >= LOC_CODE_SIZE) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
			"LED: Loc code too large in %s: %d bytes\n",
			__func__, req.lc_len);
		req.lc_len = LOC_CODE_SIZE - 1;
	}
	/* Ensure NULL termination */
	req.loc_code[req.lc_len] = 0;

	/* Decode command */
	command =  (req.ind_state & LOGICAL_IND_STATE_MASK) ?
		LED_COMMAND_FAULT : LED_COMMAND_IDENTIFY;
	state = (req.ind_state & ACTIVE_LED_STATE_MASK) ?
		LED_STATE_ON : LED_STATE_OFF;

	/* Handle requests */
	switch(req.req_type) {
	case SET_IND_ENCLOSURE:
		list_for_each_safe(&cec_ledq, led, next, link) {
			/* Only descendants of the same enclosure */
			if (!strstr(led->loc_code, req.loc_code))
				continue;

			/* Skip the enclosure */
			if (!strcmp(led->loc_code, req.loc_code))
				continue;

			if (fsp_msg_set_led_state(led->loc_code,
						  command, state))
				log_simple_error(&e_info(OPAL_RC_LED_STATE),
					"LED: Set led state failed at LC=%s\n",
					led->loc_code);
		}
		break;
	case SET_IND_SINGLE_LOC_CODE:
		/* Set led state for single descendent led */
		if (fsp_msg_set_led_state(req.loc_code, command, state))
			log_simple_error(&e_info(OPAL_RC_LED_STATE),
				"LED: Set led state failed at LC=%s\n",
				req.loc_code);
		break;
	default:
		fsp_queue_msg(fsp_mkmsg(FSP_RSP_SET_LED_STATE |
					FSP_STATUS_NOT_SUPPORTED, 0),
			      fsp_freemsg);
	}
}

/* Handle received indicator message from FSP */
static bool fsp_indicator_message(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	u32 cmd;

	/* LED support not available yet */
	if (!led_support) {
		log_simple_error(&e_info(OPAL_RC_LED_SUPPORT),
			PREFIX "Indicator message while LED support not"
			" available yet\n");
		return false;
	}

	switch(cmd_sub_mod) {
		case FSP_CMD_GET_LED_LIST:
			prlog(PR_TRACE, PREFIX
			       "FSP_CMD_GET_LED_LIST command received\n");
			fsp_get_led_list(msg);
			return true;
		case FSP_CMD_RET_LED_BUFFER:
			prlog(PR_TRACE, PREFIX
			       "FSP_CMD_RET_LED_BUFFER command received\n");
			fsp_free_led_list_buf(msg);
			return true;
		case FSP_CMD_GET_LED_STATE:
			prlog(PR_TRACE, PREFIX
			       "FSP_CMD_GET_LED_STATE command received\n");
			fsp_get_led_state(msg);
			return true;
		case FSP_CMD_SET_LED_STATE:
			prlog(PR_TRACE, PREFIX
			       "FSP_CMD_SET_LED_STATE command received\n");
			fsp_set_led_state(msg);
			return true;
		/*
		 * FSP async sub commands which have not been implemented.
		 * For these async sub commands, print for the log and ack
		 * the field service processor with a generic error.
		 */
		case FSP_CMD_GET_MTMS_LIST:
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_GET_MTMS_LIST command received\n");
			cmd = FSP_RSP_GET_MTMS_LIST;
			break;
		case FSP_CMD_RET_MTMS_BUFFER:
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_RET_MTMS_BUFFER command received\n");
			cmd = FSP_RSP_RET_MTMS_BUFFER;
			break;
		case FSP_CMD_SET_ENCL_MTMS:
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_SET_MTMS command received\n");
			cmd = FSP_RSP_SET_ENCL_MTMS;
			break;
		case FSP_CMD_CLR_INCT_ENCL:
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_CLR_INCT_ENCL command received\n");
			cmd = FSP_RSP_CLR_INCT_ENCL;
			break;
		case FSP_CMD_ENCL_MCODE_INIT:
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_ENCL_MCODE_INIT command received\n");
			cmd = FSP_RSP_ENCL_MCODE_INIT;
			break;
		case FSP_CMD_ENCL_MCODE_INTR:
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_ENCL_MCODE_INTR command received\n");
			cmd = FSP_RSP_ENCL_MCODE_INTR;
			break;
		case FSP_CMD_ENCL_POWR_TRACE:
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_ENCL_POWR_TRACE command received\n");
			cmd = FSP_RSP_ENCL_POWR_TRACE;
			break;
		case FSP_CMD_RET_ENCL_TRACE_BUFFER:
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_RET_ENCL_TRACE_BUFFER \
						command received\n");
			cmd = FSP_RSP_RET_ENCL_TRACE_BUFFER;
			break;
		case FSP_CMD_GET_SPCN_LOOP_STATUS:
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_GET_SPCN_LOOP_STATUS \
						command received\n");
			cmd = FSP_RSP_GET_SPCN_LOOP_STATUS;
			break;
		case FSP_CMD_INITIATE_LAMP_TEST:
			/* XXX: FSP ACK not required for this sub command */
			prlog(PR_TRACE, PREFIX
				"FSP_CMD_INITIATE_LAMP_TEST \
						command received\n");
			return true;
		default:
			prlog(PR_WARNING, PREFIX
			       "Invalid FSP async sub command %06x\n",
			       cmd_sub_mod);
			return false;
	}
	cmd |= FSP_STATUS_GENERIC_ERROR;
	fsp_queue_msg(fsp_mkmsg(cmd, 0), fsp_freemsg);
	return true;
}

/* Indicator class client */
static struct fsp_client fsp_indicator_client = {
	.message = fsp_indicator_message,
};

/*
 * Process the received LED data from SPCN
 *
 * Every LED state data is added into the CEC list. If the location
 * code is a enclosure type, its added into the enclosure list as well.
 *
 */
static void fsp_process_leds_data(u16 len)
{
	struct fsp_led_data *led_data = NULL;
	void *buf = NULL;

	/*
	 * Process the entire captured data from the last command
	 *
	 * TCE mapped 'led_buffer' contains the fsp_led_data structure
	 * one after the other till the total lenght 'len'.
	 *
	 */
	buf = led_buffer;
	while (len) {
		/* Prepare */
		led_data = zalloc(sizeof(struct fsp_led_data));
		assert(led_data);

		/* Resource ID */
		buf_read(buf, u16, &led_data->rid);
		len -= sizeof(led_data->rid);

		/* Location code length */
		buf_read(buf, u8, &led_data->lc_len);
		len -= sizeof(led_data->lc_len);

		if (led_data->lc_len == 0) {
			free(led_data);
			break;
		}

		/* Location code */
		strncpy(led_data->loc_code, buf, led_data->lc_len);
		strcat(led_data->loc_code, "\0");

		buf += led_data->lc_len;
		len -= led_data->lc_len;

		/* Parameters */
		buf_read(buf, u16, &led_data->parms);
		len -=  sizeof(led_data->parms);

		/* Status */
		buf_read(buf, u16, &led_data->status);
		len -=  sizeof(led_data->status);

		/*
		 * This is Enclosure LED's location code, need to go
		 * inside the enclosure LED list as well.
		 */
		if (!strstr(led_data->loc_code, "-")) {
			struct fsp_led_data *encl_led_data = NULL;
			encl_led_data = zalloc(sizeof(struct fsp_led_data));
			assert(encl_led_data);

			/* copy over the original */
			encl_led_data->rid = led_data->rid;
			encl_led_data->lc_len = led_data->lc_len;
			strncpy(encl_led_data->loc_code, led_data->loc_code,
				led_data->lc_len);
			encl_led_data->loc_code[led_data->lc_len] = '\0';
			encl_led_data->parms = led_data->parms;
			encl_led_data->status = led_data->status;

			/* Add to the list of enclosure LEDs */
			list_add_tail(&encl_ledq, &encl_led_data->link);
		}

		/* Push this onto the list */
		list_add_tail(&cec_ledq, &led_data->link);
	}
}

/* Replay the SPCN command */
static void replay_spcn_cmd(u32 last_spcn_cmd)
{
	u32 cmd_hdr = 0;
	int rc = 0;

	/* Reached threshold */
	if (replay == SPCN_REPLAY_THRESHOLD) {
		replay = 0;
		return;
	}

	replay++;
	if (last_spcn_cmd == SPCN_MOD_PRS_LED_DATA_FIRST) {
		cmd_hdr = SPCN_MOD_PRS_LED_DATA_FIRST << 24 |
			SPCN_CMD_PRS << 16;
		rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
					     SPCN_ADDR_MODE_CEC_NODE,
					     cmd_hdr, 0,
					     PSI_DMA_LED_BUF),
				   fsp_read_leds_data_complete);
		if (rc)
			prlog(PR_ERR, PREFIX
			       "Replay SPCN_MOD_PRS_LED_DATA_FIRST"
			       " command could not be queued\n");
	}

	if (last_spcn_cmd == SPCN_MOD_PRS_LED_DATA_SUB) {
		cmd_hdr = SPCN_MOD_PRS_LED_DATA_SUB << 24 | SPCN_CMD_PRS << 16;
		rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
					     SPCN_ADDR_MODE_CEC_NODE, cmd_hdr,
					     0, PSI_DMA_LED_BUF),
				   fsp_read_leds_data_complete);
		if (rc)
			prlog(PR_ERR, PREFIX
			       "Replay SPCN_MOD_PRS_LED_DATA_SUB"
			       " command could not be queued\n");
	}
}

/*
 * FSP message response handler for following SPCN LED commands
 * which are used to fetch all of the LED data from SPCN
 *
 * 1. SPCN_MOD_PRS_LED_DATA_FIRST      --> First 1KB of LED data
 * 2. SPCN_MOD_PRS_LED_DATA_SUB        --> Subsequent 1KB of LED data
 *
 * Once the SPCN_RSP_STATUS_SUCCESS response code has been received
 * indicating the last batch of 1KB LED data is here, the list addition
 * process is now complete and we enable LED support for FSP async commands
 * and for OPAL interface.
 */
static void fsp_read_leds_data_complete(struct fsp_msg *msg)
{
	struct fsp_led_data *led, *next;
	struct fsp_msg *resp = msg->resp;
	u32 cmd_hdr = 0;
	int rc = 0;

	u32 msg_status = resp->word1 & 0xff00;
	u32 led_status = (resp->data.words[1] >> 24) & 0xff;
        u16 data_len = (u16)(resp->data.words[1] & 0xffff);

	if (msg_status != FSP_STATUS_SUCCESS) {
		log_simple_error(&e_info(OPAL_RC_LED_SUPPORT),
			"LED: FSP returned error %x LED not supported\n",
								 msg_status);
		/* LED support not available */
		led_support = false;
		return;
	}

	/* SPCN command status */
        switch (led_status) {
		/* Last 1KB of LED data */
		case SPCN_RSP_STATUS_SUCCESS:
			prlog(PR_DEBUG, PREFIX
			      "SPCN_RSP_STATUS_SUCCESS: %d bytes received\n",
			      data_len);

			/* Copy data to the local list */
			fsp_process_leds_data(data_len);
			led_support = true;

			/* LEDs captured on the system */
			prlog(PR_DEBUG, PREFIX
			      "CEC LEDs captured on the system:\n");
			list_for_each_safe(&cec_ledq, led, next, link) {
				prlog(PR_DEBUG, PREFIX
				       "rid: %x\t"
				       "len: %x      "
				       "lcode: %-30s\t"
				       "parms: %04x\t"
				       "status: %04x\n",
				       led->rid,
				       led->lc_len,
				       led->loc_code,
				       led->parms,
				       led->status);
			}

			prlog(PR_DEBUG, PREFIX
			      "ENCL LEDs captured on the system:\n");
			list_for_each_safe(&encl_ledq, led, next, link) {
				prlog(PR_DEBUG, PREFIX
				       "rid: %x\t"
				       "len: %x      "
				       "lcode: %-30s\t"
				       "parms: %04x\t"
				       "status: %04x\n",
				       led->rid,
				       led->lc_len,
				       led->loc_code,
				       led->parms,
				       led->status);
			}

			break;

		/* If more 1KB of LED data present */
		case SPCN_RSP_STATUS_COND_SUCCESS:
			prlog(PR_DEBUG, PREFIX
			      "SPCN_RSP_STATUS_COND_SUCCESS: %d bytes "
			      " received\n", data_len);

			/* Copy data to the local list */
			fsp_process_leds_data(data_len);

			/* Fetch the remaining data from SPCN */
			last_spcn_cmd = SPCN_MOD_PRS_LED_DATA_SUB;
			cmd_hdr = SPCN_MOD_PRS_LED_DATA_SUB << 24 |
				SPCN_CMD_PRS << 16;
			rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
						     SPCN_ADDR_MODE_CEC_NODE,
						     cmd_hdr,
						     0, PSI_DMA_LED_BUF),
					   fsp_read_leds_data_complete);
			if (rc)
				prlog(PR_ERR, PREFIX
				       "SPCN_MOD_PRS_LED_DATA_SUB command"
				       " could not be queued\n");
			break;

		/* Other expected error codes*/
		case SPCN_RSP_STATUS_INVALID_RACK:
		case SPCN_RSP_STATUS_INVALID_SLAVE:
		case SPCN_RSP_STATUS_INVALID_MOD:
		case SPCN_RSP_STATUS_STATE_PROHIBIT:
		case SPCN_RSP_STATUS_UNKNOWN:
			/* Replay the previous SPCN command */
			replay_spcn_cmd(last_spcn_cmd);
	}
	fsp_freemsg(msg);
}

/*
 * Init the LED state
 *
 * This is called during the host boot process. This is the place where
 * we figure out all the LEDs present on the system, their state and then
 * create structure out of those information and popullate two master lists.
 * One for all the LEDs on the CEC and one for all the LEDs on the enclosure.
 * The LED information contained in the lists will cater either to various
 * FSP initiated async commands or POWERNV initiated OPAL calls. Need to make
 * sure that this initialization process is complete before allowing any requets
 * on LED. Also need to be called to re-fetch data from SPCN after any LED state
 * have been updated.
 */
static void fsp_leds_query_spcn()
{
	struct fsp_led_data *led = NULL;
	int rc = 0;

	u32 cmd_hdr = SPCN_MOD_PRS_LED_DATA_FIRST << 24 | SPCN_CMD_PRS << 16;

	/* Till the last batch of LED data */
	led_support = false;
	last_spcn_cmd = 0;

	/* Empty the lists */
	while (!list_empty(&cec_ledq)) {
		led = list_pop(&cec_ledq, struct fsp_led_data, link);
		free(led);
	}

	while (!list_empty(&encl_ledq)) {
		led = list_pop(&encl_ledq, struct fsp_led_data, link);
		free(led);
	}

	/* Allocate buffer with alignment requirements */
	if (led_buffer == NULL) {
		led_buffer = memalign(TCE_PSIZE, PSI_DMA_LED_BUF_SZ);
		if (!led_buffer)
			return;
	}

	/* TCE mapping - will not unmap */
	fsp_tce_map(PSI_DMA_LED_BUF, led_buffer, PSI_DMA_LED_BUF_SZ);

	/* Request the first 1KB of LED data */
	last_spcn_cmd = SPCN_MOD_PRS_LED_DATA_FIRST;
	rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
			SPCN_ADDR_MODE_CEC_NODE, cmd_hdr, 0,
				PSI_DMA_LED_BUF), fsp_read_leds_data_complete);
	if (rc)
		prlog(PR_ERR, PREFIX
		       "SPCN_MOD_PRS_LED_DATA_FIRST command could"
		       " not be queued\n");
}

/* Init the LED subsystem at boot time */
void fsp_led_init(void)
{
	led_buffer = NULL;

	/* Init the master lists */
	list_head_init(&cec_ledq);
	list_head_init(&encl_ledq);

	fsp_leds_query_spcn();
	prlog(PR_TRACE, PREFIX "Init completed\n");

	/* Handle FSP initiated async LED commands */
	fsp_register_client(&fsp_indicator_client, FSP_MCLASS_INDICATOR);
	prlog(PR_TRACE, PREFIX "FSP async command client registered\n");
}
