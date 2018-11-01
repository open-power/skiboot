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

#define pr_fmt(fmt) "HIOMAP: " fmt

#include <hiomap.h>
#include <inttypes.h>
#include <ipmi.h>
#include <lock.h>
#include <lpc.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <ccan/container_of/container_of.h>

#include "errors.h"
#include "ipmi-hiomap.h"

#define CMD_OP_HIOMAP_EVENT	0x0f

enum lpc_window_state { closed_window, read_window, write_window };

struct lpc_window {
	uint32_t lpc_addr; /* Offset into LPC space */
	uint32_t cur_pos;  /* Current position of the window in the flash */
	uint32_t size;     /* Size of the window into the flash */
};

struct ipmi_hiomap {
	/* Members protected by the blocklevel lock */
	uint8_t seq;
	uint8_t version;
	uint8_t block_size_shift;
	uint16_t timeout;
	struct blocklevel_device bl;
	uint32_t total_size;
	uint32_t erase_granule;
	struct lpc_window current;

	/*
	 * update, bmc_state and window_state can be accessed by both calls
	 * through read/write/erase functions and the IPMI SEL handler. All
	 * three variables are protected by lock to avoid conflict.
	 */
	struct lock lock;
	bool update;
	uint8_t bmc_state;
	enum lpc_window_state window_state;
};

struct ipmi_hiomap_result {
	struct ipmi_hiomap *ctx;
	int16_t cc;
};

#define RESULT_INIT(_name, _ctx) struct ipmi_hiomap_result _name = { _ctx, -1 }

static inline uint32_t blocks_to_bytes(struct ipmi_hiomap *ctx, uint16_t blocks)
{
	return blocks << ctx->block_size_shift;
}

static inline uint16_t bytes_to_blocks(struct ipmi_hiomap *ctx, uint32_t bytes)
{
	return bytes >> ctx->block_size_shift;
}

/* Is the current window able perform the complete operation */
static bool hiomap_window_valid(struct ipmi_hiomap *ctx, uint64_t pos,
			        uint64_t len)
{
	enum lpc_window_state window_state;
	uint8_t bmc_state;

	lock(&ctx->lock);
	bmc_state = ctx->bmc_state;
	window_state = ctx->window_state;
	unlock(&ctx->lock);

	if (bmc_state & HIOMAP_E_FLASH_LOST)
		return false;
	if (window_state == closed_window)
		return false;
	if (pos < ctx->current.cur_pos) /* start */
		return false;
	if ((pos + len) > (ctx->current.cur_pos + ctx->current.size)) /* end */
		return false;
	return true;
}


static void ipmi_hiomap_cmd_cb(struct ipmi_msg *msg)
{
	struct ipmi_hiomap_result *res = msg->user_data;
	struct ipmi_hiomap *ctx = res->ctx;

	res->cc = msg->cc;
	if (msg->cc != IPMI_CC_NO_ERROR) {
		return;
	}

	/* We at least need the command and sequence */
	if (msg->resp_size < 2) {
		prerror("Illegal response size: %u\n", msg->resp_size);
		res->cc = IPMI_ERR_UNSPECIFIED;
		ipmi_free_msg(msg);
		return;
	}

	if (msg->data[1] != ctx->seq) {
		prerror("Unmatched sequence number: wanted %u got %u\n",
			ctx->seq, msg->data[1]);
		res->cc = IPMI_ERR_UNSPECIFIED;
		ipmi_free_msg(msg);
		return;
	}

	switch (msg->data[0]) {
	case HIOMAP_C_GET_INFO:
	{
		struct hiomap_v2_info *parms;

		if (msg->resp_size != 6) {
			prerror("%u: Unexpected response size: %u\n", msg->data[0],
				msg->resp_size);
			abort();
		}

		ctx->version = msg->data[2];
		if (ctx->version < 2) {
			prerror("Failed to negotiate protocol v2 or higher: %d\n",
				ctx->version);
			abort();
		}

		parms = (struct hiomap_v2_info *)&msg->data[3];
		ctx->block_size_shift = parms->block_size_shift;
		ctx->timeout = le16_to_cpu(parms->timeout);
		break;
	}
	case HIOMAP_C_GET_FLASH_INFO:
	{
		struct hiomap_v2_flash_info *parms;

		if (msg->resp_size != 6) {
			prerror("%u: Unexpected response size: %u\n", msg->data[0],
				msg->resp_size);
			abort();
		}

		parms = (struct hiomap_v2_flash_info *)&msg->data[2];
		ctx->total_size =
			blocks_to_bytes(ctx, le16_to_cpu(parms->total_size));
		ctx->erase_granule =
			blocks_to_bytes(ctx, le16_to_cpu(parms->erase_granule));
		break;
	}
	case HIOMAP_C_CREATE_READ_WINDOW:
	case HIOMAP_C_CREATE_WRITE_WINDOW:
	{
		struct hiomap_v2_create_window *parms;

		if (msg->resp_size != 8) {
			prerror("%u: Unexpected response size: %u\n", msg->data[0],
				msg->resp_size);
			abort();
		}

		parms = (struct hiomap_v2_create_window *)&msg->data[2];
		ctx->current.lpc_addr =
			blocks_to_bytes(ctx, le16_to_cpu(parms->lpc_addr));
		ctx->current.size =
			blocks_to_bytes(ctx, le16_to_cpu(parms->size));
		ctx->current.cur_pos =
			blocks_to_bytes(ctx, le16_to_cpu(parms->offset));

		lock(&ctx->lock);
		if (msg->data[0] == HIOMAP_C_CREATE_READ_WINDOW)
			ctx->window_state = read_window;
		else
			ctx->window_state = write_window;
		unlock(&ctx->lock);

		break;
	}
	case HIOMAP_C_CLOSE_WINDOW:
		lock(&ctx->lock);
		ctx->window_state = closed_window;
		unlock(&ctx->lock);
		break;
	case HIOMAP_C_MARK_DIRTY:
	case HIOMAP_C_FLUSH:
	case HIOMAP_C_ACK:
	case HIOMAP_C_ERASE:
		break;
	default:
		prlog(PR_WARNING, "Unimplemented command handler: %u\n",
		      msg->data[0]);
		break;
	};
	ipmi_free_msg(msg);
}

static bool hiomap_get_info(struct ipmi_hiomap *ctx)
{
	RESULT_INIT(res, ctx);
	unsigned char req[3];
	struct ipmi_msg *msg;

	ctx->bmc_state = 0;

	/* Negotiate protocol version 2 */
	req[0] = HIOMAP_C_GET_INFO;
	req[1] = ++ctx->seq;
	req[2] = HIOMAP_V2;

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 6);
	ipmi_queue_msg_sync(msg);

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return false;
	}

	lock(&ctx->lock);
	ctx->bmc_state |= HIOMAP_E_DAEMON_READY;
	unlock(&ctx->lock);

	return true;
}

static bool hiomap_get_flash_info(struct ipmi_hiomap *ctx)
{
	RESULT_INIT(res, ctx);
	unsigned char req[2];
	struct ipmi_msg *msg;

	req[0] = HIOMAP_C_GET_FLASH_INFO;
	req[1] = ++ctx->seq;
	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2 + 2 + 2);
	ipmi_queue_msg_sync(msg);

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return false;
	}

	return true;
}

static bool hiomap_window_move(struct ipmi_hiomap *ctx, uint8_t command,
			       uint64_t pos, uint64_t len, uint64_t *size)
{
	enum lpc_window_state want_state;
	struct hiomap_v2_range *range;
	RESULT_INIT(res, ctx);
	unsigned char req[6];
	struct ipmi_msg *msg;
	bool valid_state;
	bool is_read;

	is_read = (command == HIOMAP_C_CREATE_READ_WINDOW);
	want_state = is_read ? read_window : write_window;
	valid_state = want_state == ctx->window_state;
	if (valid_state && hiomap_window_valid(ctx, pos, len)) {
		*size = len;
		return true;
	}

	req[0] = command;
	req[1] = ++ctx->seq;

	range = (struct hiomap_v2_range *)&req[2];
	range->offset = cpu_to_le16(bytes_to_blocks(ctx, pos));
	range->size = cpu_to_le16(bytes_to_blocks(ctx, len));

	lock(&ctx->lock);
	ctx->window_state = closed_window;
	unlock(&ctx->lock);

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req),
			 2 + 2 + 2 + 2);
	ipmi_queue_msg_sync(msg);

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return false;
	}

	*size = len;
	/* Is length past the end of the window? */
	if ((pos + len) > (ctx->current.cur_pos + ctx->current.size))
		/* Adjust size to meet current window */
		*size = (ctx->current.cur_pos + ctx->current.size) - pos;

	if (len != 0 && *size == 0) {
		prerror("Invalid window properties: len: %llu, size: %llu\n",
			len, *size);
		abort();
	}

	prlog(PR_DEBUG, "Opened %s window from 0x%x for %u bytes at 0x%x\n",
	      (command == HIOMAP_C_CREATE_READ_WINDOW) ? "read" : "write",
	      ctx->current.cur_pos, ctx->current.size, ctx->current.lpc_addr);

	return true;
}

static bool hiomap_mark_dirty(struct ipmi_hiomap *ctx, uint64_t offset,
			      uint64_t size)
{
	struct hiomap_v2_range *range;
	enum lpc_window_state state;
	RESULT_INIT(res, ctx);
	unsigned char req[6];
	struct ipmi_msg *msg;
	uint32_t pos;

	lock(&ctx->lock);
	state = ctx->window_state;
	unlock(&ctx->lock);

	if (state != write_window)
		return false;

	req[0] = HIOMAP_C_MARK_DIRTY;
	req[1] = ++ctx->seq;

	pos = offset - ctx->current.cur_pos;
	range = (struct hiomap_v2_range *)&req[2];
	range->offset = cpu_to_le16(bytes_to_blocks(ctx, pos));
	range->size = cpu_to_le16(bytes_to_blocks(ctx, size));

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2);
	ipmi_queue_msg_sync(msg);

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return false;
	}

	prlog(PR_DEBUG, "Marked flash dirty at 0x%" PRIx64 " for %" PRIu64 "\n",
	      offset, size);

	return true;
}

static bool hiomap_flush(struct ipmi_hiomap *ctx)
{
	enum lpc_window_state state;
	RESULT_INIT(res, ctx);
	unsigned char req[2];
	struct ipmi_msg *msg;

	lock(&ctx->lock);
	state = ctx->window_state;
	unlock(&ctx->lock);

	if (state != write_window)
		return false;

	req[0] = HIOMAP_C_FLUSH;
	req[1] = ++ctx->seq;

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2);
	ipmi_queue_msg_sync(msg);

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return false;
	}

	prlog(PR_DEBUG, "Flushed writes\n");

	return true;
}

static bool hiomap_ack(struct ipmi_hiomap *ctx, uint8_t ack)
{
	RESULT_INIT(res, ctx);
	unsigned char req[3];
	struct ipmi_msg *msg;

	req[0] = HIOMAP_C_ACK;
	req[1] = ++ctx->seq;
	req[2] = ack;

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2);
	ipmi_queue_msg_sync(msg);

	if (res.cc != IPMI_CC_NO_ERROR) {
		prlog(PR_DEBUG, "%s failed: %d\n", __func__, res.cc);
		return false;
	}

	prlog(PR_DEBUG, "Acked events: 0x%x\n", ack);

	return true;
}

static bool hiomap_erase(struct ipmi_hiomap *ctx, uint64_t offset,
			 uint64_t size)
{
	struct hiomap_v2_range *range;
	enum lpc_window_state state;
	RESULT_INIT(res, ctx);
	unsigned char req[6];
	struct ipmi_msg *msg;
	uint32_t pos;

	lock(&ctx->lock);
	state = ctx->window_state;
	unlock(&ctx->lock);

	if (state != write_window)
		return false;

	req[0] = HIOMAP_C_ERASE;
	req[1] = ++ctx->seq;

	pos = offset - ctx->current.cur_pos;
	range = (struct hiomap_v2_range *)&req[2];
	range->offset = cpu_to_le16(bytes_to_blocks(ctx, pos));
	range->size = cpu_to_le16(bytes_to_blocks(ctx, size));

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2);
	ipmi_queue_msg_sync(msg);

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return false;
	}

	prlog(PR_DEBUG, "Erased flash at 0x%" PRIx64 " for %" PRIu64 "\n",
	      offset, size);

	return true;
}

static void hiomap_event(uint8_t events, void *context)
{
	struct ipmi_hiomap *ctx = context;

	prlog(PR_DEBUG, "Received events: 0x%x\n", events);

	lock(&ctx->lock);
	ctx->bmc_state |= events;
	ctx->update = true;
	unlock(&ctx->lock);
}

static int lpc_window_read(struct ipmi_hiomap *ctx, uint32_t pos,
			   void *buf, uint32_t len)
{
	uint32_t off = ctx->current.lpc_addr + (pos - ctx->current.cur_pos);
	int rc;

	if ((ctx->current.lpc_addr + ctx->current.size) < (off + len))
		return FLASH_ERR_PARM_ERROR;

	prlog(PR_TRACE, "Reading at 0x%08x for 0x%08x offset: 0x%08x\n",
	      pos, len, off);

	while(len) {
		uint32_t chunk;
		uint32_t dat;

		/* XXX: make this read until it's aligned */
		if (len > 3 && !(off & 3)) {
			rc = lpc_read(OPAL_LPC_FW, off, &dat, 4);
			if (!rc)
				*(uint32_t *)buf = dat;
			chunk = 4;
		} else {
			rc = lpc_read(OPAL_LPC_FW, off, &dat, 1);
			if (!rc)
				*(uint8_t *)buf = dat;
			chunk = 1;
		}
		if (rc) {
			prlog(PR_ERR, "lpc_read failure %d to FW 0x%08x\n", rc, off);
			return rc;
		}
		len -= chunk;
		off += chunk;
		buf += chunk;
	}

	return 0;
}

static int lpc_window_write(struct ipmi_hiomap *ctx, uint32_t pos,
			    const void *buf, uint32_t len)
{
	uint32_t off = ctx->current.lpc_addr + (pos - ctx->current.cur_pos);
	enum lpc_window_state state;
	int rc;

	lock(&ctx->lock);
	state = ctx->window_state;
	unlock(&ctx->lock);

	if (state != write_window)
		return FLASH_ERR_PARM_ERROR;

	if ((ctx->current.lpc_addr + ctx->current.size) < (off + len))
		return FLASH_ERR_PARM_ERROR;

	prlog(PR_TRACE, "Writing at 0x%08x for 0x%08x offset: 0x%08x\n",
	      pos, len, off);

	while(len) {
		uint32_t chunk;

		if (len > 3 && !(off & 3)) {
			rc = lpc_write(OPAL_LPC_FW, off,
				       *(uint32_t *)buf, 4);
			chunk = 4;
		} else {
			rc = lpc_write(OPAL_LPC_FW, off,
				       *(uint8_t *)buf, 1);
			chunk = 1;
		}
		if (rc) {
			prlog(PR_ERR, "lpc_write failure %d to FW 0x%08x\n", rc, off);
			return rc;
		}
		len -= chunk;
		off += chunk;
		buf += chunk;
	}

	return 0;
}

/* Best-effort asynchronous event handling by blocklevel callbacks */
static int ipmi_hiomap_handle_events(struct ipmi_hiomap *ctx)
{
	uint8_t status;
	bool update;

	lock(&ctx->lock);
	status = ctx->bmc_state;
	update = ctx->update;
	if (update) {
		ctx->bmc_state &= ~HIOMAP_E_ACK_MASK;
		ctx->update = false;
	}
	unlock(&ctx->lock);

	if (!update)
		return 0;

	if (!(status & HIOMAP_E_DAEMON_READY)) {
		prerror("Daemon not ready\n");
		return FLASH_ERR_DEVICE_GONE;
	}

	if (status & HIOMAP_E_ACK_MASK) {
		/* ACK is unversioned, can send it if the daemon is ready */
		if (!hiomap_ack(ctx, status & HIOMAP_E_ACK_MASK)) {
			prlog(PR_DEBUG, "Failed to ack events: 0x%x\n",
			      status & HIOMAP_E_ACK_MASK);
			return FLASH_ERR_AGAIN;
		}
	}

	if (status & HIOMAP_E_FLASH_LOST) {
		prlog(PR_INFO, "Lost control of flash device\n");
		return FLASH_ERR_AGAIN;
	}

	if (status & HIOMAP_E_PROTOCOL_RESET) {
		if (!hiomap_get_info(ctx)) {
			prerror("Failure to renegotiate after protocol reset\n");
			return FLASH_ERR_DEVICE_GONE;
		}

		if (!hiomap_get_flash_info(ctx)) {
			prerror("Failure to fetch flash info after protocol reset\n");
			return FLASH_ERR_DEVICE_GONE;
		}

		prlog(PR_INFO, "Renegotiated protocol after reset\n");
		return FLASH_ERR_AGAIN;
	}

	if (status & HIOMAP_E_WINDOW_RESET) {
		prlog(PR_INFO, "Window was reset\n");
		return FLASH_ERR_AGAIN;
	}

	return 0;
}

static int ipmi_hiomap_read(struct blocklevel_device *bl, uint64_t pos,
			    void *buf, uint64_t len)
{
	struct ipmi_hiomap *ctx;
	uint64_t size;
	int rc = 0;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	ctx = container_of(bl, struct ipmi_hiomap, bl);

	rc = ipmi_hiomap_handle_events(ctx);
	if (rc)
		return rc;

	prlog(PR_TRACE, "Flash read at %#" PRIx64 " for %#" PRIx64 "\n", pos,
	      len);
	while (len > 0) {
		/* Move window and get a new size to read */
		if (!hiomap_window_move(ctx, HIOMAP_C_CREATE_READ_WINDOW, pos,
				        len, &size))
			return FLASH_ERR_PARM_ERROR;

		/* Perform the read for this window */
		rc = lpc_window_read(ctx, pos, buf, size);
		if (rc)
			return rc;

		/* Check we can trust what we read */
		if (!hiomap_window_valid(ctx, pos, size))
			return FLASH_ERR_AGAIN;

		len -= size;
		pos += size;
		buf += size;
	}
	return rc;

}

static int ipmi_hiomap_write(struct blocklevel_device *bl, uint64_t pos,
			     const void *buf, uint64_t len)
{
	struct ipmi_hiomap *ctx;
	uint64_t size;
	int rc = 0;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	ctx = container_of(bl, struct ipmi_hiomap, bl);

	rc = ipmi_hiomap_handle_events(ctx);
	if (rc)
		return rc;

	prlog(PR_TRACE, "Flash write at %#" PRIx64 " for %#" PRIx64 "\n", pos,
	      len);
	while (len > 0) {
		/* Move window and get a new size to read */
		if (!hiomap_window_move(ctx, HIOMAP_C_CREATE_WRITE_WINDOW, pos,
				        len, &size))
			return FLASH_ERR_PARM_ERROR;

		/* Perform the write for this window */
		rc = lpc_window_write(ctx, pos, buf, size);
		if (rc)
			return rc;

		if (!hiomap_mark_dirty(ctx, pos, size))
			return FLASH_ERR_PARM_ERROR;

		/*
		 * The BMC *should* flush if the window is implicitly closed,
		 * but do an explicit flush here to be sure.
		 *
		 * XXX: Removing this could improve performance
		 */
		if (!hiomap_flush(ctx))
			return FLASH_ERR_PARM_ERROR;

		len -= size;
		pos += size;
		buf += size;
	}
	return rc;
}

static int ipmi_hiomap_erase(struct blocklevel_device *bl, uint64_t pos,
			     uint64_t len)
{
	struct ipmi_hiomap *ctx;
	int rc;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	ctx = container_of(bl, struct ipmi_hiomap, bl);

	rc = ipmi_hiomap_handle_events(ctx);
	if (rc)
		return rc;

	prlog(PR_TRACE, "Flash erase at 0x%08x for 0x%08x\n", (u32) pos,
	      (u32) len);
	while (len > 0) {
		uint64_t size;

		/* Move window and get a new size to erase */
		if (!hiomap_window_move(ctx, HIOMAP_C_CREATE_WRITE_WINDOW, pos,
				        len, &size))
			return FLASH_ERR_PARM_ERROR;

		if (!hiomap_erase(ctx, pos, size))
			return FLASH_ERR_PARM_ERROR;

		/*
		 * Flush directly, don't mark that region dirty otherwise it
		 * isn't clear if a write happened there or not
		 */

		if (!hiomap_flush(ctx))
			return FLASH_ERR_PARM_ERROR;

		len -= size;
		pos += size;
	}

	return 0;
}

static int ipmi_hiomap_get_flash_info(struct blocklevel_device *bl,
				      const char **name, uint64_t *total_size,
				      uint32_t *erase_granule)
{
	struct ipmi_hiomap *ctx;
	int rc;

	ctx = container_of(bl, struct ipmi_hiomap, bl);

	rc = ipmi_hiomap_handle_events(ctx);
	if (rc)
		return rc;

	if (!hiomap_get_flash_info(ctx)) {
		abort();
	}

	ctx->bl.erase_mask = ctx->erase_granule - 1;

	if (name)
		*name = NULL;
	if (total_size)
		*total_size = ctx->total_size;
	if (erase_granule)
		*erase_granule = ctx->erase_granule;

	return 0;
}

int ipmi_hiomap_init(struct blocklevel_device **bl)
{
	struct ipmi_hiomap *ctx;
	int rc;

	if (!bmc_platform->sw->ipmi_oem_hiomap_cmd)
		/* FIXME: Find a better error code */
		return FLASH_ERR_DEVICE_GONE;

	if (!bl)
		return FLASH_ERR_PARM_ERROR;

	*bl = NULL;

	ctx = zalloc(sizeof(struct ipmi_hiomap));
	if (!ctx)
		return FLASH_ERR_MALLOC_FAILED;

	init_lock(&ctx->lock);

	ctx->bl.read = &ipmi_hiomap_read;
	ctx->bl.write = &ipmi_hiomap_write;
	ctx->bl.erase = &ipmi_hiomap_erase;
	ctx->bl.get_info = &ipmi_hiomap_get_flash_info;

	rc = ipmi_sel_register(CMD_OP_HIOMAP_EVENT, hiomap_event, ctx);
	if (rc < 0)
		goto err;

	/* Ack all pending ack-able events to avoid spurious failures */
	if (!hiomap_ack(ctx, HIOMAP_E_ACK_MASK)) {
		prlog(PR_DEBUG, "Failed to ack events: 0x%x\n",
		      HIOMAP_E_ACK_MASK);
		rc = FLASH_ERR_AGAIN;
		goto err;
	}

	/* Negotiate protocol behaviour */
	if (!hiomap_get_info(ctx)) {
		prerror("Failed to get hiomap parameters\n");
		rc = FLASH_ERR_DEVICE_GONE;
		goto err;
	}

	/* Grab the flash parameters */
	if (!hiomap_get_flash_info(ctx)) {
		prerror("Failed to get flash parameters\n");
		rc = FLASH_ERR_DEVICE_GONE;
		goto err;
	}

	prlog(PR_NOTICE, "Negotiated hiomap protocol v%u\n", ctx->version);
	prlog(PR_NOTICE, "Block size is %uKiB\n",
	      1 << (ctx->block_size_shift - 10));
	prlog(PR_NOTICE, "BMC suggested flash timeout of %us\n", ctx->timeout);
	prlog(PR_NOTICE, "Flash size is %uMiB\n", ctx->total_size >> 20);
	prlog(PR_NOTICE, "Erase granule size is %uKiB\n",
	      ctx->erase_granule >> 10);

	ctx->bl.keep_alive = 0;

	*bl = &(ctx->bl);

	return 0;

err:
	free(ctx);

	return rc;
}

void ipmi_hiomap_exit(struct blocklevel_device *bl)
{
	struct ipmi_hiomap *ctx;
	if (bl) {
		ctx = container_of(bl, struct ipmi_hiomap, bl);
		free(ctx);
	}
}
