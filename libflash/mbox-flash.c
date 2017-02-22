/* Copyright 2017 IBM Corp.
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

#define pr_fmt(fmt) "MBOX-FLASH: " fmt

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <skiboot.h>
#include <timebase.h>
#include <timer.h>
#include <libflash/libflash.h>
#include <libflash/mbox-flash.h>
#include <lpc.h>
#include <lpc-mbox.h>

#include <ccan/container_of/container_of.h>

#ifndef __SKIBOOT__
#error "This libflash backend must be compiled with skiboot"
#endif

#define MBOX_DEFAULT_TIMEOUT 30

struct lpc_window {
	uint32_t lpc_addr; /* Offset into LPC space */
	uint32_t cur_pos;  /* Current position of the window in the flash */
	uint32_t size;     /* Size of the window into the flash */
	bool open;
};

struct mbox_flash_data {
	uint32_t shift;
	struct lpc_window read;
	struct lpc_window write;
	struct blocklevel_device bl;
	uint32_t total_size;
	uint32_t erase_granule;
	int rc;
	bool busy;
	uint8_t seq;
	struct bmc_mbox_msg msg_mem;
};

static uint64_t mbox_flash_mask(struct mbox_flash_data *mbox_flash)
{
	return (1 << mbox_flash->shift) - 1;
}

__unused static uint8_t msg_get_u8(struct bmc_mbox_msg *msg, int i)
{
	return msg->args[i];
}

static void msg_put_u8(struct bmc_mbox_msg *msg, int i, uint8_t val)
{
	msg->args[i] = val;
}

static uint16_t msg_get_u16(struct bmc_mbox_msg *msg, int i)
{
	return le16_to_cpu(*(uint16_t *)(&msg->args[i]));
}

static void msg_put_u16(struct bmc_mbox_msg *msg, int i, uint16_t val)
{
	uint16_t tmp = cpu_to_le16(val);
	memcpy(&msg->args[i], &tmp, sizeof(val));
}

static uint32_t msg_get_u32(struct bmc_mbox_msg *msg, int i)
{
	return le32_to_cpu(*(uint32_t *)(&msg->args[i]));
}

static void msg_put_u32(struct bmc_mbox_msg *msg, int i, uint32_t val)
{
	uint32_t tmp = cpu_to_le32(val);
	memcpy(&msg->args[i], &tmp, sizeof(val));
}

static struct bmc_mbox_msg *msg_alloc(struct mbox_flash_data *mbox_flash,
		uint8_t command)
{
	/*
	 * Yes this causes *slow*.
	 * This file and lpc-mbox have far greater slow points, zeroed
	 * data regs are VERY useful for debugging. Think twice if this is
	 * really the performance optimisation you want to make.
	 */
	memset(&mbox_flash->msg_mem, 0, sizeof(mbox_flash->msg_mem));
	mbox_flash->msg_mem.seq = ++mbox_flash->seq;
	mbox_flash->msg_mem.command = command;
	return &mbox_flash->msg_mem;
}

static void msg_free_memory(struct bmc_mbox_msg *mem __unused)
{
	/* Allocation is so simple this isn't required */
}

static int msg_send(struct mbox_flash_data *mbox_flash, struct bmc_mbox_msg *msg)
{
	mbox_flash->busy = true;
	mbox_flash->rc = 0;
	return bmc_mbox_enqueue(msg);
}

static int wait_for_bmc(struct mbox_flash_data *mbox_flash, unsigned int timeout_sec)
{
	unsigned long last = 1, start = tb_to_secs(mftb());
	prlog(PR_TRACE, "Waiting for BMC\n");
	while (mbox_flash->busy && timeout_sec) {
		long now = tb_to_secs(mftb());
		if (now - start > last) {
			timeout_sec--;
			last = now - start;
			if (last < timeout_sec / 2)
				prlog(PR_TRACE, "Been waiting for the BMC for %lu secs\n", last);
			else
				prlog(PR_ERR, "BMC NOT RESPONDING %lu second wait\n", last);
		}
		/*
		 * Both functions are important.
		 * Well time_wait_ms() relaxes the spin... so... its nice
		 */
		time_wait_ms(MBOX_DEFAULT_POLL_MS);
		check_timers(false);
		asm volatile ("" ::: "memory");
	}

	if (mbox_flash->busy) {
		prlog(PR_ERR, "Timeout waiting for BMC\n");
		mbox_flash->busy = false;
		return MBOX_R_TIMEOUT;
	}

	return mbox_flash->rc;
}

static int lpc_window_read(struct mbox_flash_data *mbox_flash, uint32_t pos,
			   void *buf, uint32_t len)
{
	uint32_t off = mbox_flash->read.lpc_addr + (pos - mbox_flash->read.cur_pos);
	int rc;

	prlog(PR_TRACE, "Reading at 0x%08x for 0x%08x offset: 0x%08x\n",
			pos, len, off);

	while(len) {
		uint32_t chunk;
		uint32_t dat;

		/* Choose access size */
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

static int lpc_window_write(struct mbox_flash_data *mbox_flash, uint32_t pos,
			    const void *buf, uint32_t len)
{
	uint32_t off = mbox_flash->write.lpc_addr + (pos - mbox_flash->write.cur_pos);
	int rc;


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

static int mbox_flash_flush(struct mbox_flash_data *mbox_flash, uint64_t pos,
		uint64_t len)
{
	struct bmc_mbox_msg *msg;
	int rc;

	msg = msg_alloc(mbox_flash, MBOX_C_WRITE_FLUSH);
	if (!msg)
		return FLASH_ERR_MALLOC_FAILED;
	msg_put_u16(msg, 0, pos >> mbox_flash->shift);
	msg_put_u32(msg, 2, len);

	rc = msg_send(mbox_flash, msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out;
	}

	rc = wait_for_bmc(mbox_flash, MBOX_DEFAULT_TIMEOUT);
	if (rc)
		prlog(PR_ERR, "Error waiting for BMC\n");

out:
	msg_free_memory(msg);
	return rc;
}

/* Is the current window able perform the complete operation */
static bool mbox_window_valid(struct lpc_window *win, uint64_t pos,
			      uint64_t len)
{
	if (!win->open)
		return false;
	if (pos < win->cur_pos) /* start */
		return false;
	if ((pos + len) > (win->cur_pos + win->size)) /* end */
		return false;
	return true;
}

static int mbox_window_move(struct mbox_flash_data *mbox_flash,
			    struct lpc_window *win, uint8_t command,
			    uint64_t pos, uint64_t len, uint64_t *size)
{
	struct bmc_mbox_msg *msg;
	int rc;

	/* Is the window currently open valid */
	if (mbox_window_valid(win, pos, len)) {
		*size = len;
		return 0;
	}

	prlog(PR_DEBUG, "Adjusting the window\n");

	msg = msg_alloc(mbox_flash, command);
	if (!msg)
		return FLASH_ERR_MALLOC_FAILED;

	win->cur_pos = pos & ~(mbox_flash_mask(mbox_flash));
	msg_put_u16(msg, 0, pos >> mbox_flash->shift);
	rc = msg_send(mbox_flash, msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out;
	}

	rc = wait_for_bmc(mbox_flash, MBOX_DEFAULT_TIMEOUT);
	if (rc) {
		prlog(PR_ERR, "Error waiting for BMC\n");
		goto out;
	}

	*size = len;
	/* Is length past the end of the window? */
	if ((pos + len) > (win->cur_pos + win->size))
		/* Adjust size to meet current window */
		*size =  (win->cur_pos + win->size) - pos;

out:
	msg_free_memory(msg);
	return rc;
}

static int mbox_flash_write(struct blocklevel_device *bl, uint64_t pos,
			    const void *buf, uint64_t len)
{
	struct mbox_flash_data *mbox_flash;
	uint64_t size;

	int rc = 0;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	mbox_flash = container_of(bl, struct mbox_flash_data, bl);

	prlog(PR_TRACE, "Flash write at 0x%08llx for 0x%08llx\n", pos, len);
	while (len > 0) {
		/* Move window and get a new size to read */
		rc = mbox_window_move(mbox_flash, &mbox_flash->write,
				      MBOX_C_CREATE_WRITE_WINDOW, pos, len,
				      &size);
		if (rc)
			return rc;

 		/* Perform the read for this window */
		rc = lpc_window_write(mbox_flash, pos, buf, size);
		if (rc)
			return rc;

		/*
		 * Must flush here as changing the window contents
		 * without flushing entitles the BMC to throw away the
		 * data
		 */
		rc = mbox_flash_flush(mbox_flash, pos, size);
		if (rc)
			return rc;

		len -= size;
		pos += size;
		buf += size;
	}
	return rc;
}

static int mbox_flash_read(struct blocklevel_device *bl, uint64_t pos,
			   void *buf, uint64_t len)
{
	struct mbox_flash_data *mbox_flash;
	uint64_t size;

	int rc = 0;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	mbox_flash = container_of(bl, struct mbox_flash_data, bl);

	prlog(PR_TRACE, "Flash read at 0x%08llx for 0x%08llx\n", pos, len);
	while (len > 0) {
		/* Move window and get a new size to read */
		rc = mbox_window_move(mbox_flash, &mbox_flash->read,
				      MBOX_C_CREATE_READ_WINDOW, pos,
				      len, &size);
		if (rc)
			return rc;

 		/* Perform the read for this window */
		rc = lpc_window_read(mbox_flash, pos, buf, size);
		if (rc)
			return rc;

		len -= size;
		pos += size;
		buf += size;
	}
	return rc;
}

static int mbox_flash_get_info(struct blocklevel_device *bl, const char **name,
		uint64_t *total_size, uint32_t *erase_granule)
{
	struct mbox_flash_data *mbox_flash;
	struct bmc_mbox_msg *msg;
	int rc;

	mbox_flash = container_of(bl, struct mbox_flash_data, bl);
	msg = msg_alloc(mbox_flash, MBOX_C_GET_FLASH_INFO);
	if (!msg)
		return FLASH_ERR_MALLOC_FAILED;

	/*
	 * We want to avoid runtime mallocs in skiboot. The expected
	 * behavour to uses of libflash is that one can free() the memory
	 * returned.
	 * NULL will do for now.
	 */
	if (name)
		*name = NULL;

	mbox_flash->busy = true;
	rc = msg_send(mbox_flash, msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out;
	}

	if (wait_for_bmc(mbox_flash, MBOX_DEFAULT_TIMEOUT)) {
		prlog(PR_ERR, "Error waiting for BMC\n");
		goto out;
	}

	mbox_flash->bl.erase_mask = mbox_flash->erase_granule - 1;

	if (total_size)
		*total_size = mbox_flash->total_size;
	if (erase_granule)
		*erase_granule = mbox_flash->erase_granule;

out:
	msg_free_memory(msg);
	return rc;
}

static int mbox_flash_erase(struct blocklevel_device *bl __unused,
			    uint64_t pos __unused, uint64_t len __unused)
{
	/*
	 * We can probably get away with doing nothing.
	 * TODO: Rethink this, causes interesting behaviour in pflash.
	 * Users do expect pflash -{e,E} to do something. This is because
	 * on real flash this would have set that region to all 0xFF but
	 * really the erase at the blocklevel interface was only designed
	 * to be "please make this region writeable".
	 * It may be wise (despite the large performance penalty) to
	 * actually write all 0xFF here. I'll leave that as an extersise
	 * for the future.
	 */
	return 0;
}

static void mbox_flash_callback(struct bmc_mbox_msg *msg, void *priv)
{
	struct mbox_flash_data *mbox_flash = priv;

	prlog(PR_TRACE, "%s: BMC OK\n", __func__);

	if (msg->response != MBOX_R_SUCCESS) {
		prlog(PR_ERR, "Bad response code from BMC %d\n", msg->response);
		mbox_flash->rc = msg->response;
		goto out;
	}

	if (msg->seq != mbox_flash->seq) {
		/* Uhoh */
		prlog(PR_ERR, "Sequence numbers don't match! Got: %02x Expected: %02x\n",
				msg->seq, mbox_flash->seq);
		mbox_flash->rc = MBOX_R_SYSTEM_ERROR;
		goto out;
	}

	mbox_flash->rc = 0;

	switch (msg->command) {
		case MBOX_C_RESET_STATE:
			break;
		case MBOX_C_GET_MBOX_INFO:
			mbox_flash->read.size = msg_get_u16(msg, 1) << mbox_flash->shift;
			mbox_flash->write.size = msg_get_u16(msg, 3) << mbox_flash->shift;
			break;
		case MBOX_C_GET_FLASH_INFO:
			mbox_flash->total_size = msg_get_u32(msg, 0);
			mbox_flash->erase_granule = msg_get_u32(msg, 4);
			break;
		case MBOX_C_CREATE_READ_WINDOW:
			mbox_flash->read.lpc_addr = msg_get_u16(msg, 0) << mbox_flash->shift;
			mbox_flash->read.open = true;
			mbox_flash->write.open = false;
			break;
		case MBOX_C_CLOSE_WINDOW:
			break;
		case MBOX_C_CREATE_WRITE_WINDOW:
			mbox_flash->write.lpc_addr = msg_get_u16(msg, 0) << mbox_flash->shift;
			mbox_flash->write.open = true;
			mbox_flash->read.open = false;
			break;
		case MBOX_C_MARK_WRITE_DIRTY:
			break;
		case MBOX_C_WRITE_FLUSH:
			break;
		case MBOX_C_BMC_EVENT_ACK:
			break;
		default:
			prlog(PR_ERR, "Got response to unknown command %02x\n", msg->command);
			mbox_flash->rc = -1;
	}

out:
	mbox_flash->busy = false;
}

int mbox_flash_init(struct blocklevel_device **bl)
{
	struct mbox_flash_data *mbox_flash;
	struct bmc_mbox_msg *msg;
	int rc;

	if (!bl)
		return FLASH_ERR_PARM_ERROR;

	*bl = NULL;

	mbox_flash = zalloc(sizeof(struct mbox_flash_data));
	if (!mbox_flash)
		return FLASH_ERR_MALLOC_FAILED;

	/* For V1 of the protocol this is fixed. This could change */
	mbox_flash->shift = 12;

	bmc_mbox_register_callback(&mbox_flash_callback, mbox_flash);

	msg = msg_alloc(mbox_flash, MBOX_C_GET_MBOX_INFO);
	if (!msg) {
		rc = FLASH_ERR_MALLOC_FAILED;
		goto out;
	}

	msg_put_u8(msg, 0, 1); /* V1, do better */

	rc = msg_send(mbox_flash, msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out_msg;
	}

	rc = wait_for_bmc(mbox_flash, MBOX_DEFAULT_TIMEOUT);
	if (rc) {
		prlog(PR_ERR, "Error waiting for BMC\n");
		goto out_msg;
	}

	mbox_flash->bl.keep_alive = 0;
	mbox_flash->bl.read = &mbox_flash_read;
	mbox_flash->bl.write = &mbox_flash_write;
	mbox_flash->bl.erase = &mbox_flash_erase;
	mbox_flash->bl.get_info = &mbox_flash_get_info;

	*bl = &(mbox_flash->bl);
	return 0;

out_msg:
	msg_free_memory(msg);
out:
	free(mbox_flash);
	return rc;
}

void mbox_flash_exit(struct blocklevel_device *bl)
{
	struct mbox_flash_data *mbox_flash;
	if (bl) {
		mbox_flash = container_of(bl, struct mbox_flash_data, bl);
		free(mbox_flash);
	}
}
