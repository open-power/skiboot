/* Copyright 2016 IBM Corp.
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
	uint32_t lpc;
	uint32_t pos;
	uint32_t size;
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
};

static bool wait_for_bmc(struct mbox_flash_data *lpc, unsigned int timeout_sec)
{
	unsigned long last = 1, start = tb_to_secs(mftb());
	prlog(PR_DEBUG, "Waiting for BMC\n");
	while (lpc->busy && timeout_sec) {
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

	return lpc->busy;
}

static uint16_t get_u16(uint8_t *ptr)
{
	return le16_to_cpu(*(uint16_t *)ptr);
}

static void put_u16(uint8_t *ptr, uint16_t val)
{
	uint16_t valt = cpu_to_le16(val);
	memcpy(ptr, &valt, sizeof(val));
}

static uint32_t get_u32(uint8_t *ptr)
{
	return le32_to_cpu(*(uint32_t *)ptr);
}

static void put_u32(uint8_t *ptr, uint32_t val)
{
	uint32_t valt = cpu_to_le32(val);
	memcpy(ptr, &valt, sizeof(val));
}

static int lpc_window_read(struct mbox_flash_data *lpc, uint32_t pos, void *buf, uint32_t len)
{
	int rc;
	uint32_t off = lpc->read.lpc + (pos - lpc->read.pos);

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
			prerror("lpc_read failure %d to FW 0x%08x\n", rc, off);
			return rc;
		}
		len -= chunk;
		off += chunk;
		buf += chunk;
	}

	return 0;
}

static int lpc_window_write(struct mbox_flash_data *lpc, uint32_t pos, const void *buf, uint32_t len)
{
	uint32_t off = lpc->write.lpc + (pos - lpc->write.pos);
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
			prerror("LPC-SYNC: lpc_write failure %d"
				" to FW 0x%08x\n", rc, off);
			return rc;
		}
		len -= chunk;
		off += chunk;
		buf += chunk;
	}

	return 0;
}

static void write_dirty_cb(struct bmc_mbox_msg *msg)
{
	struct mbox_flash_data *lpc;

	lpc = msg->priv;

	prlog(PR_DEBUG, "WRITE_DRITY CB, BMC OK\n");

	if (msg->response != MBOX_R_SUCCESS) {
		prlog(PR_ERR, "Bad response code from BMC %d\n", msg->response);
		lpc->rc = msg->response;
		goto out;
	}

	lpc->rc = 0;

out:
	lpc->busy = false;
}

static void write_cb(struct bmc_mbox_msg *msg)
{
	struct mbox_flash_data *lpc;

	lpc = msg->priv;

	prlog(PR_DEBUG, "WRITE_WINDOW CB, BMC OK\n");

	if (msg->response != MBOX_R_SUCCESS) {
		prlog(PR_ERR, "Bad response code from BMC %d\n", msg->response);
		lpc->rc = msg->response;
		goto out;
	}

	lpc->write.lpc = get_u16(&msg->data[0]) << lpc->shift;
	lpc->write.open = true;
	lpc->read.open = false;

	lpc->rc = 0;

out:
	lpc->busy = false;
}

static int mbox_flash_write(struct blocklevel_device *bl, uint64_t pos,
		const void *buf, uint64_t len)
{
	struct mbox_flash_data *lpc;
	struct bmc_mbox_msg msg;
	int rc;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	lpc = container_of(bl, struct mbox_flash_data, bl);

	prlog(PR_TRACE, "Flash write at 0x%08llx for 0x%08llx\n", pos, len);
	if (!lpc->write.open || pos < lpc->write.pos || pos + len > lpc->write.pos + lpc->write.size) {
		prlog(PR_INFO, "Adjusting the write window\n");

		lpc->write.pos = pos & ~(lpc->shift - 1);
		msg.priv = lpc;
		msg.command = MBOX_C_WRITE_WINDOW;
		msg.callback = &write_cb;
		put_u16(&msg.data[0], pos >> lpc->shift);

		lpc->busy = true;
		rc = bmc_mbox_enqueue(&msg);
		if (rc) {
			prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
			return FLASH_ERR_MALLOC_FAILED; /* Not necessarily the reason... */
		}

		if (wait_for_bmc(lpc, MBOX_DEFAULT_TIMEOUT)) {
			prlog(PR_ERR, "Timeout waiting for BMC\n");
			return FLASH_ERR_CTRL_TIMEOUT;
		}

		if (lpc->rc)
			return lpc->rc;

	}

	rc = lpc_window_write(lpc, pos, buf, len);
	if (rc)
		return rc;

	msg.priv = lpc;
	msg.command = MBOX_C_WRITE_DIRTY;
	msg.callback = &write_dirty_cb;
	put_u16(&msg.data[0], pos >> lpc->shift);
	put_u32(&msg.data[2], len);

	lpc->busy = true;
	rc = bmc_mbox_enqueue(&msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		return FLASH_ERR_MALLOC_FAILED; /* Not necessarily the reason... */
	}

	if (wait_for_bmc(lpc, MBOX_DEFAULT_TIMEOUT)) {
		prlog(PR_ERR, "Timeout waiting for BMC\n");
		return FLASH_ERR_CTRL_TIMEOUT;
	}

	if (lpc->rc)
		prlog(PR_ERR, "Failed to write flash\n");
	return lpc->rc;
}

static void read_cb(struct bmc_mbox_msg *msg)
{
	struct mbox_flash_data *lpc;

	lpc = msg->priv;

	prlog(PR_DEBUG, "READ_WINDOW CB, BMC OK\n");

	if (msg->response != MBOX_R_SUCCESS) {
		prlog(PR_ERR, "Bad response code from BMC %d\n", msg->response);
		lpc->rc = msg->response;
		goto out;
	}

	lpc->read.lpc = get_u16(&msg->data[0]) << lpc->shift;
	lpc->read.open = true;
	lpc->write.open = false;

	lpc->rc = 0;
out:
	lpc->busy = false;
}

static int mbox_flash_read(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len)
{
	struct mbox_flash_data *lpc;
	int rc;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	lpc = container_of(bl, struct mbox_flash_data, bl);

	prlog(PR_TRACE, "Flash read at 0x%08llx for 0x%08llx\n", pos, len);
	if (!lpc->read.open || pos < lpc->read.pos || pos + len > lpc->read.pos + lpc->read.size) {
		struct bmc_mbox_msg msg;
		prlog(PR_INFO, "Adjusting the read window\n");

		lpc->read.pos = pos & ~(lpc->shift - 1);
		msg.priv = lpc;
		msg.command = MBOX_C_READ_WINDOW;
		msg.callback = &read_cb;
		put_u16(&msg.data[0], pos >> lpc->shift);

		lpc->busy = true;
		rc = bmc_mbox_enqueue(&msg);
		if (rc) {
			prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
			return FLASH_ERR_MALLOC_FAILED; /* Not necessarily the reason... */
		}

		if (wait_for_bmc(lpc, MBOX_DEFAULT_TIMEOUT)) {
			prlog(PR_ERR, "Timeout waiting for BMC\n");
			return FLASH_ERR_CTRL_TIMEOUT;
		}

		if (lpc->rc)
			return lpc->rc;
	}

	return lpc_window_read(lpc, pos, buf, len);
}

static void get_info_cb(struct bmc_mbox_msg *msg)
{
	struct mbox_flash_data *lpc;

	prlog(PR_DEBUG, "FLASH_INFO CB, BMC OK\n");

	lpc = msg->priv;

	if (msg->response != MBOX_R_SUCCESS) {
		prlog(PR_ERR, "Bad response code from BMC %d\n", msg->response);
		lpc->rc = msg->response;
		goto out;
	}

	lpc->total_size = get_u32(&msg->data[0]);
	lpc->erase_granule = get_u32(&msg->data[4]);

	lpc->rc = 0;
out:
	lpc->busy = false;
}

static int mbox_flash_get_info(struct blocklevel_device *bl, const char **name,
		uint64_t *total_size, uint32_t *erase_granule)
{
	struct mbox_flash_data *lpc;
	struct bmc_mbox_msg msg;
	int rc;

	lpc = container_of(bl, struct mbox_flash_data, bl);
	msg.command = MBOX_C_GET_FLASH_INFO;
	msg.callback = &get_info_cb;
	msg.priv = lpc;
	msg.data[0] = 1; /* V1, do better */

	/* Hmmm */
	if (name)
		*name = NULL;

	lpc->busy = true;
	rc = bmc_mbox_enqueue(&msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		return FLASH_ERR_MALLOC_FAILED; /* Not necessarily the reason... */
	}

	if (wait_for_bmc(lpc, MBOX_DEFAULT_TIMEOUT)) {
		prlog(PR_ERR, "Timeout waiting for BMC\n");
		return FLASH_ERR_CTRL_TIMEOUT;
	}

	rc = lpc->rc;
	if (rc)
		return rc;

	lpc->bl.erase_mask = lpc->erase_granule - 1;

	if (total_size)
		*total_size = lpc->total_size;
	if (erase_granule)
		*erase_granule = lpc->erase_granule;

	return rc;
}

static int mbox_flash_erase(struct blocklevel_device *bl __unused, uint64_t pos __unused, uint64_t len __unused)
{
	/*
	 * We can probably get away with doing nothing.
	 * TODO: Rethink this, causes interesting behaviour in pflash.
	 * Users do expect pflash -{e,E} to do something
	 */
	return 0;
}

static void init_cb(struct bmc_mbox_msg *msg)
{
	struct mbox_flash_data *lpc;

	prlog(PR_DEBUG, "INIT CB, BMC OK\n");

	lpc = msg->priv;

	if (msg->response != MBOX_R_SUCCESS) {
		prlog(PR_ERR, "Bad response code from BMC %d\n", msg->response);
		lpc->rc = msg->response;
		goto out;
	}

	lpc->read.size = get_u16(&msg->data[1]) << lpc->shift;
	lpc->write.size = get_u16(&msg->data[3]) << lpc->shift;

	lpc->rc = 0;
out:
	lpc->busy = false;
}

int mbox_flash_init(struct blocklevel_device **bl)
{
	struct mbox_flash_data *lpc;
	struct bmc_mbox_msg msg;
	int rc;

	if (!bl)
		return FLASH_ERR_PARM_ERROR;

	*bl = NULL;

	lpc = zalloc(sizeof(struct mbox_flash_data));
	if (!lpc)
		return FLASH_ERR_MALLOC_FAILED;

	/* For V1 of the protocol this is fixed. This could change */
	lpc->shift = 12;

	msg.command = MBOX_C_GET_MBOX_INFO;
	msg.callback = &init_cb;
	msg.priv = lpc;
	msg.data[0] = 1; /* V1, do better */

	lpc->busy = true;
	rc = bmc_mbox_enqueue(&msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		rc = FLASH_ERR_PARM_ERROR;
		goto out;
	}

	if (wait_for_bmc(lpc, MBOX_DEFAULT_TIMEOUT)) {
		prlog(PR_ERR, "Timeout waiting for BMC\n");
		rc = FLASH_ERR_CTRL_TIMEOUT;
		goto out;
	}

	rc = lpc->rc;
	if (rc)
		goto out;

	lpc->bl.keep_alive = 0;
	lpc->bl.read = &mbox_flash_read;
	lpc->bl.write = &mbox_flash_write;
	lpc->bl.erase = &mbox_flash_erase;
	lpc->bl.get_info = &mbox_flash_get_info;

	/*
	 * We're actually accessing BMC RAM, there isn't any point in
	 * having deletes, the BMC will have to do it
	 */

	*bl = &(lpc->bl);
	return 0;

out:
	free(lpc);
	return rc;
}

void mbox_flash_exit(struct blocklevel_device *bl)
{
	struct mbox_flash_data *lpc;
	if (bl) {
		lpc = container_of(bl, struct mbox_flash_data, bl);
		free(lpc);
	}
}
