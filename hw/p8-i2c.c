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
#include <opal.h>
#include <lock.h>
#include <chip.h>
#include <i2c.h>
#include <xscom.h>
#include <timebase.h>
#include <opal-msg.h>

#define USEC_PER_SEC		1000000
#define USEC_PER_MSEC		1000
#define I2C_RESET_DELAY_MS	5 /* 5 msecs */
#define MAX_POLL_COUNT(x)	((I2C_RESET_DELAY_MS * USEC_PER_MSEC)/(x))
#define I2C_FIFO_HI_LVL		4
#define I2C_FIFO_LO_LVL		4
#define I2C_PAGE_WRITE_SIZE	(0x1u << 8)
#define I2C_PAGE_WRITE_MASK	(I2C_PAGE_WRITE_SIZE - 1)

/*
 * I2C registers set.
 * Below is the offset of registers from base which is stored in the
 * 'struct p8_i2c_master'
 */

/* I2C FIFO register */
#define I2C_FIFO_REG			0x4
#define I2C_FIFO_MASK			PPC_BITMASK(0, 7)
#define I2C_FIFO_LSH			PPC_BITLSHIFT(7)

/* I2C command register */
#define I2C_CMD_REG			0x5
#define I2C_CMD_WITH_START		PPC_BIT(0)
#define I2C_CMD_WITH_ADDR		PPC_BIT(1)
#define I2C_CMD_READ_CONT		PPC_BIT(2)
#define I2C_CMD_WITH_STOP		PPC_BIT(3)
#define I2C_CMD_DEV_ADDR_MASK		PPC_BITMASK(8, 14)
#define I2C_CMD_DEV_ADDR_LSH		PPC_BITLSHIFT(14)
#define I2C_CMD_READ_NOT_WRITE		PPC_BIT(15)
#define I2C_CMD_LEN_BYTES_MASK		PPC_BITMASK(16, 31)
#define I2C_CMD_LEN_BYTES_LSH		PPC_BITLSHIFT(31)
#define I2C_MAX_TFR_LEN			0xffffull

/* I2C mode register */
#define I2C_MODE_REG			0x6
#define I2C_MODE_BIT_RATE_DIV_MASK	PPC_BITMASK(0, 15)
#define I2C_MODE_BIT_RATE_DIV_LSH	PPC_BITLSHIFT(15)
#define I2C_MODE_PORT_NUM_MASK		PPC_BITMASK(16, 21)
#define I2C_MODE_PORT_NUM_LSH		PPC_BITLSHIFT(21)
#define I2C_MODE_ENHANCED		PPC_BIT(28)
#define I2C_MODE_DIAGNOSTIC		PPC_BIT(29)
#define I2C_MODE_PACING_ALLOW		PPC_BIT(30)
#define I2C_MODE_WRAP			PPC_BIT(31)

/* I2C watermark register */
#define I2C_WATERMARK_REG		0x7
#define I2C_WATERMARK_HIGH_MASK		PPC_BITMASK(16, 19)
#define I2C_WATERMARK_HIGH_LSH		PPC_BITLSHIFT(19)
#define I2C_WATERMARK_LOW_MASK		PPC_BITMASK(24, 27)
#define I2C_WATERMARK_LOW_LSH		PPC_BITLSHIFT(27)

/* I2C interrupt mask, condition and interrupt registers */
#define I2C_INTR_MASK_REG		0x8
#define I2C_INTR_COND_REG		0x9
#define I2C_INTR_REG			0xa
#define I2C_INTR_ALL_MASK		PPC_BITMASK(16, 31)
#define I2C_INTR_ALL_LSH		PPC_BITLSHIFT(31)
#define I2C_INTR_INVALID_CMD		PPC_BIT(16)
#define I2C_INTR_LBUS_PARITY_ERR	PPC_BIT(17)
#define I2C_INTR_BKEND_OVERRUN_ERR	PPC_BIT(18)
#define I2C_INTR_BKEND_ACCESS_ERR	PPC_BIT(19)
#define I2C_INTR_ARBT_LOST_ERR		PPC_BIT(20)
#define I2C_INTR_NACK_RCVD_ERR		PPC_BIT(21)
#define I2C_INTR_DATA_REQ		PPC_BIT(22)
#define I2C_INTR_CMD_COMP		PPC_BIT(23)
#define I2C_INTR_STOP_ERR		PPC_BIT(24)
#define I2C_INTR_I2C_BUSY		PPC_BIT(25)
#define I2C_INTR_NOT_I2C_BUSY		PPC_BIT(26)
#define I2C_INTR_SCL_EQ_1		PPC_BIT(28)
#define I2C_INTR_SCL_EQ_0		PPC_BIT(29)
#define I2C_INTR_SDA_EQ_1		PPC_BIT(30)
#define I2C_INTR_SDA_EQ_0		PPC_BIT(31)

/* I2C status register */
#define I2C_RESET_I2C_REG		0xb
#define I2C_STAT_REG			0xb
#define I2C_STAT_INVALID_CMD		PPC_BIT(0)
#define I2C_STAT_LBUS_PARITY_ERR	PPC_BIT(1)
#define I2C_STAT_BKEND_OVERRUN_ERR	PPC_BIT(2)
#define I2C_STAT_BKEND_ACCESS_ERR	PPC_BIT(3)
#define I2C_STAT_ARBT_LOST_ERR		PPC_BIT(4)
#define I2C_STAT_NACK_RCVD_ERR		PPC_BIT(5)
#define I2C_STAT_DATA_REQ		PPC_BIT(6)
#define I2C_STAT_CMD_COMP		PPC_BIT(7)
#define I2C_STAT_STOP_ERR		PPC_BIT(8)
#define I2C_STAT_UPPER_THRS_MASK	PPC_BITMASK(9, 15)
#define I2C_STAT_UPPER_THRS_LSH		PPC_BITLSHIFT(15)
#define I2C_STAT_ANY_I2C_INTR		PPC_BIT(16)
#define I2C_STAT_PORT_HISTORY_BUSY	PPC_BIT(19)
#define I2C_STAT_SCL_INPUT_LEVEL	PPC_BIT(20)
#define I2C_STAT_SDA_INPUT_LEVEL	PPC_BIT(21)
#define I2C_STAT_PORT_BUSY		PPC_BIT(22)
#define I2C_STAT_INTERFACE_BUSY         PPC_BIT(23)
#define I2C_STAT_FIFO_ENTRY_COUNT_MASK  PPC_BITMASK(24, 31)
#define I2C_STAT_FIFO_ENTRY_COUNT_LSH	PPC_BITLSHIFT(31)

#define I2C_STAT_ANY_ERR (I2C_STAT_INVALID_CMD | I2C_STAT_LBUS_PARITY_ERR | \
			  I2C_STAT_BKEND_OVERRUN_ERR | \
			  I2C_STAT_BKEND_ACCESS_ERR | I2C_STAT_ARBT_LOST_ERR | \
			  I2C_STAT_NACK_RCVD_ERR | I2C_STAT_STOP_ERR)

/* I2C extended status register */
#define I2C_EXTD_STAT_REG		0xc
#define I2C_EXTD_STAT_FIFO_SIZE_MASK	PPC_BITMASK(0, 7)
#define I2C_EXTD_STAT_FIFO_SIZE_LSH	PPC_BITLSHIFT(7)
#define I2C_EXTD_STAT_MSM_CURSTATE_MASK PPC_BITMASK(11, 15)
#define I2C_EXTD_STAT_MSM_CURSTATE_LSH	PPC_BITLSHIFT(15)
#define I2C_EXTD_STAT_SCL_IN_SYNC	PPC_BIT(16)
#define I2C_EXTD_STAT_SDA_IN_SYNC	PPC_BIT(17)
#define I2C_EXTD_STAT_S_SCL		PPC_BIT(18)
#define I2C_EXTD_STAT_S_SDA		PPC_BIT(19)
#define I2C_EXTD_STAT_M_SCL		PPC_BIT(20)
#define I2C_EXTD_STAT_M_SDA		PPC_BIT(21)
#define I2C_EXTD_STAT_HIGH_WATER	PPC_BIT(22)
#define I2C_EXTD_STAT_LOW_WATER		PPC_BIT(23)
#define I2C_EXTD_STAT_I2C_BUSY		PPC_BIT(24)
#define I2C_EXTD_STAT_SELF_BUSY		PPC_BIT(25)
#define I2C_EXTD_STAT_I2C_VERSION_MASK	PPC_BITMASK(27, 31)
#define I2C_EXTD_STAT_I2C_VERSION_LSH	PPC_BITLSHIFT(31)

/* I2C residual front end/back end length */
#define I2C_RESIDUAL_LEN_REG		0xd
#define I2C_RESIDUAL_FRONT_END_MASK	PPC_BITMASK(0, 15)
#define I2C_RESIDUAL_FRONT_END_LSH	PPC_BITLSHIFT(15)
#define I2C_RESIDUAL_BACK_END_MASK	PPC_BITMASK(16, 31)
#define I2C_RESIDUAL_BACK_END_LSH	PPC_BITLSHIFT(31)

struct p8_i2cm_state {
	enum request_state {
		STATE_IDLE	= 0x1,	/* Fresh request pushed on the bus */
		STATE_OFFSET	= 0x2,	/* SMBUS offset writing in progress */
		STATE_DATA	= 0x4,	/* Device data read/write in progress */
		STATE_DATA_CONT	= 0x8,	/* Data request with no stop for data */
		STATE_ERROR	= 0x10, /* STOP sequence following an error */
	} req_state;
	uint32_t bytes_sent;
};

struct p8_i2c_master {
	struct p8_i2cm_state	state;		/* Request state of i2cm */
	struct lock		lock;		/* Lock to guard the members */
	uint64_t		poll_timer;	/* Poll timer expiration */
	uint64_t		poll_interval;	/* Polling interval in usec */
	uint64_t		poll_count;	/* Max poll attempts */
	uint64_t		xscom_base;	/* xscom base of i2cm */
	uint32_t		bit_rate_div;	/* Divisor to set bus speed*/
	uint32_t		fifo_size;	/* Maximum size of FIFO  */
	uint32_t		chip_id;	/* Chip the i2cm sits on */
	struct list_head	req_list;	/* Request queue head */
};

struct p8_i2c_master_port {
	struct i2c_bus		bus; /* Abstract bus struct for the client */
	struct p8_i2c_master	*common;
	uint32_t		bus_id;
	uint32_t		port_num;
};

struct p8_i2c_request {
	struct i2c_request	req;
	uint32_t		port_num;
};

struct opal_p8_i2c_data {
	struct i2c_bus		*bus;
	uint64_t		token;
};

static LIST_HEAD(i2c_bus_list);
static int p8_i2c_start_request(struct p8_i2c_master *master);
static void p8_i2c_complete_request(struct p8_i2c_master *master, int rc);
static int p8_i2c_prog_mode(struct p8_i2c_master *master, bool reset,
			    bool enhanced_mode);
static int p8_i2c_prog_watermark(struct p8_i2c_master *master);

static int p8_i2c_fifo_to_buf(struct p8_i2c_master *master,
			      struct i2c_request *req, uint32_t count)
{
	uint8_t *buf = (uint8_t *)req->rw_buf + master->state.bytes_sent;
	uint64_t fifo;
	uint32_t i;
	int rc = 0;

	for (i = 0; i < count; i++, buf++) {
		rc = xscom_read(master->chip_id, master->xscom_base +
				I2C_FIFO_REG, &fifo);
		if (rc) {
			prlog(PR_ERR, "I2C: Failed to read the fifo\n");
			break;
		}

		*buf = GETFIELD(I2C_FIFO, fifo);
	}

	master->state.bytes_sent += i;

	return rc;
}

static int p8_i2c_buf_to_fifo(struct p8_i2c_master *master,
			      struct i2c_request *req, uint32_t count)
{
	uint64_t fifo = 0x0ull;
	uint32_t offset, i;
	uint8_t *buf;
	int rc = 0;

	if (master->state.req_state & STATE_OFFSET) {
		offset = req->offset + master->state.bytes_sent;
		buf = (uint8_t *)&offset;
		/* MSB address byte is followed by the LSB byte */
		buf += (sizeof(offset) - req->offset_bytes);
		for (i = 0; i < req->offset_bytes; i++, buf++, count--) {
			fifo = SETFIELD(I2C_FIFO, fifo, *buf);
			rc = xscom_write(master->chip_id, master->xscom_base +
					 I2C_FIFO_REG, fifo);
			if (rc) {
				prlog(PR_ERR, "I2C:Failed to write the fifo\n");
				return -1;
			}
		}

		/*
		 * SMBUS_WRITE is combined offset and data write with same START
		 * condition, update the state as the next call to this function
		 * for the same command sequence should not write the 'offset'
		 * again.
		 * SMBUS_READ is seperate START condition for 'offset write' and
		 * data read, so state gets updated when we issue the following
		 * START condition for data read.
		 */
		if (req->op == SMBUS_WRITE)
			master->state.req_state &= ~STATE_OFFSET;
	}

	buf = (uint8_t *)req->rw_buf + master->state.bytes_sent;
	for (i = 0; i < count; i++, buf++) {
		fifo = SETFIELD(I2C_FIFO, fifo, *buf);
		rc = xscom_write(master->chip_id, master->xscom_base +
				 I2C_FIFO_REG, fifo);
		if (rc) {
			prlog(PR_ERR, "I2C: Failed to write the fifo\n");
			break;
		}
	}

	master->state.bytes_sent += i;

	return rc;
}

static int p8_i2c_get_fifo_left(struct p8_i2c_master *master, uint32_t fifo_count,
				uint32_t *fifo_left)
{
	uint32_t res_be;
	uint64_t res;
	int rc;

	*fifo_left = master->fifo_size - fifo_count;
	rc = xscom_read(master->chip_id, master->xscom_base +
			I2C_RESIDUAL_LEN_REG, &res);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to read RESIDUAL_LEN\n");
		return -1;
	}

	res_be = GETFIELD(I2C_RESIDUAL_BACK_END, res);
	if (res_be < *fifo_left)
		*fifo_left = res_be;

	return 0;
}

static int p8_i2c_enable_irqs(struct p8_i2c_master *master)
{
	int rc;

	/* Enable the interrupts */
	rc = xscom_write(master->chip_id, master->xscom_base +
			 I2C_INTR_COND_REG, I2C_STAT_ANY_ERR >> 16 |
			 I2C_INTR_CMD_COMP | I2C_INTR_DATA_REQ);
	if (rc)
		prlog(PR_ERR, "I2C: Failed to enable the interrupts\n");

	return rc;
}

static void p8_i2c_status_error(struct p8_i2c_master *master, uint64_t status)
{
	int rc;

	/* Display any error other than I2C_INTR_NACK_RCVD_ERR since
	 * getting NACK's is normal if Linux is probing the bus
	 */
	if ((status & I2C_STAT_ANY_ERR) != I2C_STAT_NACK_RCVD_ERR)
		prlog(PR_ERR, "Error occured STATUS_REG:0x%016llx, st: 0x%02x\n",
		      status, master->state.req_state);
	/* XXX */
	else
		prlog(PR_ERR, "NAK! (0x%02x)\n", master->state.req_state);

	/* Reset the i2c engine */
	rc = xscom_write(master->chip_id, master->xscom_base +
			 I2C_RESET_I2C_REG, 0);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to reset the i2c engine\n");
		goto exit;
	}

	/* Reprogram the watermark register */
	rc = p8_i2c_prog_watermark(master);
	if (rc)
		goto exit;

	/* Don't bother issuing a STOP command, just get rid of the current
	 * request and start off with the fresh one in the list
	 */
	if (status & (I2C_STAT_LBUS_PARITY_ERR | I2C_STAT_ARBT_LOST_ERR |
		      I2C_STAT_STOP_ERR)) {
		/* Reprogram the mode register */
		rc = p8_i2c_prog_mode(master, true, false);
		if (rc)
			goto exit;

		p8_i2c_complete_request(master, OPAL_HARDWARE);

	/*
	 * Reset the bus by issuing a STOP command to slave.
	 * TODO Should we give couple retries to the current request in
	 * case of NACK received error before eventually doing a STOP
	 * reset to the bus.
	 */
	} else {
		/* Reprogram the mode register with 'enhanced bit' set */
		rc = p8_i2c_prog_mode(master, true, true);
		if (rc)
			goto exit;

		/* Enable the interrupt */
		p8_i2c_enable_irqs(master);

		master->state.req_state = STATE_ERROR;
		rc = xscom_write(master->chip_id, master->xscom_base +
				 I2C_CMD_REG, I2C_CMD_WITH_STOP);
		if (rc) {
			prlog(PR_ERR, "I2C:Failed to issue the STOP\n");
			goto exit;
		}
	}

	/* TODO Fix it, the code run in paralled to OS and may lead lateny and
	 * stall to the OS
	 */ 
	time_wait_ms(I2C_RESET_DELAY_MS);

	return;

exit:
	p8_i2c_complete_request(master, rc);
}

static void p8_i2c_status_data_request(struct p8_i2c_master *master,
				       uint64_t status)
{
	struct i2c_request *req = list_top(&master->req_list,
					   struct i2c_request, link);
	uint32_t fifo_count, fifo_left;
	int rc;

	fifo_count = GETFIELD(I2C_STAT_FIFO_ENTRY_COUNT, status);

	switch (req->op) {
	case I2C_READ:
		rc = p8_i2c_fifo_to_buf(master, req, fifo_count);
		break;
	case SMBUS_READ:
		if (master->state.req_state & STATE_OFFSET) {
			rc = p8_i2c_get_fifo_left(master, fifo_count,
						  &fifo_left);
			if (rc)
				break;
			rc = p8_i2c_buf_to_fifo(master, req, fifo_left);
		} else {
			rc = p8_i2c_fifo_to_buf(master, req, fifo_count);
		}
		break;
	case I2C_WRITE:
	case SMBUS_WRITE:
		rc = p8_i2c_get_fifo_left(master, fifo_count, &fifo_left);
		if (rc)
			break;

		rc = p8_i2c_buf_to_fifo(master, req, fifo_left);
		break;
	default:
		rc = -1;
		break;
	}

	if (rc)
		prlog(PR_INFO, "I2C: i2c operation '%d' failed\n", req->op);

	p8_i2c_enable_irqs(master);
}

static void p8_i2c_status_cmd_completion(struct p8_i2c_master *master)
{
	struct p8_i2cm_state *state = &master->state;
	int rc;

	/* Continue with the same request in the list */
	if (state->req_state & STATE_OFFSET ||
	    state->req_state & STATE_DATA_CONT) {
		rc = p8_i2c_start_request(master);
		if (rc)
			p8_i2c_complete_request(master, rc);

	/* Completed the current request, remove it from the list and start
	 * off with the the fresh one
	 */
	} else {
		state->bytes_sent = 0;
		rc = (state->req_state & STATE_ERROR) ? OPAL_HARDWARE :
							OPAL_SUCCESS;
		if (rc)
			prlog(PR_ERR, "Completion with err %d\n", rc);

		p8_i2c_complete_request(master, rc);
	}
	/* Don't require to explicitly enable the interrupts as call to
	 * p8_i2c_start_request() will do
	 */
}

static void  __p8_i2c_check_status(struct p8_i2c_master *master)
{
	uint64_t status;
	int rc;

	rc = xscom_read(master->chip_id, master->xscom_base + I2C_STAT_REG,
			&status);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to read the STAT_REG\n");
		return;
	}

	if (!(status & (I2C_STAT_ANY_ERR | I2C_STAT_DATA_REQ |
			I2C_STAT_CMD_COMP)))
		return;

	/* Mask the interrupts for this engine */
	rc = xscom_write(master->chip_id, master->xscom_base + I2C_INTR_REG,
			 ~I2C_INTR_ALL_MASK);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to disable the interrupts\n");
		return;
	}

	if (status & I2C_STAT_ANY_ERR)
		p8_i2c_status_error(master, status);
	else if (status & I2C_STAT_DATA_REQ)
		p8_i2c_status_data_request(master, status);

	/* Both front end & back end data transfer are complete */
	else if (status & I2C_STAT_CMD_COMP)
		p8_i2c_status_cmd_completion(master);
}

static void p8_i2c_complete_request(struct p8_i2c_master *master, int ret)
{
	struct i2c_request *req;

	/* Delete the top request completed */
	req = list_top(&master->req_list, struct i2c_request, link);
	list_del(&req->link);
	master->state.req_state = STATE_IDLE;
	unlock(&master->lock);
	if (req->completion)
		req->completion(ret, req);

	lock(&master->lock);
}

static int p8_i2c_prog_mode(struct p8_i2c_master *master, bool reset,
			    bool enhanced_mode)
{
	struct i2c_request *req = list_top(&master->req_list,
					   struct i2c_request, link);
	struct p8_i2c_request *request = container_of(req, struct p8_i2c_request,
						      req);
	uint64_t mode;
	int rc;

	rc = xscom_read(master->chip_id, master->xscom_base +
			I2C_MODE_REG, &mode);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to read the MODE_REG\n");
		return OPAL_HARDWARE;
	}

	mode = SETFIELD(I2C_MODE_PORT_NUM, mode, request->port_num);
	if (reset) {
		mode = SETFIELD(I2C_MODE_BIT_RATE_DIV, mode,
				master->bit_rate_div);
		if (enhanced_mode)
			mode |= I2C_MODE_ENHANCED;
	}

	rc = xscom_write(master->chip_id, master->xscom_base + I2C_MODE_REG,
			 mode);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to write the MODE_REG\n");
		return OPAL_HARDWARE;
	}

	return 0;
}

static int p8_i2c_prog_watermark(struct p8_i2c_master *master)
{
	uint64_t watermark;
	int rc;

	rc = xscom_read(master->chip_id, master->xscom_base + I2C_WATERMARK_REG,
			&watermark);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to read the WATERMARK_REG\n");
		return OPAL_HARDWARE;
	}

	/* Set the high/low watermark */
	watermark = SETFIELD(I2C_WATERMARK_HIGH, watermark, I2C_FIFO_HI_LVL);
	watermark = SETFIELD(I2C_WATERMARK_LOW, watermark, I2C_FIFO_LO_LVL);
	rc = xscom_write(master->chip_id, master->xscom_base +
			 I2C_WATERMARK_REG, watermark);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to set high/low watermark level\n");
		return OPAL_HARDWARE;
	}

	return 0;
}

/*
 * START + (dev_addr + READ) + STOP
 * Need to do multiple START if data requested > I2C_MAX_TFR_LEN, with
 * 'Read continue' set and STOP condition only for the last one
 */
static void p8_i2c_read_cmd(struct p8_i2c_master *master,
			    struct i2c_request *req, uint64_t *cmd)
{
	struct p8_i2cm_state *state = &master->state;
	uint32_t data_bytes_left;

	*cmd |= I2C_CMD_READ_NOT_WRITE;
	data_bytes_left = req->rw_len - state->bytes_sent;
	if (data_bytes_left & ~I2C_MAX_TFR_LEN) {
		*cmd |= I2C_CMD_READ_CONT;
		*cmd = SETFIELD(I2C_CMD_LEN_BYTES, *cmd, I2C_MAX_TFR_LEN);
		state->req_state = STATE_DATA_CONT;
	} else {
		*cmd |= I2C_CMD_WITH_STOP;
		*cmd = SETFIELD(I2C_CMD_LEN_BYTES, *cmd, data_bytes_left);
		state->req_state = STATE_DATA;
	}
}

/* START + (dev_addr + WRITE) + STOP */
static void p8_i2c_write_cmd(struct p8_i2c_master *master,
			     struct i2c_request *req, uint64_t *cmd)
{
	*cmd |= I2C_CMD_WITH_STOP;
	*cmd = SETFIELD(I2C_CMD_LEN_BYTES, *cmd,
		        req->rw_len & I2C_MAX_TFR_LEN);
	master->state.req_state = STATE_DATA;
}

/*
 * Repeat START/address phase with no STOP in between
 * START + (dev_addr + WRITE) + offset +
 * START + (dev_addr + READ) + data(n) + STOP
 */
static void p8_smbus_read_cmd(struct p8_i2c_master *master,
			      struct i2c_request *req, uint64_t *cmd)
{
	struct p8_i2cm_state *state = &master->state;
	uint32_t data_bytes_left;

	if (state->req_state & STATE_IDLE) {
		*cmd = SETFIELD(I2C_CMD_LEN_BYTES, *cmd,
			       req->offset_bytes);
		state->req_state = STATE_OFFSET;
	} else {
		*cmd |= I2C_CMD_READ_NOT_WRITE;
		data_bytes_left = req->rw_len - state->bytes_sent;
		if (data_bytes_left & ~I2C_MAX_TFR_LEN) {
			*cmd |= I2C_CMD_READ_CONT;
			*cmd = SETFIELD(I2C_CMD_LEN_BYTES, *cmd,
					I2C_MAX_TFR_LEN);
			state->req_state = STATE_DATA_CONT;
		} else {
			*cmd |= I2C_CMD_WITH_STOP;
			*cmd = SETFIELD(I2C_CMD_LEN_BYTES, *cmd,
					data_bytes_left);
			state->req_state = STATE_DATA;
		}
	}

}

/*
 * Single START/addr/STOP phase for both the offset and data
 * START + (dev_addr + WRITE) + offset + data(n) + STOP
 */
static void p8_smbus_write_cmd(struct p8_i2c_master *master,
			       struct i2c_request *req, uint64_t *cmd)
{
	struct p8_i2cm_state *state = &master->state;
	uint32_t data_bytes_left, page_bytes_left;

	*cmd |= I2C_CMD_WITH_STOP;
	/*
	 * Slave devices where the internal device offset could be more
	 * than 1 byte, only the lower address byte gets incremented
	 * and not the higher address byte during data writes, when the
	 * internal address reaches the page boundary (256 bytes), the
	 * following byte is placed at the beginning of the same page.
	 *	So, a write request of the manner of touching multiple
	 * pages is sliced into multiple requests, each sending maximum
	 * of 1 page data to the device using repeated START-STOP.
	 */
	page_bytes_left = I2C_PAGE_WRITE_SIZE -
			  ((req->offset + state->bytes_sent) &
			   I2C_PAGE_WRITE_MASK);
	data_bytes_left = req->rw_len - state->bytes_sent;
	if (page_bytes_left < data_bytes_left) {
		*cmd = SETFIELD(I2C_CMD_LEN_BYTES, *cmd,
				page_bytes_left + req->offset_bytes);
		state->req_state = STATE_OFFSET | STATE_DATA_CONT;
	} else {
		*cmd = SETFIELD(I2C_CMD_LEN_BYTES, *cmd,
				data_bytes_left + req->offset_bytes);
		state->req_state = STATE_OFFSET | STATE_DATA;
	}
}

static int p8_i2c_start_request(struct p8_i2c_master *master)
{
	struct i2c_request *req = list_top(&master->req_list,
					   struct i2c_request, link);
	uint64_t cmd;
	int rc;

	master->poll_timer = 0;
	master->poll_count = MAX_POLL_COUNT(master->poll_interval);
	/*
	 * Setting the port-id in mode register is required only if the request
	 * is being pushed on the bus first time and *not* if it's repeated
	 * START condition
	 */
	if (master->state.req_state & STATE_IDLE) {
		rc = p8_i2c_prog_mode(master, false, false);
		if (rc)
			return rc;
	}

	/* Enable the interrupts */
	rc = p8_i2c_enable_irqs(master);
	if (rc)
		return OPAL_HARDWARE;

	/* Set up the command register */
	cmd = 0x0ull;
	cmd |= (I2C_CMD_WITH_START | I2C_CMD_WITH_ADDR);
	cmd = SETFIELD(I2C_CMD_DEV_ADDR, cmd, req->dev_addr);

	switch (req->op) {
	case I2C_READ:
		p8_i2c_read_cmd(master, req, &cmd);
		break;
	case I2C_WRITE:
		p8_i2c_write_cmd(master, req, &cmd);
		break;
	case SMBUS_READ:
		p8_smbus_read_cmd(master, req, &cmd);
		break;
	case SMBUS_WRITE:
		p8_smbus_write_cmd(master, req, &cmd);
		break;
	default:
		return OPAL_PARAMETER;
	}

	rc = xscom_write(master->chip_id, master->xscom_base + I2C_CMD_REG,
			 cmd);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to write the CMD_REG\n");
		return OPAL_HARDWARE;
	}

	return OPAL_SUCCESS;
}

static void p8_i2c_check_work(struct p8_i2c_master *master)
{
	int rc;

	if (master->state.req_state == STATE_IDLE &&
	    !list_empty(&master->req_list)) {
		rc = p8_i2c_start_request(master);
		if (rc)
			p8_i2c_complete_request(master, rc);
	}
}

static int p8_i2c_queue_request(struct i2c_bus *bus, struct i2c_request *req)
{
	struct p8_i2c_master_port *port = container_of(bus, struct p8_i2c_master_port,
						       bus);
	struct p8_i2c_master *master = port->common;
	int rc = 0;

	/* Parameter check */
	if (req->offset_bytes > sizeof(req->offset)) {
		prlog(PR_ERR, "I2C: Invalid parameters passed\n");
		return OPAL_PARAMETER;
	}

	lock(&master->lock);
	list_add_tail(&master->req_list, &req->link);
	p8_i2c_check_work(master);
	unlock(&master->lock);

	return rc;
}

static struct i2c_request *p8_i2c_alloc_request(struct i2c_bus *bus)
{
	struct p8_i2c_master_port *port = container_of(bus, struct p8_i2c_master_port,
						       bus);
	struct p8_i2c_request *request;

	request = zalloc(sizeof(*request));
	if (!request) {
		prlog(PR_ERR, "I2C: Failed to allocate i2c request\n");
		return NULL;
	}

	request->port_num = port->port_num;

	return &request->req;
}

static void p8_i2c_dealloc_request(struct i2c_request *req)
{
	struct p8_i2c_request *request = container_of(req, struct p8_i2c_request,
						      req);
	free(request);
}

static inline uint32_t p8_i2c_get_bit_rate_divisor(uint32_t lb_freq_mhz,
						   uint32_t bus_speed)
{
	uint64_t lb_freq = lb_freq_mhz * 1000;

	return (((lb_freq / bus_speed) - 1) / 4);
}

static inline uint64_t p8_i2c_get_poll_interval(uint32_t bus_speed)
{
	/* Polling Interval = 8 * (1/bus_speed) * (1/10) -> convert to uSec */
	return ((8 * USEC_PER_SEC) / (10 * bus_speed * 1000));
}

static void p8_i2c_compare_poll_timer(struct p8_i2c_master *master)
{
	uint64_t now = mftb();

	if (master->poll_timer == 0 ||
	    tb_compare(now, master->poll_timer) == TB_AAFTERB ||
	    tb_compare(now, master->poll_timer) == TB_AEQUALB) {
		if (0 == master->poll_count--) {
			prlog(PR_WARNING, "I2C: Operation timed out\n");
			p8_i2c_complete_request(master, OPAL_HARDWARE);

			return;
		}

		master->poll_timer = now + usecs_to_tb(master->poll_interval);
		p8_i2c_check_work(master);
		__p8_i2c_check_status(master);
	}
}

static void p8_i2c_poll_each_master(bool interrupt)
{
	struct p8_i2c_master *master = NULL;
	struct p8_i2c_master_port *port;
	struct i2c_bus *bus;

	list_for_each(&i2c_bus_list, bus, link) {
		port = container_of(bus, struct p8_i2c_master_port, bus);

		/* Each master serves 1 or more ports, check for the first
		 * one found..
		 */
		if (!master || master != port->common)
			master = port->common;
		else
			continue;

		lock(&master->lock);
		if (list_empty(&master->req_list)) {
			unlock(&master->lock);
			continue;
		}

		if (!interrupt)
			p8_i2c_compare_poll_timer(master);
		else
			__p8_i2c_check_status(master);

		unlock(&master->lock);
	}
}

static void p8_i2c_opal_poll(void *data __unused)
{
	p8_i2c_poll_each_master(false);
}

void p8_i2c_interrupt(void)
{
	p8_i2c_poll_each_master(true);
}

static void opal_p8_i2c_request_complete(int rc, struct i2c_request *req)
{
	struct opal_p8_i2c_data *opal_data = req->user_data;

	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL, opal_data->token, rc);
	opal_data->bus->dealloc_req(req);
	free(opal_data);
}

static int opal_p8_i2c_request(uint64_t async_token, uint32_t bus_id,
			       uint32_t dev_addr, uint64_t buffer,
			       uint32_t len, uint8_t subaddr)
{
	struct opal_p8_i2c_data *opal_data;
	struct p8_i2c_master_port *port;
	struct i2c_bus *bus = NULL;
	struct i2c_request *req;
	int rc;

	list_for_each(&i2c_bus_list, bus, link) {
		port = container_of(bus, struct p8_i2c_master_port, bus);
		if (port->bus_id == bus_id)
			break;
	}

	if (!bus) {
		prlog(PR_ERR, "I2C: Invalid 'bus_id' passed to the OPAL\n");
		return OPAL_PARAMETER;
	}

	req = bus->alloc_req(bus);
	if (!req) {
		prlog(PR_ERR, "I2C: Failed to allocate 'i2c_request'\n");
		return OPAL_NO_MEM;
	}

	opal_data = zalloc(sizeof(*opal_data));
	if (!opal_data) {
		prlog(PR_ERR, "I2C: Failed to allocate opal data\n");
		bus->dealloc_req(req);
		return OPAL_NO_MEM;
	}

	opal_data->bus = bus;
	opal_data->token = async_token;

	if (subaddr) {
		if (dev_addr & 0x1)
			req->op = SMBUS_READ;
		else
			req->op = SMBUS_WRITE;

		req->offset_bytes = 1;
		req->offset = subaddr;
	} else {
		if (dev_addr & 0x1)
			req->op = I2C_READ;
		else
			req->op = I2C_WRITE;
	}

	req->dev_addr = (dev_addr >> 1) & 0x7f;
	req->rw_len = len;
	req->rw_buf = (void *)buffer;
	req->completion = opal_p8_i2c_request_complete;
	req->user_data = opal_data;

	/* Finally, queue the OPAL i2c request and return */
	rc = bus->queue_req(bus, req);
	if (rc)
		return rc;

	return OPAL_ASYNC_COMPLETION;
}

void p8_i2c_init(void)
{
	struct p8_i2c_master_port *port, *prev_port;
	uint32_t bus_speed, lb_freq, count;
	struct dt_node *i2cm, *i2cm_port;
	struct i2c_bus *bus, *next_bus;
	struct p8_i2c_master *master;
	uint64_t mode, ex_stat;
	int rc;

	dt_for_each_compatible(dt_root, i2cm, "ibm,power8-i2cm") {
		master = zalloc(sizeof(*master));
		if (!master) {
			prlog(PR_ERR, "I2C: Failed to allocate p8_i2c_master\n");
			goto exit_free_list;
		}

		/* Bus speed in KHz */
		bus_speed = dt_prop_get_u32(i2cm, "bus-speed-khz");
		lb_freq = dt_prop_get_u32(i2cm, "local-bus-freq-mhz");

		/* Initialise the i2c master structure */
		master->state.req_state = STATE_IDLE;
		master->chip_id = dt_get_chip_id(i2cm);
		master->xscom_base = dt_get_address(i2cm, 0, NULL);

		rc = xscom_read(master->chip_id, master->xscom_base +
				I2C_EXTD_STAT_REG, &ex_stat);
		if (rc) {
			prlog(PR_ERR, "I2C: Failed to read EXTD_STAT_REG\n");
			goto exit_free_master;
		}

		master->fifo_size = GETFIELD(I2C_EXTD_STAT_FIFO_SIZE, ex_stat);
		list_head_init(&master->req_list);
		master->poll_interval = p8_i2c_get_poll_interval(bus_speed);

		/* Reset the i2c engine */
		rc = xscom_write(master->chip_id, master->xscom_base +
				 I2C_RESET_I2C_REG, 0);
		if (rc) {
			prlog(PR_ERR, "I2C: Failed to reset the i2c engine\n");
			goto exit_free_master;
		}

		/* Set the bit rate divisor value for the base bus speed
		 * this engine operates
		 */
		rc = xscom_read(master->chip_id, master->xscom_base +
				I2C_MODE_REG, &mode);
		if (rc) {
			prlog(PR_ERR, "I2C: Failed to read MODE_REG\n");
			goto exit_free_master;
		}

		master->bit_rate_div = p8_i2c_get_bit_rate_divisor(lb_freq,
								   bus_speed);
		mode = SETFIELD(I2C_MODE_BIT_RATE_DIV, mode,
				master->bit_rate_div);
		rc = xscom_write(master->chip_id, master->xscom_base +
				 I2C_MODE_REG, mode);
		if (rc) {
			prlog(PR_ERR, "I2C: Failed to set bit_rate_div in MODE_REG\n");
			goto exit_free_master;
		}

		rc = p8_i2c_prog_watermark(master);
		if (rc)
			goto exit_free_master;

		/* Allocate ports driven by this master */
		count = 0;
		dt_for_each_child(i2cm, i2cm_port)
			count++;

		port = zalloc(sizeof(*port) * count);
		if (!port) {
			prlog(PR_ERR, "I2C: Insufficient memory\n");
			goto exit_free_master;
		}

		dt_for_each_child(i2cm, i2cm_port) {
			port->bus_id = dt_prop_get_u32(i2cm_port, "ibm,opal-id");
			port->port_num = dt_prop_get_u32(i2cm_port, "reg");
			port->common = master;
			port->bus.i2c_port = i2cm_port;
			port->bus.queue_req = p8_i2c_queue_request;
			port->bus.alloc_req = p8_i2c_alloc_request;
			port->bus.dealloc_req = p8_i2c_dealloc_request;
			list_add_tail(&i2c_bus_list, &port->bus.link);
			port++;
		}
	}

	/* Register the poller, one poller will cater all the masters */
	opal_add_poller(p8_i2c_opal_poll, NULL);

	/* Register the OPAL interface */
	opal_register(OPAL_I2C_REQUEST, opal_p8_i2c_request, 6);

	return;

exit_free_master:
	free(master);
exit_free_list:
	prev_port = NULL;
	list_for_each_safe(&i2c_bus_list, bus, next_bus, link) {
		port = container_of(bus, struct p8_i2c_master_port, bus);
		if (!prev_port) {
			prev_port = port;
			continue;
		} else if (prev_port->common == port->common) {
			continue;
		} else {
			free(prev_port->common);
			free(prev_port);
			prev_port = NULL;
		}
	}

	if (prev_port) { /* Last node left */
		free(prev_port->common);
		free(prev_port);
	}
}
