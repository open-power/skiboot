/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <skiboot.h>
#include <timebase.h>
#include <opal-api.h>
#include <i2c.h>

#include "tpm_i2c_interface.h"
#include "../status_codes.h"

//#define DBG(fmt, ...) prlog(PR_DEBUG, fmt, ##__VA_ARGS__)
#define DBG(fmt, ...)

#define I2C_BYTE_TIMEOUT_MS		30  /* 30ms/byte timeout */
#define TPM_MAX_NACK_RETRIES		 2
#define REQ_COMPLETE_POLLING		 5  /* Check if req is complete
					       in 5ms interval */

struct tpm_i2c_userdata {
	int rc;
	bool done;
};

void tpm_i2c_request_complete(int rc, struct i2c_request *req)
{
	struct tpm_i2c_userdata *ud = req->user_data;
	ud->rc = rc;
	ud->done = true;
}

/**
 * tpm_i2c_request_send - send request to i2c bus
 * @tpm_bus_id: i2c bus id
 * @tpm_dev_addr: address of the tpm device
 * @read_write: SMBUS_READ or SMBUS_WRITE
 * @offset: any of the I2C interface offset defined
 * @offset_bytes: offset size in bytes
 * @buf: data to be read or written
 * @buflen: buf length
 *
 * This interacts with skiboot i2c API to send an I2C request to the tpm
 * device
 *
 * Returns: Zero on success otherwise a negative error code
 */
int tpm_i2c_request_send(int tpm_bus_id, int tpm_dev_addr, int read_write,
			 uint32_t offset, uint32_t offset_bytes, void* buf,
			 size_t buflen)
{
	int rc, waited, retries, timeout;
	struct i2c_request *req;
	struct i2c_bus *bus;
	uint64_t time_to_wait = 0;
	struct tpm_i2c_userdata ud;

	bus = i2c_find_bus_by_id(tpm_bus_id);
	if (!bus) {
		/**
		 * @fwts-label TPMI2CInvalidBusID
		 * @fwts-advice tpm_i2c_request_send was passed an invalid bus
		 * ID. This indicates a tb_init() bug.
		 */
		prlog(PR_ERR, "TPM: Invalid bus_id=%x\n", tpm_bus_id);
		rc = STB_ARG_ERROR;
		goto out;
	}

	req = i2c_alloc_req(bus);
	if (!req) {
		/**
		 * @fwts-label TPMI2CAllocationFailed
		 * @fwts-advice OPAL failed to allocate memory for an
		 * i2c_request. This points to an OPAL bug as OPAL run out of
		 * memory and this should never happen.
		 */
		prlog(PR_ERR, "TPM: i2c_alloc_req failed\n");
		rc = STB_DRIVER_ERROR;
		goto out;
	}

	req->dev_addr   = tpm_dev_addr;
	req->op         = read_write;
	req->offset     = offset;
	req->offset_bytes = offset_bytes;
	req->rw_buf     = (void*) buf;
	req->rw_len     = buflen;
	req->completion = tpm_i2c_request_complete;
	ud.done = false;
	req->user_data = &ud;

	/*
	 * Set the request timeout to 10ms per byte. Otherwise, we get
	 * an I2C master timeout for all requests sent to the TPM device
	 * since the I2C master's timeout is too short (1ms per byte).
	 */
	timeout = (buflen + offset_bytes + 2) * I2C_BYTE_TIMEOUT_MS;

	for (retries = 0; retries <= TPM_MAX_NACK_RETRIES; retries++) {
		waited = 0;
		i2c_set_req_timeout(req, timeout);
		i2c_queue_req(req);

		do {
			time_to_wait = i2c_run_req(req);
			if (!time_to_wait)
				time_to_wait = REQ_COMPLETE_POLLING;
			time_wait(time_to_wait);
			waited += time_to_wait;
		} while (!ud.done);

		rc = ud.rc;

		if (rc == OPAL_I2C_NACK_RCVD)
			continue;
		else
			/* error or success */
			break;
	}

	DBG("%s tpm req op=%x offset=%x buf=%016llx buflen=%d delay=%lu/%d,"
	    "rc=%d\n",
	    (rc) ? "!!!!" : "----", req->op, req->offset,
	    *(uint64_t*) buf, req->rw_len, tb_to_msecs(waited), timeout, rc);

	i2c_free_req(req);
	if (rc)
		rc = STB_DRIVER_ERROR;
out:
	return rc;
}
