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

#include <timebase.h>
#include <skiboot.h>
#include <device.h>
#include <i2c.h>
#include "../status_codes.h"
#include "../tpm_chip.h"
#include "tpm_i2c_interface.h"
#include "tpm_i2c_nuvoton.h"

//#define DBG(fmt, ...) prlog(PR_DEBUG, fmt, ##__VA_ARGS__)
#define DBG(fmt, ...)

#define DRIVER_NAME "i2c_tpm_nuvoton"

/*
 * Timings between various states or transitions within the interface protocol
 * as defined in the TCG PC Client Platform TPM Profile specification, Revision
 * 00.43.
 */
#define TPM_TIMEOUT_A	750
#define TPM_TIMEOUT_B	2000
#define TPM_TIMEOUT_D	30

/* I2C interface offsets */
#define TPM_STS			0x00
#define TPM_BURST_COUNT		0x01
#define TPM_DATA_FIFO_W		0x20
#define TPM_DATA_FIFO_R		0x40

/* Bit masks for the TPM STATUS register */
#define TPM_STS_VALID		0x80
#define TPM_STS_COMMAND_READY	0x40
#define TPM_STS_GO		0x20
#define TPM_STS_DATA_AVAIL	0x10
#define TPM_STS_EXPECT		0x08


/* TPM Driver values */
#define MAX_STSVALID_POLLS 	5
#define TPM_TIMEOUT_INTERVAL	10

static struct tpm_dev *tpm_device = NULL;

static int tpm_status_write_byte(uint8_t byte)
{
	uint8_t value = byte;
	return tpm_i2c_request_send(tpm_device->bus_id, tpm_device->xscom_base,
				    SMBUS_WRITE, TPM_STS, 1, &value,
				    sizeof(value));
}

static int tpm_status_read_byte(uint8_t offset, uint8_t *byte)
{
	return tpm_i2c_request_send(tpm_device->bus_id, tpm_device->xscom_base,
				    SMBUS_READ, offset, 1, byte,
				    sizeof(uint8_t));
}

static bool tpm_check_status(uint8_t status, uint8_t mask, uint8_t expected)
{
	return ((status & mask) == expected);
}

static int tpm_wait_for_command_ready(void)
{
	int rc, delay;
	uint8_t status;

	for (delay = 0; delay < TPM_TIMEOUT_B;
	     delay += TPM_TIMEOUT_INTERVAL) {
		rc = tpm_status_read_byte(TPM_STS, &status);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadCmdReady
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to read sts.commandReady, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		if (tpm_check_status(status,
				     TPM_STS_COMMAND_READY,
				     TPM_STS_COMMAND_READY)) {
			DBG("--- Command ready, delay=%d/%d\n",
			    delay, TPM_TIMEOUT_B);
			return 0;
		}
		time_wait_ms(TPM_TIMEOUT_INTERVAL);
	}
	return STB_TPM_TIMEOUT;
}

static int tpm_set_command_ready(void)
{
	int rc, retries;
	/*
	 * The first write to command ready may just abort an
	 * outstanding command, so we poll twice
	 */
	for (retries = 0; retries < 2; retries++) {
		rc = tpm_status_write_byte(TPM_STS_COMMAND_READY);
		if (rc < 0) {
			/**
			 * @fwts-label TPMWriteCmdReady
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to write sts.commandReady, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		rc = tpm_wait_for_command_ready();
		if (rc == STB_TPM_TIMEOUT)
			continue;
		return rc;
	}
	/**
	 * @fwts-label TPMCmdReadyTimeout
	 * @fwts-advice The command ready bit of the tpm status register is
	 * taking longer to be settled. Either the wait time need to be
	 * increased or the TPM device is not functional.
	 */
	prlog(PR_ERR, "NUVOTON: timeout on sts.commandReady, delay > %d\n",
	      2*TPM_TIMEOUT_B);
	return STB_TPM_TIMEOUT;
}

static int tpm_wait_for_fifo_status(uint8_t mask, uint8_t expected)
{
	int retries, rc;
	uint8_t status;

	for(retries = 0; retries <= MAX_STSVALID_POLLS; retries++) {
		rc = tpm_status_read_byte(TPM_STS, &status);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadFifoStatus
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to read fifo status: "
			      "mask %x, expected %x, rc=%d\n", mask, expected,
			      rc);
			return STB_DRIVER_ERROR;
		}
		if (tpm_check_status(status, mask, expected))
			return 0;
		/* Wait TPM STS register be settled */
		time_wait_ms(5);
	}
	return STB_TPM_TIMEOUT;
}

static int tpm_wait_for_data_avail(void)
{
	int delay, rc;
	uint8_t status;

	for (delay = 0; delay < TPM_TIMEOUT_A;
	     delay += TPM_TIMEOUT_INTERVAL) {

		rc = tpm_status_read_byte(TPM_STS, &status);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadDataAvail
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to read sts.dataAvail, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		if (tpm_check_status(status,
				     TPM_STS_VALID | TPM_STS_DATA_AVAIL,
				     TPM_STS_VALID | TPM_STS_DATA_AVAIL)) {
			DBG("---- read FIFO. Data available. delay=%d/%d\n",
			    delay, TPM_TIMEOUT_A);
			return 0;
		}
		time_wait_ms(TPM_TIMEOUT_INTERVAL);
	}
	/**
	 * @fwts-label TPMDataAvailBitTimeout
	 * @fwts-advice The data avail bit of the tpm status register is taking
	 * longer to be settled. Either the wait time need to be increased or
	 * the TPM device is not functional.
	 */
	prlog(PR_ERR, "NUVOTON: timeout on sts.dataAvail, delay=%d/%d\n",
	      delay, TPM_TIMEOUT_A);
	return STB_TPM_TIMEOUT;
}

static int tpm_read_burst_count(void)
{
	int rc, delay;
	uint8_t burst_count;

	burst_count = 0;
	delay = 0;
	do {
		/* In i2C, burstCount is 1 byte */
		rc = tpm_status_read_byte(TPM_BURST_COUNT, &burst_count);
		if (rc == 0 && burst_count > 0) {
			DBG("---- burst_count=%d, delay=%d/%d\n", burst_count,
			    delay, TPM_TIMEOUT_D);
			return (int) burst_count;
		}
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadBurstCount
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to read sts.burstCount, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		time_wait_ms(TPM_TIMEOUT_INTERVAL);
		delay += TPM_TIMEOUT_INTERVAL;

	} while (delay < TPM_TIMEOUT_D);

	/**
	 * @fwts-label TPMBurstCountTimeout
	 * @fwts-advice The burstcount bit of the tpm status register is
	 * taking longer to be settled. Either the wait time need to be
	 * increased or the TPM device is not functional.
	 */
	prlog(PR_ERR, "NUVOTON: timeout on sts.burstCount, delay=%d/%d\n",
	      delay, TPM_TIMEOUT_D);
	return STB_TPM_TIMEOUT;
}

static int tpm_write_fifo(uint8_t* buf, size_t buflen)
{
	int rc, burst_count;
	size_t curByte = 0;
	uint8_t* bytePtr = buf;
	uint8_t* curBytePtr = NULL;
	/*
	 * We will transfer the command except for the last byte
	 * that will be transfered separately to allow for
	 * overflow checking
	 */
	size_t length = buflen - 1;
	size_t tx_len = 0;

	do {
		burst_count = tpm_read_burst_count();
		if (burst_count < 0)
			return burst_count;
		/*
		 * Send in some data
		 */
		curBytePtr = &(bytePtr[curByte]);
		tx_len = (curByte + burst_count > length ?
			  (length - curByte) : burst_count);
		rc = tpm_i2c_request_send(tpm_device->bus_id,
					  tpm_device->xscom_base,
					  SMBUS_WRITE, TPM_DATA_FIFO_W,
					  1, curBytePtr, tx_len);
		curByte += tx_len;
		DBG("%s write FIFO sent %zd bytes, rc=%d\n",
		    (rc) ? "!!!!" : "----", curByte, TPM_TIMEOUT_D, rc);
		if (rc < 0)
			return rc;

		rc = tpm_wait_for_fifo_status(TPM_STS_VALID | TPM_STS_EXPECT,
					      TPM_STS_VALID | TPM_STS_EXPECT);
		if (rc == STB_DRIVER_ERROR)
			return rc;
		if (rc == STB_TPM_TIMEOUT) {
			/**
			 * @fwts-label TPMWriteFifoNotExpecting
			 * @fwts-advice The write to the TPM FIFO overflowed,
			 * the TPM is not expecting more data. This indicates a
			 * bug in the TPM device driver.
			 */
			prlog(PR_ERR, "NUVOTON: write FIFO overflow, not expecting "
			      "more data\n");
			return STB_TPM_OVERFLOW;
		}
	} while (curByte < length);

	/*
	 *  Send the final byte
	 */
	burst_count = tpm_read_burst_count();
	if (burst_count < 0)
		return burst_count;
	curBytePtr = &(bytePtr[curByte]);
	rc = tpm_i2c_request_send(tpm_device->bus_id,
				  tpm_device->xscom_base,
				  SMBUS_WRITE,
				  TPM_DATA_FIFO_W, 1,
				  curBytePtr, 1);
	DBG("%s write FIFO sent last byte, rc=%d\n",
	    (rc) ? "!!!!" : "----", TPM_TIMEOUT_D, rc);

	if (rc < 0) {
		/**
		 * @fwts-label TPMWriteFifo
		 * @fwts-advice The tpm-i2c interface doesn't seem to be
		 * working properly. Check the return code (rc) for
		 * further details.
		 */
		prlog(PR_ERR, "NUVOTON: fail to write fifo (last byte), "
		      "curByte=%zd, rc=%d\n", curByte, rc);
		return STB_DRIVER_ERROR;
	}
	rc = tpm_wait_for_fifo_status(TPM_STS_VALID | TPM_STS_EXPECT,
				      TPM_STS_VALID | TPM_STS_EXPECT);
	if (rc == STB_DRIVER_ERROR)
		return rc;
	if (rc == 0) {
		 /**
		 * @fwts-label TPMWriteFifoExpecting
		 * @fwts-advice The write to the TPM FIFO overflowed.
		 * It is expecting more data even though we think we
		 * are done. This indicates a bug in the TPM device
		 * driver.
		 */
		prlog(PR_ERR, "TPM: write FIFO overflow, expecting "
		      "more data\n");
		return STB_TPM_OVERFLOW;
	}
	return 0;
}

static int tpm_read_fifo(uint8_t* buf, size_t* buflen)
{
	int rc, burst_count;
	size_t curByte = 0;
	uint8_t* bytePtr = (uint8_t*)buf;
	uint8_t* curBytePtr = NULL;

	rc = tpm_wait_for_data_avail();
	if (rc < 0)
		goto error;

	do {
		burst_count = tpm_read_burst_count();
		if (burst_count < 0) {
			rc = burst_count;
			goto error;
		}
		/* Buffer overflow check */
		if (curByte + burst_count > *buflen)
		{
			 /**
			 * @fwts-label TPMReadFifoOverflow1
			 * @fwts-advice The read from TPM FIFO overflowed. It is
			 * expecting more data even though we think we are done.
			 * This indicates a bug in the TPM device driver.
			 */
			prlog(PR_ERR, "TPM: read FIFO overflow1\n");
			rc = STB_TPM_OVERFLOW;
		}
		/*
		 *  Read some data
		 */
		curBytePtr = &(bytePtr[curByte]);
		rc = tpm_i2c_request_send(tpm_device->bus_id,
					  tpm_device->xscom_base,
					  SMBUS_READ,
					  TPM_DATA_FIFO_R, 1,
					  curBytePtr, burst_count);
		curByte += burst_count;
		DBG("%s read FIFO. received %zd bytes, rc=%d\n",
		    (rc) ? "!!!!" : "----", curByte, rc);
		if (rc < 0)
			goto error;
		rc = tpm_wait_for_fifo_status(
					  TPM_STS_VALID | TPM_STS_DATA_AVAIL,
					  TPM_STS_VALID | TPM_STS_DATA_AVAIL);
		if (rc == STB_DRIVER_ERROR)
			goto error;
	} while (rc == 0);

	*buflen = curByte;
	return 0;

error:
	*buflen = 0;
	return rc;
}

static int tpm_transmit(struct tpm_dev *dev, uint8_t* buf, size_t cmdlen,
			size_t* buflen)
{
	int rc = 0;
	if (!dev) {
		/**
		 * @fwts-label TPMDeviceNotInitialized
		 * @fwts-advice TPM device is not initialized. This indicates a
		 * bug in the tpm_transmit() caller
		 */
		prlog(PR_ERR, "TPM: tpm device not initialized\n");
		return STB_ARG_ERROR;
	}
	tpm_device = dev;
	DBG("**** %s: dev %#x/%#x buf %016llx cmdlen %zu"
	    " buflen %zu ****\n",
	    __func__, dev->bus_id, dev->xscom_base, *(uint64_t*) buf,
	    cmdlen, *buflen);

	DBG("step 1/5: set command ready\n");
	rc = tpm_set_command_ready();
	if (rc < 0)
		goto out;

	DBG("step 2/5: write FIFO\n");
	rc = tpm_write_fifo(buf, cmdlen);
	if (rc < 0)
		goto out;

	DBG("step 3/5: write sts.go\n");
	rc = tpm_status_write_byte(TPM_STS_GO);
	if (rc < 0) {
		/**
		 * @fwts-label TPMWriteGo
		 * @fwts-advice Either the tpm device or the tpm-i2c interface
		 * doesn't seem to be working properly. Check the return code
		 * (rc) for further details.
		 */
		prlog(PR_ERR, "NUVOTON: fail to write sts.go, rc=%d\n", rc);
		rc = STB_DRIVER_ERROR;
		goto out;
	}

	DBG("step 4/5: read FIFO\n");
	rc = tpm_read_fifo(buf, buflen);
	if (rc < 0)
		goto out;

	DBG("step 5/5: write command ready\n");
	rc = tpm_status_write_byte(TPM_STS_COMMAND_READY);

out:
	DBG("**** tpm_transmit %s, rc=%d ****\n",
	    (rc) ? "ERROR" : "SUCCESS", rc);
	return rc;
}

static struct tpm_driver tpm_i2c_nuvoton_driver = {
	.name     = DRIVER_NAME,
	.transmit = tpm_transmit,
};

void tpm_i2c_nuvoton_probe(void)
{
	struct tpm_dev *tpm_device = NULL;
	struct dt_node *node = NULL;

	dt_for_each_compatible(dt_root, node, "nuvoton,npct650") {
		if (!dt_node_is_enabled(node))
			continue;
		tpm_device = (struct tpm_dev*) malloc(sizeof(struct tpm_dev));
		assert(tpm_device);
		/*
		 * Read TPM device address and bus id. Make sure the properties
		 * really exist if the default value is returned.
		 */
		tpm_device->xscom_base = dt_prop_get_u32_def(node, "reg", 0);
		if (!tpm_device->xscom_base &&
		    !dt_find_property(node, "reg")) {
			/*
			 * @fwts-label NuvotonRegNotFound
			 * @fwts-advice reg property not found. This indicates
			 * a Hostboot bug if the property really doesn't exist
			 * in the tpm node.
			 */
			prlog(PR_ERR, "NUVOTON: reg property not found, "
			      "tpm node %p\n", node);
			goto disable;
		}
		tpm_device->bus_id = dt_prop_get_u32_def(node->parent,
							 "ibm,opal-id", 0);
		if (!tpm_device->bus_id &&
		    !dt_find_property(node->parent, "ibm,opal-id")) {
			/*
			 * @fwts-label NuvotonIbmOpalIdNotFound
			 * @fwts-advice ibm,opal-id property not found. This
			 * indicates a Hostboot bug if the property really
			 * doesn't exist in the tpm node.
			 */
			prlog(PR_ERR, "NUVOTON: ibm,opal-id property not "
			      "found, tpm node parent %p\n", node->parent);
			goto disable;
		}
		if (tpm_register_chip(node, tpm_device,
				      &tpm_i2c_nuvoton_driver))
			free(tpm_device);
	}
	return;
disable:
	dt_add_property_string(node, "status", "disabled");
	prlog(PR_NOTICE, "TPM: tpm node %p disabled\n", node);
	free(tpm_device);
}
