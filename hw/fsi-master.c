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
#include <xscom.h>
#include <lock.h>
#include <timebase.h>
#include <chip.h>
#include <fsi-master.h>

/*
 * FSI Masters sit on OPB busses behind PIB2OPB bridges
 *
 * There are two cMFSI behind two different bridges at
 * different XSCOM addresses. For now we don't have them in
 * the device-tree so we hard code the address
 */
#define PIB2OPB_MFSI0_ADDR	0x20000
#define PIB2OPB_MFSI1_ADDR	0x30000

/*
 * Bridge registers on XSCOM that allow generatoin
 * of OPB cycles
 */
#define PIB2OPB_REG_CMD		0x0
#define   OPB_CMD_WRITE		0x80000000
#define   OPB_CMD_READ		0x00000000
#define   OPB_CMD_8BIT		0x00000000
#define   OPB_CMD_16BIT		0x20000000
#define   OPB_CMD_32BIT		0x60000000
#define PIB2OPB_REG_STAT	0x1
#define   OPB_STAT_BUSY		0x00010000
#define   OPB_STAT_READ_VALID   0x00020000
#define   OPB_STAT_ERR_OPB      0x09F00000
#define   OPB_STAT_ERR_CMFSI    0x0000FC00
#define   OPB_STAT_ERR_MFSI     0x000000FC
#define   OPB_STAT_ERR_ANY      (OPB_STAT_ERR_OPB | \
				 OPB_STAT_ERR_CMFSI | \
				 OPB_STAT_ERR_MFSI)
#define PIB2OPB_REG_LSTAT	0x2

/*
 * PIB2OPB 0 has 2 MFSIs, cMFSI and hMFSI, PIB2OPB 1 only
 * has cMFSI
 */
#define cMFSI_OPB_PORT_BASE	0x40000
#define cMFSI_OPB_REG_BASE	0x03000
#define hMFSI_OPB_PORT_BASE	0x80000
#define hMFSI_OPB_REG_BASE	0x03400
#define MFSI_OPB_PORT_STRIDE	0x08000


/*
 * Use a global FSI lock for now. Beware of re-entrancy
 * if we ever add support for normal chip XSCOM via FSI, in
 * which case we'll probably have to consider either per chip
 * lock (which can have AB->BA deadlock issues) or a re-entrant
 * global lock
 */
static struct lock fsi_lock = LOCK_UNLOCKED;
static uint32_t mfsi_valid_err = OPB_STAT_ERR_ANY;

/*
 * OPB accessors
 */

#define MFSI_OPB_MAX_TRIES	120

static int64_t mfsi_handle_opb_error(uint32_t chip, uint32_t xscom_base,
				     uint32_t stat)
{
	int64_t rc;

	prerror("MFSI: Error status=0x%08x !\n", stat);

	/* XXX Dump a bunch of data, create an error log ... */

	/* Clean error */
	rc = xscom_write(chip, xscom_base + PIB2OPB_REG_STAT, 0);
	if (rc)
		prerror("MFSI: XSCOM error %lld clearing status\n", rc);

	/*
	 * XXX HB resets the ports here, but that's broken as it will
	 * re-enter the opb accessors ... the HW is a mess here, it mixes
	 * the OPB stuff with the FSI stuff in horrible ways.
	 * If we want to reset the port and generally handle FSI specific
	 * errors we should do that at the upper level and leave only the
	 * OPB error handling here.
	 *
	 * We probably need to return "stat" to the callers too for that
	 * to work
	 */
	
	return OPAL_HARDWARE;
}

static int64_t mfsi_opb_poll(uint32_t chip, uint32_t xscom_base,
			     uint32_t *read_data)
{
	unsigned long retries = MFSI_OPB_MAX_TRIES;
	uint64_t sval;
	uint32_t stat;
	int64_t rc;

	/* We try again every 10us for a bit more than 1ms */
	for (;;) {
		/* Read OPB status register */
		rc = xscom_read(chip, xscom_base + PIB2OPB_REG_STAT, &sval);
		if (rc) {
			/* Do something here ? */
			prerror("MFSI: XSCOM error %lld read OPB STAT\n", rc);
			return rc;
		}
		prlog(PR_INSANE, "  STAT=0x%16llx...\n", sval);

		stat = sval >> 32;

		/* Complete */
		if (!(stat & OPB_STAT_BUSY))
			break;
		/* Error */
		if (stat & mfsi_valid_err)
			break;
		if (retries-- == 0) {
			/* XXX What should we do here ? reset it ? */
			prerror("MFSI: OPB POLL timeout !\n");
			return OPAL_HARDWARE;
		}
		time_wait_us(10);
	}

	/* Did we have an error ? */
	if (stat & mfsi_valid_err)
		return mfsi_handle_opb_error(chip, xscom_base, stat);

	if (read_data) {
		if (!(stat & OPB_STAT_READ_VALID)) {
			prerror("MFSI: Read successful but no data !\n");
			/* What do do here ? can it actually happen ? */
			sval |= 0xffffffff;
		}
		*read_data = sval & 0xffffffff;
	}

	return OPAL_SUCCESS;
}

static int64_t mfsi_opb_read(uint32_t chip, uint32_t xscom_base,
			     uint32_t addr, uint32_t *data)
{
	uint64_t opb_cmd = OPB_CMD_READ | OPB_CMD_32BIT;
	int64_t rc;

	if (addr > 0x00ffffff)
		return OPAL_PARAMETER;

	opb_cmd |= addr;
	opb_cmd <<= 32;

	prlog(PR_INSANE, "MFSI_OPB_READ: Writing 0x%16llx to XSCOM %x\n",
	      opb_cmd, xscom_base);

	rc = xscom_write(chip, xscom_base + PIB2OPB_REG_CMD, opb_cmd);
	if (rc) {
		prerror("MFSI: XSCOM error %lld writing OPB CMD\n", rc);
		return rc;
	}
	return mfsi_opb_poll(chip, xscom_base, data);
}

static int64_t mfsi_opb_write(uint32_t chip, uint32_t xscom_base,
			      uint32_t addr, uint32_t data)
{
	uint64_t opb_cmd = OPB_CMD_WRITE | OPB_CMD_32BIT;
	int64_t rc;

	if (addr > 0x00ffffff)
		return OPAL_PARAMETER;

	opb_cmd |= addr;
	opb_cmd <<= 32;
	opb_cmd |= data;

	prlog(PR_INSANE, "MFSI_OPB_WRITE: Writing 0x%16llx to XSCOM %x\n",
	    opb_cmd, xscom_base);

	rc = xscom_write(chip, xscom_base + PIB2OPB_REG_CMD, opb_cmd);
	if (rc) {
		prerror("MFSI: XSCOM error %lld writing OPB CMD\n", rc);
		return rc;
	}
	return mfsi_opb_poll(chip, xscom_base, NULL);
}

static int64_t mfsi_get_addrs(uint32_t mfsi, uint32_t port,
			      uint32_t *xscom_base, uint32_t *port_base,
			      uint32_t *reg_base)
{
	if (port > 7)
		return OPAL_PARAMETER;

	/* We hard code everything for now */
	switch(mfsi) {
	case MFSI_cMFSI0:
		*xscom_base = PIB2OPB_MFSI0_ADDR;
		*port_base = cMFSI_OPB_PORT_BASE + port * MFSI_OPB_PORT_STRIDE;
		*reg_base = cMFSI_OPB_REG_BASE;
		break;
	case MFSI_cMFSI1:
		*xscom_base = PIB2OPB_MFSI1_ADDR;
		*port_base = cMFSI_OPB_PORT_BASE + port * MFSI_OPB_PORT_STRIDE;
		*reg_base = cMFSI_OPB_REG_BASE;
		break;
	case MFSI_hMFSI0:
		*xscom_base = PIB2OPB_MFSI0_ADDR;
		*port_base = hMFSI_OPB_PORT_BASE + port * MFSI_OPB_PORT_STRIDE;
		*reg_base = hMFSI_OPB_REG_BASE;
		break;
	default:
		return OPAL_PARAMETER;
	}
	return OPAL_SUCCESS;
}

int64_t mfsi_read(uint32_t chip, uint32_t mfsi, uint32_t port,
		  uint32_t fsi_addr, uint32_t *data)
{
	int64_t rc;
	uint32_t xscom, port_addr, reg;

	rc = mfsi_get_addrs(mfsi, port, &xscom, &port_addr, &reg);
	if (rc)
		return rc;
	lock(&fsi_lock);
	rc = mfsi_opb_read(chip, xscom, port_addr + fsi_addr, data);
	/* XXX Handle FSI level errors here, maybe reset port */
	unlock(&fsi_lock);

	return rc;
}

int64_t mfsi_write(uint32_t chip, uint32_t mfsi, uint32_t port,
		   uint32_t fsi_addr, uint32_t data)
{
	int64_t rc;
	uint32_t xscom, port_addr, reg;

	rc = mfsi_get_addrs(mfsi, port, &xscom, &port_addr, &reg);
	if (rc)
		return rc;
	lock(&fsi_lock);
	rc = mfsi_opb_write(chip, xscom, port_addr + fsi_addr, data);
	/* XXX Handle FSI level errors here, maybe reset port */
	unlock(&fsi_lock);

	return rc;
}

void mfsi_init(void)
{
	struct proc_chip *chip;

	/* For now assume all chips are the same DD... might need
	 * fixing.
	 */
	chip = next_chip(NULL);
	assert(chip);
	if (chip->type == PROC_CHIP_P8_MURANO) {
		/* Hardware Bug HW222712 on Murano DD1.0 causes the
		 * any_error bit to be un-clearable so we just
		 * have to ignore it
 		 */
		if (chip->ec_level < 0x20) {
			/* 16: cMFSI any-master-error */
			/* 24: hMFSI any-master-error */
			mfsi_valid_err &= 0xFFFF7F7F;
 		}
	}
}

