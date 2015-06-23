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
#define   OPB_STAT_ANY_ERR	0x80000000
#define   OPB_STAT_ERR_OPB      0x7FEC0000
#define   OPB_STAT_ERRACK       0x00100000
#define   OPB_STAT_BUSY		0x00010000
#define   OPB_STAT_READ_VALID   0x00020000
#define   OPB_STAT_ERR_CMFSI    0x0000FC00
#define   OPB_STAT_ERR_HMFSI    0x000000FC
#define   OPB_STAT_ERR_BASE	(OPB_STAT_ANY_ERR | \
				 OPB_STAT_ERR_OPB | \
				 OPB_STAT_ERRACK)
#define PIB2OPB_REG_LSTAT	0x2
#define PIB2OPB_REG_RESET	0x4

/*
 * PIB2OPB 0 has 2 MFSIs, cMFSI and hMFSI, PIB2OPB 1 only
 * has cMFSI
 */
#define cMFSI_OPB_PORT_BASE	0x40000
#define cMFSI_OPB_REG_BASE	0x03000
#define hMFSI_OPB_PORT_BASE	0x80000
#define hMFSI_OPB_REG_BASE	0x03400
#define MFSI_OPB_PORT_STRIDE	0x08000

struct mfsi {
	uint32_t chip_id;
	uint32_t unit;
	uint32_t xscom_base;
	uint32_t port_base;
	uint32_t reg_base;
	uint32_t err_bits;
};

#define mfsi_log(__lev, __m, __fmt, ...) \
	prlog(__lev, "MFSI %x:%x: " __fmt, __m->chip_id, __m->unit, ##__VA_ARGS__)
/*
 * Use a global FSI lock for now. Beware of re-entrancy
 * if we ever add support for normal chip XSCOM via FSI, in
 * which case we'll probably have to consider either per chip
 * lock (which can have AB->BA deadlock issues) or a re-entrant
 * global lock or something else. ...
 */
static struct lock fsi_lock = LOCK_UNLOCKED;

/*
 * OPB accessors
 */

/* We try up to 1.2ms for an OPB access */
#define MFSI_OPB_MAX_TRIES	1200

static int64_t mfsi_pib2opb_reset(struct mfsi *mfsi)
{
	uint64_t stat;
	int64_t rc;

	rc = xscom_write(mfsi->chip_id,
			 mfsi->xscom_base + PIB2OPB_REG_RESET, (1ul << 63));
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld resetting PIB2OPB\n", rc);
		return rc;
	}
	rc = xscom_write(mfsi->chip_id,
			 mfsi->xscom_base + PIB2OPB_REG_STAT, (1ul << 63));
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld resetting status\n", rc);
		return rc;
	}
	rc = xscom_read(mfsi->chip_id,
			mfsi->xscom_base + PIB2OPB_REG_STAT, &stat);
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld reading status\n", rc);
		return rc;
	}
	return 0;
}


static int64_t mfsi_handle_opb_error(struct mfsi *mfsi, uint32_t stat)
{
	mfsi_log(PR_ERR, mfsi, "MFSI: Error status=0x%08x (raw=0x%08x)\n",
		 stat & mfsi->err_bits, stat);

	/* For now, just reset the PIB2OPB on error. We should collect more
	 * info and look at the remote errors in the target as well but that
	 * will be for another day.
	 */
	mfsi_pib2opb_reset(mfsi);
	
	return OPAL_HARDWARE;
}

static int64_t mfsi_opb_poll(struct mfsi *mfsi, uint32_t *read_data)
{
	unsigned long retries = MFSI_OPB_MAX_TRIES;
	uint64_t sval;
	uint32_t stat;
	int64_t rc;

	/* We try again every 10us for a bit more than 1ms */
	for (;;) {
		/* Read OPB status register */
		rc = xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_STAT, &sval);
		if (rc) {
			/* Do something here ? */
			mfsi_log(PR_ERR, mfsi, "XSCOM error %lld read OPB STAT\n", rc);
			return rc;
		}
		mfsi_log(PR_INSANE, mfsi, "  STAT=0x%16llx...\n", sval);

		stat = sval >> 32;

		/* Complete */
		if (!(stat & OPB_STAT_BUSY))
			break;
		if (retries-- == 0) {
			/* XXX What should we do here ? reset it ? */
			mfsi_log(PR_ERR, mfsi, "OPB POLL timeout !\n");
			return OPAL_HARDWARE;
		}
		time_wait_us(1);
	}

	/* Did we have an error ? */
	if (stat & mfsi->err_bits)
		return mfsi_handle_opb_error(mfsi, stat);

	if (read_data) {
		if (!(stat & OPB_STAT_READ_VALID)) {
			mfsi_log(PR_ERR, mfsi, "Read successful but no data !\n");

			/* What do do here ? can it actually happen ? */
			sval = 0xffffffff;
		}
		*read_data = sval & 0xffffffff;
	}

	return OPAL_SUCCESS;
}

static int64_t mfsi_opb_read(struct mfsi *mfsi, uint32_t opb_addr, uint32_t *data)
{
	uint64_t opb_cmd = OPB_CMD_READ | OPB_CMD_32BIT;
	int64_t rc;

	if (opb_addr > 0x00ffffff)
		return OPAL_PARAMETER;

	opb_cmd |= opb_addr;
	opb_cmd <<= 32;

	mfsi_log(PR_INSANE, mfsi, "MFSI_OPB_READ: Writing 0x%16llx to XSCOM %x\n",
		 opb_cmd, mfsi->xscom_base);

	rc = xscom_write(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_CMD, opb_cmd);
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld writing OPB CMD\n", rc);
		return rc;
	}
	return mfsi_opb_poll(mfsi, data);
}

static int64_t mfsi_opb_write(struct mfsi *mfsi, uint32_t opb_addr, uint32_t data)
{
	uint64_t opb_cmd = OPB_CMD_WRITE | OPB_CMD_32BIT;
	int64_t rc;

	if (opb_addr > 0x00ffffff)
		return OPAL_PARAMETER;

	opb_cmd |= opb_addr;
	opb_cmd <<= 32;
	opb_cmd |= data;

	mfsi_log(PR_INSANE, mfsi, "MFSI_OPB_WRITE: Writing 0x%16llx to XSCOM %x\n",
		 opb_cmd, mfsi->xscom_base);

	rc = xscom_write(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_CMD, opb_cmd);
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld writing OPB CMD\n", rc);
		return rc;
	}
	return mfsi_opb_poll(mfsi, NULL);
}

static struct mfsi *mfsi_get(uint32_t chip_id, uint32_t unit)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct mfsi *mfsi;

	if (!chip || unit > MFSI_hMFSI0)
		return NULL;
	mfsi = &chip->fsi_masters[unit];
	if (mfsi->xscom_base == 0)
		return NULL;
	return mfsi;
}

int64_t mfsi_read(uint32_t chip, uint32_t unit, uint32_t port,
		  uint32_t fsi_addr, uint32_t *data)
{
	struct mfsi *mfsi = mfsi_get(chip, unit);
	uint32_t port_addr;
	int64_t rc;

	if (!mfsi)
		return OPAL_PARAMETER;

	lock(&fsi_lock);

	/* Calculate port address */
	port_addr = mfsi->port_base + port * MFSI_OPB_PORT_STRIDE;
	port_addr += fsi_addr;

	/* Perform OPB access */
	rc = mfsi_opb_read(mfsi, port_addr, data);

	/* XXX Handle FSI level errors here */

	unlock(&fsi_lock);

	return rc;
}

int64_t mfsi_write(uint32_t chip, uint32_t unit, uint32_t port,
		   uint32_t fsi_addr, uint32_t data)
{
	struct mfsi *mfsi = mfsi_get(chip, unit);
	uint32_t port_addr;
	int64_t rc;

	lock(&fsi_lock);

	/* Calculate port address */
	port_addr = mfsi->port_base + port * MFSI_OPB_PORT_STRIDE;
	port_addr += fsi_addr;

	/* Perform OPB access */
	rc = mfsi_opb_write(mfsi, port_addr, data);

	/* XXX Handle FSI level errors here */

	unlock(&fsi_lock);

	return rc;
}

static void mfsi_add(struct proc_chip *chip, struct mfsi *mfsi, uint32_t unit)
{
	mfsi->chip_id = chip->id;
	mfsi->unit = unit;

	/* We hard code everything for now */
	switch(unit) {
	case MFSI_cMFSI0:
		mfsi->xscom_base = PIB2OPB_MFSI0_ADDR;
		mfsi->port_base = cMFSI_OPB_PORT_BASE;
		mfsi->reg_base = cMFSI_OPB_REG_BASE;
		mfsi->err_bits = OPB_STAT_ERR_BASE | OPB_STAT_ERR_CMFSI;
		break;
	case MFSI_cMFSI1:
		mfsi->xscom_base = PIB2OPB_MFSI1_ADDR;
		mfsi->port_base = cMFSI_OPB_PORT_BASE;
		mfsi->reg_base = cMFSI_OPB_REG_BASE;
		mfsi->err_bits = OPB_STAT_ERR_BASE | OPB_STAT_ERR_CMFSI;
		break;
	case MFSI_hMFSI0:
		mfsi->xscom_base = PIB2OPB_MFSI0_ADDR;
		mfsi->port_base = hMFSI_OPB_PORT_BASE;
		mfsi->reg_base = hMFSI_OPB_REG_BASE;
		mfsi->err_bits = OPB_STAT_ERR_BASE | OPB_STAT_ERR_HMFSI;
		break;
	default:
		/* ??? */
		return;
	}

	/* Hardware Bug HW222712 on Murano DD1.0 causes the
	 * any_error bit to be un-clearable so we just
	 * have to ignore it. Additionally, HostBoot applies
	 * this to Venice too, though the comment there claims
	 * this is a Simics workaround.
	 *
	 * The doc says that bit can be safely ignored, so let's
	 * just not bother and always take it out.
	 */

	/* 16: cMFSI any-master-error */
	/* 24: hMFSI any-master-error */
	mfsi->err_bits &= 0xFFFF7F7F;

	mfsi_log(PR_INFO, mfsi, "Initialized\n");
}

void mfsi_init(void)
{
	struct proc_chip *chip;

	for_each_chip(chip) {
		chip->fsi_masters = zalloc(sizeof(struct mfsi) * 3);
		mfsi_add(chip, &chip->fsi_masters[MFSI_cMFSI0], MFSI_cMFSI0);
		mfsi_add(chip, &chip->fsi_masters[MFSI_hMFSI0], MFSI_hMFSI0);
		mfsi_add(chip, &chip->fsi_masters[MFSI_cMFSI1], MFSI_cMFSI1);

	}
}

