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
#include <processor.h>
#include <device.h>
#include <chip.h>
#include <centaur.h>
#include <lock.h>
#include <fsi-master.h>
#include <timebase.h>

/*
 * Centaur chip IDs are using the XSCOM "partID" encoding
 * described in xscom.h. recap:
 *
 *     0b1000.0000.0000.0000.0000.00NN.NCCC.MMMM
 *     N=Node, C=Chip, M=Memory Channel
 *
 * We currently use FSI exclusively for centaur access. We can
 * start using MMIO on Centaur DD2.x when we have a way to handle
 * machine checks happening inside Sapphire which we don't at the
 * moment.
 */

/* Is that correct ? */
#define MAX_CENTAURS_PER_CHIP	8

/*
 * FSI2PIB register definitions (this could be moved out if we were to
 * support FSI master to other chips.
 */
#define FSI_DATA0_REG		0x1000
#define FSI_DATA1_REG		0x1004
#define FSI_CMD_REG		0x1008
#define   FSI_CMD_WR		0x80000000
#define   FSI_CMD_RD		0x00000000
#define FSI_ENG_RESET_REG	0x1018
#define FSI_STATUS_REG		0x101c
#define   FSI_STATUS_ABORT	0x00100000
#define   FSI_STATUS_ERRORS	0x00007000

/* Some Centaur XSCOMs we care about */
#define SCAC_CONFIG_REG		0x020115ce
#define SCAC_CONFIG_SET		0x020115cf
#define SCAC_CONFIG_CLR		0x020115d0
#define SCAC_ENABLE_MSK		PPC_BIT(0)

static int64_t centaur_fsiscom_complete(struct centaur_chip *centaur)
{
	int64_t rc;
	uint32_t stat;

	rc = mfsi_read(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
		       centaur->fsi_master_port, FSI_STATUS_REG, &stat);
	if (rc) {
		/* XXX Improve logging */
		prerror("CENTAUR: MFSI read error %lld reading STAT\n", rc);
		return rc;
	}
	if ((stat & (FSI_STATUS_ABORT | FSI_STATUS_ERRORS)) == 0)
		return OPAL_SUCCESS;

	prerror("CENTAUR: Remote FSI error, stat=0x%08x\n", stat);

	/* XXX Handle recovery */

	return OPAL_HARDWARE;
}

static int64_t centaur_fsiscom_read(struct centaur_chip *centaur, uint32_t pcb_addr,
				    uint64_t *val)
{
	int64_t rc;
	uint32_t data0, data1;

	rc = mfsi_write(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
			centaur->fsi_master_port, FSI_CMD_REG, pcb_addr | FSI_CMD_RD);
	if (rc) {
		/* XXX Improve logging */
		prerror("CENTAUR: MFSI write error %lld writing CMD\n", rc);
		return rc;
	}

	rc = centaur_fsiscom_complete(centaur);
	if (rc)
		return rc;

	rc = mfsi_read(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
		       centaur->fsi_master_port, FSI_DATA0_REG, &data0);
	if (rc) {
		/* XXX Improve logging */
		prerror("CENTAUR: MFSI read error %lld reading DATA0\n", rc);
		return rc;
	}
	rc = mfsi_read(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
		       centaur->fsi_master_port, FSI_DATA1_REG, &data1);
	if (rc) {
		/* XXX Improve logging */
		prerror("CENTAUR: MFSI read error %lld readking DATA1\n", rc);
		return rc;
	}

	*val = (((uint64_t)data0) << 32) | data1;

	return OPAL_SUCCESS;
}

struct centaur_chip *get_centaur(uint32_t part_id)
{
	uint32_t hchip_id, mchan;
	struct proc_chip *hchip;
	struct centaur_chip *centaur;

	if ((part_id >> 28) != 8) {
		prerror("CENTAUR: Invalid part ID 0x%x\n", part_id);
		return NULL;
	}
	hchip_id = (part_id & 0x0fffffff) >> 4;
	mchan = part_id & 0xf;

	hchip = get_chip(hchip_id);
	if (!hchip) {
		prerror("CENTAUR: Centaur 0x%x not found on non-existing chip 0%x\n",
			part_id, hchip_id);
		return NULL;
	}
	if (mchan >= MAX_CENTAURS_PER_CHIP) {
		prerror("CENTAUR: Centaur 0x%x channel out of bounds !\n", part_id);
		return NULL;
	}
	if (!hchip->centaurs) {
		prerror("CENTAUR: Centaur 0x%x not found on chip 0%x (no centaurs)\n",
			part_id, hchip_id);
		return NULL;
	}
	centaur = &hchip->centaurs[mchan];
	if (!centaur->valid) {
		prerror("CENTAUR: Centaur 0x%x not valid on chip 0%x\n",
			part_id, hchip_id);
		return NULL;
	}
	return centaur;
}

static int64_t centaur_fsiscom_write(struct centaur_chip *centaur, uint32_t pcb_addr,
				     uint64_t val)
{
	int64_t rc;

	rc = mfsi_write(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
			centaur->fsi_master_port, FSI_DATA0_REG, hi32(val));
	if (rc) {
		/* XXX Improve logging */
		prerror("CENTAUR: MFSI write error %lld writing DATA0\n", rc);
		return rc;
	}
	rc = mfsi_write(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
			centaur->fsi_master_port, FSI_DATA1_REG, lo32(val));
	if (rc) {
		/* XXX Improve logging */
		prerror("CENTAUR: MFSI write error %lld writing DATA1\n", rc);
		return rc;
	}
	rc = mfsi_write(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
			centaur->fsi_master_port, FSI_CMD_REG, pcb_addr | FSI_CMD_WR);
	if (rc) {
		/* XXX Improve logging */
		prerror("CENTAUR: MFSI write error %lld writing CMD\n", rc);
		return rc;
	}

	return centaur_fsiscom_complete(centaur);
}

int64_t centaur_xscom_read(uint32_t id, uint64_t pcb_addr, uint64_t *val)
{
	struct centaur_chip *centaur = get_centaur(id);
	int64_t rc;

	if (!centaur)
		return OPAL_PARAMETER;

	lock(&centaur->lock);
	rc = centaur_fsiscom_read(centaur, pcb_addr, val);
	unlock(&centaur->lock);

	return rc;
}

int64_t centaur_xscom_write(uint32_t id, uint64_t pcb_addr, uint64_t val)
{
	struct centaur_chip *centaur = get_centaur(id);
	int64_t rc;

	if (!centaur)
		return OPAL_PARAMETER;

	lock(&centaur->lock);
	rc = centaur_fsiscom_write(centaur, pcb_addr, val);
	unlock(&centaur->lock);

	return rc;
}

static bool centaur_check_id(struct centaur_chip *centaur)
{
	int64_t rc;
	uint64_t val;

	rc = centaur_fsiscom_read(centaur, 0xf000f, &val);
	if (rc) {
		prerror("CENTAUR:   FSISCOM error %lld reading ID register\n",
			rc);
		return false;
	}

	/* Extract CFAM id */
	val >>= 44;

	/* Identify chip */
	if ((val & 0xff) != 0xe9) {
		prerror("CENTAUR:   CFAM ID 0x%02x is not a Centaur !\n",
			(unsigned int)(val & 0xff));
		return false;
	}

	/* Get EC level from CFAM ID */
	centaur->ec_level = ((val >> 16) & 0xf) << 4;
	centaur->ec_level |= (val >> 8) & 0xf;

	return true;
}

static bool centaur_add(uint32_t part_id, uint32_t mchip, uint32_t meng,
			uint32_t mport)
{
	uint32_t hchip_id, mchan;
	struct proc_chip *hchip;
	struct centaur_chip *centaur;

	if ((part_id >> 28) != 8) {
		prerror("CENTAUR: Invalid part ID 0x%x\n", part_id);
		return false;
	}
	hchip_id = (part_id & 0x0fffffff) >> 4;
	mchan = part_id & 0xf;

	printf("CENTAUR: Found centaur for chip 0x%x channel %d\n",
	       hchip_id, mchan);
	printf("CENTAUR:   FSI host: 0x%x cMFSI%d port %d\n",
	       mchip, meng, mport);

	hchip = get_chip(hchip_id);
	if (!hchip) {
		prerror("CENTAUR:   No such chip !!!\n");
		return false;
	}

	if (mchan >= MAX_CENTAURS_PER_CHIP) {
		prerror("CENTAUR:   Channel out of bounds !\n");
		return false;
	}

	if (!hchip->centaurs) {
		hchip->centaurs =
			zalloc(sizeof(struct centaur_chip) *
			       MAX_CENTAURS_PER_CHIP);
		assert(hchip->centaurs);
	}

	centaur = &hchip->centaurs[mchan];
	if (centaur->valid) {
		prerror("CENTAUR:   Duplicate centaur !\n");
		return false;
	}
	centaur->fsi_master_chip_id = mchip;
	centaur->fsi_master_port = mport;
	centaur->fsi_master_engine = meng ? MFSI_cMFSI1 : MFSI_cMFSI0;
	init_lock(&centaur->lock);

	if (!centaur_check_id(centaur))
		return false;

	printf("CENTAUR:   ChipID 0x%x [DD%x.%x]\n", part_id,
		       centaur->ec_level >> 4,
		       centaur->ec_level & 0xf);

	centaur->valid = true;
	return true;
}

/* Returns how long to wait for logic to stop in TB ticks or a negative
 * value on error
 */
int64_t centaur_disable_sensor_cache(uint32_t part_id)
{
	struct centaur_chip *centaur = get_centaur(part_id);
	int64_t rc = 0;
	uint64_t ctrl;

	if (!centaur)
		return false;

	lock(&centaur->lock);
	centaur->scache_disable_count++;
	if (centaur->scache_disable_count == 1) {
		centaur->scache_was_enabled = false;
		rc = centaur_fsiscom_read(centaur, SCAC_CONFIG_REG, &ctrl);
		if (rc)
			goto bail;
		centaur->scache_was_enabled = !!(ctrl & SCAC_ENABLE_MSK);
		rc = centaur_fsiscom_write(centaur, SCAC_CONFIG_CLR, SCAC_ENABLE_MSK);
		if (rc)
			goto bail;
		rc = msecs_to_tb(30);
	}
 bail:
	unlock(&centaur->lock);
	return rc;
}

int64_t centaur_enable_sensor_cache(uint32_t part_id)
{
	struct centaur_chip *centaur = get_centaur(part_id);
	int64_t rc = 0;

	if (!centaur)
		return false;

	lock(&centaur->lock);
	if (centaur->scache_disable_count == 0) {
		prerror("CENTAUR: Cache count going negative !\n");
		backtrace();
		goto bail;
	}
	centaur->scache_disable_count--;
	if (centaur->scache_disable_count == 0 && centaur->scache_was_enabled)
		rc = centaur_fsiscom_write(centaur, SCAC_CONFIG_SET, SCAC_ENABLE_MSK);
 bail:
	unlock(&centaur->lock);
	return rc;
}

void centaur_init(void)
{
	struct dt_node *cn;

	dt_for_each_compatible(dt_root, cn, "ibm,centaur") {
		uint32_t chip_id, mchip, meng, mport;

		chip_id = dt_prop_get_u32(cn, "ibm,chip-id");
		mchip = dt_prop_get_u32(cn, "ibm,fsi-master-chip-id");
		meng = dt_prop_get_cell(cn, "ibm,fsi-master-port", 0);
		mport = dt_prop_get_cell(cn, "ibm,fsi-master-port", 1);

		/*
		 * If adding the centaur succeeds, we expose it to
		 * Linux as a scom-controller
		 */
		if (centaur_add(chip_id, mchip, meng, mport))
			dt_add_property(cn, "scom-controller", NULL, 0);
	}
}
