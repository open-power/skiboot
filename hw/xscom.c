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
#include <io.h>
#include <processor.h>
#include <device.h>
#include <chip.h>
#include <centaur.h>
#include <errorlog.h>
#include <opal-api.h>

/* Mask of bits to clear in HMER before an access */
#define HMER_CLR_MASK	(~(SPR_HMER_XSCOM_FAIL | \
			   SPR_HMER_XSCOM_DONE | \
			   SPR_HMER_XSCOM_STATUS))

#define XSCOM_ADDR_IND_FLAG		PPC_BIT(0)
#define XSCOM_ADDR_IND_ADDR		PPC_BITMASK(12,31)
#define XSCOM_ADDR_IND_DATA		PPC_BITMASK(48,63)

#define XSCOM_DATA_IND_READ		PPC_BIT(0)
#define XSCOM_DATA_IND_COMPLETE		PPC_BIT(32)
#define XSCOM_DATA_IND_ERR		PPC_BITMASK(33,35)
#define XSCOM_DATA_IND_DATA		PPC_BITMASK(48,63)

/* HB folks say: try 10 time for now */
#define XSCOM_IND_MAX_RETRIES		10

DEFINE_LOG_ENTRY(OPAL_RC_XSCOM_RW, OPAL_PLATFORM_ERR_EVT, OPAL_XSCOM,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA, NULL);

DEFINE_LOG_ENTRY(OPAL_RC_XSCOM_INDIRECT_RW, OPAL_PLATFORM_ERR_EVT, OPAL_XSCOM,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA, NULL);

DEFINE_LOG_ENTRY(OPAL_RC_XSCOM_RESET, OPAL_PLATFORM_ERR_EVT, OPAL_XSCOM,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA, NULL);

/*
 * Locking notes:
 *
 * We used to have a per-target lock. However due to errata HW822317
 * we can have issues on the issuer side if multiple threads try to
 * send XSCOMs simultaneously (HMER responses get mixed up), so just
 * use a global lock instead
 */
static struct lock xscom_lock = LOCK_UNLOCKED;

static inline void *xscom_addr(uint32_t gcid, uint32_t pcb_addr)
{
	struct proc_chip *chip = get_chip(gcid);
	uint64_t addr;

	assert(chip);
	addr  = chip->xscom_base;
	addr |= ((uint64_t)pcb_addr << 4) & ~0xfful;
	addr |= (pcb_addr << 3) & 0x78;

	return (void *)addr;
}

static uint64_t xscom_wait_done(void)
{
	uint64_t hmer;

	do
		hmer = mfspr(SPR_HMER);
	while(!(hmer & SPR_HMER_XSCOM_DONE));

	/*
	 * HW822317: We need to read a second time as the actual
	 * status can be delayed by 1 cycle after DONE
	 */
	return mfspr(SPR_HMER);
}

static void xscom_reset(uint32_t gcid)
{
	u64 hmer;

	/* Clear errors in HMER */
	mtspr(SPR_HMER, HMER_CLR_MASK);

	/* First we need to write 0 to a register on our chip */
	out_be64(xscom_addr(this_cpu()->chip_id, 0x202000f), 0);
	hmer = xscom_wait_done();
	if (hmer & SPR_HMER_XSCOM_FAIL)
		goto fail;

	/* Then we need to clear those two other registers on the target */
	out_be64(xscom_addr(gcid, 0x2020007), 0);
	hmer = xscom_wait_done();
	if (hmer & SPR_HMER_XSCOM_FAIL)
		goto fail;
	out_be64(xscom_addr(gcid, 0x2020009), 0);
	hmer = xscom_wait_done();
	if (hmer & SPR_HMER_XSCOM_FAIL)
		goto fail;
	return;
 fail:
	/* Fatal error resetting XSCOM */
	log_simple_error(&e_info(OPAL_RC_XSCOM_RESET),
		"XSCOM: Fatal error resetting engine after failed access !\n");

	/* XXX Generate error log ? attn ? panic ?
	 * If we decide to panic, change the above severity to PANIC
	 */
}

static bool xscom_handle_error(uint64_t hmer, uint32_t gcid, uint32_t pcb_addr,
			       bool is_write)
{
	unsigned int stat = GETFIELD(SPR_HMER_XSCOM_STATUS, hmer);

	/* XXX Figure out error codes from doc and error
	 * recovery procedures
	 */
	switch(stat) {
	/* XSCOM blocked, just retry */
	case 1:
		return true;
	}

	/* XXX: Create error log entry ? */
	log_simple_error(&e_info(OPAL_RC_XSCOM_RW),
		"XSCOM: %s error gcid=0x%x pcb_addr=0x%x stat=0x%x\n",
		is_write ? "write" : "read", gcid, pcb_addr, stat);

	/* We need to reset the XSCOM or we'll hang on the next access */
	xscom_reset(gcid);

	/* Non recovered ... just fail */
	return false;
}

static void xscom_handle_ind_error(uint64_t data, uint32_t gcid,
				   uint64_t pcb_addr, bool is_write)
{
	unsigned int stat = GETFIELD(XSCOM_DATA_IND_ERR, data);
	bool timeout = !(data & XSCOM_DATA_IND_COMPLETE);

	/* XXX: Create error log entry ? */
	if (timeout)
		log_simple_error(&e_info(OPAL_RC_XSCOM_INDIRECT_RW),
			"XSCOM: %s indirect timeout, gcid=0x%x pcb_addr=0x%llx"
			" stat=0x%x\n",
			is_write ? "write" : "read", gcid, pcb_addr, stat);
	else
		log_simple_error(&e_info(OPAL_RC_XSCOM_INDIRECT_RW),
			"XSCOM: %s indirect error, gcid=0x%x pcb_addr=0x%llx"
			" stat=0x%x\n",
			is_write ? "write" : "read", gcid, pcb_addr, stat);
}

static bool xscom_gcid_ok(uint32_t gcid)
{
	return get_chip(gcid) != NULL;
}

/*
 * Low level XSCOM access functions, perform a single direct xscom
 * access via MMIO
 */
static int __xscom_read(uint32_t gcid, uint32_t pcb_addr, uint64_t *val)
{
	uint64_t hmer;

	if (!xscom_gcid_ok(gcid)) {
		prerror("%s: invalid XSCOM gcid 0x%x\n", __func__, gcid);
		return OPAL_PARAMETER;
	}

	for (;;) {
		/* Clear status bits in HMER (HMER is special
		 * writing to it *ands* bits
		 */
		mtspr(SPR_HMER, HMER_CLR_MASK);

		/* Read value from SCOM */
		*val = in_be64(xscom_addr(gcid, pcb_addr));

		/* Wait for done bit */
		hmer = xscom_wait_done();

		/* Check for error */
		if (!(hmer & SPR_HMER_XSCOM_FAIL))
			break;

		/* Handle error and eventually retry */
		if (!xscom_handle_error(hmer, gcid, pcb_addr, false))
			return OPAL_HARDWARE;
	}
	return 0;
}

static int __xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val)
{
	uint64_t hmer;

	if (!xscom_gcid_ok(gcid)) {
		prerror("%s: invalid XSCOM gcid 0x%x\n", __func__, gcid);
		return OPAL_PARAMETER;
	}

	for (;;) {
		/* Clear status bits in HMER (HMER is special
		 * writing to it *ands* bits
		 */
		mtspr(SPR_HMER, HMER_CLR_MASK);

		/* Write value to SCOM */
		out_be64(xscom_addr(gcid, pcb_addr), val);

		/* Wait for done bit */
		hmer = xscom_wait_done();

		/* Check for error */
		if (!(hmer & SPR_HMER_XSCOM_FAIL))
			break;

		/* Handle error and eventually retry */
		if (!xscom_handle_error(hmer, gcid, pcb_addr, true))
			return OPAL_HARDWARE;
	}
	return 0;
}

/*
 * Indirect XSCOM access functions
 */
static int xscom_indirect_read(uint32_t gcid, uint64_t pcb_addr, uint64_t *val)
{
	uint32_t addr;
	uint64_t data;
	int rc, retries;

	if (proc_gen != proc_gen_p8) {
		*val = (uint64_t)-1;
		return OPAL_UNSUPPORTED;
	}

	/* Write indirect address */
	addr = pcb_addr & 0x7fffffff;
	data = XSCOM_DATA_IND_READ |
		(pcb_addr & XSCOM_ADDR_IND_ADDR);
	rc = __xscom_write(gcid, addr, data);
	if (rc)
		goto bail;

	/* Wait for completion */
	for (retries = 0; retries < XSCOM_IND_MAX_RETRIES; retries++) {
		rc = __xscom_read(gcid, addr, &data);
		if (rc)
			goto bail;
		if ((data & XSCOM_DATA_IND_COMPLETE) &&
		    ((data & XSCOM_DATA_IND_ERR) == 0)) {
			*val = data & XSCOM_DATA_IND_DATA;
			break;
		}
		if ((data & XSCOM_DATA_IND_COMPLETE) ||
		    (retries >= XSCOM_IND_MAX_RETRIES)) {
			xscom_handle_ind_error(data, gcid, pcb_addr,
					       false);
			rc = OPAL_HARDWARE;
			goto bail;
		}
	}
 bail:
	if (rc)
		*val = (uint64_t)-1;
	return rc;
}

static int xscom_indirect_write(uint32_t gcid, uint64_t pcb_addr, uint64_t val)
{
	uint32_t addr;
	uint64_t data;
	int rc, retries;

	if (proc_gen != proc_gen_p8)
		return OPAL_UNSUPPORTED;

	/* Write indirect address & data */
	addr = pcb_addr & 0x7fffffff;
	data = pcb_addr & XSCOM_ADDR_IND_ADDR;
	data |= val & XSCOM_ADDR_IND_DATA;

	rc = __xscom_write(gcid, addr, data);
	if (rc)
		goto bail;

	/* Wait for completion */
	for (retries = 0; retries < XSCOM_IND_MAX_RETRIES; retries++) {
		rc = __xscom_read(gcid, addr, &data);
		if (rc)
			goto bail;
		if ((data & XSCOM_DATA_IND_COMPLETE) &&
		    ((data & XSCOM_DATA_IND_ERR) == 0))
			break;
		if ((data & XSCOM_DATA_IND_COMPLETE) ||
		    (retries >= XSCOM_IND_MAX_RETRIES)) {
			xscom_handle_ind_error(data, gcid, pcb_addr,
					       false);
			rc = OPAL_HARDWARE;
			goto bail;
		}
	}
 bail:
	return rc;
}

static uint32_t xscom_decode_chiplet(uint32_t partid, uint64_t *pcb_addr)
{
	uint32_t gcid = (partid & 0x0fffffff) >> 4;
	uint32_t core = partid & 0xf;

	*pcb_addr |= P8_EX_PCB_SLAVE_BASE;
	*pcb_addr |= core << 24;

	return gcid;
}

/*
 * External API
 */
int xscom_read(uint32_t partid, uint64_t pcb_addr, uint64_t *val)
{
	uint32_t gcid;
	int rc;

	/* Handle part ID decoding */
	switch(partid >> 28) {
	case 0: /* Normal processor chip */
		gcid = partid;
		break;
	case 8: /* Centaur */
		return centaur_xscom_read(partid, pcb_addr, val);
	case 4: /* EX chiplet */
		gcid = xscom_decode_chiplet(partid, &pcb_addr);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* HW822317 requires us to do global locking */
	lock(&xscom_lock);

	/* Direct vs indirect access */
	if (pcb_addr & XSCOM_ADDR_IND_FLAG)
		rc = xscom_indirect_read(gcid, pcb_addr, val);
	else
		rc = __xscom_read(gcid, pcb_addr & 0x7fffffff, val);

	/* Unlock it */
	unlock(&xscom_lock);
	return rc;
}

opal_call(OPAL_XSCOM_READ, xscom_read, 3);

int xscom_write(uint32_t partid, uint64_t pcb_addr, uint64_t val)
{
	uint32_t gcid;
	int rc;

	/* Handle part ID decoding */
	switch(partid >> 28) {
	case 0: /* Normal processor chip */
		gcid = partid;
		break;
	case 8: /* Centaur */
		return centaur_xscom_write(partid, pcb_addr, val);
	case 4: /* EX chiplet */
		gcid = xscom_decode_chiplet(partid, &pcb_addr);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* HW822317 requires us to do global locking */
	lock(&xscom_lock);

	/* Direct vs indirect access */
	if (pcb_addr & XSCOM_ADDR_IND_FLAG)
		rc = xscom_indirect_write(gcid, pcb_addr, val);
	else
		rc = __xscom_write(gcid, pcb_addr & 0x7fffffff, val);

	/* Unlock it */
	unlock(&xscom_lock);
	return rc;
}
opal_call(OPAL_XSCOM_WRITE, xscom_write, 3);

int xscom_readme(uint64_t pcb_addr, uint64_t *val)
{
	return xscom_read(this_cpu()->chip_id, pcb_addr, val);
}

int xscom_writeme(uint64_t pcb_addr, uint64_t val)
{
	return xscom_write(this_cpu()->chip_id, pcb_addr, val);
}

int64_t xscom_read_cfam_chipid(uint32_t partid, uint32_t *chip_id)
{
	uint64_t val;
	int64_t rc = OPAL_SUCCESS;

	/* Mambo chip model lacks the f000f register, just make
	 * something up (Murano DD2.1)
	 */
	if (chip_quirk(QUIRK_NO_F000F))
		val = 0x221EF04980000000;
	else
		rc = xscom_read(partid, 0xf000f, &val);

	/* Extract CFAM id */
	*chip_id = (uint32_t)(val >> 44);

	return rc;
}

static void xscom_init_chip_info(struct proc_chip *chip)
{
	uint32_t val;
	int64_t rc;

	rc = xscom_read_cfam_chipid(chip->id, &val);
	if (rc) {
		prerror("XSCOM: Error %lld reading 0xf000f register\n", rc);
		/* We leave chip type to UNKNOWN */
		return;
	}

	/* Identify chip */
	switch(val & 0xff) {
	case 0xf9:
		chip->type = PROC_CHIP_P7;
		assert(proc_gen == proc_gen_p7);
		break;
	case 0xe8:
		chip->type = PROC_CHIP_P7P;
		assert(proc_gen == proc_gen_p7);
		break;
	case 0xef:
		chip->type = PROC_CHIP_P8_MURANO;
		assert(proc_gen == proc_gen_p8);
		break;
	case 0xea:
		chip->type = PROC_CHIP_P8_VENICE;
		assert(proc_gen == proc_gen_p8);
		break;
	case 0xd3:
		chip->type = PROC_CHIP_P8_NAPLES;
		assert(proc_gen == proc_gen_p8);
		break;
	default:
		printf("CHIP: Unknown chip type 0x%02x !!!\n",
		       (unsigned char)(val & 0xff));
	}

	/* Get EC level from CFAM ID */
	chip->ec_level = ((val >> 16) & 0xf) << 4;
	chip->ec_level |= (val >> 8) & 0xf;
}

void xscom_init(void)
{
	struct dt_node *xn;

	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		uint32_t gcid = dt_get_chip_id(xn);
		const struct dt_property *reg;
		struct proc_chip *chip;
		const char *chip_name;
		static const char *chip_names[] = {
			"UNKNOWN", "P7", "P7+", "P8E", "P8", "P8NVL",
		};

		chip = get_chip(gcid);
		assert(chip);

		/* XXX We need a proper address parsing. For now, we just
		 * "know" that we are looking at a u64
		 */
		reg = dt_find_property(xn, "reg");
		assert(reg);

		chip->xscom_base = dt_translate_address(xn, 0, NULL);

		/* Grab processor type and EC level */
		xscom_init_chip_info(chip);

		if (chip->type >= ARRAY_SIZE(chip_names))
			chip_name = "INVALID";
		else
			chip_name = chip_names[chip->type];

		printf("XSCOM: chip 0x%x at 0x%llx [%s DD%x.%x]\n",
		       gcid, chip->xscom_base,
		       chip_name,
		       chip->ec_level >> 4,
		       chip->ec_level & 0xf);
	}
}

void xscom_used_by_console(void)
{
	xscom_lock.in_con_path = true;

	/*
	 * Some other processor might hold it without having
	 * disabled the console locally so let's make sure that
	 * is over by taking/releasing the lock ourselves
	 */
	lock(&xscom_lock);
	unlock(&xscom_lock);
}

bool xscom_ok(void)
{
	return !lock_held_by_me(&xscom_lock);
}
