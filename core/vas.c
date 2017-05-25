/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <skiboot.h>
#include <chip.h>
#include <phys-map.h>
#include <xscom.h>
#include <io.h>
#include <vas.h>

#define vas_err(__fmt,...)	prlog(PR_ERR,"VAS: " __fmt, ##__VA_ARGS__)

#ifdef VAS_VERBOSE_DEBUG
#define vas_vdbg(__x,__fmt,...)	prlog(PR_DEBUG,"VAS: " __fmt, ##__VA_ARGS__)
#else
#define vas_vdbg(__x,__fmt,...)	do { } while (0)
#endif

static int vas_initialized;

struct vas {
	uint32_t	chip_id;
	uint32_t	vas_id;
	uint64_t	xscom_base;
	uint64_t	wcbs;
	uint32_t	vas_irq;
};

static inline void get_hvwc_mmio_bar(int chipid, uint64_t *start, uint64_t *len)
{
	phys_map_get(chipid, VAS_HYP_WIN, 0, start, len);
}

static inline void get_uwc_mmio_bar(int chipid, uint64_t *start, uint64_t *len)
{
	phys_map_get(chipid, VAS_USER_WIN, 0, start, len);
}

static inline uint64_t compute_vas_scom_addr(struct vas *vas, uint64_t reg)
{
	return vas->xscom_base + reg;
}

static int vas_scom_write(struct proc_chip *chip, uint64_t reg, uint64_t val)
{
	int rc;
	uint64_t addr;

	addr = compute_vas_scom_addr(chip->vas, reg);

	rc = xscom_write(chip->id, addr, val);
	if (rc != OPAL_SUCCESS) {
		vas_err("Error writing 0x%llx to 0x%llx, rc %d\n", val, addr,
				rc);
	}

	return rc;
}

static int init_north_ctl(struct proc_chip *chip)
{
	uint64_t val = 0ULL;

	val = SETFIELD(VAS_64K_MODE_MASK, val, true);
	val = SETFIELD(VAS_ACCEPT_PASTE_MASK, val, true);

	return vas_scom_write(chip, VAS_MISC_N_CTL, val);
}

static inline int reset_north_ctl(struct proc_chip *chip)
{
	return vas_scom_write(chip, VAS_MISC_N_CTL, 0ULL);
}

static void reset_fir(struct proc_chip *chip)
{
	uint64_t val;

	val = 0x0ULL;
	vas_scom_write(chip, VAS_FIR0, val);
	vas_scom_write(chip, VAS_FIR1, val);
	vas_scom_write(chip, VAS_FIR2, val);
	vas_scom_write(chip, VAS_FIR3, val);
	vas_scom_write(chip, VAS_FIR4, val);
	vas_scom_write(chip, VAS_FIR5, val);
	vas_scom_write(chip, VAS_FIR6, val);
	vas_scom_write(chip, VAS_FIR7, val);
}

#define	RMA_LSMP_64K_SYS_ID		PPC_BITMASK(8, 12)
#define	RMA_LSMP_64K_NODE_ID		PPC_BITMASK(15, 18)
#define	RMA_LSMP_64K_CHIP_ID		PPC_BITMASK(19, 21)

/*
 * Initialize RMA BAR on this chip to correspond to its node/chip id.
 * This will cause VAS to accept paste commands to targeted for this chip.
 * Initialize RMA Base Address Mask Register (BAMR) to its default value.
 */
static int init_rma(struct proc_chip *chip)
{
	int rc;
	uint64_t val;

	val = 0ULL;
	val = SETFIELD(RMA_LSMP_64K_SYS_ID, val, 1);
	val = SETFIELD(RMA_LSMP_64K_NODE_ID, val, P9_GCID2NODEID(chip->id));
	val = SETFIELD(RMA_LSMP_64K_CHIP_ID, val, P9_GCID2CHIPID(chip->id));

	rc = vas_scom_write(chip, VAS_RMA_BAR, val);
	if (rc)
		return rc;

	val = SETFIELD(VAS_RMA_BAMR_ADDR_MASK, 0ULL, 0xFFFC0000000ULL);

	return vas_scom_write(chip, VAS_RMA_BAMR, val);
}

/*
 * Window Context MMIO (WCM) Region for each chip is assigned in the P9
 * MMIO MAP spreadsheet. Write this value to the SCOM address associated
 * with WCM_BAR.
 */
static int init_wcm(struct proc_chip *chip)
{
	uint64_t wcmbar;

	get_hvwc_mmio_bar(chip->id, &wcmbar, NULL);

	/*
	 * Write the entire WCMBAR address to the SCOM address. VAS will
	 * extract bits that it thinks are relevant i.e bits 8..38
	 */
	return vas_scom_write(chip, VAS_WCM_BAR, wcmbar);
}

/*
 * OS/User Window Context MMIO (UWCM) Region for each is assigned in the
 * P9 MMIO MAP spreadsheet. Write this value to the SCOM address associated
 * with UWCM_BAR.
 */
static int init_uwcm(struct proc_chip *chip)
{
	uint64_t uwcmbar;

	get_uwc_mmio_bar(chip->id, &uwcmbar, NULL);

	/*
	 * Write the entire UWCMBAR address to the SCOM address. VAS will
	 * extract bits that it thinks are relevant i.e bits 8..35.
	 */
	return vas_scom_write(chip, VAS_UWCM_BAR, uwcmbar);
}

static inline void free_wcbs(struct proc_chip *chip)
{
	if (chip->vas->wcbs) {
		free((void *)chip->vas->wcbs);
		chip->vas->wcbs = 0ULL;
	}
}

/*
 * VAS needs a backing store for the 64K window contexts on a chip.
 * (64K times 512 = 8MB). This region needs to be contiguous, so
 * allocate during early boot. Then write the allocated address to
 * the SCOM address for the Backing store BAR.
 */
static int alloc_init_wcbs(struct proc_chip *chip)
{
	int rc;
	uint64_t wcbs;
	size_t size;

	/* align to the backing store size */
	size = (size_t)VAS_WCBS_SIZE;
	wcbs = (uint64_t)local_alloc(chip->id, size, size);
	if (!wcbs) {
		vas_err("Unable to allocate memory for backing store\n");
		return -ENOMEM;
	}
	memset((void *)wcbs, 0ULL, size);

	/*
	 * Write entire WCBS_BAR address to the SCOM address. VAS will extract
	 * relevant bits.
	 */
	rc = vas_scom_write(chip, VAS_WCBS_BAR, wcbs);
	if (rc != OPAL_SUCCESS)
		goto out;

	chip->vas->wcbs = wcbs;
	return OPAL_SUCCESS;

out:
	free((void *)wcbs);
	return rc;
}

static struct vas *alloc_vas(uint32_t chip_id, uint32_t vas_id, uint64_t base)
{
	struct vas *vas;

	vas = zalloc(sizeof(struct vas));
	assert(vas);

	vas->chip_id = chip_id;
	vas->vas_id = vas_id;
	vas->xscom_base = base;

	return vas;
}

/*
 * Disable one VAS instance.
 *
 * Free memory and ensure chip does not accept paste instructions.
 */
static void disable_vas_inst(struct dt_node *np)
{
	struct proc_chip *chip;

	chip = get_chip(dt_get_chip_id(np));

	if (!chip->vas)
		return;

	free_wcbs(chip);

	reset_north_ctl(chip);
}

/*
 * Initialize one VAS instance
 */
static int init_vas_inst(struct dt_node *np)
{
	uint32_t vas_id;
	uint64_t xscom_base;
	struct proc_chip *chip;

	chip = get_chip(dt_get_chip_id(np));
	vas_id = dt_prop_get_u32(np, "ibm,vas-id");
	xscom_base = dt_get_address(np, 0, NULL);

	chip->vas = alloc_vas(chip->id, vas_id, xscom_base);

	if (alloc_init_wcbs(chip))
		return -1;

	reset_fir(chip);

	if (init_wcm(chip) || init_uwcm(chip) || init_north_ctl(chip) ||
	    			init_rma(chip))
		return -1;

	prlog(PR_INFO, "VAS: Initialized chip %d\n", chip->id);
	return 0;

}

void vas_init()
{
	struct dt_node *np;

	if (proc_gen != proc_gen_p9)
		return;

	dt_for_each_compatible(dt_root, np, "ibm,power9-vas-x") {
		if (init_vas_inst(np))
			goto out;
	}

	vas_initialized = 1;
	prlog(PR_NOTICE, "VAS: Initialized\n");
	return;

out:
	dt_for_each_compatible(dt_root, np, "ibm,power9-vas-x")
		disable_vas_inst(np);

	vas_err("Disabled (failed initialization)\n");
	return;
}
