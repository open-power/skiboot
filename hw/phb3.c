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
/*
 * PHB3 support
 *
 */

/*
 *
 * FIXME:
 *   More stuff for EEH support:
 *      - PBCQ error reporting interrupt
 *	- I2C-based power management (replacing SHPC)
 *	- Directly detect fenced PHB through one dedicated HW reg
 */

#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci.h>
#include <pci-cfg.h>
#include <vpd.h>
#include <interrupts.h>
#include <opal.h>
#include <cpu.h>
#include <device.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <xscom.h>
#include <affinity.h>
#include <phb3.h>
#include <phb3-regs.h>
#include <capp.h>
#include <fsp.h>

/* Enable this to disable error interrupts for debug purposes */
#undef DISABLE_ERR_INTS

static void phb3_init_hw(struct phb3 *p);

#define PHBDBG(p, fmt, a...)	prlog(PR_DEBUG, "PHB%d: " fmt, \
				      (p)->phb.opal_id, ## a)
#define PHBINF(p, fmt, a...)	prlog(PR_INFO, "PHB%d: " fmt, \
				      (p)->phb.opal_id, ## a)
#define PHBERR(p, fmt, a...)	prlog(PR_ERR, "PHB%d: " fmt, \
				      (p)->phb.opal_id, ## a)

/*
 * Lock callbacks. Allows the OPAL API handlers to lock the
 * PHB around calls such as config space, EEH, etc...
 */
static void phb3_lock(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	lock(&p->lock);
}

static  void phb3_unlock(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	unlock(&p->lock);
}

/* Helper to select an IODA table entry */
static inline void phb3_ioda_sel(struct phb3 *p, uint32_t table,
				 uint32_t addr, bool autoinc)
{
	out_be64(p->regs + PHB_IODA_ADDR,
		 (autoinc ? PHB_IODA_AD_AUTOINC : 0)	|
		 SETFIELD(PHB_IODA_AD_TSEL, 0ul, table)	|
		 SETFIELD(PHB_IODA_AD_TADR, 0ul, addr));
}

/* Helper to set the state machine timeout */
static inline uint64_t phb3_set_sm_timeout(struct phb3 *p, uint64_t dur)
{
	uint64_t target, now = mftb();

	target = now + dur;
	if (target == 0)
		target++;
	p->delay_tgt_tb = target;

	return dur;
}

/* Check if AIB is fenced via PBCQ NFIR */
static bool phb3_fenced(struct phb3 *p)
{
	uint64_t nfir;

	/* We still probably has crazy xscom */
	xscom_read(p->chip_id, p->pe_xscom + 0x0, &nfir);
	if (nfir & PPC_BIT(16)) {
		p->flags |= PHB3_AIB_FENCED;
		p->state = PHB3_STATE_FENCED;
		return true;
	}
	return false;
}

/*
 * Configuration space access
 *
 * The PHB lock is assumed to be already held
 */
static int64_t phb3_pcicfg_check(struct phb3 *p, uint32_t bdfn,
				 uint32_t offset, uint32_t size,
				 uint8_t *pe)
{
	uint32_t sm = size - 1;

	if (offset > 0xfff || bdfn > 0xffff)
		return OPAL_PARAMETER;
	if (offset & sm)
		return OPAL_PARAMETER;

	/* The root bus only has a device at 0 and we get into an
	 * error state if we try to probe beyond that, so let's
	 * avoid that and just return an error to Linux
	 */
	if ((bdfn >> 8) == 0 && (bdfn & 0xff))
		return OPAL_HARDWARE;

	/* Check PHB state */
	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* Fetch the PE# from cache */
	*pe = p->rte_cache[bdfn];

	return OPAL_SUCCESS;
}

#define PHB3_PCI_CFG_READ(size, type)	\
static int64_t phb3_pcicfg_read##size(struct phb *phb, uint32_t bdfn,	\
                                      uint32_t offset, type *data)	\
{									\
	struct phb3 *p = phb_to_phb3(phb);				\
	uint64_t addr, val64;						\
	int64_t rc;							\
	uint8_t pe;							\
	bool use_asb = false;						\
									\
	/* Initialize data in case of error */				\
	*data = (type)0xffffffff;					\
									\
	rc = phb3_pcicfg_check(p, bdfn, offset, sizeof(type), &pe);	\
	if (rc)								\
		return rc;						\
									\
	if (p->flags & PHB3_AIB_FENCED) {				\
		if (!(p->flags & PHB3_CFG_USE_ASB))			\
			return OPAL_HARDWARE;				\
		use_asb = true;						\
	} else if ((p->flags & PHB3_CFG_BLOCKED) && bdfn != 0) {	\
		return OPAL_HARDWARE;					\
	}								\
									\
	addr = PHB_CA_ENABLE | ((uint64_t)bdfn << PHB_CA_FUNC_LSH);	\
	addr = SETFIELD(PHB_CA_REG, addr, offset);			\
	addr = SETFIELD(PHB_CA_PE, addr, pe);				\
	if (use_asb) {							\
		phb3_write_reg_asb(p, PHB_CONFIG_ADDRESS, addr);	\
		sync();							\
		val64 = bswap_64(phb3_read_reg_asb(p, PHB_CONFIG_DATA));	\
		*data = (type)(val64 >> (8 * (offset & (4 - sizeof(type)))));	\
	} else {							\
		out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);		\
		*data = in_le##size(p->regs + PHB_CONFIG_DATA +		\
				    (offset & (4 - sizeof(type))));	\
	}								\
									\
	return OPAL_SUCCESS;						\
}

#define PHB3_PCI_CFG_WRITE(size, type)	\
static int64_t phb3_pcicfg_write##size(struct phb *phb, uint32_t bdfn,	\
                                       uint32_t offset, type data)	\
{									\
	struct phb3 *p = phb_to_phb3(phb);				\
	uint64_t addr, val64 = 0;					\
	int64_t rc;							\
	uint8_t pe;							\
	bool use_asb = false;						\
									\
	rc = phb3_pcicfg_check(p, bdfn, offset, sizeof(type), &pe);	\
	if (rc)								\
		return rc;						\
									\
	if (p->flags & PHB3_AIB_FENCED) {				\
		if (!(p->flags & PHB3_CFG_USE_ASB))			\
			return OPAL_HARDWARE;				\
		use_asb = true;						\
	} else if ((p->flags & PHB3_CFG_BLOCKED) && bdfn != 0) {	\
		return OPAL_HARDWARE;					\
	}								\
									\
	addr = PHB_CA_ENABLE | ((uint64_t)bdfn << PHB_CA_FUNC_LSH);	\
	addr = SETFIELD(PHB_CA_REG, addr, offset);			\
	addr = SETFIELD(PHB_CA_PE, addr, pe);				\
	if (use_asb) {							\
		val64 = data;						\
		val64 = bswap_64(val64 << 8 * (offset & (4 - sizeof(type))));	\
		phb3_write_reg_asb(p, PHB_CONFIG_ADDRESS, addr);	\
		sync();							\
		phb3_write_reg_asb(p, PHB_CONFIG_DATA, val64);		\
	} else {							\
		out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);		\
		out_le##size(p->regs + PHB_CONFIG_DATA +		\
			     (offset & (4 - sizeof(type))), data);	\
	}								\
									\
        return OPAL_SUCCESS;						\
}

PHB3_PCI_CFG_READ(8, u8)
PHB3_PCI_CFG_READ(16, u16)
PHB3_PCI_CFG_READ(32, u32)
PHB3_PCI_CFG_WRITE(8, u8)
PHB3_PCI_CFG_WRITE(16, u16)
PHB3_PCI_CFG_WRITE(32, u32)

static uint8_t phb3_choose_bus(struct phb *phb __unused,
			       struct pci_device *bridge __unused,
			       uint8_t candidate, uint8_t *max_bus __unused,
			       bool *use_max)
{
	/* Use standard bus number selection */
	*use_max = false;
	return candidate;
}

static void phb3_root_port_init(struct phb *phb, struct pci_device *dev,
				int ecap, int aercap)
{
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/* Enable SERR and parity checking */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_SERR_EN | PCI_CFG_CMD_PERR_RESP);
	pci_cfg_write16(phb, bdfn, PCI_CFG_CMD, val16);

	/* Enable reporting various errors */
	if (!ecap) return;
	pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, &val16);
	val16 |= (PCICAP_EXP_DEVCTL_CE_REPORT |
		  PCICAP_EXP_DEVCTL_NFE_REPORT |
		  PCICAP_EXP_DEVCTL_FE_REPORT |
		  PCICAP_EXP_DEVCTL_UR_REPORT);
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

	if (!aercap) return;

	/* Mask various unrecoverable errors */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, &val32);
	val32 |= (PCIECAP_AER_UE_MASK_POISON_TLP |
		  PCIECAP_AER_UE_MASK_COMPL_TIMEOUT |
		  PCIECAP_AER_UE_MASK_COMPL_ABORT |
		  PCIECAP_AER_UE_MASK_ECRC);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, val32);

	/* Report various unrecoverable errors as fatal errors */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_UE_SEVERITY, &val32);
	val32 |= (PCIECAP_AER_UE_SEVERITY_DLLP |
		  PCIECAP_AER_UE_SEVERITY_SURPRISE_DOWN |
		  PCIECAP_AER_UE_SEVERITY_FLOW_CTL_PROT |
		  PCIECAP_AER_UE_SEVERITY_UNEXP_COMPL |
		  PCIECAP_AER_UE_SEVERITY_RECV_OVFLOW |
		  PCIECAP_AER_UE_SEVERITY_MALFORMED_TLP);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_SEVERITY, val32);

	/* Mask various recoverable errors */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, &val32);
	val32 |= PCIECAP_AER_CE_MASK_ADV_NONFATAL;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, val32);

	/* Enable ECRC check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= (PCIECAP_AER_CAPCTL_ECRCG_EN |
		  PCIECAP_AER_CAPCTL_ECRCC_EN);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);

	/* Enable all error reporting */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_RERR_CMD, &val32);
	val32 |= (PCIECAP_AER_RERR_CMD_FE |
		  PCIECAP_AER_RERR_CMD_NFE |
		  PCIECAP_AER_RERR_CMD_CE);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_RERR_CMD, val32);
}

static void phb3_switch_port_init(struct phb *phb,
				  struct pci_device *dev,
				  int ecap, int aercap)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/* Enable SERR and parity checking and disable INTx */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_PERR_RESP |
		  PCI_CFG_CMD_SERR_EN |
		  PCI_CFG_CMD_INTx_DIS);
	pci_cfg_write16(phb, bdfn, PCI_CFG_CMD, val16);

	/* Disable partity error and enable system error */
	pci_cfg_read16(phb, bdfn, PCI_CFG_BRCTL, &val16);
	val16 &= ~PCI_CFG_BRCTL_PERR_RESP_EN;
	val16 |= PCI_CFG_BRCTL_SERR_EN;
	pci_cfg_write16(phb, bdfn, PCI_CFG_BRCTL, val16);

	/* Enable reporting various errors */
	if (!ecap) return;
	pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, &val16);
	val16 |= (PCICAP_EXP_DEVCTL_CE_REPORT |
		  PCICAP_EXP_DEVCTL_NFE_REPORT |
		  PCICAP_EXP_DEVCTL_FE_REPORT);
	/* HW279570 - Disable reporting of correctable errors */
	val16 &= ~PCICAP_EXP_DEVCTL_CE_REPORT;
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

	/* Unmask all unrecoverable errors */
	if (!aercap) return;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, 0x0);

	/* Severity of unrecoverable errors */
	if (dev->dev_type == PCIE_TYPE_SWITCH_UPPORT)
		val32 = (PCIECAP_AER_UE_SEVERITY_DLLP |
			 PCIECAP_AER_UE_SEVERITY_SURPRISE_DOWN |
			 PCIECAP_AER_UE_SEVERITY_FLOW_CTL_PROT |
			 PCIECAP_AER_UE_SEVERITY_RECV_OVFLOW |
			 PCIECAP_AER_UE_SEVERITY_MALFORMED_TLP |
			 PCIECAP_AER_UE_SEVERITY_INTERNAL);
	else
		val32 = (PCIECAP_AER_UE_SEVERITY_FLOW_CTL_PROT |
			 PCIECAP_AER_UE_SEVERITY_INTERNAL);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_SEVERITY, val32);

	/*
	 * Mask various correctable errors
	 *
         * On Murano and Venice DD1.0 we disable emission of corrected
         * error messages to the PHB completely to workaround errata
         * HW257476 causing the loss of tags.
	 */
	if (p->rev < PHB3_REV_MURANO_DD20)
		val32 = 0xffffffff;
	else
		val32 = PCIECAP_AER_CE_MASK_ADV_NONFATAL;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, val32);

	/* Enable ECRC generation and disable ECRC check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= PCIECAP_AER_CAPCTL_ECRCG_EN;
	val32 &= ~PCIECAP_AER_CAPCTL_ECRCC_EN;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static void phb3_endpoint_init(struct phb *phb,
			       struct pci_device *dev,
			       int ecap, int aercap)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/* Enable SERR and parity checking */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_PERR_RESP |
		  PCI_CFG_CMD_SERR_EN);
	pci_cfg_write16(phb, bdfn, PCI_CFG_CMD, val16);

	/* Enable reporting various errors */
	if (!ecap) return;
	pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, &val16);
	val16 &= ~PCICAP_EXP_DEVCTL_CE_REPORT;
	val16 |= (PCICAP_EXP_DEVCTL_NFE_REPORT |
		  PCICAP_EXP_DEVCTL_FE_REPORT |
		  PCICAP_EXP_DEVCTL_UR_REPORT);
	/* HW279570 - Disable reporting of correctable errors */
	val16 &= ~PCICAP_EXP_DEVCTL_CE_REPORT;
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

	/*
	 * On Murano and Venice DD1.0 we disable emission of corrected
	 * error messages to the PHB completely to workaround errata
	 * HW257476 causing the loss of tags.
	 */
	if (p->rev < PHB3_REV_MURANO_DD20)
		pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK,
				0xffffffff);

	/* Enable ECRC generation and check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= (PCIECAP_AER_CAPCTL_ECRCG_EN |
		  PCIECAP_AER_CAPCTL_ECRCC_EN);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static void phb3_device_init(struct phb *phb, struct pci_device *dev)
{
	int ecap = 0;
	int aercap = 0;

	/* Figure out PCIe & AER capability */
	if (pci_has_cap(dev, PCI_CFG_CAP_ID_EXP, false)) {
		ecap = pci_cap(dev, PCI_CFG_CAP_ID_EXP, false);

		if (!pci_has_cap(dev, PCIECAP_ID_AER, true)) {
			aercap = pci_find_ecap(phb, dev->bdfn,
					       PCIECAP_ID_AER, NULL);
			if (aercap > 0)
				pci_set_cap(dev, PCIECAP_ID_AER, aercap, true);
		} else {
			aercap = pci_cap(dev, PCIECAP_ID_AER, true);
		}
	}

	/* Common initialization for the device */
	pci_device_init(phb, dev);

	if (dev->dev_type == PCIE_TYPE_ROOT_PORT)
		phb3_root_port_init(phb, dev, ecap, aercap);
	else if (dev->dev_type == PCIE_TYPE_SWITCH_UPPORT ||
		 dev->dev_type == PCIE_TYPE_SWITCH_DNPORT)
		phb3_switch_port_init(phb, dev, ecap, aercap);
	else
		phb3_endpoint_init(phb, dev, ecap, aercap);
}

static int64_t phb3_pci_reinit(struct phb *phb, uint64_t scope, uint64_t data)
{
	struct pci_device *pd;
	uint16_t bdfn = data;

	if (scope != OPAL_REINIT_PCI_DEV)
		return OPAL_PARAMETER;

	pd = pci_find_dev(phb, bdfn);
	if (!pd)
		return OPAL_PARAMETER;

	phb3_device_init(phb, pd);
	return OPAL_SUCCESS;
}

static int64_t phb3_presence_detect(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint16_t slot_stat;
	uint64_t hp_override;
	int64_t rc;

	/* Test for PHB in error state ? */
	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* XXX Check bifurcation stuff ? */

	/* Read slot status register */
	rc = phb3_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_SLOTSTAT,
					&slot_stat);
	if (rc != OPAL_SUCCESS)
		return OPAL_HARDWARE;

	/* Read hotplug override */
	hp_override = in_be64(p->regs + PHB_HOTPLUG_OVERRIDE);

	PHBDBG(p, "slot_stat: 0x%04x, hp_override: 0x%016llx\n",
	       slot_stat, hp_override);

	/* So if the slot status says nothing connected, we bail out */
	if (!(slot_stat & PCICAP_EXP_SLOTSTAT_PDETECTST))
		return OPAL_SHPC_DEV_NOT_PRESENT;

	/*
	 * At this point, we can have one of those funky IBM
	 * systems that has the presence bit set in the slot
	 * status and nothing actually connected. If so, we
	 * check the hotplug override A/B bits
	 */
	if (p->use_ab_detect &&
	    (hp_override & PHB_HPOVR_PRESENCE_A) &&
	    (hp_override & PHB_HPOVR_PRESENCE_B))
		return OPAL_SHPC_DEV_NOT_PRESENT;

	/*
	 * Anything else, we assume device present, the link state
	 * machine will perform an early bail out if no electrical
	 * signaling is established after a second.
	 */
	return OPAL_SHPC_DEV_PRESENT;
}

/* Clear IODA cache tables */
static void phb3_init_ioda_cache(struct phb3 *p)
{
	uint32_t i;
	uint64_t *data64;

	/*
	 * RTT and PELTV. RTE should be 0xFF's to indicate
	 * invalid PE# for the corresponding RID.
	 *
	 * Note: Instead we set all RTE entries to 0x00 to
	 * work around a problem where PE lookups might be
	 * done before Linux has established valid PE's
	 * (during PCI probing). We can revisit that once/if
	 * Linux has been fixed to always setup valid PEs.
	 *
	 * The value 0x00 corresponds to the default PE# Linux
	 * uses to check for config space freezes before it
	 * has assigned PE# to busses.
	 *
	 * WARNING: Additionally, we need to be careful, there's
	 * a HW issue, if we get an MSI on an RTT entry that is
	 * FF, things will go bad. We need to ensure we don't
	 * ever let a live FF RTT even temporarily when resetting
	 * for EEH etc... (HW278969).
	 */
	memset(p->rte_cache, 0x00, RTT_TABLE_SIZE);
	memset(p->peltv_cache, 0x0,  sizeof(p->peltv_cache));

	/* Disable all LSI */
	for (i = 0; i < ARRAY_SIZE(p->lxive_cache); i++) {
		data64 = &p->lxive_cache[i];
		*data64 = SETFIELD(IODA2_LXIVT_PRIORITY, 0ul, 0xff);
		*data64 = SETFIELD(IODA2_LXIVT_SERVER, *data64, 0x0);
	}

	/* Diable all MSI */
	for (i = 0; i < ARRAY_SIZE(p->ive_cache); i++) {
		data64 = &p->ive_cache[i];
		*data64 = SETFIELD(IODA2_IVT_PRIORITY, 0ul, 0xff);
		*data64 = SETFIELD(IODA2_IVT_SERVER, *data64, 0x0);
	}

	/* Clear TVT */
	memset(p->tve_cache, 0x0, sizeof(p->tve_cache));
	/* Clear M32 domain */
	memset(p->m32d_cache, 0x0, sizeof(p->m32d_cache));
	/* Clear M64 domain */
	memset(p->m64b_cache, 0x0, sizeof(p->m64b_cache));
}

/* phb3_ioda_reset - Reset the IODA tables
 *
 * @purge: If true, the cache is cleared and the cleared values
 *         are applied to HW. If false, the cached values are
 *         applied to HW
 *
 * This reset the IODA tables in the PHB. It is called at
 * initialization time, on PHB reset, and can be called
 * explicitly from OPAL
 */
static int64_t phb3_ioda_reset(struct phb *phb, bool purge)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t server, prio;
	uint64_t *pdata64, data64;
	uint32_t i;

	if (purge) {
		prlog(PR_DEBUG, "PHB%d: Purging all IODA tables...\n",
		      p->phb.opal_id);
		phb3_init_ioda_cache(p);
	}

	/* Init_27..28 - LIXVT */
	phb3_ioda_sel(p, IODA2_TBL_LXIVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->lxive_cache); i++) {
		data64 = p->lxive_cache[i];
		server = GETFIELD(IODA2_LXIVT_SERVER, data64);
		prio = GETFIELD(IODA2_LXIVT_PRIORITY, data64);
		data64 = SETFIELD(IODA2_LXIVT_SERVER, data64, server);
		data64 = SETFIELD(IODA2_LXIVT_PRIORITY, data64, prio);
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_29..30 - MRT */
	phb3_ioda_sel(p, IODA2_TBL_MRT, 0, true);
	for (i = 0; i < 8; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	/* Init_31..32 - TVT */
	phb3_ioda_sel(p, IODA2_TBL_TVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->tve_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->tve_cache[i]);

	/* Init_33..34 - M64BT */
	phb3_ioda_sel(p, IODA2_TBL_M64BT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->m64b_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->m64b_cache[i]);

	/* Init_35..36 - M32DT */
	phb3_ioda_sel(p, IODA2_TBL_M32DT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->m32d_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->m32d_cache[i]);

	/* Load RTE, PELTV */
	if (p->tbl_rtt)
		memcpy((void *)p->tbl_rtt, p->rte_cache, RTT_TABLE_SIZE);
	if (p->tbl_peltv)
		memcpy((void *)p->tbl_peltv, p->peltv_cache, PELTV_TABLE_SIZE);

	/* Load IVT */
	if (p->tbl_ivt) {
		pdata64 = (uint64_t *)p->tbl_ivt;
		for (i = 0; i < IVT_TABLE_ENTRIES; i++)
			pdata64[i * IVT_TABLE_STRIDE] = p->ive_cache[i];
	}

	/* Invalidate RTE, IVE, TCE cache */
	out_be64(p->regs + PHB_RTC_INVALIDATE, PHB_RTC_INVALIDATE_ALL);
	out_be64(p->regs + PHB_IVC_INVALIDATE, PHB_IVC_INVALIDATE_ALL);
	out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_ALL);

	/* Clear RBA */
	if (p->rev >= PHB3_REV_MURANO_DD20) {
		phb3_ioda_sel(p, IODA2_TBL_RBA, 0, true);
		for (i = 0; i < 32; i++)
			out_be64(p->regs + PHB_IODA_DATA0, 0x0ul);
	}

	/* Clear PEST & PEEV */
	for (i = 0; i < PHB3_MAX_PE_NUM; i++) {
		uint64_t pesta, pestb;

		phb3_ioda_sel(p, IODA2_TBL_PESTA, i, false);
		pesta = in_be64(p->regs + PHB_IODA_DATA0);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
		phb3_ioda_sel(p, IODA2_TBL_PESTB, i, false);
		pestb = in_be64(p->regs + PHB_IODA_DATA0);
		out_be64(p->regs + PHB_IODA_DATA0, 0);

		if ((pesta & IODA2_PESTA_MMIO_FROZEN) ||
		    (pestb & IODA2_PESTB_DMA_STOPPED))
			PHBDBG(p, "Frozen PE#%d (%s - %s)\n",
			       i, (pesta & IODA2_PESTA_MMIO_FROZEN) ? "DMA" : "",
			       (pestb & IODA2_PESTB_DMA_STOPPED) ? "MMIO" : "");
	}

	phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
	for (i = 0; i < 4; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	return OPAL_SUCCESS;
}

/*
 * Clear anything we have in PAPR Error Injection registers. Though
 * the spec says the PAPR error injection should be one-shot without
 * the "sticky" bit. However, that's false according to the experiments
 * I had. So we have to clear it at appropriate point in kernel to
 * avoid endless frozen PE.
 */
static int64_t phb3_papr_errinjct_reset(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_ADDR, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_MASK, 0x0ul);

	return OPAL_SUCCESS;
}

static int64_t phb3_set_phb_mem_window(struct phb *phb,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint64_t addr,
				       uint64_t __unused pci_addr,
				       uint64_t size)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t data64;

	/*
	 * By design, PHB3 doesn't support IODT any more.
	 * Besides, we can't enable M32 BAR as well. So
	 * the function is used to do M64 mapping and each
	 * BAR is supposed to be shared by all PEs.
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16)
			return OPAL_PARAMETER;

		data64 = p->m64b_cache[window_num];
		if (data64 & IODA2_M64BT_SINGLE_PE) {
			if ((addr & 0x1FFFFFFul) ||
			    (size & 0x1FFFFFFul))
				return OPAL_PARAMETER;
		} else {
			if ((addr & 0xFFFFFul) ||
			    (size & 0xFFFFFul))
				return OPAL_PARAMETER;
		}

		/* size should be 2^N */
		if (!size || size & (size-1))
			return OPAL_PARAMETER;

		/* address should be size aligned */
		if (addr & (size - 1))
			return OPAL_PARAMETER;

		break;
	default:
		return OPAL_PARAMETER;
	}

	if (data64 & IODA2_M64BT_SINGLE_PE) {
		data64 = SETFIELD(IODA2_M64BT_SINGLE_BASE, data64,
				  addr >> 25);
		data64 = SETFIELD(IODA2_M64BT_SINGLE_MASK, data64,
				  0x20000000 - (size >> 25));
	} else {
		data64 = SETFIELD(IODA2_M64BT_BASE, data64,
				  addr >> 20);
		data64 = SETFIELD(IODA2_M64BT_MASK, data64,
				  0x40000000 - (size >> 20));
	}
	p->m64b_cache[window_num] = data64;

	return OPAL_SUCCESS;
}

/*
 * For one specific M64 BAR, it can be shared by all PEs,
 * or owned by single PE exclusively.
 */
static int64_t phb3_phb_mmio_enable(struct phb *phb,
				    uint16_t window_type,
				    uint16_t window_num,
				    uint16_t enable)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t data64, base, mask;

	/*
	 * By design, PHB3 doesn't support IODT any more.
	 * Besides, we can't enable M32 BAR as well. So
	 * the function is used to do M64 mapping and each
	 * BAR is supposed to be shared by all PEs.
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16 ||
		    enable > OPAL_ENABLE_M64_NON_SPLIT)
			return OPAL_PARAMETER;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/*
	 * We need check the base/mask while enabling
	 * the M64 BAR. Otherwise, invalid base/mask
	 * might cause fenced AIB unintentionally
	 */
	data64 = p->m64b_cache[window_num];
	switch (enable) {
	case OPAL_DISABLE_M64:
		data64 &= ~IODA2_M64BT_SINGLE_PE;
		data64 &= ~IODA2_M64BT_ENABLE;
		break;
	case OPAL_ENABLE_M64_SPLIT:
		if (data64 & IODA2_M64BT_SINGLE_PE)
			return OPAL_PARAMETER;
		base = GETFIELD(IODA2_M64BT_BASE, data64);
		base = (base << 20);
		mask = GETFIELD(IODA2_M64BT_MASK, data64);
		if (base < p->mm0_base || !mask)
			return OPAL_PARTIAL;

		data64 |= IODA2_M64BT_ENABLE;
		break;
	case OPAL_ENABLE_M64_NON_SPLIT:
		if (!(data64 & IODA2_M64BT_SINGLE_PE))
			return OPAL_PARAMETER;
		base = GETFIELD(IODA2_M64BT_SINGLE_BASE, data64);
		base = (base << 25);
		mask = GETFIELD(IODA2_M64BT_SINGLE_MASK, data64);
		if (base < p->mm0_base || !mask)
			return OPAL_PARTIAL;

		data64 |= IODA2_M64BT_SINGLE_PE;
		data64 |= IODA2_M64BT_ENABLE;
		break;
	}

	/* Update HW and cache */
	phb3_ioda_sel(p, IODA2_TBL_M64BT, window_num, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	p->m64b_cache[window_num] = data64;
	return OPAL_SUCCESS;
}

static int64_t phb3_map_pe_mmio_window(struct phb *phb,
				       uint16_t pe_num,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint16_t segment_num)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t data64, *cache;

	if (pe_num >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	/*
	 * PHB3 doesn't support IODT any more. On the other
	 * hand, PHB3 support M64DT with much more flexibility.
	 * we need figure it out later. At least, we never use
	 * M64DT in kernel.
	 */
	switch(window_type) {
	case OPAL_IO_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M32_WINDOW_TYPE:
		if (window_num != 0 || segment_num >= PHB3_MAX_PE_NUM)
			return OPAL_PARAMETER;

		cache = &p->m32d_cache[segment_num];
		phb3_ioda_sel(p, IODA2_TBL_M32DT, segment_num, false);
		out_be64(p->regs + PHB_IODA_DATA0,
			 SETFIELD(IODA2_M32DT_PE, 0ull, pe_num));
		*cache = SETFIELD(IODA2_M32DT_PE, 0ull, pe_num);

		break;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16)
			return OPAL_PARAMETER;
		cache = &p->m64b_cache[window_num];
		data64 = *cache;

		/* The BAR shouldn't be enabled yet */
		if (data64 & IODA2_M64BT_ENABLE)
			return OPAL_PARTIAL;

		data64 |= IODA2_M64BT_SINGLE_PE;
		data64 = SETFIELD(IODA2_M64BT_PE_HI, data64, pe_num >> 5);
		data64 = SETFIELD(IODA2_M64BT_PE_LOW, data64, pe_num);
		*cache = data64;

		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_map_pe_dma_window(struct phb *phb,
				      uint16_t pe_num,
				      uint16_t window_id,
				      uint16_t tce_levels,
				      uint64_t tce_table_addr,
				      uint64_t tce_table_size,
				      uint64_t tce_page_size)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t tts_encoded;
	uint64_t data64 = 0;

	/*
	 * Sanity check. We currently only support "2 window per PE" mode
	 * ie, only bit 59 of the PCI address is used to select the window
	 */
	if (pe_num >= PHB3_MAX_PE_NUM ||
	    (window_id >> 1) != pe_num)
		return OPAL_PARAMETER;

	/*
	 * tce_table_size == 0 is used to disable an entry, in this case
	 * we ignore other arguments
	 */
	if (tce_table_size == 0) {
		phb3_ioda_sel(p, IODA2_TBL_TVT, window_id, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
		p->tve_cache[window_id] = 0;
		return OPAL_SUCCESS;
	}

	/* Additional arguments validation */
	if (tce_levels < 1 || tce_levels > 5 ||
	    !is_pow2(tce_table_size) ||
	    tce_table_size < 0x1000)
		return OPAL_PARAMETER;

	/* Encode TCE table size */
	data64 = SETFIELD(IODA2_TVT_TABLE_ADDR, 0ul, tce_table_addr >> 12);
	tts_encoded = ilog2(tce_table_size) - 11;
	if (tts_encoded > 31)
		return OPAL_PARAMETER;
	data64 = SETFIELD(IODA2_TVT_TCE_TABLE_SIZE, data64, tts_encoded);

	/* Encode TCE page size */
	switch (tce_page_size) {
	case 0x1000:	/* 4K */
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 1);
		break;
	case 0x10000:	/* 64K */
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 5);
		break;
	case 0x1000000:	/* 16M */
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 13);
		break;
	case 0x10000000: /* 256M */
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 17);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Encode number of levels */
	data64 = SETFIELD(IODA2_TVT_NUM_LEVELS, data64, tce_levels - 1);

	phb3_ioda_sel(p, IODA2_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	p->tve_cache[window_id] = data64;

	return OPAL_SUCCESS;
}

static int64_t phb3_map_pe_dma_window_real(struct phb *phb,
					   uint16_t pe_num,
					   uint16_t window_id,
					   uint64_t pci_start_addr,
					   uint64_t pci_mem_size)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t end = pci_start_addr + pci_mem_size;
	uint64_t tve;

	if (pe_num >= PHB3_MAX_PE_NUM ||
	    (window_id >> 1) != pe_num)
		return OPAL_PARAMETER;

	if (pci_mem_size) {
		/* Enable */

		/*
		 * Check that the start address has the right TVE index,
		 * we only support the 1 bit mode where each PE has 2
		 * TVEs
		 */
		if ((pci_start_addr >> 59) != (window_id & 1))
			return OPAL_PARAMETER;
		pci_start_addr &= ((1ull << 59) - 1);
		end = pci_start_addr + pci_mem_size;

		/* We have to be 16M aligned */
		if ((pci_start_addr & 0x00ffffff) ||
		    (pci_mem_size & 0x00ffffff))
			return OPAL_PARAMETER;

		/*
		 * It *looks* like this is the max we can support (we need
		 * to verify this. Also we are not checking for rollover,
		 * but then we aren't trying too hard to protect ourselves
		 * againt a completely broken OS.
		 */
		if (end > 0x0003ffffffffffffull)
			return OPAL_PARAMETER;

		/*
		 * Put start address bits 49:24 into TVE[52:53]||[0:23]
		 * and end address bits 49:24 into TVE[54:55]||[24:47]
		 * and set TVE[51]
		 */
		tve  = (pci_start_addr << 16) & (0xffffffull << 48);
		tve |= (pci_start_addr >> 38) & (3ull << 10);
		tve |= (end >>  8) & (0xfffffful << 16);
		tve |= (end >> 40) & (3ull << 8);
		tve |= PPC_BIT(51);
	} else {
		/* Disable */
		tve = 0;
	}

	phb3_ioda_sel(p, IODA2_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, tve);
	p->tve_cache[window_id] = tve;

	return OPAL_SUCCESS;
}

static void phb3_pci_msi_check_q(struct phb3 *p, uint32_t ive_num)
{
	uint64_t ive, ivc, ffi;
	uint8_t *q_byte;

	/* Each IVE has 16-bytes or 128-bytes */
	ive = p->tbl_ivt + (ive_num * IVT_TABLE_STRIDE * 8);
	q_byte = (uint8_t *)(ive + 5);

	/*
	 * Handle Q bit. If the Q bit doesn't show up,
	 * we would have CI load to make that.
	 */
	if (!(*q_byte & 0x1)) {
		/* Read from random PHB reg to force flush */
		in_be64(p->regs + PHB_IVC_UPDATE);

		/* Order with subsequent read of Q */
		sync();

		/* Q still not set, bail out */
		if (!(*q_byte & 0x1))
			return;
	}

	/* Lock FFI and send interrupt */
	while (in_be64(p->regs + PHB_FFI_LOCK))
		/* XXX Handle fences ! */
		;

	/* Clear Q bit and update IVC */
	*q_byte = 0;
	ivc = SETFIELD(PHB_IVC_UPDATE_SID, 0ul, ive_num) |
		PHB_IVC_UPDATE_ENABLE_Q;
	out_be64(p->regs + PHB_IVC_UPDATE, ivc);

	/*
	 * Resend interrupt. Note the lock clear bit isn't documented in
	 * the PHB3 spec and thus is probably unnecessary but it's in
	 * IODA2 so let's be safe here, it won't hurt to set it
	 */
	ffi = SETFIELD(PHB_FFI_REQUEST_ISN, 0ul, ive_num) | PHB_FFI_LOCK_CLEAR;
	out_be64(p->regs + PHB_FFI_REQUEST, ffi);
}

static int64_t phb3_pci_msi_eoi(struct phb *phb,
				uint32_t hwirq)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint32_t ive_num = PHB3_IRQ_NUM(hwirq);
	uint64_t ive, ivc;
	uint8_t *p_byte, gp, gen;

	/* OS might not configure IVT yet */
	if (!p->tbl_ivt)
		return OPAL_HARDWARE;

	/* Each IVE has 16-bytes or 128-bytes */
	ive = p->tbl_ivt + (ive_num * IVT_TABLE_STRIDE * 8);
	p_byte = (uint8_t *)(ive + 4);

	/* Read generation and P */
	gp = *p_byte;
	gen = gp >> 1;

	/* Increment generation count and clear P */
	*p_byte = ((gen + 1) << 1) & 0x7;

	/* Update the IVC with a match against the old gen count */
	ivc = SETFIELD(PHB_IVC_UPDATE_SID, 0ul, ive_num) |
		PHB_IVC_UPDATE_ENABLE_P |
		PHB_IVC_UPDATE_ENABLE_GEN |
		SETFIELD(PHB_IVC_UPDATE_GEN_MATCH, 0ul, gen);
	out_be64(p->regs + PHB_IVC_UPDATE, ivc);

	/* Handle Q bit */
	phb3_pci_msi_check_q(p, ive_num);

	return OPAL_SUCCESS;
}

static int64_t phb3_set_ive_pe(struct phb *phb,
			       uint32_t pe_num,
			       uint32_t ive_num)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t *cache, ivep, data64;
	uint16_t *pe_word;

	/* OS should enable the BAR in advance */
	if (!p->tbl_ivt)
		return OPAL_HARDWARE;

	/* Each IVE reserves 128 bytes */
	if (pe_num >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES)
		return OPAL_PARAMETER;

	/* Update IVE cache */
	cache = &p->ive_cache[ive_num];
	*cache = SETFIELD(IODA2_IVT_PE, *cache, pe_num);

	/* Update in-memory IVE without clobbering P and Q */
	ivep = p->tbl_ivt + (ive_num * IVT_TABLE_STRIDE * 8);
	pe_word = (uint16_t *)(ivep + 6);
	*pe_word = pe_num;

	/* Invalidate IVC */
	data64 = SETFIELD(PHB_IVC_INVALIDATE_SID, 0ul, ive_num);
	out_be64(p->regs + PHB_IVC_INVALIDATE, data64);

	return OPAL_SUCCESS;
}

static int64_t phb3_get_msi_32(struct phb *phb __unused,
			       uint32_t pe_num,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint32_t *msi_address,
			       uint32_t *message_data)
{
	/*
	 * Sanity check. We needn't check on mve_number (PE#)
	 * on PHB3 since the interrupt source is purely determined
	 * by its DMA address and data, but the check isn't
	 * harmful.
	 */
	if (pe_num >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES ||
	    msi_range != 1 || !msi_address|| !message_data)
		return OPAL_PARAMETER;

	/*
	 * DMA address and data will form the IVE index.
	 * For more details, please refer to IODA2 spec.
	 */
	*msi_address = 0xFFFF0000 | ((ive_num << 4) & 0xFFFFFE0F);
	*message_data = ive_num & 0x1F;

	return OPAL_SUCCESS;
}

static int64_t phb3_get_msi_64(struct phb *phb __unused,
			       uint32_t pe_num,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint64_t *msi_address,
			       uint32_t *message_data)
{
	/* Sanity check */
	if (pe_num >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES ||
	    msi_range != 1 || !msi_address || !message_data)
		return OPAL_PARAMETER;

	/*
	 * DMA address and data will form the IVE index.
	 * For more details, please refer to IODA2 spec.
	 */
	*msi_address = (0x1ul << 60) | ((ive_num << 4) & 0xFFFFFFFFFFFFFE0Ful);
	*message_data = ive_num & 0x1F;

	return OPAL_SUCCESS;
}

static bool phb3_err_check_pbcq(struct phb3 *p)
{
	uint64_t nfir, mask, wof, val64;
	int32_t class, bit;
	uint64_t severity[PHB3_ERR_CLASS_LAST] = {
		0x0000000000000000,	/* NONE	*/
		0x018000F800000000,	/* DEAD */
		0x7E7DC70000000000,	/* FENCED */
		0x0000000000000000,	/* ER	*/
		0x0000000000000000	/* INF	*/
	};

	/*
	 * Read on NFIR to see if XSCOM is working properly.
	 * If XSCOM doesn't work well, we need take the PHB
	 * into account any more.
	 */
	xscom_read(p->chip_id, p->pe_xscom + 0x0, &nfir);
	if (nfir == 0xffffffffffffffff) {
		p->err.err_src = PHB3_ERR_SRC_NONE;
		p->err.err_class = PHB3_ERR_CLASS_DEAD;
		phb3_set_err_pending(p, true);
		return true;
	}

	/*
	 * Check WOF. We need handle unmasked errors firstly.
	 * We probably run into the situation (on simulator)
	 * where we have asserted FIR bits, but WOF has nothing.
	 * For that case, we should check FIR as well.
	 */
	xscom_read(p->chip_id, p->pe_xscom + 0x3, &mask);
	xscom_read(p->chip_id, p->pe_xscom + 0x8, &wof);
	if (wof & ~mask)
		wof &= ~mask;
	if (!wof) {
		if (nfir & ~mask)
			nfir &= ~mask;
		if (!nfir)
			return false;
		wof = nfir;
	}

	/* We shouldn't hit class PHB3_ERR_CLASS_NONE */
	for (class = PHB3_ERR_CLASS_NONE;
	     class < PHB3_ERR_CLASS_LAST;
	     class++) {
		val64 = wof & severity[class];
		if (!val64)
			continue;

		for (bit = 0; bit < 64; bit++) {
			if (val64 & PPC_BIT(bit)) {
				p->err.err_src = PHB3_ERR_SRC_PBCQ;
				p->err.err_class = class;
				p->err.err_bit = 63 - bit;
				phb3_set_err_pending(p, true);
				return true;
			}
		}
	}

	return false;
}

static bool phb3_err_check_lem(struct phb3 *p)
{
	uint64_t fir, wof, mask, val64;
	int32_t class, bit;
	uint64_t severity[PHB3_ERR_CLASS_LAST] = {
		0x0000000000000000,	/* NONE */
		0x0000000000000000,	/* DEAD */
		0xADB670C980ADD151,	/* FENCED */
		0x000800107F500A2C,	/* ER   */
		0x42018E2200002482	/* INF  */
	};

	/*
	 * Read FIR. If XSCOM or ASB is frozen, we needn't
	 * go forward and just mark the PHB with dead state
	 */
	fir = phb3_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
	if (fir == 0xffffffffffffffff) {
		p->err.err_src = PHB3_ERR_SRC_PHB;
		p->err.err_class = PHB3_ERR_CLASS_DEAD;
		phb3_set_err_pending(p, true);
		return true;
	}

	/*
	 * Check on WOF for the unmasked errors firstly. Under
	 * some situation where we run skiboot on simulator,
	 * we already had FIR bits asserted, but WOF is still zero.
	 * For that case, we check FIR directly.
	 */
	wof = phb3_read_reg_asb(p, PHB_LEM_WOF);
	mask = phb3_read_reg_asb(p, PHB_LEM_ERROR_MASK);
	if (wof & ~mask)
		wof &= ~mask;
	if (!wof) {
		if (fir & ~mask)
			fir &= ~mask;
		if (!fir)
			return false;
		wof = fir;
	}

	/* We shouldn't hit PHB3_ERR_CLASS_NONE */
	for (class = PHB3_ERR_CLASS_NONE;
	     class < PHB3_ERR_CLASS_LAST;
	     class++) {
		val64 = wof & severity[class];
		if (!val64)
			continue;

		for (bit = 0; bit < 64; bit++) {
			if (val64 & PPC_BIT(bit)) {
				p->err.err_src = PHB3_ERR_SRC_PHB;
				p->err.err_class = class;
				p->err.err_bit = 63 - bit;
				phb3_set_err_pending(p, true);
				return true;
			}
		}
	}

	return false;
}

/*
 * The function can be called during error recovery for INF
 * and ER class. For INF case, it's expected to be called
 * when grabbing the error log. We will call it explicitly
 * when clearing frozen PE state for ER case.
 */
static void phb3_err_ER_clear(struct phb3 *p)
{
	uint32_t val32;
	uint64_t val64;
	uint64_t fir = in_be64(p->regs + PHB_LEM_FIR_ACCUM);

	/* Rec 1: Grab the PCI config lock */
	/* Removed... unnecessary. We have our own lock here */

	/* Rec 2/3/4: Take all inbound transactions */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000001c00000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x10000000);

	/* Rec 5/6/7: Clear pending non-fatal errors */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000005000000000ul);
	val32 = in_be32(p->regs + PHB_CONFIG_DATA);
	out_be32(p->regs + PHB_CONFIG_DATA, (val32 & 0xe0700000) | 0x0f000f00);

	/* Rec 8/9/10: Clear pending fatal errors for AER */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000010400000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 11/12/13: Clear pending non-fatal errors for AER */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000011000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 22/23/24: Clear root port errors */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000013000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 25/26/27: Enable IO and MMIO bar */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000004000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x470100f8);

	/* Rec 28: Release the PCI config lock */
	/* Removed... unnecessary. We have our own lock here */

	/* Rec 29...34: Clear UTL errors */
	val64 = in_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS, val64);
	val64 = in_be64(p->regs + UTL_PCIE_PORT_STATUS);
	out_be64(p->regs + UTL_PCIE_PORT_STATUS, val64);
	val64 = in_be64(p->regs + UTL_RC_STATUS);
	out_be64(p->regs + UTL_RC_STATUS, val64);

	/* Rec 39...66: Clear PHB error trap */
	val64 = in_be64(p->regs + PHB_ERR_STATUS);
	out_be64(p->regs + PHB_ERR_STATUS, val64);
	out_be64(p->regs + PHB_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_OUT_ERR_STATUS);
	out_be64(p->regs + PHB_OUT_ERR_STATUS, val64);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_INA_ERR_STATUS);
	out_be64(p->regs + PHB_INA_ERR_STATUS, val64);
	out_be64(p->regs + PHB_INA_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_INA_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_INA_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_INB_ERR_STATUS);
	out_be64(p->regs + PHB_INB_ERR_STATUS, val64);
	out_be64(p->regs + PHB_INB_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_INB_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_INB_ERR_LOG_1, 0x0ul);

	/* Rec 67/68: Clear FIR/WOF */
	out_be64(p->regs + PHB_LEM_FIR_AND_MASK, ~fir);
	out_be64(p->regs + PHB_LEM_WOF, 0x0ul);
}

static void phb3_read_phb_status(struct phb3 *p,
				 struct OpalIoPhb3ErrorData *stat)
{
	uint16_t val;
	uint64_t *pPEST;
	uint64_t val64 = 0;
	uint32_t i;

	memset(stat, 0, sizeof(struct OpalIoPhb3ErrorData));

	/* Error data common part */
	stat->common.version = OPAL_PHB_ERROR_DATA_VERSION_1;
	stat->common.ioType  = OPAL_PHB_ERROR_DATA_TYPE_PHB3;
	stat->common.len     = sizeof(struct OpalIoPhb3ErrorData);

	/*
	 * We read some registers using config space through AIB.
	 *
	 * Get to other registers using ASB when possible to get to them
	 * through a fence if one is present.
	 */

	/* Use ASB to access PCICFG if the PHB has been fenced */
	p->flags |= PHB3_CFG_USE_ASB;

	/* Grab RC bridge control, make it 32-bit */
	phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &val);
	stat->brdgCtl = val;

	/* Grab UTL status registers */
	stat->portStatusReg = hi32(phb3_read_reg_asb(p, UTL_PCIE_PORT_STATUS));
	stat->rootCmplxStatus = hi32(phb3_read_reg_asb(p, UTL_RC_STATUS));
	stat->busAgentStatus = hi32(phb3_read_reg_asb(p, UTL_SYS_BUS_AGENT_STATUS));

	/*
	 * Grab various RC PCIe capability registers. All device, slot
	 * and link status are 16-bit, so we grab the pair control+status
	 * for each of them
	 */
	phb3_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_DEVCTL,
			   &stat->deviceStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_SLOTCTL,
			   &stat->slotStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_LCTL,
			   &stat->linkStatus);

	/*
	 * I assume those are the standard config space header, cmd & status
	 * together makes 32-bit. Secondary status is 16-bit so I'll clear
	 * the top on that one
	 */
	phb3_pcicfg_read32(&p->phb, 0, PCI_CFG_CMD, &stat->devCmdStatus);
	phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_SECONDARY_STATUS, &val);
	stat->devSecStatus = val;

	/* Grab a bunch of AER regs */
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_RERR_STA,
			   &stat->rootErrorStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_UE_STATUS,
			   &stat->uncorrErrorStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_STATUS,
			   &stat->corrErrorStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG0,
			   &stat->tlpHdr1);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG1,
			   &stat->tlpHdr2);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG2,
			   &stat->tlpHdr3);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG3,
			   &stat->tlpHdr4);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_SRCID,
			   &stat->sourceId);

	/* Restore to AIB */
	p->flags &= ~PHB3_CFG_USE_ASB;

	/* PEC NFIR */
	xscom_read(p->chip_id, p->pe_xscom + 0x0, &stat->nFir);
	xscom_read(p->chip_id, p->pe_xscom + 0x3, &stat->nFirMask);
	xscom_read(p->chip_id, p->pe_xscom + 0x8, &stat->nFirWOF);

	/* PHB3 inbound and outbound error Regs */
	stat->phbPlssr = phb3_read_reg_asb(p, PHB_CPU_LOADSTORE_STATUS);
	stat->phbCsr = phb3_read_reg_asb(p, PHB_DMA_CHAN_STATUS);
	stat->lemFir = phb3_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
	stat->lemErrorMask = phb3_read_reg_asb(p, PHB_LEM_ERROR_MASK);
	stat->lemWOF = phb3_read_reg_asb(p, PHB_LEM_WOF);
	stat->phbErrorStatus = phb3_read_reg_asb(p, PHB_ERR_STATUS);
	stat->phbFirstErrorStatus = phb3_read_reg_asb(p, PHB_ERR1_STATUS);
	stat->phbErrorLog0 = phb3_read_reg_asb(p, PHB_ERR_LOG_0);
	stat->phbErrorLog1 = phb3_read_reg_asb(p, PHB_ERR_LOG_1);
	stat->mmioErrorStatus = phb3_read_reg_asb(p, PHB_OUT_ERR_STATUS);
	stat->mmioFirstErrorStatus = phb3_read_reg_asb(p, PHB_OUT_ERR1_STATUS);
	stat->mmioErrorLog0 = phb3_read_reg_asb(p, PHB_OUT_ERR_LOG_0);
	stat->mmioErrorLog1 = phb3_read_reg_asb(p, PHB_OUT_ERR_LOG_1);
	stat->dma0ErrorStatus = phb3_read_reg_asb(p, PHB_INA_ERR_STATUS);
	stat->dma0FirstErrorStatus = phb3_read_reg_asb(p, PHB_INA_ERR1_STATUS);
	stat->dma0ErrorLog0 = phb3_read_reg_asb(p, PHB_INA_ERR_LOG_0);
	stat->dma0ErrorLog1 = phb3_read_reg_asb(p, PHB_INA_ERR_LOG_1);
	stat->dma1ErrorStatus = phb3_read_reg_asb(p, PHB_INB_ERR_STATUS);
	stat->dma1FirstErrorStatus = phb3_read_reg_asb(p, PHB_INB_ERR1_STATUS);
	stat->dma1ErrorLog0 = phb3_read_reg_asb(p, PHB_INB_ERR_LOG_0);
	stat->dma1ErrorLog1 = phb3_read_reg_asb(p, PHB_INB_ERR_LOG_1);

	/*
	 * Grab PESTA & B content. The error bit (bit#0) should
	 * be fetched from IODA and the left content from memory
	 * resident tables.
	 */
	pPEST = (uint64_t *)p->tbl_pest;
	val64 = PHB_IODA_AD_AUTOINC;
	val64 = SETFIELD(PHB_IODA_AD_TSEL, val64, IODA2_TBL_PESTA);
	phb3_write_reg_asb(p, PHB_IODA_ADDR, val64);
	for (i = 0; i < OPAL_PHB3_NUM_PEST_REGS; i++) {
		stat->pestA[i] = phb3_read_reg_asb(p, PHB_IODA_DATA0);
		stat->pestA[i] |= pPEST[2 * i];
	}

	val64 = PHB_IODA_AD_AUTOINC;
	val64 = SETFIELD(PHB_IODA_AD_TSEL, val64, IODA2_TBL_PESTB);
	phb3_write_reg_asb(p, PHB_IODA_ADDR, val64);
	for (i = 0; i < OPAL_PHB3_NUM_PEST_REGS; i++) {
		stat->pestB[i] = phb3_read_reg_asb(p, PHB_IODA_DATA0);
		stat->pestB[i] |= pPEST[2 * i + 1];
	}
}

static int64_t phb3_msi_get_xive(void *data,
				 uint32_t isn,
				 uint16_t *server,
				 uint8_t *prio)
{
	struct phb3 *p = data;
	uint32_t chip, index, irq;
	uint64_t ive;

	chip = P8_IRQ_TO_CHIP(isn);
	index = P8_IRQ_TO_PHB(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (chip != p->chip_id ||
	    index != p->index ||
	    irq > PHB3_MSI_IRQ_MAX)
		return OPAL_PARAMETER;

	/*
	 * Each IVE has 16 bytes in cache. Note that the kernel
	 * should strip the link bits from server field.
	 */
	ive = p->ive_cache[irq];
	*server = GETFIELD(IODA2_IVT_SERVER, ive);
	*prio = GETFIELD(IODA2_IVT_PRIORITY, ive);

	return OPAL_SUCCESS;
}

static int64_t phb3_msi_set_xive(void *data,
				 uint32_t isn,
				 uint16_t server,
				 uint8_t prio)
{
	struct phb3 *p = data;
	uint32_t chip, index;
	uint64_t *cache, ive_num, data64, m_server, m_prio;
	uint32_t *ive;

	chip = P8_IRQ_TO_CHIP(isn);
	index = P8_IRQ_TO_PHB(isn);
	ive_num = PHB3_IRQ_NUM(isn);

	if (p->state == PHB3_STATE_BROKEN || !p->tbl_rtt)
		return OPAL_HARDWARE;
	if (chip != p->chip_id ||
	    index != p->index ||
	    ive_num > PHB3_MSI_IRQ_MAX)
		return OPAL_PARAMETER;

	/*
	 * We need strip the link from server. As Milton told
	 * me, the server is assigned as follows and the left
	 * bits unused: node/chip/core/thread/link = 2/3/4/3/2
	 *
	 * Note: the server has added the link bits to server.
	 */
	m_server = server;
	m_prio = prio;

	cache = &p->ive_cache[ive_num];
	*cache = SETFIELD(IODA2_IVT_SERVER,   *cache, m_server);
	*cache = SETFIELD(IODA2_IVT_PRIORITY, *cache, m_prio);

	/*
	 * Update IVT and IVC. We need use IVC update register
	 * to do that. Each IVE in the table has 128 bytes
	 */
	ive = (uint32_t *)(p->tbl_ivt + ive_num * IVT_TABLE_STRIDE * 8);
	data64 = PHB_IVC_UPDATE_ENABLE_SERVER | PHB_IVC_UPDATE_ENABLE_PRI;
	data64 = SETFIELD(PHB_IVC_UPDATE_SID, data64, ive_num);
	data64 = SETFIELD(PHB_IVC_UPDATE_SERVER, data64, m_server);
	data64 = SETFIELD(PHB_IVC_UPDATE_PRI, data64, m_prio);

	/*
	 * We don't use SETFIELD because we are doing a 32-bit access
	 * in order to avoid touching the P and Q bits
	 */
	*ive = (m_server << 8) | m_prio;
	out_be64(p->regs + PHB_IVC_UPDATE, data64);

	/*
	 * Handle Q bit if we're going to enable the interrupt.
	 * The OS should make sure the interrupt handler has
	 * been installed already.
	 */
	if (prio != 0xff)
		phb3_pci_msi_check_q(p, ive_num);

	return OPAL_SUCCESS;
}

static int64_t phb3_lsi_get_xive(void *data,
				 uint32_t isn,
				 uint16_t *server,
				 uint8_t *prio)
{
	struct phb3 *p = data;
	uint32_t chip, index, irq;
	uint64_t lxive;

	chip = P8_IRQ_TO_CHIP(isn);
	index = P8_IRQ_TO_PHB(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (chip != p->chip_id	||
	    index != p->index	||
	    irq < PHB3_LSI_IRQ_MIN ||
	    irq > PHB3_LSI_IRQ_MAX)
		return OPAL_PARAMETER;

	lxive = p->lxive_cache[irq - PHB3_LSI_IRQ_MIN];
	*server = GETFIELD(IODA2_LXIVT_SERVER, lxive);
	*prio = GETFIELD(IODA2_LXIVT_PRIORITY, lxive);

	return OPAL_SUCCESS;
}

static int64_t phb3_lsi_set_xive(void *data,
				 uint32_t isn,
				 uint16_t server,
				 uint8_t prio)
{
	struct phb3 *p = data;
	uint32_t chip, index, irq, entry;
	uint64_t lxive;

	chip = P8_IRQ_TO_CHIP(isn);
	index = P8_IRQ_TO_PHB(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;

	if (chip != p->chip_id	||
	    index != p->index	||
	    irq < PHB3_LSI_IRQ_MIN ||
	    irq > PHB3_LSI_IRQ_MAX)
		return OPAL_PARAMETER;

	lxive = SETFIELD(IODA2_LXIVT_SERVER, 0ul, server);
	lxive = SETFIELD(IODA2_LXIVT_PRIORITY, lxive, prio);

	/*
	 * We cache the arguments because we have to mangle
	 * it in order to hijack 3 bits of priority to extend
	 * the server number
	 */
	entry = irq - PHB3_LSI_IRQ_MIN;
	p->lxive_cache[entry] = lxive;

	/* We use HRT entry 0 always for now */
	phb3_ioda_sel(p, IODA2_TBL_LXIVT, entry, false);
	lxive = in_be64(p->regs + PHB_IODA_DATA0);
	lxive = SETFIELD(IODA2_LXIVT_SERVER, lxive, server);
	lxive = SETFIELD(IODA2_LXIVT_PRIORITY, lxive, prio);
	out_be64(p->regs + PHB_IODA_DATA0, lxive);

	return OPAL_SUCCESS;
}

static void phb3_err_interrupt(void *data, uint32_t isn)
{
	struct phb3 *p = data;

	PHBDBG(p, "Got interrupt 0x%08x\n", isn);

	/* Update pending event */
	opal_update_pending_evt(OPAL_EVENT_PCI_ERROR,
				OPAL_EVENT_PCI_ERROR);

	/* If the PHB is broken, go away */
	if (p->state == PHB3_STATE_BROKEN)
		return;

	/*
	 * Mark the PHB has pending error so that the OS
	 * can handle it at late point.
	 */
	phb3_set_err_pending(p, true);
}

/* MSIs (OS owned) */
static const struct irq_source_ops phb3_msi_irq_ops = {
	.get_xive = phb3_msi_get_xive,
	.set_xive = phb3_msi_set_xive,
};

/* LSIs (OS owned) */
static const struct irq_source_ops phb3_lsi_irq_ops = {
	.get_xive = phb3_lsi_get_xive,
	.set_xive = phb3_lsi_set_xive,
};

/* Error LSIs (skiboot owned) */
static const struct irq_source_ops phb3_err_lsi_irq_ops = {
	.get_xive = phb3_lsi_get_xive,
	.set_xive = phb3_lsi_set_xive,
	.interrupt = phb3_err_interrupt,
};

static int64_t phb3_set_pe(struct phb *phb,
			   uint64_t pe_num,
                           uint64_t bdfn,
			   uint8_t bcompare,
			   uint8_t dcompare,
			   uint8_t fcompare,
			   uint8_t action)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t mask, val, tmp, idx;
	int32_t all = 0;
	uint16_t *rte;

	/* Sanity check */
	if (!p->tbl_rtt)
		return OPAL_HARDWARE;
	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (pe_num >= PHB3_MAX_PE_NUM || bdfn > 0xffff ||
	    bcompare > OpalPciBusAll ||
	    dcompare > OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare > OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_PARAMETER;

	/* Figure out the RID range */
	if (bcompare == OpalPciBusAny) {
		mask = 0x0;
		val  = 0x0;
		all  = 0x1;
	} else {
		tmp  = ((0x1 << (bcompare + 1)) - 1) << (15 - bcompare);
		mask = tmp;
		val  = bdfn & tmp;
	}

	if (dcompare == OPAL_IGNORE_RID_DEVICE_NUMBER)
		all = (all << 1) | 0x1;
	else {
		mask |= 0xf8;
		val  |= (bdfn & 0xf8);
	}

	if (fcompare == OPAL_IGNORE_RID_FUNCTION_NUMBER)
		all = (all << 1) | 0x1;
	else {
		mask |= 0x7;
		val  |= (bdfn & 0x7);
	}

	/* Map or unmap the RTT range */
	if (all == 0x7) {
		if (action == OPAL_MAP_PE) {
			for (idx = 0; idx < RTT_TABLE_ENTRIES; idx++)
				p->rte_cache[idx] = pe_num;
		} else {
			memset(p->rte_cache, 0xff, RTT_TABLE_SIZE);
		}
		memcpy((void *)p->tbl_rtt, p->rte_cache, RTT_TABLE_SIZE);
		out_be64(p->regs + PHB_RTC_INVALIDATE,
			 PHB_RTC_INVALIDATE_ALL);
	} else {
		rte = (uint16_t *)p->tbl_rtt;
		for (idx = 0; idx < RTT_TABLE_ENTRIES; idx++, rte++) {
			if ((idx & mask) != val)
				continue;
			p->rte_cache[idx] = (action ? pe_num : 0xffff);
			*rte = p->rte_cache[idx];

			/*
			 * We might not need invalidate RTC one by one since
			 * the RTT is expected to be updated in batch mode
			 * in host kernel.
			 */
			out_be64(p->regs + PHB_RTC_INVALIDATE,
				 SETFIELD(PHB_RTC_INVALIDATE_RID, 0ul, idx));
		}
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_set_peltv(struct phb *phb,
			      uint32_t parent_pe,
			      uint32_t child_pe,
			      uint8_t state)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint8_t *peltv;
	uint32_t idx, mask;

	/* Sanity check */
	if (!p->tbl_peltv)
		return OPAL_HARDWARE;
	if (parent_pe >= PHB3_MAX_PE_NUM || child_pe >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	/* Find index for parent PE */
	idx = parent_pe * (PHB3_MAX_PE_NUM / 8);
	idx += (child_pe / 8);
	mask = 0x1 << (7 - (child_pe % 8));

	peltv = (uint8_t *)p->tbl_peltv;
	peltv += idx;
	if (state) {
		*peltv |= mask;
		p->peltv_cache[idx] |= mask;
	} else {
		*peltv &= ~mask;
		p->peltv_cache[idx] &= ~mask;
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_link_state(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
	uint16_t lstat;
	int64_t rc;

	/* XXX Test for PHB in error state ? */

	/* Link is up, let's find the actual speed */
	if (!(reg & PHB_PCIE_DLP_TC_DL_LINKACT))
		return OPAL_SHPC_LINK_DOWN;

	rc = phb3_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_LSTAT,
				&lstat);
	if (rc < 0) {
		/* Shouldn't happen */
		PHBERR(p, "Failed to read link status\n");
		return OPAL_HARDWARE;
	}
	if (!(lstat & PCICAP_EXP_LSTAT_DLLL_ACT))
		return OPAL_SHPC_LINK_DOWN;

	return GETFIELD(PCICAP_EXP_LSTAT_WIDTH, lstat);
}

static int64_t phb3_power_state(struct phb __unused *phb)
{
	/* XXX Test for PHB in error state ? */

	/* XXX TODO - External power control ? */

	return OPAL_SHPC_POWER_ON;
}

static int64_t phb3_slot_power_off(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;
	if (p->state != PHB3_STATE_FUNCTIONAL)
		return OPAL_BUSY;

	/* XXX TODO - External power control ? */

	return OPAL_SUCCESS;
}

static int64_t phb3_slot_power_on(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;
	if (p->state != PHB3_STATE_FUNCTIONAL)
		return OPAL_BUSY;

	/* XXX TODO - External power control ? */

	return OPAL_SUCCESS;
}

static void phb3_setup_for_link_down(struct phb3 *p)
{
	uint32_t reg32;

	/* Mark link down */
	p->has_link = false;

	/* Mask PCIE port interrupts */
	out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN, 0xad42800000000000);

	/* Mask AER receiver error */
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_MASK, &reg32);
	reg32 |= PCIECAP_AER_CE_RECVR_ERR;
	phb3_pcicfg_write32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_MASK, reg32);
}

static void phb3_setup_for_link_up(struct phb3 *p)
{
	uint32_t reg32;
	
	/* Clear AER receiver error status */
	phb3_pcicfg_write32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_STATUS,
			    PCIECAP_AER_CE_RECVR_ERR);
	/* Unmask receiver error status in AER */
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_MASK, &reg32);
	reg32 &= ~PCIECAP_AER_CE_RECVR_ERR;
	phb3_pcicfg_write32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_MASK, reg32);

	/* Clear spurrious errors and enable PCIE port interrupts */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS, 0xffdfffffffffffff);
	out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN, 0xad5a800000000000);

	/* Mark link down */
	p->has_link = true;

	/* Don't block PCI-CFG */
	p->flags &= ~PHB3_CFG_BLOCKED;

	/*
	 * For complete reset, we might be required to restore
	 * bus numbers for PCI bridges.
	 */
	if (p->flags & PHB3_RESTORE_BUS_NUM) {
		p->flags &= ~PHB3_RESTORE_BUS_NUM;
		pci_restore_bridge_buses(&p->phb);
	}
}

static int64_t phb3_sm_link_poll(struct phb3 *p)
{
	uint64_t reg;

	/* This is the state machine to wait for the link to come
	 * up. Currently we just wait until we timeout, eventually
	 * we want to add retries and fallback to Gen1.
	 */
	switch(p->state) {
	case PHB3_STATE_WAIT_LINK_ELECTRICAL:
		/* Wait for the link electrical connection to be
		 * established (shorter timeout). This allows us to
		 * workaround spurrious presence detect on some machines
		 * without waiting 10s each time
		 *
		 * Note: We *also* check for the full link up bit here
		 * because simics doesn't seem to implement the electrical
		 * link bit at all
		 */
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg & (PHB_PCIE_DLP_INBAND_PRESENCE |
			   PHB_PCIE_DLP_TC_DL_LINKACT)) {
			PHBDBG(p, "Electrical link detected...\n");
			p->state = PHB3_STATE_WAIT_LINK;
			p->retries = PHB3_LINK_WAIT_RETRIES;
		} else if (p->retries-- == 0) {
			PHBDBG(p, "Timeout waiting for electrical link\n");
			PHBDBG(p, "DLP train control: 0x%016llx\n", reg);
			/* No link, we still mark the PHB as functional */
			p->state = PHB3_STATE_FUNCTIONAL;
			return OPAL_SUCCESS;
		}
		return phb3_set_sm_timeout(p, msecs_to_tb(100));
	case PHB3_STATE_WAIT_LINK:
		/* XXX I used the PHB_PCIE_LINK_MANAGEMENT register here but
		 *     simics doesn't seem to give me anything, so I've switched
		 *     to PCIE_DLP_TRAIN_CTL which appears more reliable
		 */
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg & PHB_PCIE_DLP_TC_DL_LINKACT) {
			/* Setup PHB for link up */
			phb3_setup_for_link_up(p);
			PHBDBG(p, "Link is up!\n");
			p->state = PHB3_STATE_FUNCTIONAL;
			return OPAL_SUCCESS;
		}
		if (p->retries-- == 0) {
			PHBDBG(p, "Timeout waiting for link up\n");
			PHBDBG(p, "DLP train control: 0x%016llx\n", reg);
			/* No link, we still mark the PHB as functional */
			p->state = PHB3_STATE_FUNCTIONAL;
			return OPAL_SUCCESS;
		}
		return phb3_set_sm_timeout(p, msecs_to_tb(100));
	default:
		/* How did we get here ? */
		assert(false);
	}
	return OPAL_HARDWARE;
}

static int64_t phb3_start_link_poll(struct phb3 *p)
{
	/*
	 * Wait for link up to 10s. However, we give up after
	 * only a second if the electrical connection isn't
	 * stablished according to the DLP link control register
	 */
	p->retries = PHB3_LINK_ELECTRICAL_RETRIES;
	p->state = PHB3_STATE_WAIT_LINK_ELECTRICAL;
	return phb3_set_sm_timeout(p, msecs_to_tb(100));
}

static int64_t phb3_sm_hot_reset(struct phb3 *p)
{
	uint16_t brctl;

	switch (p->state) {
	case PHB3_STATE_FUNCTIONAL:
		/* We need do nothing with available slot */
		if (phb3_presence_detect(&p->phb) != OPAL_SHPC_DEV_PRESENT) {
			PHBDBG(p, "Slot hreset: no device\n");
			return OPAL_CLOSED;
		}

		/* Prepare for link going down */
		phb3_setup_for_link_down(p);

		/* Turn on hot reset */
		phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl |= PCI_CFG_BRCTL_SECONDARY_RESET;
		phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		PHBDBG(p, "Slot hreset: assert reset\n");

		p->state = PHB3_STATE_HRESET_DELAY;
		return phb3_set_sm_timeout(p, secs_to_tb(1));
	case PHB3_STATE_HRESET_DELAY:
		/* Turn off hot reset */
		phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		PHBDBG(p, "Slot hreset: deassert reset\n");

		/*
		 * Due to some oddball adapters bouncing the link
		 * training a couple of times, we wait for a full second
		 * before we start checking the link status, otherwise
		 * we can get a spurrious link down interrupt which
		 * causes us to EEH immediately.
		 */
		p->state = PHB3_STATE_HRESET_DELAY2;
		return phb3_set_sm_timeout(p, secs_to_tb(1));
	case PHB3_STATE_HRESET_DELAY2:
		return phb3_start_link_poll(p);
	default:
		PHBDBG(p, "Slot hreset: wrong state %d\n", p->state);
		break;
	}

	p->state = PHB3_STATE_FUNCTIONAL;
	return OPAL_HARDWARE;
}

static int64_t phb3_hot_reset(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->state != PHB3_STATE_FUNCTIONAL) {
		PHBDBG(p, "phb3_hot_reset: wrong state %d\n",
		       p->state);
		return OPAL_HARDWARE;
	}

	p->flags |= PHB3_CFG_BLOCKED;
	return phb3_sm_hot_reset(p);
}

static int64_t phb3_sm_fundamental_reset(struct phb3 *p)
{
	uint64_t reg;


	/*
	 * Check if there's something connected. We do that here
	 * instead of the switch case below because we want to do
	 * that before we test the skip_perst
	 */
	if (p->state == PHB3_STATE_FUNCTIONAL &&
	    phb3_presence_detect(&p->phb) != OPAL_SHPC_DEV_PRESENT) {
		PHBDBG(p, "Slot freset: no device\n");
		return OPAL_CLOSED;
	}

	/* Handle boot time skipping of reset */
	if (p->skip_perst && p->state == PHB3_STATE_FUNCTIONAL) {
		PHBINF(p, "Cold boot, skipping PERST assertion\n");
		p->state = PHB3_STATE_FRESET_ASSERT_DELAY;
		/* PERST skipping happens only once */
		p->skip_perst = false;
	}

	switch(p->state) {
	case PHB3_STATE_FUNCTIONAL:
		PHBINF(p, "Performing PERST...\n");

		/* Prepare for link going down */
		phb3_setup_for_link_down(p);

		/* Assert PERST */
		reg = in_be64(p->regs + PHB_RESET);
		reg &= ~0x2000000000000000ul;
		out_be64(p->regs + PHB_RESET, reg);
		PHBDBG(p, "Slot freset: Asserting PERST\n");

		/* XXX Check delay for PERST... doing 1s for now */
		p->state = PHB3_STATE_FRESET_ASSERT_DELAY;
		return phb3_set_sm_timeout(p, secs_to_tb(1));

	case PHB3_STATE_FRESET_ASSERT_DELAY:
		/* Deassert PERST */
		reg = in_be64(p->regs + PHB_RESET);
		reg |= 0x2000000000000000ul;
		out_be64(p->regs + PHB_RESET, reg);
		PHBDBG(p, "Slot freset: Deasserting PERST\n");

		p->state = PHB3_STATE_FRESET_DEASSERT_DELAY;
		/* CAPP fpga requires 1s to flash before polling link */
		return phb3_set_sm_timeout(p, secs_to_tb(1));

	case PHB3_STATE_FRESET_DEASSERT_DELAY:
		/* Switch to generic link poll state machine */
		return phb3_start_link_poll(p);

	default:
		PHBDBG(p, "Slot freset: wrong state %d\n",
		       p->state);
		break;
	}

	p->state = PHB3_STATE_FUNCTIONAL;
	return OPAL_HARDWARE;
}

static int64_t phb3_fundamental_reset(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->state != PHB3_STATE_FUNCTIONAL) {
		PHBDBG(p, "phb3_fundamental_reset: wrong state %d\n", p->state);
		return OPAL_HARDWARE;
	}

	p->flags |= PHB3_CFG_BLOCKED;
	return phb3_sm_fundamental_reset(p);
}

static void do_capp_recovery_scoms(struct phb3 *phb);
/*
 * The OS is expected to do fundamental reset after complete
 * reset to make sure the PHB could be recovered from the
 * fenced state. However, the OS needn't do that explicitly
 * since fundamental reset will be done automatically while
 * powering on the PHB.
 *
 *
 * Usually, we need power off/on the PHB. That includes the
 * fundamental reset. However, we don't know how to control
 * the power stuff yet. So skip that and do fundamental reset
 * directly after reinitialization the hardware.
 */
static int64_t phb3_sm_complete_reset(struct phb3 *p)
{
	uint64_t cqsts, val;

	switch (p->state) {
	case PHB3_STATE_FENCED:
	case PHB3_STATE_FUNCTIONAL:

		/* do steps 3-5 of capp recovery procedure */
		if (p->flags & PHB3_CAPP_RECOVERY)
			do_capp_recovery_scoms(p);

		/*
		 * The users might be doing error injection through PBCQ
		 * Error Inject Control Register. Without clearing that,
		 * we will get recrusive error during recovery and it will
		 * fail eventually.
		 */
		xscom_write(p->chip_id, p->pe_xscom + 0xa, 0x0ul);

		/*
		 * We might have escalated frozen state on non-existing PE
		 * to fenced PHB. For the case, the PHB isn't fenced in the
		 * hardware level and it's not safe to do ETU reset. So we
		 * have to force fenced PHB prior to ETU reset.
		 */
		if (!phb3_fenced(p))
			xscom_write(p->chip_id, p->pe_xscom + 0x2, 0x000000f000000000ull);

		/* Clear errors in NFIR and raise ETU reset */
		xscom_read(p->chip_id, p->pe_xscom + 0x0, &p->nfir_cache);

		xscom_read(p->chip_id, p->spci_xscom + 1, &val);/* HW275117 */
		xscom_write(p->chip_id, p->pci_xscom + 0xa,
			    0x8000000000000000);
		p->state = PHB3_STATE_CRESET_WAIT_CQ;
		p->retries = 500;
		return phb3_set_sm_timeout(p, msecs_to_tb(10));
	case PHB3_STATE_CRESET_WAIT_CQ:
		xscom_read(p->chip_id, p->pe_xscom + 0x1c, &val);
		xscom_read(p->chip_id, p->pe_xscom + 0x1d, &val);
		xscom_read(p->chip_id, p->pe_xscom + 0x1e, &val);
		xscom_read(p->chip_id, p->pe_xscom + 0xf, &cqsts);
		if (!(cqsts & 0xC000000000000000)) {
			xscom_write(p->chip_id, p->pe_xscom + 0x1, ~p->nfir_cache);

			p->state = PHB3_STATE_CRESET_REINIT;
			return phb3_set_sm_timeout(p, msecs_to_tb(100));
		}

		if (p->retries-- == 0) {
			PHBERR(p, "Timeout waiting for pending transaction\n");
			goto error;
		}
		return phb3_set_sm_timeout(p, msecs_to_tb(10));
	case PHB3_STATE_CRESET_REINIT:
		p->flags &= ~PHB3_AIB_FENCED;
		p->flags &= ~PHB3_CAPP_RECOVERY;
		phb3_init_hw(p);

		p->state = PHB3_STATE_CRESET_FRESET;
		return phb3_set_sm_timeout(p, msecs_to_tb(100));
	case PHB3_STATE_CRESET_FRESET:
		p->state = PHB3_STATE_FUNCTIONAL;
		p->flags |= PHB3_CFG_BLOCKED;
		return phb3_sm_fundamental_reset(p);
	default:
		assert(false);
	}

	/* Mark the PHB as dead and expect it to be removed */
error:
	p->state = PHB3_STATE_BROKEN;
	return OPAL_PARAMETER;
}

static int64_t phb3_complete_reset(struct phb *phb, uint8_t assert)
{
	struct phb3 *p = phb_to_phb3(phb);

	if ((assert == OPAL_ASSERT_RESET &&
	    p->state != PHB3_STATE_FUNCTIONAL &&
	    p->state != PHB3_STATE_FENCED) ||
	    (assert == OPAL_DEASSERT_RESET &&
	    p->state != PHB3_STATE_FUNCTIONAL)) {
		PHBERR(p, "phb3_creset: wrong state %d\n",
		       p->state);
		return OPAL_HARDWARE;
	}

	/* Block PCI-CFG access */
	p->flags |= PHB3_CFG_BLOCKED;

	if (assert == OPAL_ASSERT_RESET) {
		PHBINF(p, "Starting PHB reset sequence\n");
		return phb3_sm_complete_reset(p);
	} else {
		/* Restore bus numbers for bridges */
		p->flags |= PHB3_RESTORE_BUS_NUM;

		return phb3_sm_hot_reset(p);
	}
}

static int64_t phb3_poll(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t now = mftb();

	if (p->state == PHB3_STATE_FUNCTIONAL)
		return OPAL_SUCCESS;

	/* Check timer */
	if (p->delay_tgt_tb &&
	    tb_compare(now, p->delay_tgt_tb) == TB_ABEFOREB)
		return p->delay_tgt_tb - now;

	/* Expired (or not armed), clear it */
	p->delay_tgt_tb = 0;

	/* Dispatch to the right state machine */
	switch(p->state) {
	case PHB3_STATE_HRESET_DELAY:
	case PHB3_STATE_HRESET_DELAY2:
		return phb3_sm_hot_reset(p);
	case PHB3_STATE_FRESET_ASSERT_DELAY:
	case PHB3_STATE_FRESET_DEASSERT_DELAY:
		return phb3_sm_fundamental_reset(p);
	case PHB3_STATE_CRESET_WAIT_CQ:
	case PHB3_STATE_CRESET_REINIT:
	case PHB3_STATE_CRESET_FRESET:
		return phb3_sm_complete_reset(p);
	case PHB3_STATE_WAIT_LINK_ELECTRICAL:
	case PHB3_STATE_WAIT_LINK:
		return phb3_sm_link_poll(p);
	default:
		PHBDBG(p, "phb3_poll: wrong state %d\n", p->state);
		break;
	}

	/* Unknown state, could be a HW error */
	return OPAL_HARDWARE;
}

static int64_t phb3_eeh_freeze_status(struct phb *phb, uint64_t pe_number,
				      uint8_t *freeze_state,
				      uint16_t *pci_error_type,
				      uint16_t *severity,
				      uint64_t *phb_status)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t peev_bit = PPC_BIT(pe_number & 0x3f);
	uint64_t peev, pesta, pestb;

	/* Defaults: not frozen */
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	*pci_error_type = OPAL_EEH_NO_ERROR;

	/* Check dead */
	if (p->state == PHB3_STATE_BROKEN) {
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_DEAD;
		return OPAL_HARDWARE;
	}

	/* Check fence and CAPP recovery */
	if (phb3_fenced(p) || (p->flags & PHB3_CAPP_RECOVERY)) {
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_FENCED;
		goto bail;
	}

	/* Check the PEEV */
	phb3_ioda_sel(p, IODA2_TBL_PEEV, pe_number / 64, false);
	peev = in_be64(p->regs + PHB_IODA_DATA0);
	if (!(peev & peev_bit))
		return OPAL_SUCCESS;

	/* Indicate that we have an ER pending */
	phb3_set_err_pending(p, true);
	if (severity)
		*severity = OPAL_EEH_SEV_PE_ER;

	/* Read the PESTA & PESTB */
	phb3_ioda_sel(p, IODA2_TBL_PESTA, pe_number, false);
	pesta = in_be64(p->regs + PHB_IODA_DATA0);
	phb3_ioda_sel(p, IODA2_TBL_PESTB, pe_number, false);
	pestb = in_be64(p->regs + PHB_IODA_DATA0);

	/* Convert them */
	if (pesta & IODA2_PESTA_MMIO_FROZEN)
		*freeze_state |= OPAL_EEH_STOPPED_MMIO_FREEZE;
	if (pestb & IODA2_PESTB_DMA_STOPPED)
		*freeze_state |= OPAL_EEH_STOPPED_DMA_FREEZE;

bail:
	if (phb_status)
		phb3_read_phb_status(p,
			(struct OpalIoPhb3ErrorData *)phb_status);

	return OPAL_SUCCESS;
}

static int64_t phb3_eeh_freeze_clear(struct phb *phb, uint64_t pe_number,
				     uint64_t eeh_action_token)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t err, peev[4];
	int32_t i;
	bool frozen_pe = false;

	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* Summary. If nothing, move to clearing the PESTs which can
	 * contain a freeze state from a previous error or simply set
	 * explicitely by the user
	 */
	err = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (err == 0xffffffffffffffff) {
		if (phb3_fenced(p)) {
			PHBERR(p, "eeh_freeze_clear on fenced PHB\n");
			return OPAL_HARDWARE;
		}
	}
	if (err != 0)
		phb3_err_ER_clear(p);

	/*
	 * We have PEEV in system memory. It would give more performance
	 * to access that directly.
	 */
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO) {
		phb3_ioda_sel(p, IODA2_TBL_PESTA, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_DMA) {
		phb3_ioda_sel(p, IODA2_TBL_PESTB, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}


	/* Update ER pending indication */
	phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
	for (i = 0; i < ARRAY_SIZE(peev); i++) {
		peev[i] = in_be64(p->regs + PHB_IODA_DATA0);
		if (peev[i]) {
			frozen_pe = true;
			break;
		}
	}
	if (frozen_pe) {
		p->err.err_src	 = PHB3_ERR_SRC_PHB;
		p->err.err_class = PHB3_ERR_CLASS_ER;
		p->err.err_bit   = -1;
		phb3_set_err_pending(p, true);
	} else
		phb3_set_err_pending(p, false);

	return OPAL_SUCCESS;
}

static int64_t phb3_eeh_freeze_set(struct phb *phb, uint64_t pe_number,
                                   uint64_t eeh_action_token)
{
        struct phb3 *p = phb_to_phb3(phb);
        uint64_t data;

	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;

	if (pe_number >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	if (eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_MMIO &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_DMA &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_ALL)
		return OPAL_PARAMETER;

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_MMIO) {
		phb3_ioda_sel(p, IODA2_TBL_PESTA, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA2_PESTA_MMIO_FROZEN;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_DMA) {
		phb3_ioda_sel(p, IODA2_TBL_PESTB, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA2_PESTB_DMA_STOPPED;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_eeh_next_error(struct phb *phb,
				   uint64_t *first_frozen_pe,
				   uint16_t *pci_error_type,
				   uint16_t *severity)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t fir, peev[4];
	uint32_t cfg32;
	int32_t i, j;

	/* If the PHB is broken, we needn't go forward */
	if (p->state == PHB3_STATE_BROKEN) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_DEAD;
		return OPAL_SUCCESS;
	}

	if ((p->flags & PHB3_CAPP_RECOVERY)) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_FENCED;
		return OPAL_SUCCESS;
	}

	/*
	 * Check if we already have pending errors. If that's
	 * the case, then to get more information about the
	 * pending errors. Here we try PBCQ prior to PHB.
	 */
	if (phb3_err_pending(p) &&
	    !phb3_err_check_pbcq(p) &&
	    !phb3_err_check_lem(p))
		phb3_set_err_pending(p, false);

	/* Clear result */
	*pci_error_type  = OPAL_EEH_NO_ERROR;
	*severity	 = OPAL_EEH_SEV_NO_ERROR;
	*first_frozen_pe = (uint64_t)-1;

	/* Check frozen PEs */
	if (!phb3_err_pending(p)) {
		phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
		for (i = 0; i < ARRAY_SIZE(peev); i++) {
			peev[i] = in_be64(p->regs + PHB_IODA_DATA0);
			if (peev[i]) {
				p->err.err_src	 = PHB3_ERR_SRC_PHB;
				p->err.err_class = PHB3_ERR_CLASS_ER;
				p->err.err_bit	 = -1;
				phb3_set_err_pending(p, true);
				break;
			}
		}
        }

	/* Mapping errors */
	if (phb3_err_pending(p)) {
		/*
		 * If the frozen PE is caused by a malfunctioning TLP, we
		 * need reset the PHB. So convert ER to PHB-fatal error
		 * for the case.
		 */
		if (p->err.err_class == PHB3_ERR_CLASS_ER) {
			fir = phb3_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
			if (fir & PPC_BIT(60)) {
				phb3_pcicfg_read32(&p->phb, 0,
					p->aercap + PCIECAP_AER_UE_STATUS, &cfg32);
				if (cfg32 & PCIECAP_AER_UE_MALFORMED_TLP)
					p->err.err_class = PHB3_ERR_CLASS_FENCED;
			}
		}

		switch (p->err.err_class) {
		case PHB3_ERR_CLASS_DEAD:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_PHB_DEAD;
			break;
		case PHB3_ERR_CLASS_FENCED:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_PHB_FENCED;
			break;
		case PHB3_ERR_CLASS_ER:
			*pci_error_type = OPAL_EEH_PE_ERROR;
			*severity = OPAL_EEH_SEV_PE_ER;

			phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
			for (i = 0; i < ARRAY_SIZE(peev); i++)
				peev[i] = in_be64(p->regs + PHB_IODA_DATA0);
			for (i = ARRAY_SIZE(peev) - 1; i >= 0; i--) {
				for (j = 0; j < 64; j++) {
					if (peev[i] & PPC_BIT(j)) {
						*first_frozen_pe = i * 64 + j;
						break;
					}
				}

				if (*first_frozen_pe != (uint64_t)(-1))
					break;
			}

			/* No frozen PE ? */
			if (*first_frozen_pe == (uint64_t)-1) {
				*pci_error_type = OPAL_EEH_NO_ERROR;
				*severity = OPAL_EEH_SEV_NO_ERROR;
				phb3_set_err_pending(p, false);
			}

                        break;
		case PHB3_ERR_CLASS_INF:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_INF;
			break;
		default:
			*pci_error_type = OPAL_EEH_NO_ERROR;
			*severity = OPAL_EEH_SEV_NO_ERROR;
			phb3_set_err_pending(p, false);
		}
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_err_inject_finalize(struct phb3 *p, uint64_t addr,
					uint64_t mask, uint64_t ctrl,
					bool is_write)
{
	if (is_write)
		ctrl |= PHB_PAPR_ERR_INJ_CTL_WR;
	else
		ctrl |= PHB_PAPR_ERR_INJ_CTL_RD;

	out_be64(p->regs + PHB_PAPR_ERR_INJ_ADDR, addr);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_MASK, mask);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, ctrl);

	return OPAL_SUCCESS;
}

static int64_t phb3_err_inject_mem32(struct phb3 *p, uint32_t pe_no,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	uint64_t base, len, segstart, segsize;
	uint64_t a, m;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_OUTB;
	uint32_t index;

	segsize = (M32_PCI_SIZE / PHB3_MAX_PE_NUM);
	a = base = len = 0x0ull;

	for (index = 0; index < PHB3_MAX_PE_NUM; index++) {
		if (GETFIELD(IODA2_M32DT_PE, p->m32d_cache[index]) != pe_no)
			continue;

		/* Obviously, we can't support discontiguous segments.
		 * We have to pick the first batch of contiguous segments
		 * for that case
		 */
		segstart = p->mm1_base + segsize * index;
		if (!len) {
			base = segstart;
			len = segsize;
		} else if ((base + len) == segstart) {
			len += segsize;
		}

		/* Check the specified address is valid one */
		if (addr >= segstart && addr < (segstart + segsize)) {
			a = addr;
			break;
		}
	}

	/* No MM32 segments assigned to the PE */
	if (!len)
		return OPAL_PARAMETER;

	/* Specified address is out of range */
	if (!a) {
		a = base;
		len = len & ~(len - 1);
		m = ~(len - 1);
	} else {
		m = mask;
	}

	a = SETFIELD(PHB_PAPR_ERR_INJ_ADDR_MMIO, 0x0ull, a);
	m = SETFIELD(PHB_PAPR_ERR_INJ_MASK_MMIO, 0x0ull, m);

	return phb3_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t phb3_err_inject_mem64(struct phb3 *p, uint32_t pe_no,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	uint64_t base, len, segstart, segsize;
	uint64_t cache, a, m;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_OUTB;
	uint32_t index;

	a = base = len = 0x0ull;
	for (index = 0; index < ARRAY_SIZE(p->m64b_cache); index++) {
		cache = p->m64b_cache[index];
		if (!(cache & IODA2_M64BT_ENABLE))
			continue;

		if (cache & IODA2_M64BT_SINGLE_PE) {
			if (GETFIELD(IODA2_M64BT_PE_HI, cache) != (pe_no >> 5) ||
			    GETFIELD(IODA2_M64BT_PE_LOW, cache) != (pe_no & 0x1f))
				continue;

			segstart = GETFIELD(IODA2_M64BT_SINGLE_BASE, cache);
			segstart <<= 25;	/* 32MB aligned */
			segsize = GETFIELD(IODA2_M64BT_SINGLE_MASK, cache);
			segsize = (0x2000000ull - segsize) << 25;
		} else {
			segstart = GETFIELD(IODA2_M64BT_BASE, cache);
			segstart <<= 20;	/* 1MB aligned */
			segsize = GETFIELD(IODA2_M64BT_MASK, cache);
			segsize = (0x40000000ull - segsize) << 20;

			segsize /= PHB3_MAX_PE_NUM;
			segstart = segstart + segsize * pe_no;
		}

		/* We expect contiguous segments. Otherwise, to
		 * pick the bigger one, which has more possibility
		 * to be accessed
		 */
		if (!len) {
			base = segstart;
			len = segsize;
		} else if ((base + len) == segstart) {
			len += segsize;
		} else if (segsize > len) {
			base = segstart;
			len = segsize;
		}

		/* Specified address is valid one */
		if (addr >= segstart && addr < (segstart + segsize)) {
			a = addr;
			break;
		}
	}

	/* No MM64 segments assigned to the PE */
	if (!len)
		return OPAL_PARAMETER;

	/* Address specified or calculated */
	if (!a) {
		a = base;
		len = len & ~(len - 1);
		m = ~(len - 1);
	} else {
		m = mask;
	}

	a = SETFIELD(PHB_PAPR_ERR_INJ_ADDR_MMIO, 0x0ull, a);
	m = SETFIELD(PHB_PAPR_ERR_INJ_MASK_MMIO, 0x0ull, m);

	return phb3_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t phb3_err_inject_cfg(struct phb3 *p, uint32_t pe_no,
				   uint64_t addr, uint64_t mask,
				   bool is_write)
{
	uint64_t a, m, prefer;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_CFG;
	int bus_no, bdfn;

	a = 0xffffull;
	prefer = 0xffffull;
	for (bdfn = 0; bdfn < RTT_TABLE_ENTRIES; bdfn++) {
		if (p->rte_cache[bdfn] != pe_no)
			continue;

		/* Select minimal bus number as PE
		 * primary bus number
		 */
		bus_no = (bdfn >> 8);
		if (prefer == 0xffffull)
			prefer = SETFIELD(PHB_PAPR_ERR_INJ_MASK_CFG, 0x0ull, bus_no);

		/* Address should no greater than max bus
		 * number within PE
		 */
		if ((GETFIELD(PHB_PAPR_ERR_INJ_MASK_CFG, addr) == bus_no)) {
			a = addr;
			break;
		}
	}

	/* Invalid PE number */
	if (prefer == 0xffffull)
		return OPAL_PARAMETER;

	/* Specified address is out of range */
	if (a == 0xffffull) {
		a = prefer;
		m = PHB_PAPR_ERR_INJ_MASK_CFG_MASK;
	} else {
		m = mask;
	}

	return phb3_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t phb3_err_inject_dma(struct phb3 *p, uint32_t pe_no,
				   uint64_t addr, uint64_t mask,
				   bool is_write, bool is_64bits)
{
	uint32_t index, page_size;
	uint64_t tve, table_entries;
	uint64_t base, start, end, len, a, m;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_INB;

	/* TVE index and base address */
	if (!is_64bits) {
		index = (pe_no << 1);
		base = 0x0ull;
	} else {
		index = ((pe_no << 1) + 1);
		base = (0x1ull << 59);
	}

	/* Raw data of table entries and page size */
	tve = p->tve_cache[index];
	table_entries = GETFIELD(IODA2_TVT_TCE_TABLE_SIZE, tve);
	table_entries = (0x1ull << (table_entries + 8));
	page_size = GETFIELD(IODA2_TVT_IO_PSIZE, tve);
	if (!page_size && !(tve & PPC_BIT(51)))
		return OPAL_UNSUPPORTED;

	/* Check the page size */
	switch (page_size) {
	case 0:	/* bypass */
		start = ((tve & (0x3ull << 10)) << 14) |
			((tve & (0xffffffull << 40)) >> 40);
		end   = ((tve & (0x3ull << 8)) << 16) |
			((tve & (0xffffffull << 16)) >> 16);

		/* 16MB aligned size */
		len   = (end - start) << 24;
		break;
	case 5:  /* 64KB */
		len = table_entries * 0x10000ull;
		break;
	case 13: /* 16MB */
		len = table_entries * 0x1000000ull;
		break;
	case 17: /* 256MB */
		len = table_entries * 0x10000000ull;
		break;
	case 1:  /* 4KB */
	default:
		len = table_entries * 0x1000ull;
	}

	/* The specified address is in range */
	if (addr && addr >= base && addr < (base + len)) {
		a = addr;
		m = mask;
	} else {
		a = base;
		len = len & ~(len - 1);
		m = ~(len - 1);
	}

	return phb3_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t phb3_err_inject_dma32(struct phb3 *p, uint32_t pe_no,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	return phb3_err_inject_dma(p, pe_no, addr, mask, is_write, false);
}

static int64_t phb3_err_inject_dma64(struct phb3 *p, uint32_t pe_no,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	return phb3_err_inject_dma(p, pe_no, addr, mask, is_write, true);	
}

static int64_t phb3_err_inject(struct phb *phb, uint32_t pe_no,
			       uint32_t type, uint32_t func,
			       uint64_t addr, uint64_t mask)
{
	struct phb3 *p = phb_to_phb3(phb);
	int64_t (*handler)(struct phb3 *p, uint32_t pe_no,
			   uint64_t addr, uint64_t mask, bool is_write);
	bool is_write;

	/* How could we get here without valid RTT? */
	if (!p->tbl_rtt)
		return OPAL_HARDWARE;

	/* We can't inject error to the reserved PE#0 */
	if (pe_no == 0x0 || pe_no >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	/* Clear leftover from last time */
	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);

	switch (func) {
	case OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_DATA:
		is_write = false;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb3_err_inject_mem64;
		else
			handler = phb3_err_inject_mem32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_DATA:
		is_write = true;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb3_err_inject_mem64;
		else
			handler = phb3_err_inject_mem32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_DATA:
		is_write = false;
		handler = phb3_err_inject_cfg;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_DATA:
		is_write = true;
		handler = phb3_err_inject_cfg;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_DATA:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_MASTER:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_TARGET:
		is_write = false;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb3_err_inject_dma64;
		else
			handler = phb3_err_inject_dma32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_DATA:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_MASTER:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_TARGET:
		is_write = true;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb3_err_inject_dma64;
		else
			handler = phb3_err_inject_dma32;
		break;
	default:
		return OPAL_PARAMETER;
	}

	return handler(p, pe_no, addr, mask, is_write);
}

static int64_t phb3_get_diag_data(struct phb *phb,
				  void *diag_buffer,
				  uint64_t diag_buffer_len)
{
	struct phb3 *p = phb_to_phb3(phb);
	struct OpalIoPhb3ErrorData *data = diag_buffer;

	if (diag_buffer_len < sizeof(struct OpalIoPhb3ErrorData))
		return OPAL_PARAMETER;
	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;

	/*
	 * Dummy check for fence so that phb3_read_phb_status knows
	 * whether to use ASB or AIB
	 */
	phb3_fenced(p);
	phb3_read_phb_status(p, data);

	/*
	 * We're running to here probably because of errors
	 * (INF class). For that case, we need clear the error
	 * explicitly.
	 */
	if (phb3_err_pending(p) &&
	    p->err.err_class == PHB3_ERR_CLASS_INF &&
	    p->err.err_src == PHB3_ERR_SRC_PHB) {
		phb3_err_ER_clear(p);
		phb3_set_err_pending(p, false);
	}

	return OPAL_SUCCESS;
}

static uint64_t capp_fsp_lid_load(struct phb3 *p)
{
#define CAPP_UCODE_MURANO_20 0x80a02002
#define CAPP_UCODE_MURANO_21 0x80a02001
#define CAPP_UCODE_MAX_SIZE 0x20000
	uint32_t lid_no;
	void *data;
	size_t size;
	int rc;

	switch (p->rev) {
	case PHB3_REV_MURANO_DD20:
		lid_no = CAPP_UCODE_MURANO_20;
		break;
	case PHB3_REV_MURANO_DD21:
		lid_no = CAPP_UCODE_MURANO_21;
		break;
	default:
		prerror("PHB3: No CAPP LID for this PHB version\n");
		return 0;
	}

	data = malloc(CAPP_UCODE_MAX_SIZE);
	if (!data) {
		prerror("PHB3: Failed to allocated memory for capp ucode lid\n");
		return 0;
	}

	lid_no = fsp_adjust_lid_side(lid_no);
	size = CAPP_UCODE_MAX_SIZE;
	rc = fsp_fetch_data(0, FSP_DATASET_NONSP_LID, lid_no, 0, data, &size);
	if (rc) {
		prerror("PHB3: Error %d loading capp ucode lid\n", rc);
		free(data);
		return 0;
	}

	return (uint64_t)data;
}

static int64_t capp_load_ucode(struct phb3 *p)
{

	struct capp_ucode_lid_hdr *ucode_hdr;
	struct capp_ucode_data_hdr *data_hdr;
	struct capp_lid_hdr *lid_hdr;
	uint64_t data, *val;
	int size_read = 0;
	int tmp;
	int i;

	/* if fsp not present p->ucode_base gotten from device tree */
	if (fsp_present() && (p->capp_ucode_base == 0))
		p->capp_ucode_base = capp_fsp_lid_load(p);

	if (p->capp_ucode_base == 0) {
		PHBERR(p, "capp ucode base address not set\n");
		return OPAL_HARDWARE;
	}

	PHBINF(p, "Loading capp microcode @%llx\n", p->capp_ucode_base);
	lid_hdr = (struct capp_lid_hdr *)p->capp_ucode_base;
	if (lid_hdr->eyecatcher != 0x434150504c494448)
		/* lid header not present due to older fw or bml boot */
		ucode_hdr = (struct capp_ucode_lid_hdr *)(p->capp_ucode_base);
	else
		ucode_hdr = (struct capp_ucode_lid_hdr *)(p->capp_ucode_base +
			lid_hdr->ucode_offset);

	if (ucode_hdr->eyecatcher != 0x43415050554C4944) {
		PHBERR(p, "capi ucode lid header eyecatcher not found\n");
		return OPAL_HARDWARE;
	}

	data_hdr = (struct capp_ucode_data_hdr *)(ucode_hdr + 1);
	while (size_read < ucode_hdr->data_size) {
		if (data_hdr->eyecatcher != 0x4341505055434F44) {
			PHBERR(p, "capi ucode data header eyecatcher not found!\n");
			return OPAL_HARDWARE;
		}

		val = (uint64_t *)(data_hdr + 1);
		if (data_hdr->reg == apc_master_cresp) {
			xscom_write(p->chip_id, CAPP_APC_MASTER_ARRAY_ADDR_REG, 0);
			for (i = 0; i < data_hdr->num_data_chunks; i++)
				xscom_write(p->chip_id, CAPP_APC_MASTER_ARRAY_WRITE_REG, *val++);
			xscom_read(p->chip_id, CAPP_APC_MASTER_ARRAY_ADDR_REG, &data);
		} else if (data_hdr->reg == apc_master_uop_table) {
			xscom_write(p->chip_id, CAPP_APC_MASTER_ARRAY_ADDR_REG, 0x180ULL << 52);
			for (i = 0; i < data_hdr->num_data_chunks; i++)
				xscom_write(p->chip_id, CAPP_APC_MASTER_ARRAY_WRITE_REG, *val++);
			xscom_read(p->chip_id, CAPP_APC_MASTER_ARRAY_ADDR_REG, &data);
		} else if (data_hdr->reg == snp_ttype) {
			xscom_write(p->chip_id, CAPP_SNP_ARRAY_ADDR_REG, 0x5000ULL << 48);
			for (i = 0; i < data_hdr->num_data_chunks; i++)
				xscom_write(p->chip_id, CAPP_SNP_ARRAY_WRITE_REG, *val++);
			xscom_read(p->chip_id, CAPP_SNP_ARRAY_ADDR_REG, &data);
		} else if (data_hdr->reg == snp_uop_table) {
			xscom_write(p->chip_id, CAPP_SNP_ARRAY_ADDR_REG, 0x4000ULL << 48);
			for (i = 0; i < data_hdr->num_data_chunks; i++)
				xscom_write(p->chip_id, CAPP_SNP_ARRAY_WRITE_REG, *val++);
			xscom_read(p->chip_id, CAPP_SNP_ARRAY_ADDR_REG, &data);
		}

		size_read += sizeof(*data_hdr) + data_hdr->num_data_chunks * 8;
		tmp = data_hdr->num_data_chunks;
		data_hdr++;
		data_hdr = (struct capp_ucode_data_hdr *)((uint64_t *)data_hdr + tmp);
	}

	p->capp_ucode_loaded = true;
	return OPAL_SUCCESS;
}

static void phb3_init_capp_regs(struct phb3 *p)
{
	/* writing field vals directly */
	uint64_t reg;

	xscom_read(p->chip_id, APC_MASTER_PB_CTRL, &reg);
	reg |= PPC_BIT(3);
	xscom_write(p->chip_id, APC_MASTER_PB_CTRL, reg);
	/*      port0    port1
	 * 100   PHB0   disabled
	 * we're told it's the same for Venice
         */
	xscom_write(p->chip_id, APC_MASTER_CAPI_CTRL, 	0x4070000000000000);

	/* tlb and mmio */
	xscom_write(p->chip_id, TRANSPORT_CONTROL, 	0x4028000104000000);

	xscom_write(p->chip_id, CANNED_PRESP_MAP0, 	0);
	xscom_write(p->chip_id, CANNED_PRESP_MAP1, 	0xFFFFFFFF00000000);
	xscom_write(p->chip_id, CANNED_PRESP_MAP2, 	0);

	/* error recovery */
	xscom_write(p->chip_id, CAPP_ERR_STATUS_CTRL,  	0);

	xscom_write(p->chip_id, FLUSH_SUE_STATE_MAP,   	0x1DC20B6600000000);
	xscom_write(p->chip_id, CAPP_EPOCH_TIMER_CTRL, 	0xC0000000FFF0FFE0);
	xscom_write(p->chip_id, FLUSH_UOP_CONFIG1, 	0xB188280728000000);
	xscom_write(p->chip_id, FLUSH_UOP_CONFIG2, 	0xB188400F00000000);
	xscom_write(p->chip_id, SNOOP_CAPI_CONFIG, 	0xA1F0000000000000);
}

/* override some inits with CAPI defaults */
static void phb3_init_capp_errors(struct phb3 *p)
{
	out_be64(p->regs + PHB_ERR_AIB_FENCE_ENABLE,       0xffffffdd0c80ffc0);
	out_be64(p->regs + PHB_OUT_ERR_AIB_FENCE_ENABLE,   0x9cf3fe08f8dc700f);
	out_be64(p->regs + PHB_INA_ERR_AIB_FENCE_ENABLE,   0xffff57fbff01ffde);
	out_be64(p->regs + PHB_INB_ERR_AIB_FENCE_ENABLE,   0xfcffe0fbff7ff0ec);
}

static int64_t phb3_set_capi_mode(struct phb *phb, uint64_t mode,
				  uint64_t pe_number)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t reg;
	int i;

	xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL, &reg);
	if ((reg & PPC_BIT(5))) {
		PHBERR(p, "CAPP recovery failed (%016llx)\n", reg);
		return OPAL_HARDWARE;
	} else if ((reg & PPC_BIT(0)) && (!(reg & PPC_BIT(1)))) {
		PHBDBG(p, "CAPP recovery in progress\n");
		return OPAL_BUSY;
	}

	xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL, &reg);
	if ((reg & PPC_BIT(5))) {
		PHBERR(p, "CAPP recovery failed (%016llx)\n", reg);
		return OPAL_HARDWARE;
	} else if ((reg & PPC_BIT(0)) && (!(reg & PPC_BIT(1)))) {
		PHBDBG(p, "CAPP recovery in progress\n");
		return OPAL_BUSY;
	}

	if (mode == OPAL_PHB_CAPI_MODE_PCIE)
		return OPAL_UNSUPPORTED;

	if (mode == OPAL_PHB_CAPI_MODE_SNOOP_OFF) {
		xscom_write(p->chip_id, SNOOP_CAPI_CONFIG, 	0x0000000000000000);
		return OPAL_SUCCESS;
	}

	if (mode == OPAL_PHB_CAPI_MODE_SNOOP_ON) {
		xscom_write(p->chip_id, CAPP_ERR_STATUS_CTRL,  	0x0000000000000000);
		xscom_write(p->chip_id, SNOOP_CAPI_CONFIG, 	0xA1F0000000000000);
		return OPAL_SUCCESS;
	}

	if (mode != OPAL_PHB_CAPI_MODE_CAPI)
		return OPAL_UNSUPPORTED;

	xscom_read(p->chip_id, 0x9013c03, &reg);
	if (reg & PPC_BIT(0)) {
		PHBDBG(p, "Already in CAPP mode\n");
		return OPAL_SUCCESS;
	}

	if (!p->capp_ucode_loaded) {
		PHBERR(p, "capp ucode not loaded into capp unit\n");
		return OPAL_HARDWARE;
	}

	/* poll cqstat */
	for (i = 0; i < 500; i++) {
		xscom_read(p->chip_id, p->pe_xscom + 0xf, &reg);
		if (!(reg & 0xC000000000000000))
			break;
		time_wait_ms(10);
	}
	if (reg & 0xC000000000000000) {
		PHBERR(p, "Timeout waiting for pending transaction\n");
		return OPAL_HARDWARE;
	}

	xscom_write(p->chip_id, p->spci_xscom + 0x3, 0x8000000000000000ull);
	/* FIXME security timer bar
	xscom_write(p->chip_id, p->spci_xscom + 0x4, 0x8000000000000000ull);
	*/

	/* aib mode */
	xscom_read(p->chip_id, p->pci_xscom + 0xf, &reg);
	reg &= ~PPC_BITMASK(6,7);
	reg |= PPC_BIT(8);
	reg |= PPC_BITMASK(40, 41);
	reg &= ~PPC_BIT(42);
	xscom_write(p->chip_id, p->pci_xscom + 0xf, reg);

	/* pci hwconf0 */
	xscom_read(p->chip_id, p->pe_xscom + 0x18, &reg);
	reg |= PPC_BIT(14);
	reg &= ~PPC_BIT(15);
	xscom_write(p->chip_id, p->pe_xscom + 0x18, reg);

	/* pci hwconf1 */
	xscom_read(p->chip_id, p->pe_xscom + 0x19, &reg);
	reg &= ~PPC_BITMASK(17,18);
	xscom_write(p->chip_id, p->pe_xscom + 0x19, reg);

	/* aib tx cmd cred */
	xscom_read(p->chip_id, p->pci_xscom + 0xd, &reg);
	reg &= ~PPC_BITMASK(42,46);
	reg |= PPC_BIT(47);
	xscom_write(p->chip_id, p->pci_xscom + 0xd, reg);

	xscom_write(p->chip_id, p->pci_xscom + 0xc, 0xff00000000000000ull);

	/* pci mode ctl */
	xscom_read(p->chip_id, p->pe_xscom + 0xb, &reg);
	reg |= PPC_BIT(25);
	xscom_write(p->chip_id, p->pe_xscom + 0xb, reg);

	/* set tve no translate mode allow mmio window */
	memset(p->tve_cache, 0x0, sizeof(p->tve_cache));
	/* Allow address range 0x0002000000000000: 0x0002FFFFFFFFFFF */
	p->tve_cache[pe_number * 2] = 0x000000FFFFFF0a00ULL;

	phb3_ioda_sel(p, IODA2_TBL_TVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->tve_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->tve_cache[i]);

	/* set m64 bar to pass mmio window */
	memset(p->m64b_cache, 0x0, sizeof(p->m64b_cache));
	p->m64b_cache[0] = PPC_BIT(0); /*enable*/
	p->m64b_cache[0] |= PPC_BIT(1); /*single pe*/
	p->m64b_cache[0] |= (p->mm0_base << 12) | ((pe_number & 0x3e0) << 27); /*base and upper pe*/
	p->m64b_cache[0] |= 0x3fffc000 | (pe_number & 0x1f); /*mask and lower pe*/

	p->m64b_cache[1] = PPC_BIT(0); /*enable*/
	p->m64b_cache[1] |= PPC_BIT(1); /*single pe*/
	p->m64b_cache[1] |= (0x0002000000000000ULL << 12) | ((pe_number & 0x3e0) << 27); /*base and upper pe*/
	p->m64b_cache[1] |= 0x3f000000 | (pe_number & 0x1f); /*mask and lower pe*/

	phb3_ioda_sel(p, IODA2_TBL_M64BT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->m64b_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->m64b_cache[i]);

	out_be64(p->regs + PHB_PHB3_CONFIG, PHB_PHB3C_64B_TCE_EN);
	out_be64(p->regs + PHB_PHB3_CONFIG, PHB_PHB3C_64BIT_MSI_EN);

	phb3_init_capp_errors(p);

	phb3_init_capp_regs(p);
	return OPAL_SUCCESS;
}

static int64_t phb3_set_capp_recovery(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->flags & PHB3_CAPP_RECOVERY)
		return 0;

	/* set opal event flag to indicate eeh condition */
	opal_update_pending_evt(OPAL_EVENT_PCI_ERROR,
				OPAL_EVENT_PCI_ERROR);

	p->flags |= PHB3_CAPP_RECOVERY;

	return 0;
}

static void do_capp_recovery_scoms(struct phb3 *p)
{
	uint64_t reg;
	PHBDBG(p, "Doing CAPP recovery scoms\n");

	xscom_write(p->chip_id, 0x201301a, 0); /* disable snoops */
	capp_load_ucode(p);
	xscom_write(p->chip_id, 0x2013013, 0); /* clear err rpt reg*/
	xscom_write(p->chip_id, 0x2013000, 0); /* clear capp fir */

	xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL, &reg);
	reg &= ~(PPC_BIT(0) | PPC_BIT(1));
	xscom_write(p->chip_id, CAPP_ERR_STATUS_CTRL, reg);
}

static const struct phb_ops phb3_ops = {
	.lock			= phb3_lock,
	.unlock			= phb3_unlock,
	.cfg_read8		= phb3_pcicfg_read8,
	.cfg_read16		= phb3_pcicfg_read16,
	.cfg_read32		= phb3_pcicfg_read32,
	.cfg_write8		= phb3_pcicfg_write8,
	.cfg_write16		= phb3_pcicfg_write16,
	.cfg_write32		= phb3_pcicfg_write32,
	.choose_bus		= phb3_choose_bus,
	.device_init		= phb3_device_init,
	.presence_detect	= phb3_presence_detect,
	.ioda_reset		= phb3_ioda_reset,
	.papr_errinjct_reset	= phb3_papr_errinjct_reset,
	.pci_reinit		= phb3_pci_reinit,
	.set_phb_mem_window	= phb3_set_phb_mem_window,
	.phb_mmio_enable	= phb3_phb_mmio_enable,
	.map_pe_mmio_window	= phb3_map_pe_mmio_window,
	.map_pe_dma_window	= phb3_map_pe_dma_window,
	.map_pe_dma_window_real = phb3_map_pe_dma_window_real,
	.pci_msi_eoi		= phb3_pci_msi_eoi,
	.set_xive_pe		= phb3_set_ive_pe,
	.get_msi_32		= phb3_get_msi_32,
	.get_msi_64		= phb3_get_msi_64,
	.set_pe			= phb3_set_pe,
	.set_peltv		= phb3_set_peltv,
	.link_state		= phb3_link_state,
	.power_state		= phb3_power_state,
	.slot_power_off		= phb3_slot_power_off,
	.slot_power_on		= phb3_slot_power_on,
	.hot_reset		= phb3_hot_reset,
	.fundamental_reset	= phb3_fundamental_reset,
	.complete_reset		= phb3_complete_reset,
	.poll			= phb3_poll,
	.eeh_freeze_status	= phb3_eeh_freeze_status,
	.eeh_freeze_clear	= phb3_eeh_freeze_clear,
	.eeh_freeze_set		= phb3_eeh_freeze_set,
	.next_error		= phb3_eeh_next_error,
	.err_inject		= phb3_err_inject,
	.get_diag_data		= NULL,
	.get_diag_data2		= phb3_get_diag_data,
	.set_capi_mode		= phb3_set_capi_mode,
	.set_capp_recovery	= phb3_set_capp_recovery,
};

/*
 * We should access those registers at the stage since the
 * AIB isn't ready yet.
 */
static void phb3_setup_aib(struct phb3 *p)
{
	/* Init_2 - AIB TX Channel Mapping Register */
	phb3_write_reg_asb(p, PHB_AIB_TX_CHAN_MAPPING,    	0x0211230000000000);

	/* Init_3 - AIB RX command credit register */
	if (p->rev >= PHB3_REV_VENICE_DD20)
		phb3_write_reg_asb(p, PHB_AIB_RX_CMD_CRED,	0x0020000100020001);
	else
		phb3_write_reg_asb(p, PHB_AIB_RX_CMD_CRED,	0x0020000100010001);
	
	/* Init_4 - AIB rx data credit register */
	if (p->rev >= PHB3_REV_VENICE_DD20)
		phb3_write_reg_asb(p, PHB_AIB_RX_DATA_CRED,	0x0020002000010001);
	else
		phb3_write_reg_asb(p, PHB_AIB_RX_DATA_CRED,	0x0020002000000001);

	/* Init_5 - AIB rx credit init timer register */
	phb3_write_reg_asb(p, PHB_AIB_RX_CRED_INIT_TIMER,	0x0f00000000000000);

	/* Init_6 - AIB Tag Enable register */
	phb3_write_reg_asb(p, PHB_AIB_TAG_ENABLE,		0xffffffff00000000);

	/* Init_7 - TCE Tag Enable register */
	phb3_write_reg_asb(p, PHB_TCE_TAG_ENABLE,         0xffffffff00000000);
}

static void phb3_init_ioda2(struct phb3 *p)
{
	/* Init_14 - LSI Source ID */
	out_be64(p->regs + PHB_LSI_SOURCE_ID,
		 SETFIELD(PHB_LSI_SRC_ID, 0ul, 0xff));

	/* Init_15 - IVT BAR / Length
	 * Init_16 - RBA BAR
	 * 	   - RTT BAR
	 * Init_17 - PELT-V BAR
	 */
	out_be64(p->regs + PHB_RTT_BAR,
		 p->tbl_rtt | PHB_RTT_BAR_ENABLE);
	out_be64(p->regs + PHB_PELTV_BAR,
		 p->tbl_peltv | PHB_PELTV_BAR_ENABLE);
	out_be64(p->regs + PHB_IVT_BAR,
		 p->tbl_ivt | 0x800 | PHB_IVT_BAR_ENABLE);

	/* DD2.0 or the subsequent chips don't have memory
	 * resident RBA.
	 */
	if (p->rev >= PHB3_REV_MURANO_DD20)
		out_be64(p->regs + PHB_RBA_BAR, 0x0ul);
	else
		out_be64(p->regs + PHB_RBA_BAR,
			 p->tbl_rba | PHB_RBA_BAR_ENABLE);

	/* Init_18..21 - Setup M32 */
	out_be64(p->regs + PHB_M32_BASE_ADDR, p->mm1_base);
	out_be64(p->regs + PHB_M32_BASE_MASK, ~(M32_PCI_SIZE - 1));
	out_be64(p->regs + PHB_M32_START_ADDR, M32_PCI_START);

	/* Init_22 - Setup PEST BAR */
	out_be64(p->regs + PHB_PEST_BAR,
		 p->tbl_pest | PHB_PEST_BAR_ENABLE);

	/* Init_23 - PCIE Outbound upper address */
	out_be64(p->regs + PHB_M64_UPPER_BITS, 0);

	/* Init_24 - Interrupt represent timers
	 * The register doesn't take effect on Murano DD1.0
	 */
	if (p->rev >= PHB3_REV_MURANO_DD20)
		out_be64(p->regs + PHB_INTREP_TIMER, 0x0004000000000000);
	else
		out_be64(p->regs + PHB_INTREP_TIMER, 0);

	/* Init_25 - PHB3 Configuration Register. Clear TCE cache then
	 *           configure the PHB
	 */
	out_be64(p->regs + PHB_PHB3_CONFIG, PHB_PHB3C_64B_TCE_EN);
	out_be64(p->regs + PHB_PHB3_CONFIG,
		 PHB_PHB3C_M32_EN | PHB_PHB3C_32BIT_MSI_EN |
		 PHB_PHB3C_64BIT_MSI_EN);

	/* Init_26 - At least 512ns delay according to spec */
	time_wait_ms(1);

	/* Init_27..36 - On-chip IODA tables init */
	phb3_ioda_reset(&p->phb, false);
}

static bool phb3_wait_dlp_reset(struct phb3 *p)
{
	unsigned int i;
	uint64_t val;

	/*
	 * Firmware cannot access the UTL core regs or PCI config space
	 * until the cores are out of DL_PGRESET.
	 * DL_PGRESET should be polled until it is inactive with a value
	 * of '0'. The recommended polling frequency is once every 1ms.
	 * Firmware should poll at least 200 attempts before giving up.
	 * MMIO Stores to the link are silently dropped by the UTL core if
	 * the link is down.
	 * MMIO Loads to the link will be dropped by the UTL core and will
	 * eventually time-out and will return an all ones response if the
	 * link is down.
	 */
#define DLP_RESET_ATTEMPTS	400

	PHBDBG(p, "Waiting for DLP PG reset to complete...\n");
	for (i = 0; i < DLP_RESET_ATTEMPTS; i++) {
		val = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (!(val & PHB_PCIE_DLP_TC_DL_PGRESET))
			break;
		time_wait_ms(1);
	}
	if (val & PHB_PCIE_DLP_TC_DL_PGRESET) {
		PHBERR(p, "Timeout waiting for DLP PG reset !\n");
		return false;
	}
	return true;
}

/* phb3_init_rc - Initialize the Root Complex config space
 */
static bool phb3_init_rc_cfg(struct phb3 *p)
{
	int64_t ecap, aercap;

	/* XXX Handle errors ? */

	/* Init_45..46:
	 *
	 * Set primary bus to 0, secondary to 1 and subordinate to 0xff
	 */
	phb3_pcicfg_write32(&p->phb, 0, PCI_CFG_PRIMARY_BUS, 0x00ff0100);

	/* Init_47..52
	 *
	 * IO and Memory base & limits are set to base > limit, which
	 * allows all inbounds.
	 *
	 * XXX This has the potential of confusing the OS which might
	 * think that nothing is forwarded downstream. We probably need
	 * to fix this to match the IO and M32 PHB windows
	 */
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_IO_BASE, 0x0010);
	phb3_pcicfg_write32(&p->phb, 0, PCI_CFG_MEM_BASE, 0x00000010);
	phb3_pcicfg_write32(&p->phb, 0, PCI_CFG_PREF_MEM_BASE, 0x00000010);

	/* Init_53..54 - Setup bridge control enable forwarding of CORR, FATAL,
	 * and NONFATAL errors
	*/
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, PCI_CFG_BRCTL_SERR_EN);

	/* Init_55..56
	 *
	 * PCIE Device control/status, enable error reporting, disable relaxed
	 * ordering, set MPS to 128 (see note), clear errors.
	 *
	 * Note: The doc recommends to set MPS to 4K. This has proved to have
	 * some issues as it requires specific claming of MRSS on devices and
	 * we've found devices in the field that misbehave when doing that.
	 *
	 * We currently leave it all to 128 bytes (minimum setting) at init
	 * time. The generic PCIe probing later on might apply a different
	 * value, or the kernel will, but we play it safe at early init
	 */
	if (p->ecap <= 0) {
		ecap = pci_find_cap(&p->phb, 0, PCI_CFG_CAP_ID_EXP);
		if (ecap < 0) {
			PHBERR(p, "Can't locate PCI-E capability\n");
			return false;
		}
		p->ecap = ecap;
	} else {
		ecap = p->ecap;
	}

	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVSTAT,
			     PCICAP_EXP_DEVSTAT_CE	|
			     PCICAP_EXP_DEVSTAT_NFE	|
			     PCICAP_EXP_DEVSTAT_FE	|
			     PCICAP_EXP_DEVSTAT_UE);

	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVCTL,
			     PCICAP_EXP_DEVCTL_CE_REPORT	|
			     PCICAP_EXP_DEVCTL_NFE_REPORT	|
			     PCICAP_EXP_DEVCTL_FE_REPORT	|
			     PCICAP_EXP_DEVCTL_UR_REPORT	|
			     SETFIELD(PCICAP_EXP_DEVCTL_MPS, 0, PCIE_MPS_128B));

	/* Init_57..58
	 *
	 * Root Control Register. Enable error reporting
	 *
	 * Note: Added CRS visibility.
	 */
	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_RC,
			     PCICAP_EXP_RC_SYSERR_ON_CE		|
			     PCICAP_EXP_RC_SYSERR_ON_NFE	|
			     PCICAP_EXP_RC_SYSERR_ON_FE		|
			     PCICAP_EXP_RC_CRS_VISIBLE);

	/* Init_59..60
	 *
	 * Device Control 2. Enable ARI fwd, set timer to RTOS timer
	 */
	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DCTL2,
			     SETFIELD(PCICAP_EXP_DCTL2_CMPTOUT, 0, 0xf) |
			     PCICAP_EXP_DCTL2_ARI_FWD);

	/* Init_61..76
	 *
	 * AER inits
	 */
	aercap = pci_find_ecap(&p->phb, 0, PCIECAP_ID_AER, NULL);
	if (aercap < 0) {
		/* Shouldn't happen */
		PHBERR(p, "Failed to locate AER Ecapability in bridge\n");
		return false;
	}
	p->aercap = aercap;

	/* Clear all UE status */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_STATUS,
			     0xffffffff);
	/* Disable some error reporting as per the PHB3 spec */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_MASK,
			     PCIECAP_AER_UE_POISON_TLP		|
			     PCIECAP_AER_UE_COMPL_TIMEOUT	|
			     PCIECAP_AER_UE_COMPL_ABORT		|
			     PCIECAP_AER_UE_ECRC);
	/* Report some errors as fatal */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_SEVERITY,
			     PCIECAP_AER_UE_DLP 		|
			     PCIECAP_AER_UE_SURPRISE_DOWN	|
			     PCIECAP_AER_UE_FLOW_CTL_PROT	|
			     PCIECAP_AER_UE_UNEXP_COMPL		|
			     PCIECAP_AER_UE_RECV_OVFLOW		|
			     PCIECAP_AER_UE_MALFORMED_TLP);
	/* Clear all CE status */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CE_STATUS,
			     0xffffffff);
	/* Disable some error reporting as per the PHB3 spec */
	/* Note: When link down, also disable rcvr errors */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CE_MASK,
			    PCIECAP_AER_CE_ADV_NONFATAL |
			    p->has_link ? 0 : PCIECAP_AER_CE_RECVR_ERR);
	/* Enable ECRC generation & checking */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CAPCTL,
			     PCIECAP_AER_CAPCTL_ECRCG_EN	|
			     PCIECAP_AER_CAPCTL_ECRCC_EN);
	/* Enable reporting in root error control */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_RERR_CMD,
			     PCIECAP_AER_RERR_CMD_FE		|
			     PCIECAP_AER_RERR_CMD_NFE		|
			     PCIECAP_AER_RERR_CMD_CE);
	/* Clear root error status */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_RERR_STA,
			     0xffffffff);

	return true;
}

static void phb3_init_utl(struct phb3 *p)
{
	/* Init_77..79: Clear spurrious errors and assign errors to the
	 * right "interrupt" signal
	 */
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS,       0xffffffffffffffff);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_ERR_SEVERITY, 0x5000000000000000);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_IRQ_EN,       0xfcc0000000000000);

	/* Init_80..81: Setup tag allocations
	 *
         * Don't touch UTL_GBIF_READ_TAGS_ALLOC, it differs betwen PHBs
         * and the default is correct
	 */
	out_be64(p->regs + UTL_PCIE_TAGS_ALLOC,            0x0800000000000000);

	/* Init_82: PCI Express port control
	 * SW283991: Set Outbound Non-Posted request timeout to 16ms (RTOS).
	 */
	out_be64(p->regs + UTL_PCIE_PORT_CONTROL,          0x8588007000000000);

	/* Init_83..85: Clean & setup port errors */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS,           0xffdfffffffffffff);
	out_be64(p->regs + UTL_PCIE_PORT_ERROR_SEV,        0x5039000000000000);

	if (p->has_link)
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,   0xad5a800000000000);
	else
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,   0xad42800000000000);

	/* Init_86 : Cleanup RC errors */
	out_be64(p->regs + UTL_RC_STATUS,                  0xffffffffffffffff);
}

static void phb3_init_errors(struct phb3 *p)
{
	/* Init_88: LEM Error Mask : Temporarily disable error interrupts */
	out_be64(p->regs + PHB_LEM_ERROR_MASK,		   0xffffffffffffffff);

	/* Init_89..97: Disable all error interrupts until end of init */
	out_be64(p->regs + PHB_ERR_STATUS,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_ERR1_STATUS,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR_LEM_ENABLE,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_ERR_FREEZE_ENABLE,	   0x0000000080800000);
	out_be64(p->regs + PHB_ERR_AIB_FENCE_ENABLE,	   0xffffffdd0c00ffc0);
	out_be64(p->regs + PHB_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR_STATUS_MASK,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR1_STATUS_MASK,	   0x0000000000000000);

	/* Init_98_106: Configure MMIO error traps & clear old state
	 *
	 * Don't enable BAR multi-hit detection in bit 41.
	 */
	out_be64(p->regs + PHB_OUT_ERR_STATUS,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS,		   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR_LEM_ENABLE,	   0xfdffffffffbfffff);
	out_be64(p->regs + PHB_OUT_ERR_FREEZE_ENABLE,	   0x0000420800000000);
	out_be64(p->regs + PHB_OUT_ERR_AIB_FENCE_ENABLE,   0x9cf3bc00f89c700f);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR_STATUS_MASK,	   0x0000000000400000);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS_MASK,	   0x0000000000400000);

	/* Init_107_115: Configure DMA_A error traps & clear old state */
	out_be64(p->regs + PHB_INA_ERR_STATUS,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_INA_ERR1_STATUS,		   0x0000000000000000);
	out_be64(p->regs + PHB_INA_ERR_LEM_ENABLE,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_INA_ERR_FREEZE_ENABLE,	   0xc00003a901006000);
	out_be64(p->regs + PHB_INA_ERR_AIB_FENCE_ENABLE,   0x3fff5452fe019fde);
	out_be64(p->regs + PHB_INA_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_INA_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_INA_ERR_STATUS_MASK,	   0x0000000000000000);
	out_be64(p->regs + PHB_INA_ERR1_STATUS_MASK,	   0x0000000000000000);

	/* Init_116_124: Configure DMA_B error traps & clear old state */
	out_be64(p->regs + PHB_INB_ERR_STATUS,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_INB_ERR1_STATUS,		   0x0000000000000000);
	out_be64(p->regs + PHB_INB_ERR_LEM_ENABLE,	   0xffffffffffffffff);

	/*
	 * Workaround for errata HW257476, turn correctable messages into
	 * ER freezes on Murano and Venice DD1.0
	 */
	if (p->rev < PHB3_REV_MURANO_DD20)
		out_be64(p->regs + PHB_INB_ERR_FREEZE_ENABLE,
			                                   0x0000600000000070);
	else
		out_be64(p->regs + PHB_INB_ERR_FREEZE_ENABLE,
			                                   0x0000600000000060);

	out_be64(p->regs + PHB_INB_ERR_AIB_FENCE_ENABLE,   0xfcff80fbff7ff08c);
	out_be64(p->regs + PHB_INB_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_INB_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_INB_ERR_STATUS_MASK,	   0x0000000000000000);
	out_be64(p->regs + PHB_INB_ERR1_STATUS_MASK,	   0x0000000000000000);

	/* Init_125..128: Cleanup & configure LEM */
	out_be64(p->regs + PHB_LEM_FIR_ACCUM,		   0x0000000000000000);
	out_be64(p->regs + PHB_LEM_ACTION0,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_LEM_ACTION1,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_LEM_WOF,			   0x0000000000000000);
}

static void phb3_init_hw(struct phb3 *p)
{
	uint64_t val;

	PHBDBG(p, "Initializing PHB...\n");

	/* Lift reset */
	xscom_read(p->chip_id, p->spci_xscom + 1, &val);/* HW275117 */
	xscom_write(p->chip_id, p->pci_xscom + 0xa, 0);
	time_wait_ms(100);

	/* Grab version and fit it in an int */
	val = phb3_read_reg_asb(p, PHB_VERSION);
	if (val == 0 || val == 0xffffffffffffffff) {
		PHBERR(p, "Failed to read version, PHB appears broken\n");
		goto failed;
	}

	p->rev = ((val >> 16) & 0x00ff0000) | (val & 0xffff);
	PHBDBG(p, "Core revision 0x%x\n", p->rev);

	/* Setup AIB credits etc... */
	phb3_setup_aib(p);

	/* Init_8 - PCIE System Configuration Register
	 *
	 * Not changed from default values. Beware that bits [04:09] should
	 * be different between PHBs (x16 vs x8).
	 */
	PHBDBG(p, "Default system config: 0x%016llx\n",
	       in_be64(p->regs + PHB_PCIE_SYSTEM_CONFIG));
	if (p->index == 2)
		val = 0x421000fc00000000;
	else
		val = 0x441000fc00000000;
	val |= (uint64_t)p->max_link_speed << PPC_BITLSHIFT(35);
	out_be64(p->regs + PHB_PCIE_SYSTEM_CONFIG, val);

	PHBDBG(p, "New system config    : 0x%016llx\n",
	       in_be64(p->regs + PHB_PCIE_SYSTEM_CONFIG));

	/* Init_9..12 - PCIE DLP Lane EQ control */
	if (p->lane_eq) {
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL0,
			 be64_to_cpu(p->lane_eq[0]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL1,
			 be64_to_cpu(p->lane_eq[1]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL2,
			 be64_to_cpu(p->lane_eq[2]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL3,
			 be64_to_cpu(p->lane_eq[3]));
	}

	/* Init_XX - (PHB2 errata)
	 *
         * Set proper credits, needs adjustment due to wrong defaults
	 * on PHB2 before we lift the reset.
	 */
	if (p->index == 2)
		out_be64(p->regs + PHB_PCIE_SYS_LINK_INIT, 0x9008133332120000);

	/* Init_13 - PCIE Reset */
	/*
	 * Lift the PHB resets but not PERST, this will be lifted
	 * later by the initial PERST state machine
	 */
	PHBDBG(p, "PHB_RESET is 0x%016llx\n", in_be64(p->regs + PHB_RESET));
	out_be64(p->regs + PHB_RESET,			   0xd000000000000000);

	/* Architected IODA2 inits */
	phb3_init_ioda2(p);

	/* Init_37..42 - Clear UTL & DLP error logs */
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG1,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG2,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG3,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG4,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_DLP_ERRLOG1,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_DLP_ERRLOG2,	   0xffffffffffffffff);

	/* Init_43 - Wait for UTL core to come out of reset */
	if (!phb3_wait_dlp_reset(p))
		goto failed;

	/* Init_44 - Clear port status */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS,	   0xffffffffffffffff);

	/* Init_45..76: Init root complex config space */
	if (!phb3_init_rc_cfg(p))
		goto failed;

	/* Init_77..86 : Init UTL */
	phb3_init_utl(p);

	/*
	 * Init_87: PHB Control register. Various PHB settings
	 *          Enable IVC for Murano DD2.0 or later one
	 */
#ifdef IVT_TABLE_IVE_16B
	val = 0xf3a80e4b00000000;
#else
	val = 0xf3a80ecb00000000;
#endif
	if (p->rev >= PHB3_REV_MURANO_DD20)
		val |= 0x0000010000000000;
	out_be64(p->regs + PHB_CONTROL, val);

	/* Init_88..128  : Setup error registers */
	phb3_init_errors(p);

	/* Init_129: Read error summary */
	val = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (val) {
		PHBERR(p, "Errors detected during PHB init: 0x%16llx\n", val);
		goto failed;
	}

	/* NOTE: At this point the spec waits for the link to come up. We
	 * don't bother as we are doing a PERST soon.
	 */

	/* XXX I don't know why the spec does this now and not earlier, so
	 * to be sure to get it right we might want to move it to the freset
	 * state machine, though the generic PCI layer will probably do
	 * this anyway (ie, enable MEM, etc... in the RC)
	 *
	 * Note:The spec enables IO but PHB3 doesn't do IO space .... so we
	 * leave that clear.
	 */
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_CMD,
			    PCI_CFG_CMD_MEM_EN |
			    PCI_CFG_CMD_BUS_MASTER_EN |
			    PCI_CFG_CMD_PERR_RESP |
			    PCI_CFG_CMD_SERR_EN);

	/* Clear errors */
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_STAT,
			    PCI_CFG_STAT_SENT_TABORT |
			    PCI_CFG_STAT_RECV_TABORT |
			    PCI_CFG_STAT_RECV_MABORT |
			    PCI_CFG_STAT_SENT_SERR |
			    PCI_CFG_STAT_RECV_PERR);

	/* Init_136 - Re-enable error interrupts */

	/* TBD: Should we mask any of these for PERST ? */
	out_be64(p->regs + PHB_ERR_IRQ_ENABLE,	   0x0000002280b80000);
	out_be64(p->regs + PHB_OUT_ERR_IRQ_ENABLE, 0x600c42fc042080f0);
	out_be64(p->regs + PHB_INA_ERR_IRQ_ENABLE, 0xc000a3a901826020);
	out_be64(p->regs + PHB_INB_ERR_IRQ_ENABLE, 0x0000600000800070);
	out_be64(p->regs + PHB_LEM_ERROR_MASK,	   0x42498e327f502eae);

	/*
	 * Init_141 - Enable DMA address speculation
	 *
	 * Errata#20131017: Disable speculation until Murano DD2.0
	 *
	 * Note: We keep IVT speculation disabled (bit 4). It should work with
	 * Murano DD2.0 and later but lacks sufficient testing. We will re-enable
	 * it once that has been done.
	 */
	if (p->rev >= PHB3_REV_MURANO_DD20)
		out_be64(p->regs + PHB_TCE_SPEC_CTL,		0xf000000000000000);
	else
		out_be64(p->regs + PHB_TCE_SPEC_CTL,		0x0ul);

	/* Errata#20131017: avoid TCE queue overflow */
	if (p->rev == PHB3_REV_MURANO_DD20)
		phb3_write_reg_asb(p, PHB_TCE_WATERMARK,	0x0003000000030302);

	/* Init_142 - PHB3 - Timeout Control Register 1
	 * SW283991: Increase timeouts
	 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL1,			0x1715152016200000);

	/* Init_143 - PHB3 - Timeout Control Register 2 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL2,			0x2320d71600000000);

	/* Mark the PHB as functional which enables all the various sequences */
	p->state = PHB3_STATE_FUNCTIONAL;

	PHBDBG(p, "Initialization complete\n");

	return;

 failed:
	PHBERR(p, "Initialization failed\n");
	p->state = PHB3_STATE_BROKEN;
}

static void phb3_allocate_tables(struct phb3 *p)
{
	/* XXX Our current memalign implementation sucks,
	 *
	 * It will do the job, however it doesn't support freeing
	 * the memory and wastes space by always allocating twice
	 * as much as requested (size + alignment)
	 */
	p->tbl_rtt = (uint64_t)local_alloc(p->chip_id, RTT_TABLE_SIZE, RTT_TABLE_SIZE);
	assert(p->tbl_rtt);
	memset((void *)p->tbl_rtt, 0, RTT_TABLE_SIZE);

	p->tbl_peltv = (uint64_t)local_alloc(p->chip_id, PELTV_TABLE_SIZE, PELTV_TABLE_SIZE);
	assert(p->tbl_peltv);
	memset((void *)p->tbl_peltv, 0, PELTV_TABLE_SIZE);

	p->tbl_pest = (uint64_t)local_alloc(p->chip_id, PEST_TABLE_SIZE, PEST_TABLE_SIZE);
	assert(p->tbl_pest);
	memset((void *)p->tbl_pest, 0, PEST_TABLE_SIZE);

	p->tbl_ivt = (uint64_t)local_alloc(p->chip_id, IVT_TABLE_SIZE, IVT_TABLE_SIZE);
	assert(p->tbl_ivt);
	memset((void *)p->tbl_ivt, 0, IVT_TABLE_SIZE);

	p->tbl_rba = (uint64_t)local_alloc(p->chip_id, RBA_TABLE_SIZE, RBA_TABLE_SIZE);
	assert(p->tbl_rba);
	memset((void *)p->tbl_rba, 0, RBA_TABLE_SIZE);
}

static void phb3_add_properties(struct phb3 *p)
{
	struct dt_node *np = p->phb.dt_node;
	uint32_t lsibase, icsp = get_ics_phandle();
	uint64_t m32b, m64b, m64s, reg, tkill;

	reg = cleanup_addr((uint64_t)p->regs);

	/* Add various properties that HB doesn't have to
	 * add, some of them simply because they result from
	 * policy decisions made in skiboot rather than in HB
	 * such as the MMIO windows going to PCI, interrupts,
	 * etc...
	 */
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0); /* ??? */

	dt_add_property_cells(np, "interrupt-parent", icsp);

	/* XXX FIXME: add slot-name */
	//dt_property_cell("bus-width", 8); /* Figure it out from VPD ? */

	/* "ranges", we only expose M32 (PHB3 doesn't do IO)
	 *
	 * Note: The kernel expects us to have chopped of 64k from the
	 * M32 size (for the 32-bit MSIs). If we don't do that, it will
	 * get confused (OPAL does it)
	 */
	m32b = cleanup_addr(p->mm1_base);
	m64b = cleanup_addr(p->mm0_base);
	m64s = p->mm0_size;
	dt_add_property_cells(np, "ranges",
			      /* M32 space */
			      0x02000000, 0x00000000, M32_PCI_START,
			      hi32(m32b), lo32(m32b), 0, M32_PCI_SIZE - 0x10000);

	/* XXX FIXME: add opal-memwin32, dmawins, etc... */
	dt_add_property_cells(np, "ibm,opal-m64-window",
			      hi32(m64b), lo32(m64b),
			      hi32(m64b), lo32(m64b),
			      hi32(m64s), lo32(m64s));
	dt_add_property(np, "ibm,opal-single-pe", NULL, 0);
	//dt_add_property_cells(np, "ibm,opal-msi-ports", 2048);
	dt_add_property_cells(np, "ibm,opal-num-pes", 256);
	dt_add_property_cells(np, "ibm,opal-reserved-pe", 0);
	dt_add_property_cells(np, "ibm,opal-msi-ranges",
			      p->base_msi, PHB3_MSI_IRQ_COUNT);
	tkill = reg + PHB_TCE_KILL;
	dt_add_property_cells(np, "ibm,opal-tce-kill",
			      hi32(tkill), lo32(tkill));

	/*
	 * Indicate to Linux that the architected IODA2 MSI EOI method
	 * is supported
	 */
	dt_add_property_string(np, "ibm,msi-eoi-method", "ioda2");

	/* The interrupt maps will be generated in the RC node by the
	 * PCI code based on the content of this structure:
	 */
	lsibase = p->base_lsi;
	p->phb.lstate.int_size = 1;
	p->phb.lstate.int_val[0][0] = lsibase + PHB3_LSI_PCIE_INTA;
	p->phb.lstate.int_val[1][0] = lsibase + PHB3_LSI_PCIE_INTB;
	p->phb.lstate.int_val[2][0] = lsibase + PHB3_LSI_PCIE_INTC;
	p->phb.lstate.int_val[3][0] = lsibase + PHB3_LSI_PCIE_INTD;
	p->phb.lstate.int_parent[0] = icsp;
	p->phb.lstate.int_parent[1] = icsp;
	p->phb.lstate.int_parent[2] = icsp;
	p->phb.lstate.int_parent[3] = icsp;

	/* Indicators for variable tables */
	dt_add_property_cells(np, "ibm,opal-rtt-table",
		hi32(p->tbl_rtt), lo32(p->tbl_rtt), RTT_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-peltv-table",
		hi32(p->tbl_peltv), lo32(p->tbl_peltv), PELTV_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-pest-table",
		hi32(p->tbl_pest), lo32(p->tbl_pest), PEST_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-ivt-table",
		hi32(p->tbl_ivt), lo32(p->tbl_ivt), IVT_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-ive-stride",
		IVT_TABLE_STRIDE);
	dt_add_property_cells(np, "ibm,opal-rba-table",
		hi32(p->tbl_rba), lo32(p->tbl_rba), RBA_TABLE_SIZE);
}

static bool phb3_calculate_windows(struct phb3 *p)
{
	const struct dt_property *prop;

	/* Get PBCQ MMIO windows from device-tree */
	prop = dt_require_property(p->phb.dt_node,
				   "ibm,mmio-window", -1);
	assert(prop->len >= (2 * sizeof(uint64_t)));

	p->mm0_base = ((const uint64_t *)prop->prop)[0];
	p->mm0_size = ((const uint64_t *)prop->prop)[1];
	if (prop->len > 16) {
		p->mm1_base = ((const uint64_t *)prop->prop)[2];
		p->mm1_size = ((const uint64_t *)prop->prop)[3];
	}

	/* Sort them so that 0 is big and 1 is small */
	if (p->mm1_size && p->mm1_size > p->mm0_size) {
		uint64_t b = p->mm0_base;
		uint64_t s = p->mm0_size;
		p->mm0_base = p->mm1_base;
		p->mm0_size = p->mm1_size;
		p->mm1_base = b;
		p->mm1_size = s;
	}

	/* If 1 is too small, ditch it */
	if (p->mm1_size < M32_PCI_SIZE)
		p->mm1_size = 0;

	/* If 1 doesn't exist, carve it out of 0 */
	if (p->mm1_size == 0) {
		p->mm0_size /= 2;
		p->mm1_base = p->mm0_base + p->mm0_size;
		p->mm1_size = p->mm0_size;
	}

	/* Crop mm1 to our desired size */
	if (p->mm1_size > M32_PCI_SIZE)
		p->mm1_size = M32_PCI_SIZE;

	return true;
}

static void phb3_create(struct dt_node *np)
{
	const struct dt_property *prop;
	struct phb3 *p = zalloc(sizeof(struct phb3));
	size_t lane_eq_len;
	struct dt_node *iplp;
	char *path;

	assert(p);

	/* Populate base stuff */
	p->index = dt_prop_get_u32(np, "ibm,phb-index");
	p->chip_id = dt_prop_get_u32(np, "ibm,chip-id");
	p->regs = (void *)dt_get_address(np, 0, NULL);
	p->base_msi = PHB3_MSI_IRQ_BASE(p->chip_id, p->index);
	p->base_lsi = PHB3_LSI_IRQ_BASE(p->chip_id, p->index);
	p->phb.dt_node = np;
	p->phb.ops = &phb3_ops;
	p->phb.phb_type = phb_type_pcie_v3;
	p->phb.scan_map = 0x1; /* Only device 0 to scan */
	p->capp_ucode_base = 0;
	p->capp_ucode_loaded = false;
	if (dt_has_node_property(np, "ibm,capp-ucode", NULL))
		p->capp_ucode_base = dt_prop_get_u32(np, "ibm,capp-ucode");
	p->max_link_speed = dt_prop_get_u32_def(np, "ibm,max-link-speed", 3);
	p->state = PHB3_STATE_UNINITIALIZED;

	if (!phb3_calculate_windows(p))
		return;

	/* Get the various XSCOM register bases from the device-tree */
	prop = dt_require_property(np, "ibm,xscom-bases", 3 * sizeof(uint32_t));
	p->pe_xscom = ((const uint32_t *)prop->prop)[0];
	p->spci_xscom = ((const uint32_t *)prop->prop)[1];
	p->pci_xscom = ((const uint32_t *)prop->prop)[2];

	/*
	 * We skip the initial PERST assertion requested by the generic code
	 * when doing a cold boot because we are coming out of cold boot already
	 * so we save boot time that way. The PERST state machine will still
	 * handle waiting for the link to come up, it will just avoid actually
	 * asserting & deasserting the PERST output
	 *
	 * For a hot IPL, we still do a PERST
	 *
	 * Note: In absence of property (ie, FSP-less), we stick to the old
	 * behaviour and set skip_perst to true
	 */
	p->skip_perst = true; /* Default */

	iplp = dt_find_by_path(dt_root, "ipl-params/ipl-params");
	if (iplp) {
		const char *ipl_type = dt_prop_get_def(iplp, "cec-major-type", NULL);
		if (ipl_type && (!strcmp(ipl_type, "hot")))
			p->skip_perst = false;
	}

	/* By default link is assumed down */
	p->has_link = false;

	/* We register the PHB before we initialize it so we
	 * get a useful OPAL ID for it
	 */
	pci_register_phb(&p->phb);

	/* Hello ! */
	path = dt_get_path(np);
	PHBINF(p, "Found %s @%p\n", path, p->regs);
	PHBINF(p, "  M32 [0x%016llx..0x%016llx]\n",
	       p->mm1_base, p->mm1_base + p->mm1_size - 1);
	PHBINF(p, "  M64 [0x%016llx..0x%016llx]\n",
	       p->mm0_base, p->mm0_base + p->mm0_size - 1);
	free(path);

	/* Check if we can use the A/B detect pins */
	p->use_ab_detect = dt_has_node_property(np, "ibm,use-ab-detect", NULL);

	/* Find base location code from root node */
	p->phb.base_loc_code = dt_prop_get_def(dt_root,
					       "ibm,io-base-loc-code", NULL);
	if (!p->phb.base_loc_code)
		PHBERR(p, "Base location code not found !\n");

	/* Check for lane equalization values from HB or HDAT */
	p->lane_eq = dt_prop_get_def_size(np, "ibm,lane-eq", NULL, &lane_eq_len);
	if (p->lane_eq && lane_eq_len != (8 * 4)) {
		PHBERR(p, "Device-tree has ibm,lane-eq with wrong len %ld\n",
			lane_eq_len);
		p->lane_eq = NULL;
	}
	if (p->lane_eq) {
		PHBDBG(p, "Override lane equalization settings:\n");
		PHBDBG(p, "  0x%016llx 0x%016llx\n",
		       be64_to_cpu(p->lane_eq[0]), be64_to_cpu(p->lane_eq[1]));
		PHBDBG(p, "  0x%016llx 0x%016llx\n",
		       be64_to_cpu(p->lane_eq[2]), be64_to_cpu(p->lane_eq[3]));
	}

	/*
	 * Grab CEC IO VPD load info from the root of the device-tree,
	 * on P8 there's a single such VPD for the whole machine
	 */
	prop = dt_find_property(dt_root, "ibm,io-vpd");
	if (!prop) {
		/* LX VPD Lid not already loaded */
		vpd_iohub_load(dt_root);
	}

	/* Allocate the SkiBoot internal in-memory tables for the PHB */
	phb3_allocate_tables(p);

	phb3_add_properties(p);

	/* Clear IODA2 cache */
	phb3_init_ioda_cache(p);

	/* Register interrupt sources */
	register_irq_source(&phb3_msi_irq_ops, p, p->base_msi,
			    PHB3_MSI_IRQ_COUNT);
	register_irq_source(&phb3_lsi_irq_ops, p, p->base_lsi, 4);

#ifndef DISABLE_ERR_INTS
	register_irq_source(&phb3_err_lsi_irq_ops, p,
			    p->base_lsi + PHB3_LSI_PCIE_INF, 2);
#endif
	/* Get the HW up and running */
	phb3_init_hw(p);

	/* Load capp microcode into capp unit if PHB0 */
	if (p->index == 0)
		capp_load_ucode(p);

	/* Platform additional setup */
	if (platform.pci_setup_phb)
		platform.pci_setup_phb(&p->phb, p->index);
}

static void phb3_probe_pbcq(struct dt_node *pbcq)
{
	uint32_t spci_xscom, pci_xscom, pe_xscom, gcid, pno;
	uint64_t val, phb_bar, bar_en;
	uint64_t mmio0_bar, mmio0_bmask, mmio0_sz;
	uint64_t mmio1_bar, mmio1_bmask, mmio1_sz;
	uint64_t reg[2];
	uint64_t mmio_win[4];
	unsigned int mmio_win_sz;
	struct dt_node *np;
	char *path;
	uint64_t capp_ucode_base;
	unsigned int max_link_speed;

	gcid = dt_get_chip_id(pbcq);
	pno = dt_prop_get_u32(pbcq, "ibm,phb-index");
	path = dt_get_path(pbcq);
	prlog(PR_NOTICE, "Chip %d Found PBCQ%d at %s\n", gcid, pno, path);
	free(path);

	pe_xscom = dt_get_address(pbcq, 0, NULL);
	pci_xscom = dt_get_address(pbcq, 1, NULL);
	spci_xscom = dt_get_address(pbcq, 2, NULL);
	prlog(PR_DEBUG, "PHB3[%d:%d]: X[PE]=0x%08x X[PCI]=0x%08x"
	      " X[SPCI]=0x%08x\n",
	      gcid, pno, pe_xscom, pci_xscom, spci_xscom);

	/* Check if CAPP mode */
	if (xscom_read(gcid, spci_xscom + 0x03, &val)) {
		prerror("PHB3[%d:%d]: Cannot read AIB CAPP ENABLE\n",
			gcid, pno);
		return;
	}
	if (val >> 63) {
		prerror("PHB3[%d:%d]: Ignoring bridge in CAPP mode\n",
			gcid, pno);
		return;
	}

	/* Get PE BARs, assume only 0 and 2 are used for now */
	xscom_read(gcid, pe_xscom + 0x42, &phb_bar);
	phb_bar >>= 14;
	prlog(PR_DEBUG, "PHB3[%d:%d] REGS     = 0x%016llx [4k]\n",
		gcid, pno, phb_bar);
	if (phb_bar == 0) {
		prerror("PHB3[%d:%d]: No PHB BAR set !\n", gcid, pno);
		return;
	}

	/* Dbl check PHB BAR */
	xscom_read(gcid, spci_xscom + 1, &val);/* HW275117 */
	xscom_read(gcid, pci_xscom + 0x0b, &val);
	val >>= 14;
	prlog(PR_DEBUG, "PHB3[%d:%d] PCIBAR   = 0x%016llx\n", gcid, pno, val);
	if (phb_bar != val) {
		prerror("PHB3[%d:%d] PCIBAR invalid, fixing up...\n",
			gcid, pno);
		xscom_read(gcid, spci_xscom + 1, &val);/* HW275117 */
		xscom_write(gcid, pci_xscom + 0x0b, phb_bar << 14);
	}

	/* Check MMIO BARs */
	xscom_read(gcid, pe_xscom + 0x40, &mmio0_bar);
	xscom_read(gcid, pe_xscom + 0x43, &mmio0_bmask);
	mmio0_bmask &= 0xffffffffc0000000ull;
	mmio0_sz = ((~mmio0_bmask) >> 14) + 1;
	mmio0_bar >>= 14;
	prlog(PR_DEBUG, "PHB3[%d:%d] MMIO0    = 0x%016llx [0x%016llx]\n",
		gcid, pno, mmio0_bar, mmio0_sz);
	xscom_read(gcid, pe_xscom + 0x41, &mmio1_bar);
	xscom_read(gcid, pe_xscom + 0x44, &mmio1_bmask);
	mmio1_bmask &= 0xffffffffc0000000ull;
	mmio1_sz = ((~mmio1_bmask) >> 14) + 1;
	mmio1_bar >>= 14;
	prlog(PR_DEBUG, "PHB3[%d:%d] MMIO1    = 0x%016llx [0x%016llx]\n",
		gcid, pno, mmio1_bar, mmio1_sz);

	/* Check BAR enable
	 *
	 * XXX BAR aren't always enabled by HB, we'll make assumptions
	 * that BARs are valid if they value is non-0
	 */
	xscom_read(gcid, pe_xscom + 0x45, &bar_en);
	prlog(PR_DEBUG, "PHB3[%d:%d] BAREN    = 0x%016llx\n",
		gcid, pno, bar_en);

	/* Always enable PHB BAR */
	bar_en |= 0x2000000000000000ull;

	/* Build MMIO windows list */
	mmio_win_sz = 0;
	if (mmio0_bar) {
		mmio_win[mmio_win_sz++] = mmio0_bar;
		mmio_win[mmio_win_sz++] = mmio0_sz;
		bar_en |= 0x8000000000000000ul;
	}
	if (mmio1_bar) {
		mmio_win[mmio_win_sz++] = mmio1_bar;
		mmio_win[mmio_win_sz++] = mmio1_sz;
		bar_en |= 0x4000000000000000ul;
	}

	/* No MMIO windows ? Barf ! */
	if (mmio_win_sz == 0) {
		prerror("PHB3[%d:%d]: No MMIO windows enabled !\n",
			gcid, pno);
		return;
	}

	/* Set the interrupt routing stuff, 8 relevant bits in mask
	 * (11 bits per PHB)
	 */
	val = P8_CHIP_IRQ_PHB_BASE(gcid, pno);
	val = (val << 45);
	xscom_write(gcid, pe_xscom + 0x1a, val);
	xscom_write(gcid, pe_xscom + 0x1b, 0xff00000000000000ul);

	/* Configure LSI location to the top of the map */
	xscom_write(gcid, pe_xscom + 0x1f, 0xff00000000000000ul);

	/* Now add IRSN message bits to BAR enable and write it */
	bar_en |= 0x1800000000000000ul;
	xscom_write(gcid, pe_xscom + 0x45, bar_en);

	prlog(PR_DEBUG, "PHB3[%d:%d] NEWBAREN = 0x%016llx\n",
	      gcid, pno, bar_en);

	xscom_read(gcid, pe_xscom + 0x1a, &val);
	prlog(PR_DEBUG, "PHB3[%d:%d] IRSNC    = 0x%016llx\n",
	      gcid, pno, val);
	xscom_read(gcid, pe_xscom + 0x1b, &val);
	prlog(PR_DEBUG, "PHB3[%d:%d] IRSNM    = 0x%016llx\n",
	      gcid, pno, val);
	prlog(PR_DEBUG, "PHB3[%d:%d] LSI      = 0x%016llx\n",
	      gcid, pno, val);

	/* Create PHB node */
	reg[0] = phb_bar;
	reg[1] = 0x1000;

	np = dt_new_addr(dt_root, "pciex", reg[0]);
	if (!np)
		return;

	dt_add_property_strings(np, "compatible", "ibm,power8-pciex",
				"ibm,ioda2-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", reg, sizeof(reg));

	/* Everything else is handled later by skiboot, we just
	 * stick a few hints here
	 */
	dt_add_property_cells(np, "ibm,xscom-bases",
			      pe_xscom, spci_xscom, pci_xscom);
	dt_add_property(np, "ibm,mmio-window", mmio_win, 8 * mmio_win_sz);
	dt_add_property_cells(np, "ibm,phb-index", pno);
	dt_add_property_cells(np, "ibm,pbcq", pbcq->phandle);
	dt_add_property_cells(np, "ibm,chip-id", gcid);
	if (dt_has_node_property(pbcq, "ibm,use-ab-detect", NULL))
		dt_add_property(np, "ibm,use-ab-detect", NULL, 0);
	if (dt_has_node_property(pbcq, "ibm,hub-id", NULL))
		dt_add_property_cells(np, "ibm,hub-id",
				      dt_prop_get_u32(pbcq, "ibm,hub-id"));
	if (dt_has_node_property(pbcq, "ibm,loc-code", NULL)) {
		const char *lc = dt_prop_get(pbcq, "ibm,loc-code");
		dt_add_property_string(np, "ibm,loc-code", lc);
	}
	if (dt_has_node_property(pbcq, "ibm,lane-eq", NULL)) {
		size_t leq_size;
		const void *leq = dt_prop_get_def_size(pbcq, "ibm,lane-eq",
						       NULL, &leq_size);
		if (leq != NULL && leq_size == 4 * 8)
			dt_add_property(np, "ibm,lane-eq", leq, leq_size);
	}
	if (dt_has_node_property(pbcq, "ibm,capp-ucode", NULL)) {
		capp_ucode_base = dt_prop_get_u32(pbcq, "ibm,capp-ucode");
		dt_add_property_cells(np, "ibm,capp-ucode", capp_ucode_base);
	}
	max_link_speed = dt_prop_get_u32_def(pbcq, "ibm,max-link-speed", 3);
	dt_add_property_cells(np, "ibm,max-link-speed", max_link_speed);
	dt_add_property_cells(np, "ibm,capi-flags",
			      OPAL_PHB_CAPI_FLAG_SNOOP_CONTROL);

	add_chip_dev_associativity(np);
}

void probe_phb3(void)
{
	struct dt_node *np;

	/* Look for PBCQ XSCOM nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power8-pbcq")
		phb3_probe_pbcq(np);

	/* Look for newly created PHB nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power8-pciex")
		phb3_create(np);
}
