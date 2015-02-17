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
#include <p5ioc2.h>
#include <p5ioc2-regs.h>
#include <io.h>
#include <timebase.h>
#include <affinity.h>
#include <pci.h>
#include <pci-cfg.h>
#include <interrupts.h>
#include <ccan/str/str.h>

#define PHBDBG(p, fmt, a...)	prlog(PR_DEBUG, "PHB%d: " fmt, \
				      (p)->phb.opal_id, ## a)
#define PHBERR(p, fmt, a...)	prlog(PR_ERR, "PHB%d: " fmt, \
				      (p)->phb.opal_id, ## a)

/* Helper to set the state machine timeout */
static inline uint64_t p5ioc2_set_sm_timeout(struct p5ioc2_phb *p, uint64_t dur)
{
	uint64_t target, now = mftb();

	target = now + dur;
	if (target == 0)
		target++;
	p->delay_tgt_tb = target;

	return dur;
}

/*
 * Lock callbacks. Allows the OPAL API handlers to lock the
 * PHB around calls such as config space, EEH, etc...
 */
static void p5ioc2_phb_lock(struct phb *phb)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);

	lock(&p->lock);
}

static  void p5ioc2_phb_unlock(struct phb *phb)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);

	unlock(&p->lock);
}

/*
 * Configuration space access
 *
 * The PHB lock is assumed to be already held
 */
static int64_t p5ioc2_pcicfg_address(struct p5ioc2_phb *p, uint32_t bdfn,
				     uint32_t offset, uint32_t size)
{
	uint32_t addr, sm = size - 1;

	if (bdfn > 0xffff)
		return OPAL_PARAMETER;
	/* XXX Should we enable 4K config space on PCI-X 2.0 ? */
	if ((offset > 0xff && !p->is_pcie) || offset > 0xfff)
		return OPAL_PARAMETER;
	if (offset & sm)
		return OPAL_PARAMETER;

	/* The root bus only has a device at 0 and we get into an
	 * error state if we try to probe beyond that, so let's
	 * avoid that and just return an error to Linux
	 */
	if (p->is_pcie && (bdfn >> 8) == 0 && (bdfn & 0xff))
		return OPAL_HARDWARE;

	/* Prevent special operation generation */
	if (((bdfn >> 3) & 0x1f) == 0x1f)
		return OPAL_HARDWARE;

	/* Check PHB state */
	if (p->state == P5IOC2_PHB_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* Additionally, should we prevent writes to the PHB own
	 * bus number register ?
	 */

	addr = CAP_PCADR_ENABLE;
	addr = SETFIELD(CAP_PCADR_BDFN, addr, bdfn);
	addr = SETFIELD(CAP_PCADR_EXTOFF, addr, offset >> 8);
	addr |= (offset & 0xff);
	out_le32(p->regs + CAP_PCADR, addr);

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_pcicfg_read8(struct phb *phb, uint32_t bdfn,
				  uint32_t offset, uint8_t *data)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	int64_t rc;

	/* Initialize data in case of error */
	*data = 0xff;

	rc = p5ioc2_pcicfg_address(p, bdfn, offset, 1);
	if (rc)
		return rc;

	*data = in_8(p->regs + CAP_PCDAT + (offset & 3));

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_pcicfg_read16(struct phb *phb, uint32_t bdfn,
				   uint32_t offset, uint16_t *data)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	int64_t rc;

	/* Initialize data in case of error */
	*data = 0xffff;

	rc = p5ioc2_pcicfg_address(p, bdfn, offset, 2);
	if (rc)
		return rc;

	*data = in_le16(p->regs + CAP_PCDAT + (offset & 3));

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_pcicfg_read32(struct phb *phb, uint32_t bdfn,
				   uint32_t offset, uint32_t *data)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	int64_t rc;

	/* Initialize data in case of error */
	*data = 0xffffffff;

	rc = p5ioc2_pcicfg_address(p, bdfn, offset, 4);
	if (rc)
		return rc;

	*data = in_le32(p->regs + CAP_PCDAT);

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_pcicfg_write8(struct phb *phb, uint32_t bdfn,
				   uint32_t offset, uint8_t data)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	int64_t rc;

	rc = p5ioc2_pcicfg_address(p, bdfn, offset, 1);
	if (rc)
		return rc;

	out_8(p->regs + CAP_PCDAT + (offset & 3), data);

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_pcicfg_write16(struct phb *phb, uint32_t bdfn,
				    uint32_t offset, uint16_t data)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	int64_t rc;

	rc = p5ioc2_pcicfg_address(p, bdfn, offset, 2);
	if (rc)
		return rc;

	out_le16(p->regs + CAP_PCDAT + (offset & 3), data);

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_pcicfg_write32(struct phb *phb, uint32_t bdfn,
				    uint32_t offset, uint32_t data)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	int64_t rc;

	rc = p5ioc2_pcicfg_address(p, bdfn, offset, 4);
	if (rc)
		return rc;

	out_le32(p->regs + CAP_PCDAT, data);

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_presence_detect(struct phb *phb)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	uint16_t slotstat;
	int64_t rc;

	if (!p->is_pcie) {
		uint32_t lsr;

		lsr = in_be32(p->regs + SHPC_LOGICAL_SLOT);
		if (GETFIELD(SHPC_LOGICAL_SLOT_PRSNT, lsr)
		    != SHPC_SLOT_STATE_EMPTY)
			return OPAL_SHPC_DEV_PRESENT;
		else
		return OPAL_SHPC_DEV_NOT_PRESENT;
	}

	rc = p5ioc2_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_SLOTSTAT,
				 &slotstat);
	if (rc || !(slotstat & PCICAP_EXP_SLOTSTAT_PDETECTST))
		return OPAL_SHPC_DEV_NOT_PRESENT;
	return OPAL_SHPC_DEV_PRESENT;
}

static int64_t p5ioc2_link_state(struct phb *phb)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	uint16_t lstat;
	int64_t rc;

	/* XXX Test for PHB in error state ? */
	if (!p->is_pcie)
		return OPAL_SHPC_LINK_UP_x1;

	rc = p5ioc2_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_LSTAT,
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

static int64_t p5ioc2_power_state(struct phb *phb __unused)
{
	/* XXX FIXME */
#if 0
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	uint64_t reg = in_be64(p->regs + PHB_PCIE_SLOTCTL2);

	/* XXX Test for PHB in error state ? */

	if (reg & PHB_PCIE_SLOTCTL2_PWR_EN_STAT)
		return OPAL_SHPC_POWER_ON;

	return OPAL_SHPC_POWER_OFF;
#else
	return OPAL_SHPC_POWER_ON;
#endif
}

/* p5ioc2_sm_slot_power_off - Slot power off state machine
 */
static int64_t p5ioc2_sm_slot_power_off(struct p5ioc2_phb *p)
{
	switch(p->state) {
	default:
		break;
	}

	/* Unknown state, hardware error ? */
	return OPAL_HARDWARE;
}

static int64_t p5ioc2_slot_power_off(struct phb *phb)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);

	if (p->state != P5IOC2_PHB_STATE_FUNCTIONAL)
		return OPAL_BUSY;

	/* run state machine */
	return p5ioc2_sm_slot_power_off(p);
}

static int64_t p5ioc2_sm_slot_power_on(struct p5ioc2_phb *p __unused)
{
#if 0
	uint64_t reg;
	uint32_t reg32;
	uint16_t brctl;

	switch(p->state) {
	case P5IOC2_PHB_STATE_FUNCTIONAL:
		/* Check presence */
		reg = in_be64(p->regs + PHB_PCIE_SLOTCTL2);
		if (!(reg & PHB_PCIE_SLOTCTL2_PRSTN_STAT)) {
			PHBDBG(p, "Slot power on: no device\n");
			return OPAL_CLOSED;
		}

		/* Adjust UTL interrupt settings to disable various
		 * errors that would interfere with the process
		 */
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN, 0x7e00000000000000);

		/* If the power is not on, turn it on now */
		if (!(reg & PHB_PCIE_SLOTCTL2_PWR_EN_STAT)) {
			reg = in_be64(p->regs + PHB_HOTPLUG_OVERRIDE);
			reg &= ~(0x8c00000000000000ul);
			reg |= 0x8400000000000000ul;
			out_be64(p->regs + PHB_HOTPLUG_OVERRIDE, reg);
			p->state = PHB_STATE_SPUP_STABILIZE_DELAY;
			PHBDBG(p, "Slot power on: powering on...\n");
			return p5ioc2_set_sm_timeout(p, secs_to_tb(2));
		}
		/* Power is already on */
	power_ok:
		/* Ensure hot reset is deasserted */
		p5ioc2_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		p5ioc2_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		p->retries = 40;
		p->state = PHB_STATE_SPUP_WAIT_LINK;
		PHBDBG(p, "Slot power on: waiting for link\n");
		/* Fall through */
	case PHB_STATE_SPUP_WAIT_LINK:
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		/* Link is up ? Complete */

		/* XXX TODO: Check link width problem and if present
		 * go straight to the host reset code path.
		 */
		if (reg & PHB_PCIE_DLP_TC_DL_LINKACT) {
			/* Restore UTL interrupts */
			out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,
				 0xfe65000000000000);
			p->state = PHB_STATE_FUNCTIONAL;
			PHBDBG(p, "Slot power on: up !\n");
			return OPAL_SUCCESS;
		}
		/* Retries */
		p->retries--;
		if (p->retries == 0) {
			/* XXX Improve logging */
			PHBERR(p,"Slot power on: Timeout waiting for link\n");
			goto error;
		}
		/* Check time elapsed */
		if ((p->retries % 20) != 0)
			return p5ioc2_set_sm_timeout(p, msecs_to_tb(10));

		/* >200ms, time to try a hot reset after clearing the
		 * link status bit (doco says to do so)
		 */
		out_be64(p->regs + UTL_PCIE_PORT_STATUS, 0x0080000000000000);

		/* Mask receiver error status in AER */
		p5ioc2_pcicfg_read32(&p->phb, 0,
				    p->aercap + PCIECAP_AER_CE_MASK, &reg32);
		reg32 |= PCIECAP_AER_CE_RECVR_ERR;
		p5ioc2_pcicfg_write32(&p->phb, 0,
				     p->aercap + PCIECAP_AER_CE_MASK, reg32);

		/* Turn on host reset */
		p5ioc2_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl |= PCI_CFG_BRCTL_SECONDARY_RESET;
		p5ioc2_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		p->state = PHB_STATE_SPUP_HOT_RESET_DELAY;
		PHBDBG(p, "Slot power on: soft reset...\n");
		return p5ioc2_set_sm_timeout(p, secs_to_tb(1));
	case PHB_STATE_SPUP_HOT_RESET_DELAY:
		/* Turn off host reset */
		p5ioc2_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		p5ioc2_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		/* Clear spurious errors */
		out_be64(p->regs + UTL_PCIE_PORT_STATUS, 0x00e0000000000000);
		p5ioc2_pcicfg_write32(&p->phb, 0,
				     p->aercap + PCIECAP_AER_CE_STATUS,
				     PCIECAP_AER_CE_RECVR_ERR);
		/* Unmask receiver error status in AER */
		p5ioc2_pcicfg_read32(&p->phb, 0,
				    p->aercap + PCIECAP_AER_CE_MASK, &reg32);
		reg32 &= ~PCIECAP_AER_CE_RECVR_ERR;
		p5ioc2_pcicfg_write32(&p->phb, 0,
				     p->aercap + PCIECAP_AER_CE_MASK, reg32);
		/* Go back to waiting for link */
		p->state = PHB_STATE_SPUP_WAIT_LINK;
		PHBDBG(p, "Slot power on: waiting for link (2)\n");
		return p5ioc2_set_sm_timeout(p, msecs_to_tb(10));

	case PHB_STATE_SPUP_STABILIZE_DELAY:
		/* Come here after the 2s delay after power up */
		p->retries = 1000;
		p->state = PHB_STATE_SPUP_SLOT_STATUS;
		PHBDBG(p, "Slot power on: waiting for power\n");
		/* Fall through */
	case PHB_STATE_SPUP_SLOT_STATUS:
		reg = in_be64(p->regs + PHB_PCIE_SLOTCTL2);

		/* Doc says to check LED status, but we ignore that, there
		 * no point really and it's easier that way
		 */
		if (reg & PHB_PCIE_SLOTCTL2_PWR_EN_STAT)
			goto power_ok;
		if (p->retries-- == 0) {
			/* XXX Improve error logging */
			PHBERR(p, "Timeout powering up slot\n");
			goto error;
		}
		return p5ioc2_set_sm_timeout(p, msecs_to_tb(10));
	default:
		break;
	}

	/* Unknown state, hardware error ? */
 error:
	p->state = PHB_STATE_FUNCTIONAL;
	return OPAL_HARDWARE;
#else
	return OPAL_SUCCESS;
#endif
}

static int64_t p5ioc2_slot_power_on(struct phb *phb)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);

	if (p->state != P5IOC2_PHB_STATE_FUNCTIONAL)
		return OPAL_BUSY;

	/* run state machine */
	return p5ioc2_sm_slot_power_on(p);
}

static int64_t p5ioc2_sm_hot_reset(struct p5ioc2_phb *p)
{
	switch(p->state) {
	default:
		break;
	}

	/* Unknown state, hardware error ? */
	return OPAL_HARDWARE;
}

static int64_t p5ioc2_hot_reset(struct phb *phb)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);

	if (p->state != P5IOC2_PHB_STATE_FUNCTIONAL)
		return OPAL_BUSY;

	/* run state machine */
	return p5ioc2_sm_hot_reset(p);
}

static int64_t p5ioc2_sm_freset(struct p5ioc2_phb *p)
{
	switch(p->state) {
	default:
		break;
	}

	/* XXX Not implemented, return success to make
	 * pci.c happy, otherwise probing of slots will
	 * fail
	 */
	return OPAL_SUCCESS;
}

static int64_t p5ioc2_freset(struct phb *phb)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);

	if (p->state != P5IOC2_PHB_STATE_FUNCTIONAL)
		return OPAL_BUSY;

	/* run state machine */
	return p5ioc2_sm_freset(p);
}

static int64_t p5ioc2_poll(struct phb *phb)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	uint64_t now = mftb();

	if (p->state == P5IOC2_PHB_STATE_FUNCTIONAL)
		return OPAL_SUCCESS;

	/* Check timer */
	if (p->delay_tgt_tb &&
	    tb_compare(now, p->delay_tgt_tb) == TB_ABEFOREB)
		return p->delay_tgt_tb - now;

	/* Expired (or not armed), clear it */
	p->delay_tgt_tb = 0;

#if 0
	/* Dispatch to the right state machine */
	switch(p->state) {
	case PHB_STATE_SPUP_STABILIZE_DELAY:
	case PHB_STATE_SPUP_SLOT_STATUS:
	case PHB_STATE_SPUP_WAIT_LINK:
	case PHB_STATE_SPUP_HOT_RESET_DELAY:
		return p5ioc2_sm_slot_power_on(p);
	case PHB_STATE_SPDOWN_STABILIZE_DELAY:
	case PHB_STATE_SPDOWN_SLOT_STATUS:
		return p5ioc2_sm_slot_power_off(p);
	case PHB_STATE_HRESET_DELAY:
		return p5ioc2_sm_hot_reset(p);
	default:
		break;
	}
#endif
	/* Unknown state, could be a HW error */
	return OPAL_HARDWARE;
}

static int64_t p5ioc2_eeh_freeze_status(struct phb *phb, uint64_t pe_number,
					uint8_t *freeze_state,
					uint16_t *pci_error_type,
					uint16_t *severity,
					uint64_t *phb_status __unused)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	uint32_t cfgrw;

	/* Defaults: not frozen */
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	*pci_error_type = OPAL_EEH_NO_ERROR;
	if (severity)
		*severity = OPAL_EEH_SEV_NO_ERROR;

	if (pe_number != 0)
		return OPAL_PARAMETER;

	/* XXX Handle PHB status */
	/* XXX We currently only check for PE freeze, not fence */

	cfgrw = in_be32(p->regs + CAP_PCFGRW);
	if (cfgrw & CAP_PCFGRW_MMIO_FROZEN)
		*freeze_state |= OPAL_EEH_STOPPED_MMIO_FREEZE;
	if (cfgrw & CAP_PCFGRW_DMA_FROZEN)
		*freeze_state |= OPAL_EEH_STOPPED_DMA_FREEZE;

	if (severity &&
	    (cfgrw & (CAP_PCFGRW_MMIO_FROZEN | CAP_PCFGRW_MMIO_FROZEN)))
		*severity = OPAL_EEH_SEV_PE_ER;

	/* XXX Don't bother populating pci_error_type */
	/* Should read the bits from PLSSR */

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_eeh_next_error(struct phb *phb, uint64_t *first_frozen_pe,
				     uint16_t *pci_error_type, uint16_t *severity)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	uint32_t cfgrw;

	/* XXX Don't bother */
	*pci_error_type = OPAL_EEH_NO_ERROR;
	*first_frozen_pe = 0;

	cfgrw = in_be32(p->regs + CAP_PCFGRW);
	if (cfgrw & (CAP_PCFGRW_MMIO_FROZEN | CAP_PCFGRW_MMIO_FROZEN))
		*severity = OPAL_EEH_SEV_PE_ER;

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_eeh_freeze_clear(struct phb *phb, uint64_t pe_number,
				       uint64_t eeh_action_token)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	uint32_t cfgrw;

	if (pe_number != 0)
		return OPAL_PARAMETER;

	/*
	 * This sequence isn't very well documented. We play guess
	 * games based on the documentation, what we do on P7IOC,
	 * and common sense.
	 *
	 * Basically we start from the low level (UTL), clear all
	 * error conditions there. Then we clear error conditions
	 * in the PLSSR and DMACSR.
	 *
	 * Once that's done, we unfreeze the PHB
	 *
	 * Note: Should we also clear the error bits in the config
	 * space ? The docs don't say anything... TODO: Check what
	 * OPAL does if possible or ask Milton.
	 */

	/* Clear UTL error regs on PCIe */
	if (p->is_pcie) {
		uint32_t err;
	
		err = in_be32(p->regs + UTL_SYS_BUS_AGENT_STATUS);
		out_be32(p->regs + UTL_SYS_BUS_AGENT_STATUS, err);
		err = in_be32(p->regs + UTL_PCIE_PORT_STATUS);
		out_be32(p->regs + UTL_PCIE_PORT_STATUS, err);
		err = in_be32(p->regs + UTL_RC_STATUS);
		out_be32(p->regs + UTL_RC_STATUS, err);
	}

	/* XXX We should probably clear the error regs in the cfg space... */

	/* Clear PLSSR and DMACSR */
	out_be32(p->regs + CAP_DMACSR, 0);
	out_be32(p->regs + CAP_PLSSR, 0);

	/* Clear freeze state as requested */
	cfgrw = in_be32(p->regs + CAP_PCFGRW);
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO) {
		cfgrw &= ~CAP_PCFGRW_MMIO_FROZEN;
		out_be32(p->regs + CAP_PCFGRW, cfgrw);
	}
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_DMA) {
		cfgrw &= ~CAP_PCFGRW_DMA_FROZEN;
		out_be32(p->regs + CAP_PCFGRW, cfgrw);
	}

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_get_msi_64(struct phb *phb __unused, uint32_t mve_number,
				uint32_t xive_num, uint8_t msi_range,
				uint64_t *msi_address, uint32_t *message_data)
{
	if (mve_number > 255 || xive_num > 255 || msi_range != 1)
		return OPAL_PARAMETER;

	*msi_address = 0x1000000000000000ul;
	*message_data = xive_num;

	return OPAL_SUCCESS;
}

static uint8_t p5ioc2_choose_bus(struct phb *phb __unused,
				struct pci_device *bridge __unused,
				uint8_t candidate, uint8_t *max_bus __unused,
				bool *use_max)
{
	/* Use standard bus number selection */
	*use_max = false;
	return candidate;
}

/* p5ioc2_phb_ioda_reset - Reset the IODA tables
 *
 * This reset the IODA tables in the PHB. It is called at
 * initialization time, on PHB reset, and can be called
 * explicitly from OPAL
 *
 * Note: We don't handle EEH on p5ioc2, we use no cache
 * and thus always purge
 */
static int64_t p5ioc2_ioda_reset(struct phb *phb, bool purge __unused)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	unsigned int i;

	/* Init XIVRs */
	for (i = 0; i < 16; i++) {
		p->xive_cache[i] = SETFIELD(CAP_XIVR_PRIO, 0, 0xff);
		out_be32(p->regs + CAP_XIVRn(i), 0x000000ff);
	}

	return OPAL_SUCCESS;
}

static int64_t p5ioc2_set_phb_tce_memory(struct phb *phb,
					 uint64_t tce_mem_addr,
					 uint64_t tce_mem_size)
{
	struct p5ioc2_phb *p = phb_to_p5ioc2_phb(phb);
	uint64_t tar;
	uint32_t cfg;

	printf("PHB%d: set_tce_memory: 0x%016llx 0x%016llx\n",
	       p->index, tce_mem_addr, tce_mem_size);
	printf("PHB%d: bridge values : 0x%016llx 0x%016llx\n",
	       p->index, p->ioc->tce_base, p->ioc->tce_size);

	/* First check if it fits in the memory established for
	 * the IO HUB
	 */
	if (tce_mem_addr &&
	    (tce_mem_addr < p->ioc->tce_base ||
	     tce_mem_addr > (p->ioc->tce_base + p->ioc->tce_size) ||
	     (tce_mem_addr + tce_mem_size) >
	     (p->ioc->tce_base + p->ioc->tce_size))) {
		prerror("PHB%d: TCEs not in bridge range\n", p->index);
		return OPAL_PARAMETER;
	}

	/* Supported sizes are power of two's naturally aligned
	 * and between 64K and 8M (p5ioc2 spec)
	 */
	if (tce_mem_addr && !is_pow2(tce_mem_size)) {
		prerror("PHB%d: Size is not a power of 2\n", p->index);
		return OPAL_PARAMETER;
	}
	if (tce_mem_addr & (tce_mem_size - 1)) {
		prerror("PHB%d: Not naturally aligned\n", p->index);
		return OPAL_PARAMETER;
	}
	if (tce_mem_addr &&
	    (tce_mem_size < 0x10000 || tce_mem_size > 0x800000)) {
		prerror("PHB%d: Size out of range\n", p->index);
		return OPAL_PARAMETER;
	}

	/* First we disable TCEs in the bridge */
	cfg = in_be32(p->regs + CAP_PCFGRW);
	cfg &= ~CAP_PCFGRW_TCE_EN;
	out_be32(p->regs + CAP_PCFGRW, cfg);


	/* Now there's a blurb in the spec about all TARm needing
	 * to have the same size.. I will let that as a surprise
	 * for the user ... Linux does it fine and I'd rather not
	 * keep more state to check than I need to
	 */
	tar = 0;
	if (tce_mem_addr) {
		tar = SETFIELD(CA_TAR_HUBID, 0ul, p->ca ? 4 : 1);
		tar = SETFIELD(CA_TAR_ALTHUBID, tar, p->ca ? 4 : 1);
		tar = SETFIELD(CA_TAR_NUM_TCE, tar, ilog2(tce_mem_size) - 16);
		tar |= tce_mem_addr; /* addr is naturally aligned */
		tar |= CA_TAR_VALID;
		printf("PHB%d: Writing TAR: 0x%016llx\n", p->index, tar);
	}
	out_be64(p->ca_regs + CA_TARn(p->index), tar);

	/* Now set the TCE enable if we set a valid address */
	if (tce_mem_addr) {
		cfg |= CAP_PCFGRW_TCE_EN;
		out_be32(p->regs + CAP_PCFGRW, cfg);
	}

	return OPAL_SUCCESS;
}


static const struct phb_ops p5ioc2_phb_ops = {
	.lock			= p5ioc2_phb_lock,
	.unlock			= p5ioc2_phb_unlock,
	.cfg_read8		= p5ioc2_pcicfg_read8,
	.cfg_read16		= p5ioc2_pcicfg_read16,
	.cfg_read32		= p5ioc2_pcicfg_read32,
	.cfg_write8		= p5ioc2_pcicfg_write8,
	.cfg_write16		= p5ioc2_pcicfg_write16,
	.cfg_write32		= p5ioc2_pcicfg_write32,
	.choose_bus		= p5ioc2_choose_bus,
	.eeh_freeze_status	= p5ioc2_eeh_freeze_status,
	.eeh_freeze_clear	= p5ioc2_eeh_freeze_clear,
	.next_error		= p5ioc2_eeh_next_error,
	.get_msi_64		= p5ioc2_get_msi_64,
	.ioda_reset		= p5ioc2_ioda_reset,
	.set_phb_tce_memory	= p5ioc2_set_phb_tce_memory,
	.presence_detect	= p5ioc2_presence_detect,
	.link_state		= p5ioc2_link_state,
	.power_state		= p5ioc2_power_state,
	.slot_power_off		= p5ioc2_slot_power_off,
	.slot_power_on		= p5ioc2_slot_power_on,
	.hot_reset		= p5ioc2_hot_reset,
	.fundamental_reset	= p5ioc2_freset,
	.poll			= p5ioc2_poll,
};

/* p5ioc2_phb_get_xive - Interrupt control from OPAL */
static int64_t p5ioc2_phb_get_xive(void *data, uint32_t isn,
				   uint16_t *server, uint8_t *prio)
{
	struct p5ioc2_phb *p = data;
	uint32_t irq, xivr, fbuid = P7_IRQ_FBUID(isn);

	if (fbuid != p->buid)
		return OPAL_PARAMETER;
	irq = isn & 0xf;

	xivr = p->xive_cache[irq];
	*server = GETFIELD(CAP_XIVR_SERVER, xivr);
	*prio = GETFIELD(CAP_XIVR_PRIO, xivr);

	return OPAL_SUCCESS;
}

/* p5ioc2_phb_set_xive - Interrupt control from OPAL */
static int64_t p5ioc2_phb_set_xive(void *data, uint32_t isn,
				   uint16_t server, uint8_t prio)
{
	struct p5ioc2_phb *p = data;
	uint32_t irq, xivr, fbuid = P7_IRQ_FBUID(isn);

	if (fbuid != p->buid)
		return OPAL_PARAMETER;
	irq = isn & 0xf;

	printf("PHB%d: Set XIVE isn %04x (irq=%d) server=%x, prio=%x\n",
	       p->index, isn, irq, server, prio);

	xivr = SETFIELD(CAP_XIVR_SERVER, 0, server);
	xivr = SETFIELD(CAP_XIVR_PRIO, xivr, prio);
	p->xive_cache[irq] = xivr;

	/* Now we mangle the server and priority */
	if (prio == 0xff) {
		server = 0;
		prio = 0xff;
	} else {
		prio = (prio >> 3) | ((server & 7) << 5);
		server = server >> 3;
	}

	/* We use HRT entry 0 always for now */
	xivr = SETFIELD(CAP_XIVR_SERVER, 0, server);
	xivr = SETFIELD(CAP_XIVR_PRIO, xivr, prio);
	out_be32(p->regs + CAP_XIVRn(irq), xivr);
	printf("PHB%d: wrote 0x%08x to XIVR %d\n", p->index, xivr, irq);

	return OPAL_SUCCESS;
}

/* IRQ ops for OS interrupts (not internal) */
static const struct irq_source_ops p5ioc2_phb_os_irq_ops = {
	.get_xive = p5ioc2_phb_get_xive,
	.set_xive = p5ioc2_phb_set_xive,
};


static void p5ioc2_phb_init_utl(struct p5ioc2_phb *p __unused)
{
	/* XXX FIXME */
}

static void p5ioc2_phb_init_pcie(struct p5ioc2_phb *p)
{
	int64_t ecap, aercap;

	ecap = pci_find_cap(&p->phb, 0, PCI_CFG_CAP_ID_EXP);
	if (ecap < 0) {
		/* Shouldn't happen */
		prerror("P5IOC2: Failed to locate PCI-E cap in bridge\n");
		return;
	}
	p->ecap = ecap;

	aercap = pci_find_ecap(&p->phb, 0, PCIECAP_ID_AER, NULL);
	if (aercap < 0) {
		/* Shouldn't happen */
		prerror("P5IOC2: Failed to locate AER ext cap in bridge\n");
		return;
	}
	p->aercap = aercap;

	/* XXX plenty more to do ... */
}

static void p5ioc2_phb_hwinit(struct p5ioc2_phb *p)
{
	uint16_t pcicmd;
	uint32_t phbid;

	printf("P5IOC2: Initializing PHB HW...\n");

	/* Enable PHB and and disable address decoding */
	phbid = in_be32(p->ca_regs + CA_PHBIDn(p->index));
	phbid |= CA_PHBID_PHB_ENABLE;
	phbid &= ~CA_PHBID_ADDRSPACE_ENABLE;
	out_be32(p->ca_regs + CA_PHBIDn(p->index), phbid);

	/* Set BUID */
	out_be32(p->regs + CAP_BUID, SETFIELD(CAP_BUID_MASK, 0,
					      P7_BUID_BASE(p->buid)));
	out_be32(p->regs + CAP_MSIBASE, P7_BUID_BASE(p->buid) << 16);

	/* Set IO and Memory mapping */
	out_be32(p->regs + CAP_IOAD_H, hi32(p->io_base + IO_PCI_START));
	out_be32(p->regs + CAP_IOAD_L, lo32(p->io_base + IO_PCI_START));
	out_be32(p->regs + CAP_IOSZ, ~(IO_PCI_SIZE - 1));
	out_be32(p->regs + CAP_IO_ST, IO_PCI_START);
	out_be32(p->regs + CAP_MEM1_H, hi32(p->mm_base + MM_PCI_START));
	out_be32(p->regs + CAP_MEM1_L, lo32(p->mm_base + MM_PCI_START));
	out_be32(p->regs + CAP_MSZ1, ~(MM_PCI_SIZE - 1));
	out_be32(p->regs + CAP_MEM_ST, MM_PCI_START);

	/* Setup the MODE registers. We captures the values used
	 * by pHyp/OPAL
	 */
	out_be32(p->regs + CAP_MODE0, 0x00800010);
	out_be32(p->regs + CAP_MODE1, 0x00800000);
	out_be32(p->regs + CAP_MODE3, 0xFFC00050);
	if (p->is_pcie)
		out_be32(p->regs + CAP_MODE2, 0x00000400);
	else
		out_be32(p->regs + CAP_MODE2, 0x00000408);

	/* XXX Setup of the arbiter... not sure what to do here,
	 * probably system specific (depends on whow things are
	 * wired on the motherboard). I set things up based on
	 * the values I read on a Juno machine. We setup the BPR
	 * with the various timeouts etc... as well based one
	 * similarily captured values
	 */
	if (p->is_pcie) {
		out_be32(p->regs + CAP_AER, 0x04000000);
		out_be32(p->regs + CAP_BPR, 0x0000004f);
	} else {
		out_be32(p->regs + CAP_AER, 0x84000000);
		out_be32(p->regs + CAP_BPR, 0x000f00ff);
	}

	/* XXX Setup error reporting registers */

	/* Clear errors in PLSSR and DMACSR */
	out_be32(p->regs + CAP_DMACSR, 0);
	out_be32(p->regs + CAP_PLSSR, 0);	

	/* Configure MSIs on PCIe only */
	if (p->is_pcie) {
		/* XXX Check that setting ! That's what OPAL uses but
		 * I suspect it might not be correct. We enable a masking
		 * of 3 bits and no offset, which makes me think only
		 * some MSIs will work... not 100% certain.
		 */
		out_be32(p->regs + CAP_MVE0, CAP_MVE_VALID |
			 SETFIELD(CAP_MVE_TBL_OFF, 0, 0) |
			 SETFIELD(CAP_MVE_NUM_INT, 0, 0x3));
		out_be32(p->regs + CAP_MVE1, 0);
	}

	/* Configuration. We keep TCEs disabled */
	out_be32(p->regs + CAP_PCFGRW,
		 CAP_PCFGRW_ERR_RECOV_EN |
		 CAP_PCFGRW_FREEZE_EN |
		 CAP_PCFGRW_DAC_DISABLE |
		 (p->is_pcie ? CAP_PCFGRW_MSI_EN : 0));

	/* Re-enable address decode */
	phbid |= CA_PHBID_ADDRSPACE_ENABLE;
	out_be32(p->ca_regs + CA_PHBIDn(p->index), phbid);

	/* PCIe specific inits */
	if (p->is_pcie) {
		p5ioc2_phb_init_utl(p);
		p5ioc2_phb_init_pcie(p);
	}

	/* Take out reset pins on PCI-X. PCI-E will be handled via the hotplug
	 * controller separately
	 */
	if (!p->is_pcie) {
		uint32_t val;

		/* Setting 1's will deassert the reset signals */
		out_be32(p->regs + CAP_CRR, CAP_CRR_RESET1 | CAP_CRR_RESET2);

		/* Set max sub bus */
		p5ioc2_pcicfg_write8(&p->phb, 0, 0x41, 0xff);

		/* XXX SHPC stuff */
		printf("P5IOC2: SHPC Slots available 1  : %08x\n",
		       in_be32(p->regs + 0xb20));
		printf("P5IOC2: SHPC Slots available 2  : %08x\n",
		       in_be32(p->regs + 0xb24));
		printf("P5IOC2: SHPC Slots config       : %08x\n",
		       in_be32(p->regs + 0xb28));
		printf("P5IOC2: SHPC Secondary bus conf : %08x\n",
		       in_be32(p->regs + 0xb2c));

		p5ioc2_pcicfg_read32(&p->phb, 0, 0, &val);
		printf("P5IOC2: val0: %08x\n", val);
		p5ioc2_pcicfg_read32(&p->phb, 0, 4, &val);
		printf("P5IOC2: val4: %08x\n", val);
	}

	/* Enable PCI command/status */
	p5ioc2_pcicfg_read16(&p->phb, 0, PCI_CFG_CMD, &pcicmd);
	pcicmd |= PCI_CFG_CMD_IO_EN | PCI_CFG_CMD_MEM_EN |
		PCI_CFG_CMD_BUS_MASTER_EN;
	p5ioc2_pcicfg_write16(&p->phb, 0, PCI_CFG_CMD, pcicmd);

	p->state = P5IOC2_PHB_STATE_FUNCTIONAL;
}

static void p5ioc2_pcie_add_node(struct p5ioc2_phb *p)
{
	uint64_t reg[2], mmb, iob;
	uint32_t lsibase, icsp = get_ics_phandle();
	struct dt_node *np;

	reg[0] = cleanup_addr((uint64_t)p->regs);
	reg[1] = 0x1000;

	np = dt_new_addr(p->ioc->dt_node, "pciex", reg[0]);
	if (!np)
		return;

	p->phb.dt_node = np;
	dt_add_property_strings(np, "compatible", "ibm,p5ioc2-pciex");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", reg, sizeof(reg));
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0); /* ??? */
	dt_add_property_cells(np, "interrupt-parent", icsp);
	/* XXX FIXME: add phb own interrupts */
	dt_add_property_cells(np, "ibm,opal-num-pes", 1);
	dt_add_property_cells(np, "ibm,opal-msi-ranges", (p->buid << 4) + 5, 8);
	/* XXX FIXME: add slot-name */
	iob = cleanup_addr(p->io_base + IO_PCI_START);
	mmb = cleanup_addr(p->mm_base + MM_PCI_START);
	dt_add_property_cells(np, "ranges",
			      /* IO space */
			      0x01000000, 0x00000000, 0x00000000,
			      hi32(iob), lo32(iob), 0, IO_PCI_SIZE,
			      /* M32 space */
			      0x02000000, 0x00000000, MM_PCI_START,
			      hi32(mmb), lo32(mmb), 0, MM_PCI_SIZE);

	/* Add associativity properties */
	add_chip_dev_associativity(np);

	/* The interrupt maps will be generated in the RC node by the
	 * PCI code based on the content of this structure:
	 */
	lsibase = p->buid << 4;
	p->phb.lstate.int_size = 1;
	p->phb.lstate.int_val[0][0] = lsibase + 1;
	p->phb.lstate.int_val[1][0] = lsibase + 2;
	p->phb.lstate.int_val[2][0] = lsibase + 3;
	p->phb.lstate.int_val[3][0] = lsibase + 4;
	p->phb.lstate.int_parent[0] = icsp;
	p->phb.lstate.int_parent[1] = icsp;
	p->phb.lstate.int_parent[2] = icsp;
	p->phb.lstate.int_parent[3] = icsp;

	/* reset clear timestamp... to add if we do a reset and want
	 * to avoid waiting in skiboot
	 */
	//dt_property_cells("reset-clear-timestamp",....
}

static void p5ioc2_pcix_add_node(struct p5ioc2_phb *p)
{
	uint64_t reg[2], mmb, iob;
	uint32_t lsibase, icsp = get_ics_phandle();
	struct dt_node *np;

	reg[0] = cleanup_addr((uint64_t)p->regs);
	reg[1] = 0x1000;

	np = dt_new_addr(p->ioc->dt_node, "pci", reg[0]);
	if (!np)
		return;

	p->phb.dt_node = np;
	dt_add_property_strings(np, "compatible", "ibm,p5ioc2-pcix");
	dt_add_property_strings(np, "device_type", "pci");
	dt_add_property(np, "reg", reg, sizeof(reg));
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0); /* ??? */
	//dt_add_property_cells(np, "bus-width", 8); /* Figure out from VPD ? */
	dt_add_property_cells(np, "interrupt-parent", icsp);
	/* XXX FIXME: add phb own interrupts */
	dt_add_property_cells(np, "ibm,opal-num-pes", 1);
	/* XXX FIXME: add slot-name */
	iob = cleanup_addr(p->io_base + IO_PCI_START);
	mmb = cleanup_addr(p->mm_base + MM_PCI_START);
	dt_add_property_cells(np, "ranges",
			      /* IO space */
			      0x01000000, 0x00000000, 0x00000000,
			      hi32(iob), lo32(iob), 0, IO_PCI_SIZE,
			      /* M32 space */
			      0x02000000, 0x00000000, MM_PCI_START,
			      hi32(mmb), lo32(mmb), 0, MM_PCI_SIZE);

	/* Add associativity properties */
	add_chip_dev_associativity(np);

	/* The interrupt maps will be generated in the RC node by the
	 * PCI code based on the content of this structure:
	 */
	lsibase = p->buid << 4;
	p->phb.lstate.int_size = 1;
	p->phb.lstate.int_val[0][0] = lsibase + 1;
	p->phb.lstate.int_val[1][0] = lsibase + 2;
	p->phb.lstate.int_val[2][0] = lsibase + 3;
	p->phb.lstate.int_val[3][0] = lsibase + 4;
	p->phb.lstate.int_parent[0] = icsp;
	p->phb.lstate.int_parent[1] = icsp;
	p->phb.lstate.int_parent[2] = icsp;
	p->phb.lstate.int_parent[3] = icsp;

	/* On PCI-X we need to create an interrupt map here */
	pci_std_swizzle_irq_map(np, NULL, &p->phb.lstate, 0);
}

void p5ioc2_phb_setup(struct p5ioc2 *ioc, struct p5ioc2_phb *p,
		      uint8_t ca, uint8_t index, bool active,
		      uint32_t buid)
{
	uint32_t phbid;

	p->index = index;
	p->ca = ca;
	p->ioc = ioc;
	p->active = active;
	p->phb.ops = &p5ioc2_phb_ops;
	p->buid = buid;
	p->ca_regs = ca ? ioc->ca1_regs : ioc->ca0_regs;
	p->regs = p->ca_regs + CA_PHBn_REGS(index);

	printf("P5IOC2: Initializing PHB %d on CA%d, regs @%p, BUID 0x%04x\n",
	       p->index, p->ca, p->regs, p->buid);

	/* Memory map: described in p5ioc2.h */
	p->mm_base = ca ? ioc->ca1_mm_region : ioc->ca0_mm_region;
	p->mm_base += MM_WINDOW_SIZE * index;
	p->io_base = (uint64_t)p->ca_regs;
	p->io_base += IO_PCI_SIZE * (index + 1);
	p->state = P5IOC2_PHB_STATE_UNINITIALIZED;

	/* Query PHB type */
	phbid = in_be32(p->ca_regs + CA_PHBIDn(p->index));

	switch(GETFIELD(CA_PHBID_PHB_TYPE, phbid)) {
	case CA_PHBTYPE_PCIX1_0:
		p->is_pcie = false;
		p->phb.scan_map = 0x0003;
		p->phb.phb_type = phb_type_pcix_v1;
		printf("P5IOC2: PHB is PCI/PCI-X 1.0\n");
		break;
	case CA_PHBTYPE_PCIX2_0:
		p->is_pcie = false;
		p->phb.scan_map = 0x0003;
		p->phb.phb_type = phb_type_pcix_v2;
		printf("P5IOC2: PHB is PCI/PCI-X 2.0\n");
		break;
	case CA_PHBTYPE_PCIE_G1:
		p->is_pcie = true;
		p->phb.scan_map = 0x0001;
		p->phb.phb_type = phb_type_pcie_v1;
		printf("P5IOC2: PHB is PCI Express Gen 1\n");
		break;
	case CA_PHBTYPE_PCIE_G2:
		p->is_pcie = true;
		p->phb.scan_map = 0x0001;
		p->phb.phb_type = phb_type_pcie_v2;
		printf("P5IOC2: PHB is PCI Express Gen 2\n");
		break;
	default:
		printf("P5IOC2: Unknown PHB type ! phbid=%08x\n", phbid);
		p->is_pcie = true;
		p->phb.scan_map = 0x0001;
		p->phb.phb_type = phb_type_pcie_v1;
	}

	/* Find P5IOC2 base location code in IOC */
	p->phb.base_loc_code = dt_prop_get_def(ioc->dt_node,
					       "ibm,io-base-loc-code", NULL);
	if (!p->phb.base_loc_code)
		prerror("P5IOC2: Base location code not found !\n");

	/* Add device nodes */
	if (p->is_pcie)
		p5ioc2_pcie_add_node(p);
	else
		p5ioc2_pcix_add_node(p);

	/* Initialize PHB HW */
	p5ioc2_phb_hwinit(p);

	/* Register all 16 interrupt sources for now as OS visible
	 *
	 * If we ever add some EEH, we might take out the error interrupts
	 * and register them as OPAL internal interrupts instead
	 */
	register_irq_source(&p5ioc2_phb_os_irq_ops, p, p->buid << 4, 16);

	/* We cannot query the PHB type yet as the registers aren't routed
	 * so we'll do that in the inits, at which point we'll establish
	 * the scan map
	 */

	/* We register the PHB before we initialize it so we
	 * get a useful OPAL ID for it
	 */
	pci_register_phb(&p->phb);

	/* Platform additional setup */
	if (platform.pci_setup_phb)
		platform.pci_setup_phb(&p->phb, p->index);
}

