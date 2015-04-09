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
#include <opal-api.h>
#include <pci.h>
#include <pci-cfg.h>
#include <timebase.h>
#include <lock.h>

#define OPAL_PCICFG_ACCESS(op, cb, type)	\
static int64_t opal_pci_config_##op(uint64_t phb_id,			\
				    uint64_t bus_dev_func,		\
				    uint64_t offset, type data)		\
{									\
	struct phb *phb = pci_get_phb(phb_id);				\
	int64_t rc;							\
									\
	if (!phb)							\
		return OPAL_PARAMETER;					\
	phb->ops->lock(phb);						\
	rc = phb->ops->cfg_##cb(phb, bus_dev_func, offset, data);	\
	phb->ops->unlock(phb);						\
	pci_put_phb(phb);						\
									\
	return rc;							\
}

OPAL_PCICFG_ACCESS(read_byte,		read8, uint8_t *)
OPAL_PCICFG_ACCESS(read_half_word,	read16, uint16_t *)
OPAL_PCICFG_ACCESS(read_word,		read32, uint32_t *)
OPAL_PCICFG_ACCESS(write_byte,		write8, uint8_t)
OPAL_PCICFG_ACCESS(write_half_word,	write16, uint16_t)
OPAL_PCICFG_ACCESS(write_word,		write32, uint32_t)

opal_call(OPAL_PCI_CONFIG_READ_BYTE, opal_pci_config_read_byte, 4);
opal_call(OPAL_PCI_CONFIG_READ_HALF_WORD, opal_pci_config_read_half_word, 4);
opal_call(OPAL_PCI_CONFIG_READ_WORD, opal_pci_config_read_word, 4);
opal_call(OPAL_PCI_CONFIG_WRITE_BYTE, opal_pci_config_write_byte, 4);
opal_call(OPAL_PCI_CONFIG_WRITE_HALF_WORD, opal_pci_config_write_half_word, 4);
opal_call(OPAL_PCI_CONFIG_WRITE_WORD, opal_pci_config_write_word, 4);

static struct lock opal_eeh_evt_lock = LOCK_UNLOCKED;
static uint64_t opal_eeh_evt = 0;

void opal_pci_eeh_set_evt(uint64_t phb_id)
{
	lock(&opal_eeh_evt_lock);
	opal_eeh_evt |= 1ULL << phb_id;
	opal_update_pending_evt(OPAL_EVENT_PCI_ERROR, OPAL_EVENT_PCI_ERROR);
	unlock(&opal_eeh_evt_lock);
}

void opal_pci_eeh_clear_evt(uint64_t phb_id)
{
	lock(&opal_eeh_evt_lock);
	opal_eeh_evt &= ~(1ULL << phb_id);
	if (!opal_eeh_evt)
		opal_update_pending_evt(OPAL_EVENT_PCI_ERROR, 0);
	unlock(&opal_eeh_evt_lock);
}

static int64_t opal_pci_eeh_freeze_status(uint64_t phb_id, uint64_t pe_number,
					  uint8_t *freeze_state,
					  uint16_t *pci_error_type,
					  uint64_t *phb_status)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->eeh_freeze_status)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->eeh_freeze_status(phb, pe_number, freeze_state,
					 pci_error_type, NULL, phb_status);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_EEH_FREEZE_STATUS, opal_pci_eeh_freeze_status, 5);

static int64_t opal_pci_eeh_freeze_clear(uint64_t phb_id, uint64_t pe_number,
					 uint64_t eeh_action_token)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->eeh_freeze_clear)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->eeh_freeze_clear(phb, pe_number, eeh_action_token);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_EEH_FREEZE_CLEAR, opal_pci_eeh_freeze_clear, 3);

static int64_t opal_pci_eeh_freeze_set(uint64_t phb_id, uint64_t pe_number,
				       uint64_t eeh_action_token)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->eeh_freeze_set)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->eeh_freeze_set(phb, pe_number, eeh_action_token);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_EEH_FREEZE_SET, opal_pci_eeh_freeze_set, 3);

static int64_t opal_pci_err_inject(uint64_t phb_id, uint32_t pe_no,
				   uint32_t type, uint32_t func,
				   uint64_t addr, uint64_t mask)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops || !phb->ops->err_inject)
		return OPAL_UNSUPPORTED;

	if (type != OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR &&
	    type != OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
		return OPAL_PARAMETER;

	phb->ops->lock(phb);
	rc = phb->ops->err_inject(phb, pe_no, type, func, addr, mask);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_ERR_INJECT, opal_pci_err_inject, 6);

static int64_t opal_pci_phb_mmio_enable(uint64_t phb_id, uint16_t window_type,
					uint16_t window_num, uint16_t enable)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->phb_mmio_enable)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->phb_mmio_enable(phb, window_type, window_num, enable);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_PHB_MMIO_ENABLE, opal_pci_phb_mmio_enable, 4);

static int64_t opal_pci_set_phb_mem_window(uint64_t phb_id,
					   uint16_t window_type,
					   uint16_t window_num,
					   uint64_t addr,
					   uint64_t pci_addr,
					   uint64_t size)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_phb_mem_window)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->set_phb_mem_window(phb, window_type, window_num,
					  addr, pci_addr, size);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_PHB_MEM_WINDOW, opal_pci_set_phb_mem_window, 6);

static int64_t opal_pci_map_pe_mmio_window(uint64_t phb_id, uint16_t pe_number,
					   uint16_t window_type,
					   uint16_t window_num,
					   uint16_t segment_num)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->map_pe_mmio_window)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->map_pe_mmio_window(phb, pe_number, window_type,
					  window_num, segment_num);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_MAP_PE_MMIO_WINDOW, opal_pci_map_pe_mmio_window, 5);

static int64_t opal_pci_set_phb_table_memory(uint64_t phb_id __unused,
					     uint64_t rtt_addr __unused,
					     uint64_t ivt_addr __unused,
					     uint64_t ivt_len __unused,
					     uint64_t rej_array_addr __unused,
					     uint64_t peltv_addr __unused)
{
	/* IODA2 (P8) stuff, TODO */
	return OPAL_UNSUPPORTED;
}
opal_call(OPAL_PCI_SET_PHB_TABLE_MEMORY, opal_pci_set_phb_table_memory, 6);

static int64_t opal_pci_set_pe(uint64_t phb_id, uint64_t pe_number,
			       uint64_t bus_dev_func, uint8_t bus_compare,
			       uint8_t dev_compare, uint8_t func_compare,
			       uint8_t pe_action)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_pe)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->set_pe(phb, pe_number, bus_dev_func, bus_compare,
			      dev_compare, func_compare, pe_action);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_PE, opal_pci_set_pe, 7);

static int64_t opal_pci_set_peltv(uint64_t phb_id, uint32_t parent_pe,
				  uint32_t child_pe, uint8_t state)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_peltv)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->set_peltv(phb, parent_pe, child_pe, state);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_PELTV, opal_pci_set_peltv, 4);

static int64_t opal_pci_set_mve(uint64_t phb_id, uint32_t mve_number,
				uint32_t pe_number)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_mve)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->set_mve(phb, mve_number, pe_number);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_MVE, opal_pci_set_mve, 3);

static int64_t opal_pci_set_mve_enable(uint64_t phb_id, uint32_t mve_number,
				       uint32_t state)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_mve_enable)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->set_mve_enable(phb, mve_number, state);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_MVE_ENABLE, opal_pci_set_mve_enable, 3);

static int64_t opal_pci_get_xive_reissue(uint64_t phb_id __unused,
					 uint32_t xive_number __unused,
					 uint8_t *p_bit __unused,
					 uint8_t *q_bit __unused)
{
	/* IODA2 (P8) stuff, TODO */
	return OPAL_UNSUPPORTED;
}
opal_call(OPAL_PCI_GET_XIVE_REISSUE, opal_pci_get_xive_reissue, 4);

static int64_t opal_pci_set_xive_reissue(uint64_t phb_id __unused,
					 uint32_t xive_number __unused,
					 uint8_t p_bit __unused,
					 uint8_t q_bit __unused)
{
	/* IODA2 (P8) stuff, TODO */
	return OPAL_UNSUPPORTED;
}
opal_call(OPAL_PCI_SET_XIVE_REISSUE, opal_pci_set_xive_reissue, 4);

static int64_t opal_pci_msi_eoi(uint64_t phb_id,
				uint32_t hwirq)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->pci_msi_eoi)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->pci_msi_eoi(phb, hwirq);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_MSI_EOI, opal_pci_msi_eoi, 2);

static int64_t opal_pci_set_xive_pe(uint64_t phb_id, uint32_t pe_number,
				    uint32_t xive_num)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_xive_pe)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->set_xive_pe(phb, pe_number, xive_num);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_XIVE_PE, opal_pci_set_xive_pe, 3);

static int64_t opal_get_xive_source(uint64_t phb_id, uint32_t xive_num,
				    int32_t *interrupt_source_number)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->get_xive_source)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->get_xive_source(phb, xive_num, interrupt_source_number);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_GET_XIVE_SOURCE, opal_get_xive_source, 3);

static int64_t opal_get_msi_32(uint64_t phb_id, uint32_t mve_number,
			       uint32_t xive_num, uint8_t msi_range,
			       uint32_t *msi_address, uint32_t *message_data)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->get_msi_32)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->get_msi_32(phb, mve_number, xive_num, msi_range,
				  msi_address, message_data);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_GET_MSI_32, opal_get_msi_32, 6);

static int64_t opal_get_msi_64(uint64_t phb_id, uint32_t mve_number,
			       uint32_t xive_num, uint8_t msi_range,
			       uint64_t *msi_address, uint32_t *message_data)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->get_msi_64)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->get_msi_64(phb, mve_number, xive_num, msi_range,
				  msi_address, message_data);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_GET_MSI_64, opal_get_msi_64, 6);

static int64_t opal_pci_map_pe_dma_window(uint64_t phb_id, uint16_t pe_number,
					  uint16_t window_id,
					  uint16_t tce_levels,
					  uint64_t tce_table_addr,
					  uint64_t tce_table_size,
					  uint64_t tce_page_size)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->map_pe_dma_window)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->map_pe_dma_window(phb, pe_number, window_id,
					 tce_levels, tce_table_addr,
					 tce_table_size, tce_page_size);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_MAP_PE_DMA_WINDOW, opal_pci_map_pe_dma_window, 7);

static int64_t opal_pci_map_pe_dma_window_real(uint64_t phb_id,
					       uint16_t pe_number,
					       uint16_t window_id,
					       uint64_t pci_start_addr,
					       uint64_t pci_mem_size)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->map_pe_dma_window_real)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->map_pe_dma_window_real(phb, pe_number, window_id,
					      pci_start_addr, pci_mem_size);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_MAP_PE_DMA_WINDOW_REAL, opal_pci_map_pe_dma_window_real, 5);

static int64_t opal_pci_reset(uint64_t phb_id, uint8_t reset_scope,
                              uint8_t assert_state)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc = OPAL_SUCCESS;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops)
		return OPAL_UNSUPPORTED;
	if (assert_state != OPAL_ASSERT_RESET &&
	    assert_state != OPAL_DEASSERT_RESET)
		return OPAL_PARAMETER;

	phb->ops->lock(phb);

	switch(reset_scope) {
	case OPAL_RESET_PHB_COMPLETE:
		if (!phb->ops->complete_reset) {
			rc = OPAL_UNSUPPORTED;
			break;
		}

		rc = phb->ops->complete_reset(phb, assert_state);
		if (rc < 0)
			prerror("PHB#%d: Failure on complete reset, rc=%lld\n",
				phb->opal_id, rc);
		break;
	case OPAL_RESET_PCI_FUNDAMENTAL:
		if (!phb->ops->fundamental_reset) {
			rc = OPAL_UNSUPPORTED;
			break;
		}

		/* We need do nothing on deassert time */
		if (assert_state != OPAL_ASSERT_RESET)
			break;

		rc = phb->ops->fundamental_reset(phb);
		if (rc < 0)
			prerror("PHB#%d: Failure on fundamental reset, rc=%lld\n",
				phb->opal_id, rc);
		break;
	case OPAL_RESET_PCI_HOT:
		if (!phb->ops->hot_reset) {
			rc = OPAL_UNSUPPORTED;
			break;
		}

		/* We need do nothing on deassert time */
		if (assert_state != OPAL_ASSERT_RESET)
			break;

		rc = phb->ops->hot_reset(phb);
		if (rc < 0)
			prerror("PHB#%d: Failure on hot reset, rc=%lld\n",
				phb->opal_id, rc);
		break;
	case OPAL_RESET_PCI_IODA_TABLE:
		if (assert_state != OPAL_ASSERT_RESET)
			break;
		if (phb->ops->ioda_reset)
			phb->ops->ioda_reset(phb, true);
		break;
	case OPAL_RESET_PHB_ERROR:
		if (assert_state != OPAL_ASSERT_RESET)
			break;
		if (phb->ops->papr_errinjct_reset)
			phb->ops->papr_errinjct_reset(phb);
		break;
	default:
		rc = OPAL_UNSUPPORTED;
	}
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return (rc > 0) ? tb_to_msecs(rc) : rc;
}
opal_call(OPAL_PCI_RESET, opal_pci_reset, 3);

static int64_t opal_pci_reinit(uint64_t phb_id,
			       uint64_t reinit_scope,
			       uint64_t data)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops || !phb->ops->pci_reinit)
		return OPAL_UNSUPPORTED;

	phb->ops->lock(phb);
	rc = phb->ops->pci_reinit(phb, reinit_scope, data);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_REINIT, opal_pci_reinit, 3);

static int64_t opal_pci_poll(uint64_t phb_id)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops || !phb->ops->poll)
		return OPAL_UNSUPPORTED;

	phb->ops->lock(phb);
	rc = phb->ops->poll(phb);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	/* Return milliseconds for caller to sleep: round up */
	if (rc > 0) {
		rc = tb_to_msecs(rc);
		if (rc == 0)
			rc = 1;
	}

	return rc;
}
opal_call(OPAL_PCI_POLL, opal_pci_poll, 1);

static int64_t opal_pci_set_phb_tce_memory(uint64_t phb_id,
					   uint64_t tce_mem_addr,
					   uint64_t tce_mem_size)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_phb_tce_memory)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->set_phb_tce_memory(phb, tce_mem_addr, tce_mem_size);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_PHB_TCE_MEMORY, opal_pci_set_phb_tce_memory, 3);

static int64_t opal_pci_get_phb_diag_data(uint64_t phb_id,
					  void *diag_buffer,
					  uint64_t diag_buffer_len)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->get_diag_data)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->get_diag_data(phb, diag_buffer, diag_buffer_len);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_GET_PHB_DIAG_DATA, opal_pci_get_phb_diag_data, 3);

static int64_t opal_pci_get_phb_diag_data2(uint64_t phb_id,
					   void *diag_buffer,
					   uint64_t diag_buffer_len)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->get_diag_data2)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->get_diag_data2(phb, diag_buffer, diag_buffer_len);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_GET_PHB_DIAG_DATA2, opal_pci_get_phb_diag_data2, 3);

static int64_t opal_pci_next_error(uint64_t phb_id, uint64_t *first_frozen_pe,
				   uint16_t *pci_error_type, uint16_t *severity)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->next_error)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);

	opal_pci_eeh_clear_evt(phb_id);
	rc = phb->ops->next_error(phb, first_frozen_pe, pci_error_type,
				  severity);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_NEXT_ERROR, opal_pci_next_error, 4);

static int64_t opal_pci_eeh_freeze_status2(uint64_t phb_id, uint64_t pe_number,
					   uint8_t *freeze_state,
					   uint16_t *pci_error_type,
					   uint16_t *severity,
					   uint64_t *phb_status)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->eeh_freeze_status)
		return OPAL_UNSUPPORTED;
	phb->ops->lock(phb);
	rc = phb->ops->eeh_freeze_status(phb, pe_number, freeze_state,
					 pci_error_type, severity, phb_status);
	phb->ops->unlock(phb);
	pci_put_phb(phb);

	return rc;
}
opal_call(OPAL_PCI_EEH_FREEZE_STATUS2, opal_pci_eeh_freeze_status2, 6);

static int64_t opal_pci_set_phb_capi_mode(uint64_t phb_id, uint64_t mode, uint64_t pe_number)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_capi_mode)
		return OPAL_UNSUPPORTED;

	phb->ops->lock(phb);
	rc = phb->ops->set_capi_mode(phb, mode, pe_number);
	phb->ops->unlock(phb);
	return rc;
}
opal_call(OPAL_PCI_SET_PHB_CAPI_MODE, opal_pci_set_phb_capi_mode, 3);
