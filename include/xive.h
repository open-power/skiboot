// SPDX-License-Identifier: Apache-2.0
/*
 * XIVE: eXternal Interrupt Virtualization Engine. POWER9 interrupt
 * controller
 *
 * Copyright (c) 2016-2019, IBM Corporation.
 */

#ifndef XIVE_H
#define XIVE_H

/* Internal APIs to other modules */

/* IRQ allocators return this on failure */
#define XIVE_IRQ_ERROR	0xffffffff

void init_xive(void);
int64_t xive_reset(void);

/* Allocate a chunk of HW sources */
uint32_t xive_alloc_hw_irqs(uint32_t chip_id, uint32_t count, uint32_t align);
/* Allocate a chunk of IPI sources */
uint32_t xive_alloc_ipi_irqs(uint32_t chip_id, uint32_t count, uint32_t align);

/* Get notification port address for a HW source entity */
#define XIVE_HW_SRC_PHBn(__n)	(__n)
#define XIVE_HW_SRC_PSI		8

uint64_t xive_get_notify_port(uint32_t chip_id, uint32_t ent);
uint32_t xive_get_notify_base(uint32_t girq);

/* XIVE feature flag to de/activate store EOI */
#define XIVE_STORE_EOI_ENABLED 0

/* Internal IRQ flags */
#define XIVE_SRC_TRIGGER_PAGE	0x01 /* Trigger page exist (either separate
				      * or not, so different from the OPAL
				      * flag which is only set when the
				      * trigger page is separate).
				      */
#define XIVE_SRC_EOI_PAGE1	0x02 /* EOI on the second page */
#define XIVE_SRC_STORE_EOI	0x04 /* EOI using stores supported */
#define XIVE_SRC_LSI		0x08 /* Interrupt is an LSI */
#define XIVE_SRC_SHIFT_BUG	0x10 /* ESB update offset << 4 (PHB4 LSI DD1) */

struct irq_source_ops;
void xive_register_hw_source(uint32_t base, uint32_t count, uint32_t shift,
			     void *mmio, uint32_t flags, void *data,
			     const struct irq_source_ops *ops);
void xive_register_ipi_source(uint32_t base, uint32_t count, void *data,
			      const struct irq_source_ops *ops);

void xive_cpu_callin(struct cpu_thread *cpu);

/* Get the trigger page address for an interrupt allocated with
 * xive_alloc_ipi_irqs()
 */
void *xive_get_trigger_port(uint32_t girq);

/* To be used by PSI to prevent asserted LSI to constantly re-fire */
struct irq_source;
void xive_source_mask(struct irq_source *is, uint32_t isn);

void xive_cpu_reset(void);
void xive_late_init(void);

#endif /* XIVE_H */
