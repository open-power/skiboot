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

#ifndef __P5IOC2_H
#define __P5IOC2_H

#include <stdint.h>
#include <cec.h>
#include <io.h>
#include <cec.h>
#include <pci.h>
#include <lock.h>
#include <device.h>

#include <ccan/container_of/container_of.h>

/*
 * Various definitions which are the result of various
 * things we have hard wired (routing etc...)
 */

/* It looks like our registers are at an offset from GX BAR 0 ... */
#define P5IOC2_REGS_OFFSET		0x01F00000

#define P5IOC2_CA0_REG_OFFSET		0	   /* From BAR6, R0 */
#define P5IOC2_CA1_REG_OFFSET		0x01000000 /* From BAR6, R1 */
#define P5IOC2_CA0_MM_OFFSET		0	   /* From BAR0, R0 and 1 */
#define P5IOC2_CA1_MM_OFFSET	        0x400000000ul /* From BAR0, R1 and 2 */
#define P5IOC2_CA_PHB_COUNT		4
#define P5IOC2_CA0_RIO_ID		2
#define P5IOC2_CA1_RIO_ID		3
#define P5IOC2_CA0_BUID			0x10
#define P5IOC2_CA1_BUID			0x20

/*
 * Our memory space is slightly different than pHyp
 * (or even BML). We do as follow:
 *
 *  - IO space is in the Calgary MMIO, at (phb_index +1) * 1M
 *    (pHyp seems to mangle the IO space location) and is always
 *    1M in size mapping to PCI 0
 *
 * -  Memory space is in the BAR0 mapped region. Each PHB gets
 *    allocated a 4G window at base + (phb_index * 4G). It uses
 *    a portion of that space based on the chosen size of the
 *    MMIO space, typically 2G.
 */
#define MM_WINDOW_SIZE	0x100000000ul
#define MM_PCI_START	 0x80000000
#define MM_PCI_SIZE	 0x80000000
#define IO_PCI_START	 0x00000000
#define IO_PCI_SIZE	 0x00100000

/*
 * CAn interrupts
 *
 * Within Calgary BUID space
 */
#define P5IOC2_CA_HOST_IRQ		0
#define P5IOC2_CA_SPCN_IRQ		1
#define P5IOC2_CA_PERF_IRQ		2

/*
 * The PHB states are similar to P7IOC, see the explanation
 * in p7ioc.h
 */
enum p5ioc2_phb_state {
	/* First init state */
	P5IOC2_PHB_STATE_UNINITIALIZED,

	/* During PHB HW inits */
	P5IOC2_PHB_STATE_INITIALIZING,

	/* Set if the PHB is for some reason unusable */
	P5IOC2_PHB_STATE_BROKEN,

	/* Normal PHB functional state */
	P5IOC2_PHB_STATE_FUNCTIONAL,
};

/*
 * Structure for a PHB
 */

struct p5ioc2;

struct p5ioc2_phb {
	bool				active;	/* Is this PHB functional ? */
	bool				is_pcie;
	uint8_t				ca;	/* CA0 or CA1 */
	uint8_t				index;	/* 0..3 index inside CA */
	void				*ca_regs;  /* Calgary regs */
	void				*regs;	   /* PHB regs */
	struct lock			lock;
	uint32_t			buid;
	uint64_t			mm_base;
	uint64_t			io_base;
	int64_t				ecap;	/* cached PCI-E cap offset */
	int64_t				aercap; /* cached AER ecap offset */
	enum p5ioc2_phb_state		state;
	uint64_t			delay_tgt_tb;
	uint64_t			retries;
	uint64_t			xive_cache[16];
	struct p5ioc2			*ioc;
	struct phb			phb;
};

static inline struct p5ioc2_phb *phb_to_p5ioc2_phb(struct phb *phb)
{
	return container_of(phb, struct p5ioc2_phb, phb);
}

extern void p5ioc2_phb_setup(struct p5ioc2 *ioc, struct p5ioc2_phb *p,
			     uint8_t ca, uint8_t index, bool active,
			     uint32_t buid);

/*
 * State structure for P5IOC2 IO HUB
 */
struct p5ioc2 {
	/* Device node */
	struct dt_node			*dt_node;

	/* MMIO regs for the chip */
	void				*regs;

	/* BAR6 (matches GX BAR 1) is used for internal Calgary MMIO and
	 * for PCI IO space.
	 */
	uint64_t			bar6;

	/* BAR0 (matches GX BAR 2) is used for PCI memory space */
	uint64_t			bar0;

	/* Calgary 0 and 1 registers. We assume their BBAR values as such
	 * that CA0 is at bar6 and CA1 at bar6 + 16M
	 */
	void*				ca0_regs;
	void*				ca1_regs;

	/* The large MM regions assigned off bar0 to CA0 and CA1 for use
	 * by their PHBs (16G each)
	 */
	uint64_t			ca0_mm_region;
	uint64_t			ca1_mm_region;

	/* BUID base for the PHB. This does include the top bits
	 * (chip, GX bus ID, etc...). This is initialized from the
	 * SPIRA.
	 */
	uint32_t			buid_base;

	/* TCE region set by the user */
	uint64_t			tce_base;
	uint64_t			tce_size;

	/* Calgary 0 and 1 PHBs */
	struct p5ioc2_phb		ca0_phbs[P5IOC2_CA_PHB_COUNT];
	struct p5ioc2_phb		ca1_phbs[P5IOC2_CA_PHB_COUNT];

	uint32_t			host_chip;
	uint32_t			gx_bus;
	struct io_hub			hub;
};

static inline struct p5ioc2 *iohub_to_p5ioc2(struct io_hub *hub)
{
	return container_of(hub, struct p5ioc2, hub);
}

#endif /* __P5IOC2_H */
