/* Copyright 2016 IBM Corp.
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
#include <chip.h>
#include <io.h>
#include <xive.h>
#include <xscom-p9-regs.h>
#include <interrupts.h>
#include <timebase.h>
#include <bitmap.h>

/* Use Block group mode to move chip_id into block .... */
#define USE_BLOCK_GROUP_MODE

/* Indirect mode */
#define USE_INDIRECT

/* Always notify from EQ to VP (no EOI on EQs). Will speed up
 * EOIs at the expense of potentially higher powerbus traffic.
 */
#define EQ_ALWAYS_NOTIFY

/* Verbose debug */
#undef XIVE_VERBOSE_DEBUG

/*
 *
 * VSDs, blocks, set translation etc...
 *
 * This stuff confused me to no end so here's an attempt at explaining
 * my understanding of it and how I use it in OPAL & Linux
 *
 * For the following data structures, the XIVE use a mechanism called
 * Virtualization Structure Tables (VST) to manage the memory layout
 * and access: ESBs (Event State Buffers, aka IPI sources), EAS/IVT
 * (Event assignment structures), END/EQs (Notification descriptors
 * aka event queues) and NVT/VPD (Notification Virtual Targets).
 *
 * These structures divide those tables into 16 "blocks". Each XIVE
 * instance has a definition for all 16 blocks that can either represent
 * an actual table in memory or a remote XIVE MMIO port to access a
 * block that is owned by that remote XIVE.
 *
 * Our SW design will consist of allocating one block per chip (and thus
 * per XIVE instance) for now, thus giving us up to 16 supported chips in
 * the system. We may have to revisit that if we ever support systems with
 * more than 16 chips but that isn't on our radar at the moment or if we
 * want to do like pHyp on some machines and dedicate 2 blocks per chip
 * for some structures.
 *
 * Thus we need to be careful that we never expose to Linux the concept
 * of block and block boundaries, but instead we provide full number ranges
 * so that consecutive blocks can be supported.
 *
 * We will pre-allocate some of the tables in order to support a "fallback"
 * mode operations where an old-style XICS is emulated via OPAL calls. This
 * is achieved by having a default of one VP per physical thread associated
 * with one EQ and one IPI. There is also enought EATs to cover all the PHBs.
 *
 * Similarily, for MMIO access, the BARs support what is called "set
 * translation" which allows tyhe BAR to be devided into a certain
 * number of sets. The VC BAR (ESBs, ENDs, ...) supports 64 sets and
 * the PC BAT supports 16. Each "set" can be routed to a specific
 * block and offset within a block.
 *
 * For now, we will not use much of that functionality. We will use a
 * fixed split between ESB and ENDs for the VC BAR as defined by the
 * constants below and we will allocate all the PC BARs set to the
 * local block of that chip
 */


/* BAR default values (should be initialized by HostBoot but for
 * now we do it). Based on the memory map document by Dave Larson
 *
 * Fixed IC and TM BARs first.
 */
/* Use 64K for everything by default */
#define IC_PAGE_SIZE	0x10000
#define TM_PAGE_SIZE	0x10000
#define IPI_ESB_SHIFT	(16 + 1)

#define IC_BAR_DEFAULT	0x30203100000ull
#define IC_BAR_SIZE	(8 * IC_PAGE_SIZE)
#define TM_BAR_DEFAULT	0x30203180000ull
#define TM_BAR_SIZE	(4 * TM_PAGE_SIZE)

/* VC BAR contains set translations for the ESBs and the EQs.
 *
 * It's divided in 64 sets, each of which can be either ESB pages or EQ pages.
 * The table configuring this is the EDT
 *
 * Additionally, the ESB pages come in pair of Linux_Trig_Mode isn't enabled
 * (which we won't enable for now as it assumes write-only permission which
 * the MMU doesn't support).
 *
 * To get started we just hard wire the following setup:
 *
 * VC_BAR size is 512G. We split it into 384G of ESBs (48 sets) and 128G
 * of ENDs (16 sets) for the time being. IE. Each set is thus 8GB
 */

#define VC_BAR_DEFAULT	0x10000000000ull
#define VC_BAR_SIZE	0x08000000000ull
#define VC_ESB_SETS	48
#define VC_END_SETS	16
#define VC_MAX_SETS	64

/* PC BAR contains the virtual processors
 *
 * The table configuring the set translation (16 sets) is the VDT
 */
#define PC_BAR_DEFAULT	0x18000000000ull
#define PC_BAR_SIZE	0x01000000000ull
#define PC_MAX_SETS	16

/* XXX This is the currently top limit of number of ESB/SBE entries
 * and EAS/IVT entries pre-allocated per chip. This should probably
 * turn into a device-tree property or NVRAM setting, or maybe
 * calculated from the amount of system RAM...
 *
 * This is currently set to 1M
 *
 * This is independent of the sizing of the MMIO space.
 *
 * WARNING: Due to how XICS emulation works, we cannot support more
 * interrupts per chip at this stage as the full interrupt number
 * (block + index) has to fit in a 24-bit number.
 *
 * That gives us a pre-allocated space of 256KB per chip for the state
 * bits and 8M per chip for the EAS/IVT.
 *
 * Note: The HW interrupts from PCIe and similar other entities that
 * use their own state bit array will have to share that IVT space,
 * so we could potentially make the IVT size twice as big, but for now
 * we will simply share it and ensure we don't hand out IPIs that
 * overlap the HW interrupts.
 */
#define MAX_INT_ENTRIES		(1 * 1024 * 1024)

/* Corresponding direct table sizes */
#define SBE_SIZE	(MAX_INT_ENTRIES / 4)
#define IVT_SIZE	(MAX_INT_ENTRIES * 8)

/* Max number of EQs. We allocate an indirect table big enough so
 * that when fully populated we can have that many EQs.
 *
 * The max number of EQs we support in our MMIO space is 128G/128K
 * ie. 1M. Since one EQ is 8 words (32 bytes), a 64K page can hold
 * 2K EQs. We need 512 pointers, ie, 4K of memory for the indirect
 * table.
 *
 * XXX Adjust that based on BAR value ?
 */
#ifdef USE_INDIRECT
#define MAX_EQ_COUNT		(1 * 1024 * 1024)
#define EQ_PER_PAGE		(0x10000 / 32) // Use sizeof ?
#define IND_EQ_TABLE_SIZE	((MAX_EQ_COUNT / EQ_PER_PAGE) * 8)
#else
#define MAX_EQ_COUNT		(4 * 1024)
#define EQT_SIZE		(MAX_EQ_COUNT * 32)
#endif

/* Number of priorities (and thus EQDs) we allocate for each VP */
#define NUM_INT_PRIORITIES	8

/* Priority used for the one queue in XICS emulation */
#define XIVE_EMULATION_PRIO	7

/* Max number of VPs. We allocate an indirect table big enough so
 * that when fully populated we can have that many VPs.
 *
 * The max number of VPs we support in our MMIO space is 64G/64K
 * ie. 1M. Since one VP is 16 words (64 bytes), a 64K page can hold
 * 1K EQ. We need 1024 pointers, ie, 8K of memory for the indirect
 * table.
 *
 * HOWEVER: A block supports only up to 512K VPs (19 bits of target
 * in the EQ). Since we currently only support 1 block per chip,
 * we will allocate half of the above. We might add support for
 * 2 blocks per chip later if necessary.
 *
 * XXX Adjust that based on BAR value ?
 */
#ifdef USE_INDIRECT
#define MAX_VP_COUNT		(512 * 1024)
#define VP_PER_PAGE		(0x10000 / 64) // Use sizeof ?
#define IND_VP_TABLE_SIZE	((MAX_VP_COUNT / VP_PER_PAGE) * 8)
#else
#define MAX_VP_COUNT		(4 * 1024)
#define VPT_SIZE		(MAX_VP_COUNT * 64)
#endif

#ifdef USE_BLOCK_GROUP_MODE

/* Initial number of VPs (XXX Make it a variable ?). Round things
 * up to a max of 32 cores per chip
 */
#define INITIAL_VP_BASE		0x80
#define INITIAL_VP_COUNT	0x80

#else

/* Initial number of VPs on block 0 only */
#define INITIAL_BLK0_VP_BASE	0x800
#define INITIAL_BLK0_VP_COUNT	(2 * 1024)

#endif

/* The xive operation mode indicates the active "API" and corresponds
 * to the "version" parameter of the opal_xive_reset() call
 */
static enum {
	XIVE_MODE_EMU	= 0,
	XIVE_MODE_EXPL	= 1,
} xive_mode;


/* Each source controller has one of these. There's one embedded
 * in the XIVE struct for IPIs
 */
struct xive_src {
	struct irq_source		is;
	const struct irq_source_ops	*orig_ops;
	struct xive			*xive;
	void				*esb_mmio;
	uint32_t			esb_base;
	uint32_t			esb_shift;
	uint32_t			flags;
};

struct xive_cpu_state {
	struct xive	*xive;
	void		*tm_ring1;

	/* Base HW VP and associated queues */
	uint32_t	vp_blk;
	uint32_t	vp_idx;
	uint32_t	eq_blk;
	uint32_t	eq_idx; /* Base eq index of a block of 8 */

	/* Pre-allocated IPI */
	uint32_t	ipi_irq;

	/* Use for XICS emulation */
	struct lock	lock;
	uint8_t		cppr;
	uint8_t		mfrr;
	uint8_t		pending;
	uint8_t		prev_cppr;
	uint32_t	*eqbuf;
	uint32_t	eqptr;
	uint32_t	eqmsk;
	uint8_t		eqgen;
	void		*eqmmio;
};

struct xive {
	uint32_t	chip_id;
	uint32_t	block_id;
	struct dt_node	*x_node;
	struct dt_node	*m_node;

	uint64_t	xscom_base;

	/* MMIO regions */
	void		*ic_base;
	uint64_t	ic_size;
	uint32_t	ic_shift;
	void		*tm_base;
	uint64_t	tm_size;
	uint32_t	tm_shift;
	void		*pc_base;
	uint64_t	pc_size;
	void		*vc_base;
	uint64_t	vc_size;

	void		*esb_mmio;
	void		*eq_mmio;

	/* Set on XSCOM register access error */
	bool		last_reg_error;

	/* Per-XIVE mutex */
	struct lock	lock;

	/* Pre-allocated tables.
	 *
	 * We setup all the VDS for actual tables (ie, by opposition to
	 * forwarding ports) as either direct pre-allocated or indirect
	 * and partially populated.
	 *
	 * Currently, the ESB/SBE and the EAS/IVT tables are direct and
	 * fully pre-allocated based on MAX_INT_ENTRIES.
	 *
	 * The other tables are indirect, we thus pre-allocate the indirect
	 * table (ie, pages of pointers) and populate enough of the pages
	 * for our basic setup using 64K pages.
	 *
	 * The size of the indirect tables are driven by MAX_VP_COUNT and
	 * MAX_EQ_COUNT. The number of pre-allocated ones are driven by
	 * INITIAL_VP_COUNT (number of EQ depends on number of VP) in block
	 * mode, otherwise we only preallocate INITIAL_BLK0_VP_COUNT on
	 * block 0.
	 */

	/* Direct SBE and IVT tables */
	void		*sbe_base;
	void		*ivt_base;

#ifdef USE_INDIRECT
	/* Indirect END/EQ table. NULL entries are unallocated, count is
	 * the numbre of pointers (ie, sub page placeholders).
	 */
	uint64_t	*eq_ind_base;
	uint32_t	eq_ind_count;
#else
	void		*eq_base;
#endif
	/* EQ allocation bitmap. Each bit represent 8 EQs */
	bitmap_t	*eq_map;

#ifdef USE_INDIRECT
	/* Indirect NVT/VP table. NULL entries are unallocated, count is
	 * the numbre of pointers (ie, sub page placeholders).
	 */
	uint64_t	*vp_ind_base;
	uint64_t	vp_ind_count;
#else
	void		*vp_base;
#endif
	/* To ease a possible change to supporting more than one block of
	 * interrupts per chip, we store here the "base" global number
	 * and max number of interrupts for this chip. The global number
	 * encompass the block number and index.
	 */
	uint32_t	int_base;
	uint32_t	int_max;

	/* Due to the overlap between IPIs and HW sources in the IVT table,
	 * we keep some kind of top-down allocator. It is used for HW sources
	 * to "allocate" interrupt entries and will limit what can be handed
	 * out as IPIs. Of course this assumes we "allocate" all HW sources
	 * before we start handing out IPIs.
	 *
	 * Note: The numbers here are global interrupt numbers so that we can
	 * potentially handle more than one block per chip in the future.
	 */
	uint32_t	int_hw_bot;	/* Bottom of HW allocation */
	uint32_t	int_ipi_top;	/* Highest IPI handed out so far + 1 */

	/* Embedded source IPIs */
	struct xive_src	ipis;
};


/* Block <-> Chip conversions.
 *
 * As chipIDs may not be within the range of 16 block IDs supported by XIVE,
 * we have a 2 way conversion scheme.
 *
 * From block to chip, use the global table below.
 *
 * From chip to block, a field in struct proc_chip contains the first block
 * of that chip. For now we only support one block per chip but that might
 * change in the future
 */
#define XIVE_INVALID_CHIP	0xffffffff
static uint32_t xive_block_to_chip[16];

/* Conversion between GIRQ and block/index.
 *
 * ------------------------------------
 * |0000000E|BLOC|               INDEX|
 * ------------------------------------
 *      8      4           20
 *
 * the E bit indicates that this is an escalation interrupt, in
 * that case, the BLOC/INDEX represents the EQ containig the
 * corresponding escalation descriptor.
 *
 * Global interrupt numbers for non-escalation interrupts are thus
 * limited to 24 bits which is necessary for our XICS emulation since
 * the top 8 bits are reserved for the CPPR value.
 *
 */
#define GIRQ_TO_BLK(__g)	(((__g) >> 20) & 0xf)
#define GIRQ_TO_IDX(__g)	((__g) & 0x000fffff)
#define BLKIDX_TO_GIRQ(__b,__i)	(((uint32_t)(__b)) << 20 | (__i))
#define GIRQ_IS_ESCALATION(__g)	((__g) & 0x01000000)

/* VP IDs are just the concatenation of the BLK and index as found
 * in an EQ target field for example
 */

/* For now, it's one chip per block for both VC and PC */
#define PC_BLK_TO_CHIP(__b)	(xive_block_to_chip[__b])
#define VC_BLK_TO_CHIP(__b)	(xive_block_to_chip[__b])
#define GIRQ_TO_CHIP(__isn)	(VC_BLK_TO_CHIP(GIRQ_TO_BLK(__isn)))

/* Routing of physical processors to VPs */
#ifdef USE_BLOCK_GROUP_MODE
#define PIR2VP_IDX(__pir)	(0x80 | P9_PIR2LOCALCPU(__pir))
#define PIR2VP_BLK(__pir)	(P9_PIR2GCID(__pir))
#define VP2PIR(__blk, __idx)	(P9_PIRFROMLOCALCPU(VC_BLK_TO_CHIP(__blk), (__idx) & 0x7f))
#else
#define PIR2VP_IDX(__pir)	(0x800 | (P9_PIR2GCID(__pir) << 7) | P9_PIR2LOCALCPU(__pir))
#define PIR2VP_BLK(__pir)	(0)
#define VP2PIR(__blk, __idx)	(P9_PIRFROMLOCALCPU(((__idx) >> 7) & 0xf, (__idx) & 0x7f))
#endif

#define xive_regw(__x, __r, __v) \
	__xive_regw(__x, __r, X_##__r, __v, #__r)
#define xive_regr(__x, __r) \
	__xive_regr(__x, __r, X_##__r, #__r)
#define xive_regwx(__x, __r, __v) \
	__xive_regw(__x, 0, X_##__r, __v, #__r)
#define xive_regrx(__x, __r) \
	__xive_regr(__x, 0, X_##__r, #__r)

#ifdef XIVE_VERBOSE_DEBUG
#define xive_vdbg(__x,__fmt,...)	prlog(PR_DEBUG,"XIVE[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_vdbg(__c,__fmt,...)	prlog(PR_DEBUG,"XIVE[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#else
#define xive_vdbg(x,fmt,...)		do { } while(0)
#define xive_cpu_vdbg(x,fmt,...)	do { } while(0)
#endif

#define xive_dbg(__x,__fmt,...)		prlog(PR_DEBUG,"XIVE[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_dbg(__c,__fmt,...)	prlog(PR_DEBUG,"XIVE[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#define xive_warn(__x,__fmt,...)	prlog(PR_WARNING,"XIVE[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_warn(__c,__fmt,...)	prlog(PR_WARNING,"XIVE[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#define xive_err(__x,__fmt,...)		prlog(PR_ERR,"XIVE[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_err(__c,__fmt,...)	prlog(PR_ERR,"XIVE[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)

static void __xive_regw(struct xive *x, uint32_t m_reg, uint32_t x_reg, uint64_t v,
			const char *rname)
{
	bool use_xscom = (m_reg == 0) || !x->ic_base;
	int64_t rc;

	x->last_reg_error = false;

	if (use_xscom) {
		assert(x_reg != 0);
		rc = xscom_write(x->chip_id, x->xscom_base + x_reg, v);
		if (rc) {
			if (!rname)
				rname = "???";
			xive_err(x, "Error writing register %s\n", rname);
			/* Anything else we can do here ? */
			x->last_reg_error = true;
		}
	} else {
		out_be64(x->ic_base + m_reg, v);
	}
}

static uint64_t __xive_regr(struct xive *x, uint32_t m_reg, uint32_t x_reg,
			    const char *rname)
{
	bool use_xscom = (m_reg == 0) || !x->ic_base;
	int64_t rc;
	uint64_t val;

	x->last_reg_error = false;

	if (use_xscom) {
		rc = xscom_read(x->chip_id, x->xscom_base + x_reg, &val);
		if (rc) {
			if (!rname)
				rname = "???";
			xive_err(x, "Error reading register %s\n", rname);
			/* Anything else we can do here ? */
			x->last_reg_error = true;
			return -1ull;
		}
	} else {
		val = in_be64(x->ic_base + m_reg);
	}
	return val;
}

/* Locate a controller from an IRQ number */
static struct xive *xive_from_isn(uint32_t isn)
{
	uint32_t chip_id = GIRQ_TO_CHIP(isn);
	struct proc_chip *c = get_chip(chip_id);

	if (!c)
		return NULL;
	return c->xive;
}

static struct xive *xive_from_pc_blk(uint32_t blk)
{
	uint32_t chip_id = PC_BLK_TO_CHIP(blk);
	struct proc_chip *c = get_chip(chip_id);

	if (!c)
		return NULL;
	return c->xive;
}

static struct xive *xive_from_vc_blk(uint32_t blk)
{
	uint32_t chip_id = VC_BLK_TO_CHIP(blk);
	struct proc_chip *c = get_chip(chip_id);

	if (!c)
		return NULL;
	return c->xive;
}

static struct xive_eq *xive_get_eq(struct xive *x, unsigned int idx)
{
	struct xive_eq *p;

#ifdef USE_INDIRECT
	if (idx >= (x->eq_ind_count * EQ_PER_PAGE))
		return NULL;
	p = (struct xive_eq *)(x->eq_ind_base[idx / EQ_PER_PAGE] &
			       VSD_ADDRESS_MASK);
	if (!p)
		return NULL;

	return &p[idx % EQ_PER_PAGE];
#else
	if (idx >= MAX_EQ_COUNT)
		return NULL;
	if (!x->eq_base)
		return NULL;
	p = x->eq_base;
	return p + idx;
#endif
}

static struct xive_ive *xive_get_ive(struct xive *x, unsigned int isn)
{
	struct xive_ive *ivt;
	uint32_t idx = GIRQ_TO_IDX(isn);

	if (GIRQ_IS_ESCALATION(isn)) {
		/* Allright, an escalation IVE is buried inside an EQ, let's
		 * try to find it
		 */
		struct xive_eq *eq;

		if (x->chip_id != VC_BLK_TO_CHIP(GIRQ_TO_BLK(isn))) {
			xive_err(x, "xive_get_ive, ESC ISN 0x%x not on right chip\n", isn);
			return NULL;
		}
		eq = xive_get_eq(x, idx);
		if (!eq) {
			xive_err(x, "xive_get_ive, ESC ISN 0x%x EQ not found\n", isn);
			return NULL;
		}
		return (struct xive_ive *)(char *)&eq->w4;
	} else {
		/* Check the block matches */
		if (isn < x->int_base || isn >= x->int_max) {
			xive_err(x, "xive_get_ive, ISN 0x%x not on right chip\n", isn);
			return NULL;
		}
		assert (idx < MAX_INT_ENTRIES);

		/* If we support >1 block per chip, this should still work as
		 * we are likely to make the table contiguous anyway
		 */
		ivt = x->ivt_base;
		assert(ivt);

		return ivt + idx;
	}
}

static struct xive_vp *xive_get_vp(struct xive *x, unsigned int idx)
{
	struct xive_vp *p;

#ifdef USE_INDIRECT
	assert(idx < (x->vp_ind_count * VP_PER_PAGE));
	p = (struct xive_vp *)(x->vp_ind_base[idx / VP_PER_PAGE] &
			       VSD_ADDRESS_MASK);
	assert(p);

	return &p[idx % VP_PER_PAGE];
#else
	assert(idx < MAX_VP_COUNT);
	p = x->vp_base;
	return p + idx;
#endif
}

static void xive_init_vp(struct xive *x __unused, struct xive_vp *vp,
			 uint32_t eq_blk, uint32_t eq_idx)
{
	/* Stash the EQ base in the pressure relief interrupt field
	 * and set the ACK# to 0xff to disable pressure relief interrupts
	 */
	vp->w1 = (eq_blk << 28) | eq_idx;
	vp->w5 = 0xff000000;
	lwsync();

	/* XXX TODO: Look at the special cache line stuff */
	vp->w0 = VP_W0_VALID;
}

static void xive_init_eq(uint32_t vp_blk, uint32_t vp_idx,
			 struct xive_eq *eq, void *backing_page,
			 uint8_t prio)
{
	eq->w1 = EQ_W1_GENERATION;
	eq->w3 = ((uint64_t)backing_page) & 0xffffffff;
	eq->w2 = (((uint64_t)backing_page)) >> 32 & 0x0fffffff;
	eq->w6 = SETFIELD(EQ_W6_NVT_BLOCK, 0ul, vp_blk) |
		SETFIELD(EQ_W6_NVT_INDEX, 0ul, vp_idx);
	eq->w7 = SETFIELD(EQ_W7_F0_PRIORITY, 0ul, prio);
	eieio();
	eq->w0 = EQ_W0_VALID | EQ_W0_ENQUEUE |
		SETFIELD(EQ_W0_QSIZE, 0ul, EQ_QSIZE_64K) |
		EQ_W0_FIRMWARE;
#ifdef EQ_ALWAYS_NOTIFY
	eq->w0 |= EQ_W0_UCOND_NOTIFY;
#endif
}

static uint32_t *xive_get_eq_buf(uint32_t eq_blk, uint32_t eq_idx)
{
	struct xive *x = xive_from_vc_blk(eq_blk);
	struct xive_eq *eq = xive_get_eq(x, eq_idx);
	uint64_t addr;

	assert(eq);
	assert(eq->w0 & EQ_W0_VALID);
	addr = (((uint64_t)eq->w2) & 0x0fffffff) << 32 | eq->w3;

	return (uint32_t *)addr;
}

#define XIVE_ALLOC_IS_ERR(_idx)	((_idx) >= 0xfffffff0)

#define XIVE_ALLOC_NO_SPACE	0xffffffff /* No possible space */
#define XIVE_ALLOC_NO_IND	0xfffffffe /* Indirect need provisioning */
#define XIVE_ALLOC_NO_MEM	0xfffffffd /* Local allocation failed */

static uint32_t xive_alloc_eq_set(struct xive *x, bool alloc_indirect __unused)
{
	uint32_t ind_idx __unused;
	int idx;

	xive_vdbg(x, "Allocating EQ set...\n");

	assert(x->eq_map);

	/* Allocate from the EQ bitmap. Each bit is 8 EQs */
	idx = bitmap_find_zero_bit(*x->eq_map, 0, MAX_EQ_COUNT >> 3);
	if (idx < 0) {
		xive_dbg(x, "Allocation from EQ bitmap failed !\n");
		return XIVE_ALLOC_NO_SPACE;
	}
	bitmap_set_bit(*x->eq_map, idx);

	idx <<= 3;

	xive_vdbg(x, "Got EQs 0x%x..0x%x\n", idx, idx + 7);

#ifdef USE_INDIRECT
	/* Calculate the indirect page where the EQs reside */
	ind_idx = idx / EQ_PER_PAGE;

	/* Is there an indirect page ? If not, check if we can provision it */
	if (!x->eq_ind_base[ind_idx]) {
		/* Default flags */
		uint64_t vsd_flags = SETFIELD(VSD_TSIZE, 0ull, 4) |
			SETFIELD(VSD_MODE, 0ull, VSD_MODE_EXCLUSIVE);
		void *page;

		/* If alloc_indirect is set, allocate the memory from OPAL own,
		 * otherwise try to provision from the donated pool
		 */
		if (alloc_indirect) {
			/* Allocate/provision indirect page during boot only */
			xive_dbg(x, "Indirect empty, provisioning from local pool\n");
			page = local_alloc(x->chip_id, 0x10000, 0x10000);
			if (!page) {
				xive_dbg(x, "provisioning failed !\n");
				return XIVE_ALLOC_NO_MEM;
			}
			vsd_flags |= VSD_FIRMWARE;
		} else {
			return XIVE_ALLOC_NO_IND;
		}
		memset(page, 0, 0x10000);
		x->eq_ind_base[ind_idx] = vsd_flags | (((uint64_t)page) & VSD_ADDRESS_MASK);
		/* Any cache scrub needed ? */
	}
#endif
	return idx;
}

#if 0 /* Not used yet. This will be used to kill the cache
       * of indirect VSDs
       */
static int64_t xive_vc_ind_cache_kill(struct xive *x, uint64_t type,
				      uint64_t block, uint64_t idx)
{
	uint64_t val;

	xive_regw(x, VC_AT_MACRO_KILL_MASK,
		  SETFIELD(VC_KILL_BLOCK_ID, 0ull, -1ull) |
		  SETFIELD(VC_KILL_OFFSET, 0ull, -1ull));
	xive_regw(x, VC_AT_MACRO_KILL, VC_KILL_VALID |
		  SETFIELD(VC_KILL_TYPE, 0ull, type) |
		  SETFIELD(VC_KILL_BLOCK_ID, 0ull, block) |
		  SETFIELD(VC_KILL_OFFSET, 0ull, idx));

	/* XXX SIMICS problem ? */
	if (chip_quirk(QUIRK_SIMICS))
		return 0;

	/* XXX Add timeout */
	for (;;) {
		val = xive_regr(x, VC_AT_MACRO_KILL);
		if (!(val & VC_KILL_VALID))
			break;
	}
	return 0;
}
#endif

enum xive_cache_type {
	xive_cache_ivc,
	xive_cache_sbc,
	xive_cache_eqc,
	xive_cache_vpc,
};

static int64_t __xive_cache_scrub(struct xive *x, enum xive_cache_type ctype,
				  uint64_t block, uint64_t idx,
				  bool want_inval, bool want_disable)
{
	uint64_t sreg, sregx, mreg, mregx;
	uint64_t mval, sval;

	switch (ctype) {
	case xive_cache_ivc:
		sreg = VC_IVC_SCRUB_TRIG;
		sregx = X_VC_IVC_SCRUB_TRIG;
		mreg = VC_IVC_SCRUB_MASK;
		mregx = X_VC_IVC_SCRUB_MASK;
		break;
	case xive_cache_sbc:
		sreg = VC_SBC_SCRUB_TRIG;
		sregx = X_VC_SBC_SCRUB_TRIG;
		mreg = VC_SBC_SCRUB_MASK;
		mregx = X_VC_SBC_SCRUB_MASK;
		break;
	case xive_cache_eqc:
		sreg = VC_EQC_SCRUB_TRIG;
		sregx = X_VC_EQC_SCRUB_TRIG;
		mreg = VC_EQC_SCRUB_MASK;
		mregx = X_VC_EQC_SCRUB_MASK;
		break;
	case xive_cache_vpc:
		sreg = PC_VPC_SCRUB_TRIG;
		sregx = X_PC_VPC_SCRUB_TRIG;
		mreg = PC_VPC_SCRUB_MASK;
		mregx = X_PC_VPC_SCRUB_MASK;
		break;
	default:
		return OPAL_PARAMETER;
	}
	if (ctype == xive_cache_vpc) {
		mval = PC_SCRUB_BLOCK_ID | PC_SCRUB_OFFSET;
		sval = SETFIELD(PC_SCRUB_BLOCK_ID, idx, block) |
			PC_SCRUB_VALID;
	} else {
		mval = VC_SCRUB_BLOCK_ID | VC_SCRUB_OFFSET;
		sval = SETFIELD(VC_SCRUB_BLOCK_ID, idx, block) |
			VC_SCRUB_VALID;
	}
	if (want_inval)
		sval |= PC_SCRUB_WANT_INVAL;
	if (want_disable)
		sval |= PC_SCRUB_WANT_DISABLE;

	__xive_regw(x, mreg, mregx, mval, NULL);
	__xive_regw(x, sreg, sregx, sval, NULL);

	/* XXX Add timeout !!! */
	for (;;) {
		sval = __xive_regr(x, sreg, sregx, NULL);
		if (!(sval & VC_SCRUB_VALID))
			break;
		time_wait_us(1);
	}
	return 0;
}

static int64_t xive_ivc_scrub(struct xive *x, uint64_t block, uint64_t idx)
{
	return __xive_cache_scrub(x, xive_cache_ivc, block, idx, false, false);
}

static int64_t __xive_cache_watch(struct xive *x, enum xive_cache_type ctype,
				  uint64_t block, uint64_t idx,
				  uint32_t start_dword, uint32_t dword_count,
				  void *new_data, bool light_watch)
{
	uint64_t sreg, sregx, dreg0, dreg0x;
	uint64_t dval0, sval, status;
	int64_t i;

	switch (ctype) {
	case xive_cache_eqc:
		sreg = VC_EQC_CWATCH_SPEC;
		sregx = X_VC_EQC_CWATCH_SPEC;
		dreg0 = VC_EQC_CWATCH_DAT0;
		dreg0x = X_VC_EQC_CWATCH_DAT0;
		sval = SETFIELD(VC_EQC_CWATCH_BLOCKID, idx, block);
		break;
	case xive_cache_vpc:
		sreg = PC_VPC_CWATCH_SPEC;
		sregx = X_PC_VPC_CWATCH_SPEC;
		dreg0 = PC_VPC_CWATCH_DAT0;
		dreg0x = X_PC_VPC_CWATCH_DAT0;
		sval = SETFIELD(PC_VPC_CWATCH_BLOCKID, idx, block);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* The full bit is in the same position for EQC and VPC */
	if (!light_watch)
		sval |= VC_EQC_CWATCH_FULL;

	do {
		/* Write the cache watch spec */
		__xive_regw(x, sreg, sregx, sval, NULL);

		/* Load data0 register to populate the watch */
		dval0 = __xive_regr(x, dreg0, dreg0x, NULL);

		/* Write the words into the watch facility. We write in reverse
		 * order in case word 0 is part of it as it must be the last
		 * one written.
		 */
		for (i = start_dword + dword_count - 1; i >= start_dword ;i--) {
			uint64_t dw = ((uint64_t *)new_data)[i - start_dword];
			__xive_regw(x, dreg0 + i * 8, dreg0x + i, dw, NULL);
		}

		/* Write data0 register to trigger the update if word 0 wasn't
		 * written above
		 */
		if (start_dword > 0)
			__xive_regw(x, dreg0, dreg0x, dval0, NULL);

		/* This may not be necessary for light updates (it's possible\
		 * that a sync in sufficient, TBD). Ensure the above is
		 * complete and check the status of the watch.
		 */
		status = __xive_regr(x, sreg, sregx, NULL);

		/* XXX Add timeout ? */

		/* Bits FULL and CONFLICT are in the same position in
		 * EQC and VPC
		 */
	} while((status & VC_EQC_CWATCH_FULL) &&
		(status & VC_EQC_CWATCH_CONFLICT));

	return 0;
}

static int64_t xive_eqc_cache_update(struct xive *x, uint64_t block,
				     uint64_t idx, uint32_t start_dword,
				     uint32_t dword_count, void *new_data,
				     bool light_watch)
{
	return __xive_cache_watch(x, xive_cache_eqc, block, idx,
				  start_dword, dword_count,
				  new_data, light_watch);
}

static bool xive_set_vsd(struct xive *x, uint32_t tbl, uint32_t idx, uint64_t v)
{
	/* Set VC version */
	xive_regw(x, VC_VSD_TABLE_ADDR,
		  SETFIELD(VST_TABLE_SELECT, 0ull, tbl) |
		  SETFIELD(VST_TABLE_OFFSET, 0ull, idx));
	if (x->last_reg_error)
		return false;
	xive_regw(x, VC_VSD_TABLE_DATA, v);
	if (x->last_reg_error)
		return false;

	/* Except for IRQ table, also set PC version */
	if (tbl == VST_TSEL_IRQ)
		return true;

	xive_regw(x, PC_VSD_TABLE_ADDR,
		  SETFIELD(VST_TABLE_SELECT, 0ull, tbl) |
		  SETFIELD(VST_TABLE_OFFSET, 0ull, idx));
	if (x->last_reg_error)
		return false;
	xive_regw(x, PC_VSD_TABLE_DATA, v);
	if (x->last_reg_error)
		return false;
	return true;
}

static bool xive_set_local_tables(struct xive *x)
{
	uint64_t base;

	/* These have to be power of 2 sized */
	assert(is_pow2(SBE_SIZE));
	assert(is_pow2(IVT_SIZE));

	/* All tables set as exclusive */
	base = SETFIELD(VSD_MODE, 0ull, VSD_MODE_EXCLUSIVE);

	/* Set IVT as direct mode */
	if (!xive_set_vsd(x, VST_TSEL_IVT, x->block_id, base |
			  (((uint64_t)x->ivt_base) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(IVT_SIZE) - 12)))
		return false;

	/* Set SBE as direct mode */
	if (!xive_set_vsd(x, VST_TSEL_SBE, x->block_id, base |
			  (((uint64_t)x->sbe_base) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(SBE_SIZE) - 12)))
		return false;

#ifdef USE_INDIRECT
	/* Set EQDT as indirect mode with 64K subpages */
	if (!xive_set_vsd(x, VST_TSEL_EQDT, x->block_id, base |
			  (((uint64_t)x->eq_ind_base) & VSD_ADDRESS_MASK) |
			  VSD_INDIRECT | SETFIELD(VSD_TSIZE, 0ull, 4)))
		return false;

	/* Set VPDT as indirect mode with 64K subpages */
	if (!xive_set_vsd(x, VST_TSEL_VPDT, x->block_id, base |
			  (((uint64_t)x->vp_ind_base) & VSD_ADDRESS_MASK) |
			  VSD_INDIRECT | SETFIELD(VSD_TSIZE, 0ull, 4)))
		return false;
#else
	/* Set EQDT as direct mode */
	if (!xive_set_vsd(x, VST_TSEL_EQDT, x->block_id, base |
			  (((uint64_t)x->eq_base) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(EQT_SIZE) - 12)))
		return false;

	/* Set VPDT as direct mode */
	if (!xive_set_vsd(x, VST_TSEL_VPDT, x->block_id, base |
			  (((uint64_t)x->vp_base) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(VPT_SIZE) - 12)))
		return false;
#endif

	return true;
}

static bool xive_read_bars(struct xive *x)
{
	uint64_t bar, msk;

	/* Read IC BAR */
	bar = xive_regrx(x, CQ_IC_BAR);
	if (bar & CQ_IC_BAR_64K)
		x->ic_shift = 16;
	else
		x->ic_shift = 12;
	x->ic_size = 8ul << x->ic_shift;
	x->ic_base = (void *)(bar & 0x00ffffffffffffffull);

	/* Read TM BAR */
	bar = xive_regrx(x, CQ_TM1_BAR);
	assert(bar & CQ_TM_BAR_VALID);
	if (bar & CQ_TM_BAR_64K)
		x->tm_shift = 16;
	else
		x->tm_shift = 12;
	x->tm_size = 4ul << x->tm_shift;
	x->tm_base = (void *)(bar & 0x00ffffffffffffffull);

	/* Read PC BAR */
	bar = xive_regr(x, CQ_PC_BAR);
	msk = xive_regr(x, CQ_PC_BARM) | 0xffffffc000000000ul;
	assert(bar & CQ_PC_BAR_VALID);
	x->pc_size = (~msk) + 1;
	x->pc_base = (void *)(bar & 0x00ffffffffffffffull);

	/* Read VC BAR */
	bar = xive_regr(x, CQ_VC_BAR);
	msk = xive_regr(x, CQ_VC_BARM) | 0xfffff80000000000ul;
	assert(bar & CQ_VC_BAR_VALID);
	x->vc_size = (~msk) + 1;
	x->vc_base = (void *)(bar & 0x00ffffffffffffffull);

	return true;
}

static bool xive_configure_bars(struct xive *x)
{
	uint64_t mmio_base, chip_base, val;

	/* Calculate MMIO base offset for that chip */
	mmio_base = 0x006000000000000ull;
	chip_base = mmio_base | (0x40000000000ull * (uint64_t)x->chip_id);

	/* IC BAR */
	x->ic_base = (void *)(chip_base | IC_BAR_DEFAULT);
	x->ic_size = IC_BAR_SIZE;
	val = (uint64_t)x->ic_base | CQ_IC_BAR_VALID;
	if (IC_PAGE_SIZE == 0x10000) {
		val |= CQ_IC_BAR_64K;
		x->ic_shift = 16;
	} else
		x->ic_shift = 12;
	xive_regwx(x, CQ_IC_BAR, val);
	if (x->last_reg_error)
		return false;

	/* TM BAR, only configure TM1. Note that this has the same address
	 * for each chip !!!
	 */
	x->tm_base = (void *)(mmio_base | TM_BAR_DEFAULT);
	x->tm_size = TM_BAR_SIZE;
	val = (uint64_t)x->tm_base | CQ_TM_BAR_VALID;
	if (TM_PAGE_SIZE == 0x10000) {
		x->tm_shift = 16;
		val |= CQ_TM_BAR_64K;
	} else
		x->tm_shift = 12;
	xive_regwx(x, CQ_TM1_BAR, val);
	if (x->last_reg_error)
		return false;
	xive_regwx(x, CQ_TM2_BAR, 0);
	if (x->last_reg_error)
		return false;

	/* PC BAR. Clear first, write mask, then write value */
	x->pc_base = (void *)(chip_base | PC_BAR_DEFAULT);
	x->pc_size = PC_BAR_SIZE;
	xive_regwx(x, CQ_PC_BAR, 0);
	if (x->last_reg_error)
		return false;
	val = ~(PC_BAR_SIZE - 1) & CQ_PC_BARM_MASK;
	xive_regwx(x, CQ_PC_BARM, val);
	if (x->last_reg_error)
		return false;
	val = (uint64_t)x->pc_base | CQ_PC_BAR_VALID;
	xive_regwx(x, CQ_PC_BAR, val);
	if (x->last_reg_error)
		return false;

	/* VC BAR. Clear first, write mask, then write value */
	x->vc_base = (void *)(chip_base | VC_BAR_DEFAULT);
	x->vc_size = VC_BAR_SIZE;
	xive_regwx(x, CQ_VC_BAR, 0);
	if (x->last_reg_error)
		return false;
	val = ~(VC_BAR_SIZE - 1) & CQ_VC_BARM_MASK;
	xive_regwx(x, CQ_VC_BARM, val);
	if (x->last_reg_error)
		return false;
	val = (uint64_t)x->vc_base | CQ_VC_BAR_VALID;
	xive_regwx(x, CQ_VC_BAR, val);
	if (x->last_reg_error)
		return false;

	return true;
}

static void xive_dump_mmio(struct xive *x)
{
	prlog(PR_DEBUG, " CQ_CFG_PB_GEN = %016llx\n",
	      in_be64(x->ic_base + CQ_CFG_PB_GEN));
	prlog(PR_DEBUG, " CQ_MSGSND     = %016llx\n",
	      in_be64(x->ic_base + CQ_MSGSND));
}

static bool xive_check_update_bars(struct xive *x)
{
	uint64_t val;
	bool force_assign;

	/* Check if IC BAR is enabled */
	val = xive_regrx(x, CQ_IC_BAR);
	if (x->last_reg_error)
		return false;

	/* Check if device-tree tells us to force-assign the BARs */
	force_assign = dt_has_node_property(x->x_node,
					    "force-assign-bars", NULL);
	if ((val & CQ_IC_BAR_VALID) && !force_assign) {
		xive_dbg(x, "IC BAR valid, using existing values\n");
		if (!xive_read_bars(x))
			return false;
	} else {
		xive_warn(x, "IC BAR invalid, reconfiguring\n");
		if (!xive_configure_bars(x))
			return false;
	}

	/* Calculate some MMIO bases in the VC BAR */
	x->esb_mmio = x->vc_base;
	x->eq_mmio = x->vc_base + (x->vc_size / VC_MAX_SETS) * VC_ESB_SETS;

	/* Print things out */
	xive_dbg(x, "IC: %14p [0x%012llx/%d]\n", x->ic_base, x->ic_size,
		 x->ic_shift);
	xive_dbg(x, "TM: %14p [0x%012llx/%d]\n", x->tm_base, x->tm_size,
		 x->tm_shift);
	xive_dbg(x, "PC: %14p [0x%012llx]\n", x->pc_base, x->pc_size);
	xive_dbg(x, "VC: %14p [0x%012llx]\n", x->vc_base, x->vc_size);

	return true;
}

static bool xive_config_init(struct xive *x)
{
	uint64_t val __unused;

	/* Configure PC and VC page sizes and disable Linux trigger mode */
	xive_regwx(x, CQ_PBI_CTL, CQ_PBI_PC_64K | CQ_PBI_VC_64K);
	if (x->last_reg_error)
		return false;

	/*** The rest can use MMIO ***/

#ifdef USE_INDIRECT
	/* Enable indirect mode in VC config */
	val = xive_regr(x, VC_GLOBAL_CONFIG);
	val |= VC_GCONF_INDIRECT;
	xive_regw(x, VC_GLOBAL_CONFIG, val);

	/* Enable indirect mode in PC config */
	val = xive_regr(x, PC_GLOBAL_CONFIG);
	val |= PC_GCONF_INDIRECT;
	xive_regw(x, PC_GLOBAL_CONFIG, val);
#endif

	val = xive_regr(x, PC_TCTXT_CFG);
#ifdef USE_BLOCK_GROUP_MODE
	val |= PC_TCTXT_CFG_BLKGRP_EN | PC_TCTXT_CFG_HARD_CHIPID_BLK;
#endif
	val |= PC_TCTXT_CHIPID_OVERRIDE;
	val = SETFIELD(PC_TCTXT_CHIPID, val, x->block_id);
	xive_regw(x, PC_TCTXT_CFG, val);

	return true;
}

static bool xive_setup_set_xlate(struct xive *x)
{
	unsigned int i;

	/* Configure EDT for ESBs (aka IPIs) */
	xive_regw(x, CQ_TAR, CQ_TAR_TBL_AUTOINC | CQ_TAR_TSEL_EDT);
	if (x->last_reg_error)
		return false;
	for (i = 0; i < VC_ESB_SETS; i++) {
		xive_regw(x, CQ_TDR,
			  /* IPI type */
			  (1ull << 62) |
			  /* block ID */
			  (((uint64_t)x->block_id) << 48) |
			  /* offset */
			  (((uint64_t)i) << 32));
		if (x->last_reg_error)
			return false;
	}

	/* Configure EDT for ENDs (aka EQs) */
	for (i = 0; i < VC_END_SETS; i++) {
		xive_regw(x, CQ_TDR,
			  /* EQ type */
			  (2ull << 62) |
			  /* block ID */
			  (((uint64_t)x->block_id) << 48) |
			  /* offset */
			  (((uint64_t)i) << 32));
		if (x->last_reg_error)
			return false;
	}

	/* Configure VDT */
	xive_regw(x, CQ_TAR, CQ_TAR_TBL_AUTOINC | CQ_TAR_TSEL_VDT);
	if (x->last_reg_error)
		return false;
	for (i = 0; i < PC_MAX_SETS; i++) {
		xive_regw(x, CQ_TDR,
			  /* Valid bit */
			  (1ull << 63) |
			  /* block ID */
			  (((uint64_t)x->block_id) << 48) |
			  /* offset */
			  (((uint64_t)i) << 32));
		if (x->last_reg_error)
			return false;
	}
	return true;
}

static bool xive_prealloc_tables(struct xive *x)
{
	unsigned int i, vp_init_count, vp_init_base;
	unsigned int pbase __unused, pend __unused;
	uint64_t al __unused;

	/* ESB/SBE has 4 entries per byte */
	x->sbe_base = local_alloc(x->chip_id, SBE_SIZE, SBE_SIZE);
	if (!x->sbe_base) {
		xive_err(x, "Failed to allocate SBE\n");
		return false;
	}
	/* SBEs are initialized to 0b01 which corresponds to "ints off" */
	memset(x->sbe_base, 0x55, SBE_SIZE);

	/* EAS/IVT entries are 8 bytes */
	x->ivt_base = local_alloc(x->chip_id, IVT_SIZE, IVT_SIZE);
	if (!x->ivt_base) {
		xive_err(x, "Failed to allocate IVT\n");
		return false;
	}
	/* We clear the entries (non-valid). They will be initialized
	 * when actually used
	 */
	memset(x->ivt_base, 0, IVT_SIZE);

#ifdef USE_INDIRECT
	/* Indirect EQ table. (XXX Align to 64K until I figure out the
	 * HW requirements)
	 */
	al = (IND_EQ_TABLE_SIZE + 0xffff) & ~0xffffull;
	x->eq_ind_base = local_alloc(x->chip_id, al, al);
	if (!x->eq_ind_base) {
		xive_err(x, "Failed to allocate EQ indirect table\n");
		return false;
	}
	memset(x->eq_ind_base, 0, al);
	x->eq_ind_count = IND_EQ_TABLE_SIZE / 8;

	/* Indirect VP table. (XXX Align to 64K until I figure out the
	 * HW requirements)
	 */
	al = (IND_VP_TABLE_SIZE + 0xffff) & ~0xffffull;
	x->vp_ind_base = local_alloc(x->chip_id, al, al);
	if (!x->vp_ind_base) {
		xive_err(x, "Failed to allocate VP indirect table\n");
		return false;
	}
	x->vp_ind_count = IND_VP_TABLE_SIZE / 8;
	memset(x->vp_ind_base, 0, al);

#else /* USE_INDIRECT */

	x->eq_base = local_alloc(x->chip_id, EQT_SIZE, EQT_SIZE);
	if (!x->eq_base) {
		xive_err(x, "Failed to allocate EQ table\n");
		return false;
	}
	memset(x->eq_base, 0, EQT_SIZE);

	/* EAS/IVT entries are 8 bytes */
	x->vp_base = local_alloc(x->chip_id, VPT_SIZE, VPT_SIZE);
	if (!x->vp_base) {
		xive_err(x, "Failed to allocate VP table\n");
		return false;
	}
	/* We clear the entries (non-valid). They will be initialized
	 * when actually used
	 */
	memset(x->vp_base, 0, VPT_SIZE);

#endif /* USE_INDIRECT */

	/* Populate/initialize VP/EQs */
#ifdef USE_BLOCK_GROUP_MODE
	vp_init_count = INITIAL_VP_COUNT;
	vp_init_base = INITIAL_VP_BASE;
#else
	vp_init_count = x->block_id == 0 ? INITIAL_BLK0_VP_COUNT : 0;
	vp_init_base = INITIAL_BLK0_VP_BASE;
#endif

#ifdef USE_INDIRECT
	/* Allocate pages for some VPs in indirect mode */
	pbase = vp_init_base / VP_PER_PAGE;
	pend  = (vp_init_base + vp_init_count) / VP_PER_PAGE;
	xive_dbg(x, "Allocating pages %d to %d of VPs (for %d VPs)\n",
		 pbase, pend, INITIAL_VP_COUNT);
	for (i = pbase; i <= pend; i++) {
		void *page;

		/* Indirect entries have a VSD format */
		page = local_alloc(x->chip_id, 0x10000, 0x10000);
		if (!page) {
			xive_err(x, "Failed to allocate VP page\n");
			return false;
		}
		memset(page, 0, 0x10000);
		x->vp_ind_base[i] = ((uint64_t)page) & VSD_ADDRESS_MASK;

		x->vp_ind_base[i] |= SETFIELD(VSD_TSIZE, 0ull, 4);
		x->vp_ind_base[i] |= SETFIELD(VSD_MODE, 0ull, VSD_MODE_EXCLUSIVE);
	}
#endif /* USE_INDIRECT */

	return true;
}

static void xive_create_mmio_dt_node(struct xive *x)
{
	x->m_node = dt_new_addr(dt_root, "interrupt-controller",
				(uint64_t)x->ic_base);
	assert(x->m_node);

	dt_add_property_u64s(x->m_node, "reg",
			     (uint64_t)x->ic_base, x->ic_size,
			     (uint64_t)x->tm_base, x->tm_size,
			     (uint64_t)x->pc_base, x->pc_size,
			     (uint64_t)x->vc_base, x->vc_size);

	/* XXX Only put in "ibm,power9-xive" when we support the exploitation
	 * related APIs and properties
	 */
	dt_add_property_strings(x->m_node, "compatible", /*"ibm,power9-xive",*/ "ibm,opal-intc");

	dt_add_property_cells(x->m_node, "ibm,xive-max-sources",
			      MAX_INT_ENTRIES);
}

static void xive_setup_forward_ports(struct xive *x, struct proc_chip *remote_chip)
{
	struct xive *remote_xive = remote_chip->xive;
	uint64_t base = SETFIELD(VSD_MODE, 0ull, VSD_MODE_FORWARD);
	uint32_t remote_id = remote_xive->block_id;
	uint64_t nport;

	/* ESB(SBE), EAS(IVT) and END(EQ) point to the notify port */
	nport = ((uint64_t)remote_xive->ic_base) + (1ul << remote_xive->ic_shift);
	if (!xive_set_vsd(x, VST_TSEL_IVT, remote_id, base | nport))
		goto error;
	if (!xive_set_vsd(x, VST_TSEL_SBE, remote_id, base | nport))
		goto error;
	if (!xive_set_vsd(x, VST_TSEL_EQDT, remote_id, base | nport))
		goto error;

	/* NVT/VPD points to the remote NVT MMIO sets */
	if (!xive_set_vsd(x, VST_TSEL_VPDT, remote_id,
			  base | (uint64_t)remote_xive->pc_base))
		goto error;
	return;

 error:
	xive_err(x, "Failure configuring forwarding ports\n");
}

static void late_init_one_xive(struct xive *x)
{
	struct proc_chip *chip;

	/* We need to setup the cross-chip forward ports. Let's
	 * iterate all chip and set them up accordingly
	 */
	for_each_chip(chip) {
		/* We skip ourselves or chips without a xive */
		if (chip->xive == x || !chip->xive)
			continue;

		/* Setup our forward ports to that chip */
		xive_setup_forward_ports(x, chip);
	}
}

uint32_t xive_alloc_hw_irqs(uint32_t chip_id, uint32_t count, uint32_t align)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct xive *x;
	uint32_t base, i;

	assert(chip);
	assert(is_pow2(align));

	x = chip->xive;
	assert(x);

	lock(&x->lock);

	/* Allocate the HW interrupts */
	base = x->int_hw_bot - count;
	base &= ~(align - 1);
	if (base < x->int_ipi_top) {
		xive_err(x,
			 "HW alloc request for %d interrupts aligned to %d failed\n",
			 count, align);
		unlock(&x->lock);
		return XIVE_IRQ_ERROR;
	}
	x->int_hw_bot = base;

	/* Initialize the corresponding IVT entries to sane defaults,
	 * IE entry is valid, not routed and masked, EQ data is set
	 * to the GIRQ number.
	 */
	for (i = 0; i < count; i++) {
		struct xive_ive *ive = xive_get_ive(x, base + i);

		ive->w = IVE_VALID | IVE_MASKED | SETFIELD(IVE_EQ_DATA, 0ul, base + i);
	}

	unlock(&x->lock);
	return base;
}

uint32_t xive_alloc_ipi_irqs(uint32_t chip_id, uint32_t count, uint32_t align)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct xive *x;
	uint32_t base, i;

	assert(chip);
	assert(is_pow2(align));

	x = chip->xive;
	assert(x);

	lock(&x->lock);

	/* Allocate the IPI interrupts */
	base = x->int_ipi_top + (align - 1);
	base &= ~(align - 1);
	if (base >= x->int_hw_bot) {
		xive_err(x,
			 "IPI alloc request for %d interrupts aligned to %d failed\n",
			 count, align);
		unlock(&x->lock);
		return XIVE_IRQ_ERROR;
	}
	x->int_ipi_top = base + count;

	/* Initialize the corresponding IVT entries to sane defaults,
	 * IE entry is valid, not routed and masked, EQ data is set
	 * to the GIRQ number.
	 */
	for (i = 0; i < count; i++) {
		struct xive_ive *ive = xive_get_ive(x, base + i);

		ive->w = IVE_VALID | IVE_MASKED |
			SETFIELD(IVE_EQ_DATA, 0ul, base + i);
	}

	unlock(&x->lock);
	return base;
}

void *xive_get_trigger_port(uint32_t girq)
{
	uint32_t idx = GIRQ_TO_IDX(girq);
	struct xive *x;

	/* Find XIVE on which the IVE resides */
	x = xive_from_isn(girq);
	if (!x)
		return NULL;

	if (GIRQ_IS_ESCALATION(girq)) {
		/* Page 2 of the EQ MMIO space is the escalate irq */
		return x->eq_mmio + idx * 0x20000 + 0x10000;
	} else {
		/* Make sure it's an IPI on that chip */
		if (girq < x->int_base ||
		    girq >= x->int_ipi_top)
			return NULL;

		return x->esb_mmio + idx * 0x20000;
	}
}

uint64_t xive_get_notify_port(uint32_t chip_id, uint32_t ent)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct xive *x;
	uint32_t offset = 0;

	assert(chip);
	x = chip->xive;
	assert(x);

	/* This is where we can assign a different HW queue to a different
	 * source by offsetting into the cache lines of the notify port
	 *
	 * For now we keep it very basic, this will have to be looked at
	 * again on real HW with some proper performance analysis.
	 *
	 * Here's what Florian says on the matter:
	 *
	 * <<
	 * The first 2k of the notify port page can all be used for PCIe triggers
	 *
	 * However the idea would be that we try to use the first 4 cache lines to
	 * balance the PCIe Interrupt requests to use the least used snoop buses
	 * (we went from 2 to 4 snoop buses for P9). snoop 0 is heavily used
	 * (I think TLBIs are using that in addition to the normal addresses),
	 * snoop 3 is used for all Int commands, so I think snoop 2 (CL 2 in the
	 * page) is the least used overall. So we probably should that one for
	 * the Int commands from PCIe.
	 *
	 * In addition, our EAS cache supports hashing to provide "private" cache
	 * areas for the PHBs in the shared 1k EAS cache. This allows e.g. to avoid
	 * that one "thrashing" PHB thrashes the EAS cache for everyone, or provide
	 * a PHB with a private area that would allow high cache hits in case of a
	 * device using very few interrupts. The hashing is based on the offset within
	 * the cache line. So using that, you can e.g. set the EAS cache up so that
	 * IPIs use 512 entries, the x16 PHB uses 256 entries and the x8 PHBs 128
	 * entries each - or IPIs using all entries and sharing with PHBs, so PHBs
	 * would use 512 entries and 256 entries respectively.
	 *
	 * This is a tuning we would probably do later in the lab, but as a "prep"
	 * we should set up the different PHBs such that they are using different
	 * 8B-aligned offsets within the cache line, so e.g.
	 * PH4_0  addr        0x100        (CL 2 DW0
	 * PH4_1  addr        0x108        (CL 2 DW1)
	 * PH4_2  addr        0x110        (CL 2 DW2)
	 * etc.
	 * >>
	 */
	switch(ent) {
	case XIVE_HW_SRC_PHBn(0):
		offset = 0x100;
		break;
	case XIVE_HW_SRC_PHBn(1):
		offset = 0x108;
		break;
	case XIVE_HW_SRC_PHBn(2):
		offset = 0x110;
		break;
	case XIVE_HW_SRC_PHBn(3):
		offset = 0x118;
		break;
	case XIVE_HW_SRC_PHBn(4):
		offset = 0x120;
		break;
	case XIVE_HW_SRC_PHBn(5):
		offset = 0x128;
		break;
	case XIVE_HW_SRC_PSI:
		offset = 0x130;
		break;
	default:
		assert(false);
		return 0;
	}

	/* Notify port is the second page of the IC BAR */
	return ((uint64_t)x->ic_base) + (1ul << x->ic_shift) + offset;
}

/* Manufacture the powerbus packet bits 32:63 */
__attrconst uint32_t xive_get_notify_base(uint32_t girq)
{
	return (GIRQ_TO_BLK(girq) << 28)  | GIRQ_TO_IDX(girq);
}

static bool xive_get_eq_info(uint32_t isn, uint32_t *out_target,
			     uint8_t *out_prio, uint32_t *out_lirq)
{
	struct xive_ive *ive;
	struct xive *x, *eq_x;
	struct xive_eq *eq;
	uint32_t eq_blk, eq_idx;
	uint32_t vp_blk, vp_idx;
	uint32_t prio, server;
	bool is_escalation = GIRQ_IS_ESCALATION(isn);

	/* Find XIVE on which the IVE resides */
	x = xive_from_isn(isn);
	if (!x)
		return false;
	/* Grab the IVE */
	ive = xive_get_ive(x, isn);
	if (!ive)
		return false;
	if (!(ive->w & IVE_VALID) && !is_escalation) {
		xive_err(x, "ISN %x lead to invalid IVE !\n", isn);
		return false;
	}
	/* Find the EQ and its xive instance */
	eq_blk = GETFIELD(IVE_EQ_BLOCK, ive->w);
	eq_idx = GETFIELD(IVE_EQ_INDEX, ive->w);
	eq_x = xive_from_vc_blk(eq_blk);
	if (!eq_x) {
		xive_err(x, "Can't find controller for EQ BLK %d\n", eq_blk);
		return false;
	}
	eq = xive_get_eq(eq_x, eq_idx);
	if (!eq) {
		xive_err(eq_x, "Can't locate EQ %d\n", eq_idx);
		return false;
	}
	/* XXX Check valid and format 0 */

	/* No priority conversion, return the actual one ! */
	prio = GETFIELD(EQ_W7_F0_PRIORITY, eq->w7);
	if (out_prio)
		*out_prio = prio;

	vp_blk = GETFIELD(EQ_W6_NVT_BLOCK, eq->w6);
	vp_idx = GETFIELD(EQ_W6_NVT_INDEX, eq->w6);
	server = VP2PIR(vp_blk, vp_idx);

	if (out_target)
		*out_target = server;
	if (out_lirq)
		*out_lirq = GETFIELD(IVE_EQ_DATA, ive->w);

	xive_vdbg(eq_x, "EQ info for ISN %x: prio=%d, server=0x%x (VP %x/%x)\n",
		  isn, prio, server, vp_blk, vp_idx);
	return true;
}

static inline bool xive_eq_for_target(uint32_t target, uint8_t prio,
				      uint32_t *out_eq_blk,
				      uint32_t *out_eq_idx)
{
	struct xive *x;
	struct xive_vp *vp;
	uint32_t vp_blk, vp_idx;
	uint32_t eq_blk, eq_idx;

	if (prio > 7)
		return false;

	/* XXX This will have to change when having VPs that aren't
	 * the physical processors
	 */
	vp_blk = PIR2VP_BLK(target);
	vp_idx = PIR2VP_IDX(target);

	/* Grab the target VP's XIVE */
	x = xive_from_pc_blk(vp_blk);
	if (!x)
		return false;

	/* Find the VP structrure where we stashed the EQ number */
	vp = xive_get_vp(x, vp_idx);

	/* Grab it, it's in the pressure relief interrupt field,
	 * top 4 bits are the block (word 1).
	 */
	eq_blk = vp->w1 >> 28;
	eq_idx = vp->w1 & 0x0fffffff;

	/* Currently the EQ block and VP block should be the same */
	assert(eq_blk == vp_blk);

	if (out_eq_blk)
		*out_eq_blk = eq_blk;
	if (out_eq_idx)
		*out_eq_idx = eq_idx + prio;

	return true;
}

static bool xive_set_eq_info(uint32_t isn, uint32_t target, uint8_t prio,
			     uint32_t lirq)
{
	struct xive *x;
	struct xive_ive *ive;
	uint32_t eq_blk, eq_idx;
	bool is_escalation = GIRQ_IS_ESCALATION(isn);
	uint64_t new_ive;

	/* Find XIVE on which the IVE resides */
	x = xive_from_isn(isn);
	if (!x)
		return false;
	/* Grab the IVE */
	ive = xive_get_ive(x, isn);
	if (!ive)
		return false;
	if (!(ive->w & IVE_VALID) && !is_escalation) {
		xive_err(x, "ISN %x lead to invalid IVE !\n", isn);
		return false;
	}

	lock(&x->lock);

	/* If using emulation mode, fixup prio to the only supported one */
	if (xive_mode == XIVE_MODE_EMU && prio != 0xff)
		prio = XIVE_EMULATION_PRIO;

	/* Read existing IVE */
	new_ive = ive->w;

	/* Are we masking ? */
	if (prio == 0xff && !is_escalation) {
		new_ive |= IVE_MASKED;
		xive_vdbg(x, "ISN %x masked !\n", isn);

		/* Put prio 7 in the EQ */
		prio = 7;
	} else {
		/* Unmasking */
		new_ive = ive->w & ~IVE_MASKED;
		xive_vdbg(x, "ISN %x unmasked !\n", isn);
	}

	/* Re-target the IVE. First find the EQ
	 * correponding to the target
	 */
	if (!xive_eq_for_target(target, prio, &eq_blk, &eq_idx)) {
		xive_err(x, "Can't find EQ for target/prio 0x%x/%d\n",
			 target, prio);
		unlock(&x->lock);
		return false;
	}

	/* Try to update it atomically to avoid an intermediary
	 * stale state
	 */
	new_ive = SETFIELD(IVE_EQ_BLOCK, new_ive, eq_blk);
	new_ive = SETFIELD(IVE_EQ_INDEX, new_ive, eq_idx);
	new_ive = SETFIELD(IVE_EQ_DATA, new_ive, lirq);

	xive_vdbg(x,"ISN %x routed to eq %x/%x lirq=%08x IVE=%016llx !\n",
		  isn, eq_blk, eq_idx, lirq, new_ive);

	/* Updating the cache differs between real IVEs and escalation
	 * IVEs inside an EQ
	 */
	if (is_escalation) {
		xive_eqc_cache_update(x, x->block_id, GIRQ_TO_IDX(isn),
				      2, 1, &new_ive, true);
	} else {
		sync();
		ive->w = new_ive;
		xive_ivc_scrub(x, x->block_id, GIRQ_TO_IDX(isn));
	}

	unlock(&x->lock);
	return true;
}

static int64_t xive_source_get_xive(struct irq_source *is __unused,
				    uint32_t isn, uint16_t *server,
				    uint8_t *prio)
{
	uint32_t target_id;

	if (xive_get_eq_info(isn, &target_id, prio, NULL)) {
		*server = target_id << 2;
		return OPAL_SUCCESS;
	} else
		return OPAL_PARAMETER;
}

static void xive_update_irq_mask(struct xive_src *s, uint32_t idx, bool masked)
{
	void *mmio_base = s->esb_mmio + (1ul << s->esb_shift) * idx;
	uint32_t offset;

	if (s->flags & XIVE_SRC_EOI_PAGE1)
		mmio_base += 1ull << (s->esb_shift - 1);
	if (masked)
		offset = 0xd00; /* PQ = 01 */
	else
		offset = 0xc00; /* PQ = 00 */

	if (s->flags & XIVE_SRC_SHIFT_BUG)
		offset <<= 4;

	in_be64(mmio_base + offset);
}

static int64_t xive_source_set_xive(struct irq_source *is, uint32_t isn,
				    uint16_t server, uint8_t prio)
{
	struct xive_src *s = container_of(is, struct xive_src, is);

	/*
	 * WARNING: There is an inherent race with the use of the
	 * mask bit in the EAS/IVT. When masked, interrupts are "lost"
	 * but their P/Q bits are still set. So when unmasking, one has
	 * to check the P bit and possibly trigger a resend.
	 *
	 * We "deal" with it by relying on the fact that the OS will
	 * lazy disable MSIs. Thus mask will only be called if the
	 * interrupt occurred while already logically masked. Thus
	 * losing subsequent occurrences is of no consequences, we just
	 * need to "cleanup" P and Q when unmasking.
	 *
	 * This needs to be documented in the OPAL APIs
	 */

	/* Unmangle server */
	server >>= 2;

	/* Let XIVE configure the EQ */
	if (!xive_set_eq_info(isn, server, prio, isn))
		return OPAL_PARAMETER;

	/* Ensure it's enabled/disabled in the source controller */
	xive_update_irq_mask(s, isn - s->esb_base, prio == 0xff);

	return OPAL_SUCCESS;
}

static void xive_source_eoi(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);
	uint32_t idx = isn - s->esb_base;
	struct xive_ive *ive;
	void *mmio_base;
	uint64_t eoi_val;

	/* Grab the IVE */
	ive = s->xive->ivt_base;
	if (!ive)
		return;
	ive += GIRQ_TO_IDX(isn);

	/* If it's invalid or masked, don't do anything */
	if ((ive->w & IVE_MASKED) || !(ive->w & IVE_VALID))
		return;

	/* Grab MMIO control address for that ESB */
	mmio_base = s->esb_mmio + (1ull << s->esb_shift) * idx;

	/* If the XIVE supports the new "store EOI facility, use it */
	if (s->flags & XIVE_SRC_STORE_EOI)
		out_be64(mmio_base, 0);
	else {
		uint64_t offset;

		/* Otherwise for EOI, we use the special MMIO that does
		 * a clear of both P and Q and returns the old Q.
		 *
		 * This allows us to then do a re-trigger if Q was set
		 rather than synthetizing an interrupt in software
		*/
		if (s->flags & XIVE_SRC_EOI_PAGE1)
			mmio_base += 1ull << (s->esb_shift - 1);
		offset = 0xc00;
		if (s->flags & XIVE_SRC_SHIFT_BUG)
			offset <<= 4;
		eoi_val = in_be64(mmio_base + offset);
		xive_vdbg(s->xive, "ISN: %08x EOI=%llx\n", isn, eoi_val);
		if ((s->flags & XIVE_SRC_LSI) || !(eoi_val & 1))
			return;

		/* Re-trigger always on page0 or page1 ? */
		out_be64(mmio_base, 0);
	}
}

static void xive_source_interrupt(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);

	if (!s->orig_ops || !s->orig_ops->interrupt)
		return;
	s->orig_ops->interrupt(is, isn);
}

static uint64_t xive_source_attributes(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);

	if (!s->orig_ops || !s->orig_ops->attributes)
		return IRQ_ATTR_TARGET_LINUX;
	return s->orig_ops->attributes(is, isn);
}

static const struct irq_source_ops xive_irq_source_ops = {
	.get_xive = xive_source_get_xive,
	.set_xive = xive_source_set_xive,
	.eoi = xive_source_eoi,
	.interrupt = xive_source_interrupt,
	.attributes = xive_source_attributes,
};

static void __xive_register_source(struct xive *x, struct xive_src *s,
				   uint32_t base, uint32_t count,
				   uint32_t shift, void *mmio, uint32_t flags,
				   bool secondary, void *data,
				   const struct irq_source_ops *orig_ops)
{
	s->esb_base = base;
	s->esb_shift = shift;
	s->esb_mmio = mmio;
	s->flags = flags;
	s->orig_ops = orig_ops;
	s->xive = x;
	s->is.start = base;
	s->is.end = base + count;
	s->is.ops = &xive_irq_source_ops;
	s->is.data = data;

	__register_irq_source(&s->is, secondary);
}

void xive_register_hw_source(uint32_t base, uint32_t count, uint32_t shift,
			     void *mmio, uint32_t flags, void *data,
			     const struct irq_source_ops *ops)
{
	struct xive_src *s;
	struct xive *x = xive_from_isn(base);

	assert(x);

	s = malloc(sizeof(struct xive_src));
	assert(s);
	__xive_register_source(x, s, base, count, shift, mmio, flags,
			       false, data, ops);
}

void xive_register_ipi_source(uint32_t base, uint32_t count, void *data,
			      const struct irq_source_ops *ops)
{
	struct xive_src *s;
	struct xive *x = xive_from_isn(base);
	uint32_t base_idx = GIRQ_TO_IDX(base);
	void *mmio_base;

	assert(x);
	assert(base >= x->int_base && (base + count) <= x->int_ipi_top);

	s = malloc(sizeof(struct xive_src));
	assert(s);

	/* Callbacks assume the MMIO base corresponds to the first
	 * interrupt of that source structure so adjust it
	 */
	mmio_base = x->esb_mmio + (1ul << IPI_ESB_SHIFT) * base_idx;
	__xive_register_source(x, s, base, count, IPI_ESB_SHIFT, mmio_base,
			       XIVE_SRC_EOI_PAGE1, false, data, ops);
}

static void init_one_xive(struct dt_node *np)
{
	struct xive *x;
	struct proc_chip *chip;

	x = zalloc(sizeof(struct xive));
	assert(x);
	x->x_node = np;
	x->xscom_base = dt_get_address(np, 0, NULL);
	x->chip_id = dt_get_chip_id(np);

	/* For now, make block ID and chip ID the same, we'll have to change
	 * that if chip IDs become too sparse
	 */
	x->block_id = x->chip_id;
	xive_block_to_chip[x->block_id] = x->chip_id;
	init_lock(&x->lock);

	chip = get_chip(x->chip_id);
	assert(chip);
	xive_dbg(x, "Initializing...\n");
	chip->xive = x;

	/* Base interrupt numbers and allocator init */
	/* XXX Consider allocating half as many ESBs than MMIO space
	 * so that HW sources land outside of ESB space...
	 */
	x->int_base	= BLKIDX_TO_GIRQ(x->block_id, 0);
	x->int_max	= x->int_base + MAX_INT_ENTRIES;
	x->int_hw_bot	= x->int_max;
	x->int_ipi_top	= x->int_base;

	/* Make sure we never hand out "2" as it's reserved for XICS emulation
	 * IPI returns. Generally start handing out at 0x10
	 */
	if (x->int_ipi_top < 0x10)
		x->int_ipi_top = 0x10;

	x->eq_map = zalloc(BITMAP_BYTES(MAX_EQ_COUNT >> 3));
	assert(x->eq_map);

	xive_dbg(x, "Handling interrupts [%08x..%08x]\n",
		 x->int_base, x->int_max - 1);

	/* System dependant values that must be set before BARs */
	//xive_regwx(x, CQ_CFG_PB_GEN, xx);
	//xive_regwx(x, CQ_MSGSND, xx);

	/* Verify the BARs are initialized and if not, setup a default layout */
	xive_check_update_bars(x);

	/* Some basic global inits such as page sizes etc... */
	if (!xive_config_init(x))
		goto fail;

	/* Configure the set translations for MMIO */
	if (!xive_setup_set_xlate(x))
		goto fail;

	/* Dump some MMIO registers for diagnostics */
	xive_dump_mmio(x);

	/* Pre-allocate a number of tables */
	if (!xive_prealloc_tables(x))
		goto fail;

	/* Configure local tables in VSDs (forward ports will be
	 * handled later)
	 */
	if (!xive_set_local_tables(x))
		goto fail;

	/* Register built-in source controllers (aka IPIs) */
	/* XXX Add new EOI mode for DD2 */
	__xive_register_source(x, &x->ipis, x->int_base,
			       x->int_hw_bot - x->int_base, IPI_ESB_SHIFT,
			       x->esb_mmio, XIVE_SRC_EOI_PAGE1,
			       true, NULL, NULL);

	/* XXX Add registration of escalation sources too */

	/* Create a device-tree node for Linux use */
	xive_create_mmio_dt_node(x);

	return;
 fail:
	xive_err(x, "Initialization failed...\n");

	/* Should this be fatal ? */
	//assert(false);
}

/*
 * XICS emulation
 */
static void xive_ipi_init(struct xive *x, struct cpu_thread *cpu)
{
	struct xive_cpu_state *xs = cpu->xstate;

	assert(xs);

	xive_source_set_xive(&x->ipis.is, xs->ipi_irq, cpu->pir << 2,
			     XIVE_EMULATION_PRIO);
}

static void xive_ipi_eoi(struct xive *x, uint32_t idx)
{
	uint8_t *mm = x->esb_mmio + idx * 0x20000;
	uint8_t eoi_val;

	/* For EOI, we use the special MMIO that does a clear of both
	 * P and Q and returns the old Q.
	 *
	 * This allows us to then do a re-trigger if Q was set rather
	 * than synthetizing an interrupt in software
	 */
	eoi_val = in_8(mm + 0x10c00);
	if (eoi_val & 1) {
		out_8(mm, 0);
	}
}

static void xive_ipi_trigger(struct xive *x, uint32_t idx)
{
	uint8_t *mm = x->esb_mmio + idx * 0x20000;

	xive_vdbg(x, "Trigger IPI 0x%x\n", idx);

	out_8(mm, 0);
}


void xive_cpu_callin(struct cpu_thread *cpu)
{
	struct xive_cpu_state *xs = cpu->xstate;
	struct proc_chip *chip = get_chip(cpu->chip_id);
	struct xive *x = chip->xive;
	uint32_t fc, bit;

	if (!xs)
		return;

	/* First enable us in PTER. We currently assume that the
	 * PIR bits can be directly used to index in PTER. That might
	 * need to be verified
	 */

	/* Get fused core number */
	fc = (cpu->pir >> 3) & 0xf;
	/* Get bit in register */
	bit = cpu->pir & 0x3f;
	/* Get which register to access */
	if (fc < 8)
		xive_regw(x, PC_THREAD_EN_REG0_SET, PPC_BIT(bit));
	else
		xive_regw(x, PC_THREAD_EN_REG1_SET, PPC_BIT(bit));

	/* Set CPPR to 0 */
	out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_CPPR, 0);

	/* Set VT to 1 */
	out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_WORD2, 0x80);

	xive_cpu_dbg(cpu, "Initialized interrupt management area\n");

	/* Now unmask the IPI */
	xive_ipi_init(x, cpu);
}

static void xive_provision_cpu(struct xive_cpu_state *xs, struct cpu_thread *c)
{
	struct xive_vp *vp;
	struct xive_eq eq;
	struct xive *x;
	void *p;

	/* For now VPs are pre-allocated */
	xs->vp_blk = PIR2VP_BLK(c->pir);
	xs->vp_idx = PIR2VP_IDX(c->pir);

	/* Grab the XIVE where the VP resides. It could be different from
	 * the local chip XIVE if not using block group mode
	 */
	x = xive_from_pc_blk(xs->vp_blk);
	assert(x);

	/* Grab VP pointer */
	vp = xive_get_vp(x, xs->vp_idx);
	assert(vp);

	/* For now we use identical block IDs for VC and PC but that might
	 * change. We allocate the EQs on the same XIVE as the VP.
	 */
	xs->eq_blk = xs->vp_blk;

	/* Allocate a set of EQs for that VP */
	xs->eq_idx = xive_alloc_eq_set(x, true);
	assert(!XIVE_ALLOC_IS_ERR(xs->eq_idx));

	/* Provision one of the queues. Allocate the memory on the
	 * chip where the CPU resides
	 */
	p = local_alloc(c->chip_id, 0x10000, 0x10000);
	if (!p) {
		xive_err(x, "Failed to allocate EQ backing store\n");
		assert(false);
	}

	/* Initialize the structure */
	xive_init_eq(xs->vp_blk, xs->vp_idx, &eq, p, XIVE_EMULATION_PRIO);

	/* Use the cache watch to write it out */
	xive_eqc_cache_update(x, xs->vp_blk, xs->eq_idx + XIVE_EMULATION_PRIO,
			      0, 4, &eq, false);

	/* Initialize/enable the VP */
	xive_init_vp(x, vp, xs->eq_blk, xs->eq_idx);
}

static void xive_init_xics_emulation(struct xive_cpu_state *xs)
{
	struct xive *x;

	xs->cppr = 0;
	xs->mfrr = 0xff;

	xs->eqbuf = xive_get_eq_buf(xs->vp_blk, xs->eq_idx + XIVE_EMULATION_PRIO);
	assert(xs->eqbuf);

	xs->eqptr = 0;
	xs->eqmsk = (0x10000/4) - 1;
	xs->eqgen = false;

	x = xive_from_vc_blk(xs->eq_blk);
	assert(x);
	xs->eqmmio = x->eq_mmio + (xs->eq_idx + XIVE_EMULATION_PRIO) * 0x20000;
}

static void xive_init_cpu(struct cpu_thread *c)
{
	struct proc_chip *chip = get_chip(c->chip_id);
	struct xive *x = chip->xive;
	struct xive_cpu_state *xs;

	if (!x)
		return;

	/* First, if we are the first CPU of an EX pair, we need to
	 * setup the special BAR
	 */
	/* XXX This is very P9 specific ... */
	if ((c->pir & 0x7) == 0) {
		uint64_t xa, val;
		int64_t rc;

		xive_cpu_dbg(c, "Setting up special BAR\n");
		xa = XSCOM_ADDR_P9_EX(pir_to_core_id(c->pir), P9X_EX_NCU_SPEC_BAR);
		printf("NCU_SPEC_BAR_XA=%08llx\n", xa);
		val = (uint64_t)x->tm_base | P9X_EX_NCU_SPEC_BAR_ENABLE;
		if (x->tm_shift == 16)
			val |= P9X_EX_NCU_SPEC_BAR_256K;
		rc = xscom_write(c->chip_id, xa, val);
		if (rc) {
			xive_cpu_err(c, "Failed to setup NCU_SPEC_BAR\n");
			/* XXXX  what do do now ? */
		}
	}

	/* Initialize the state structure */
	c->xstate = xs = local_alloc(c->chip_id, sizeof(struct xive_cpu_state), 1);
	assert(xs);
	xs->xive = x;

	init_lock(&xs->lock);

	/* Shortcut to TM HV ring */
	xs->tm_ring1 = x->tm_base + (1u << x->tm_shift);

	/* Allocate an IPI */
	xs->ipi_irq = xive_alloc_ipi_irqs(c->chip_id, 1, 1);

	xive_cpu_dbg(c, "CPU IPI is irq %08x\n", xs->ipi_irq);

	/* Provision a VP and some EQDs for a physical CPU */
	xive_provision_cpu(xs, c);

	/* Initialize the XICS emulation related fields */
	xive_init_xics_emulation(xs);
}

static void xive_init_cpu_properties(struct cpu_thread *cpu)
{
	struct cpu_thread *t;
	uint32_t iprop[8][2] = { };
	uint32_t i;

	assert(cpu_thread_count <= 8);

	if (!cpu->node)
		return;
	for (i = 0; i < cpu_thread_count; i++) {
		t = (i == 0) ? cpu : find_cpu_by_pir(cpu->pir + i);
		if (!t)
			continue;
		iprop[i][0] = t->xstate->ipi_irq;
		iprop[i][1] = 0; /* Edge */
	}
	dt_add_property(cpu->node, "interrupts", iprop, cpu_thread_count * 8);
	dt_add_property_cells(cpu->node, "interrupt-parent", get_ics_phandle());
}

static uint32_t xive_read_eq(struct xive_cpu_state *xs, bool just_peek)
{
	uint32_t cur;

	xive_cpu_vdbg(this_cpu(), "  EQ %s... IDX=%x MSK=%x G=%d\n",
		      just_peek ? "peek" : "read",
		      xs->eqptr, xs->eqmsk, xs->eqgen);
	cur = xs->eqbuf[xs->eqptr];
	xive_cpu_vdbg(this_cpu(), "    cur: %08x [%08x %08x %08x ...]\n", cur,
		      xs->eqbuf[(xs->eqptr + 1) & xs->eqmsk],
		      xs->eqbuf[(xs->eqptr + 2) & xs->eqmsk],
		      xs->eqbuf[(xs->eqptr + 3) & xs->eqmsk]);
	if ((cur >> 31) == xs->eqgen)
		return 0;
	if (!just_peek) {
		xs->eqptr = (xs->eqptr + 1) & xs->eqmsk;
		if (xs->eqptr == 0)
			xs->eqgen = !xs->eqgen;
	}
	return cur & 0x00ffffff;
}

static uint8_t xive_sanitize_cppr(uint8_t cppr)
{
	if (cppr == 0xff || cppr == 0)
		return cppr;
	else
		return XIVE_EMULATION_PRIO;
}

static inline uint8_t opal_xive_check_pending(struct xive_cpu_state *xs,
					      uint8_t cppr)
{
	uint8_t mask = (cppr > 7) ? 0xff : ((1 << cppr) - 1);

	return xs->pending & mask;
}

static int64_t opal_xive_eoi(uint32_t xirr)
{
	struct cpu_thread *c = this_cpu();
	struct xive_cpu_state *xs = c->xstate;
	uint32_t isn = xirr & 0x00ffffff;
	uint8_t cppr, irqprio;
	struct xive *src_x;
	bool special_ipi = false;

	if (xive_mode != XIVE_MODE_EMU)
		return OPAL_WRONG_STATE;
	if (!xs)
		return OPAL_INTERNAL_ERROR;

	xive_cpu_vdbg(c, "EOI xirr=%08x cur_cppr=%d\n", xirr, xs->cppr);

	/* Limit supported CPPR values from OS */
	cppr = xive_sanitize_cppr(xirr >> 24);

	lock(&xs->lock);

	/* Snapshor current CPPR, it's assumed to be our IRQ priority */
	irqprio = xs->cppr;

	/* If this was our magic IPI, convert to IRQ number */
	if (isn == 2) {
		isn = xs->ipi_irq;
		special_ipi = true;
		xive_cpu_vdbg(c, "User EOI for IPI !\n");
	}

	/* First check if we have stuff in that queue. If we do, don't bother with
	 * doing an EOI on the EQ. Just mark that priority pending, we'll come
	 * back later.
	 *
	 * If/when supporting multiple queues we would have to check them all
	 * in ascending prio order up to the passed-in CPPR value (exclusive).
	 */
	if (xive_read_eq(xs, true)) {
		xive_cpu_vdbg(c, "  isn %08x, skip, queue non empty\n", xirr);
		xs->pending |= 1 << irqprio;
	}
#ifndef EQ_ALWAYS_NOTIFY
	else {
		uint8_t eoi_val;

		/* Perform EQ level EOI. Only one EQ for now ...
		 *
		 * Note: We aren't doing an actual EOI. Instead we are clearing
		 * both P and Q and will re-check the queue if Q was set.
		 */
		eoi_val = in_8(xs->eqmmio + 0xc00);
		xive_cpu_vdbg(c, "  isn %08x, eoi_val=%02x\n", xirr, eoi_val);

		/* Q was set ? Check EQ again after doing a sync to ensure
		 * ordering.
		 */
		if (eoi_val & 1) {
			sync();
			if (xive_read_eq(xs, true))
				xs->pending |= 1 << irqprio;
		}
	}
#endif

	/* Perform source level EOI if it's not our emulated MFRR IPI
	 * otherwise EOI ourselves
	 */
	src_x = xive_from_isn(isn);
	if (src_x) {
		uint32_t idx = GIRQ_TO_IDX(isn);

		/* Is it an IPI ? */
		if (special_ipi) {
			xive_ipi_eoi(src_x, idx);

			/* Check mfrr and eventually re-trigger. We check
			 * against the new CPPR since we are about to update
			 * the HW.
			 */
			if (xs->mfrr < cppr)
				xive_ipi_trigger(src_x, idx);
		} else {
			/* Otherwise go through the source mechanism */
			xive_vdbg(src_x, "EOI of IDX %x in EXT range\n", idx);
			irq_source_eoi(isn);
		}
	} else {
		xive_cpu_err(c, "  EOI unknown ISN %08x\n", isn);
	}

	/* Finally restore CPPR */
	xs->cppr = cppr;
	out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_CPPR, cppr);

	xive_cpu_vdbg(c, "  pending=0x%x cppr=%d\n", xs->pending, cppr);

	unlock(&xs->lock);

	/* Return whether something is pending that is suitable for
	 * delivery considering the new CPPR value. This can be done
	 * without lock as these fields are per-cpu.
	 */
	return opal_xive_check_pending(xs, cppr);
}

static int64_t opal_xive_get_xirr(uint32_t *out_xirr, bool just_poll)
{
	struct cpu_thread *c = this_cpu();
	struct xive_cpu_state *xs = c->xstate;
	uint16_t ack;
	uint8_t active, old_cppr;

	if (xive_mode != XIVE_MODE_EMU)
		return OPAL_WRONG_STATE;
	if (!xs)
		return OPAL_INTERNAL_ERROR;
	if (!out_xirr)
		return OPAL_PARAMETER;

	*out_xirr = 0;

	lock(&xs->lock);

	/*
	 * Due to the need to fetch multiple interrupts from the EQ, we
	 * need to play some tricks.
	 *
	 * The "pending" byte in "xs" keeps track of the priorities that
	 * are known to have stuff to read (currently we only use one).
	 *
	 * It is set in EOI and cleared when consumed here. We don't bother
	 * looking ahead here, EOI will do it.
	 *
	 * We do need to still do an ACK every time in case a higher prio
	 * exception occurred (though we don't do prio yet... right ? still
	 * let's get the basic design right !).
	 *
	 * Note that if we haven't found anything via ack, but did find
	 * something in the queue, we must also raise CPPR back.
	 */

	/* Perform the HV Ack cycle */
	if (just_poll)
		ack = in_be64(xs->tm_ring1 + TM_QW3_HV_PHYS) >> 48;
	else
		ack = in_be16(xs->tm_ring1 + TM_SPC_ACK_HV_REG);
	xive_cpu_vdbg(c, "get_xirr,%s=%04x\n", just_poll ? "POLL" : "ACK", ack);

	/* Capture the old CPPR which we will return with the interrupt */
	old_cppr = xs->cppr;

	switch(GETFIELD(TM_QW3_NSR_HE, (ack >> 8))) {
	case TM_QW3_NSR_HE_NONE:
		break;
	case TM_QW3_NSR_HE_POOL:
		break;
	case TM_QW3_NSR_HE_PHYS:
		/* Mark pending and keep track of the CPPR update */
		if (!just_poll) {
			xs->cppr = ack & 0xff;
			xs->pending |= 1 << xs->cppr;
		}
		break;
	case TM_QW3_NSR_HE_LSI:
		break;
	}

	/* Calculate "active" lines as being the pending interrupts
	 * masked by the "old" CPPR
	 */
	active = opal_xive_check_pending(xs, old_cppr);

	xive_cpu_vdbg(c, "  cppr=%d->%d pending=0x%x active=%x\n",
		      old_cppr, xs->cppr, xs->pending, active);
	if (active) {
		/* Find highest pending */
		uint8_t prio = ffs(active) - 1;
		uint32_t val;

		/* XXX Use "p" to select queue */
		val = xive_read_eq(xs, just_poll);

		/* Convert to magic IPI if needed */
		if (val == xs->ipi_irq)
			val = 2;

		*out_xirr = (old_cppr << 24) | val;

		/* If we are polling, that's it */
		if (just_poll)
			goto skip;

		/* Clear the pending bit. EOI will set it again if needed. We
		 * could check the queue but that's not really critical here.
		 */
		xs->pending &= ~(1 << prio);

		/* There should always be an interrupt here I think, unless
		 * some race occurred, but let's be safe. If we don't find
		 * anything, we just return.
		 */
		if (!val)
			goto skip;

		xive_cpu_vdbg(c, "  found irq, prio=%d\n", prio);

		/* We could have fetched a pending interrupt left over
		 * by a previous EOI, so the CPPR might need adjusting
		 */
		if (xs->cppr > prio) {
			xs->cppr = prio;
			out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_CPPR, prio);
			xive_cpu_vdbg(c, "  adjusted CPPR\n");
		}
	}
 skip:

	xive_cpu_vdbg(c, "  returning XIRR=%08x, pending=0x%x\n",
		      *out_xirr, xs->pending);

	unlock(&xs->lock);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_set_cppr(uint8_t cppr)
{
	struct cpu_thread *c = this_cpu();
	struct xive_cpu_state *xs = c->xstate;

	if (xive_mode != XIVE_MODE_EMU)
		return OPAL_WRONG_STATE;

	/* Limit supported CPPR values */
	cppr = xive_sanitize_cppr(cppr);

	if (!xs)
		return OPAL_INTERNAL_ERROR;
	xive_cpu_vdbg(c, "CPPR setting to %d\n", cppr);

	lock(&xs->lock);
	c->xstate->cppr = cppr;
	out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_CPPR, cppr);

	unlock(&xs->lock);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_set_mfrr(uint32_t cpu, uint8_t mfrr)
{
	struct cpu_thread *c = find_cpu_by_server(cpu);
	struct xive_cpu_state *xs;
	uint8_t old_mfrr;

	if (xive_mode != XIVE_MODE_EMU)
		return OPAL_WRONG_STATE;
	if (!c)
		return OPAL_PARAMETER;
	xs = c->xstate;
	if (!xs)
		return OPAL_INTERNAL_ERROR;

	lock(&xs->lock);
	old_mfrr = xs->mfrr;
	xive_cpu_vdbg(c, "  Setting MFRR to %x, old is %x\n", mfrr, old_mfrr);
	xs->mfrr = mfrr;
	if (old_mfrr > mfrr && mfrr < xs->cppr)
		xive_ipi_trigger(xs->xive, GIRQ_TO_IDX(xs->ipi_irq));
	unlock(&xs->lock);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_reset(uint64_t version)
{
	if (version > 1)
		return OPAL_PARAMETER;

	xive_mode = version;

	return OPAL_SUCCESS;
}

static int64_t opal_xive_get_irq_info(uint32_t girq,
				      uint64_t *out_flags,
				      uint64_t *out_eoi_page,
				      uint64_t *out_trig_page,
				      uint32_t *out_esb_shift,
				      uint32_t *out_src_chip)
{
	struct irq_source *is = irq_find_source(girq);
	struct xive_src *s = container_of(is, struct xive_src, is);
	uint32_t idx;
	uint64_t mm_base;
	uint64_t eoi_page = 0, trig_page = 0;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;
	if (is == NULL || out_flags == NULL)
		return OPAL_PARAMETER;
	assert(is->ops == &xive_irq_source_ops);

	*out_flags = s->flags;
	idx = girq - s->esb_base;

	if (out_esb_shift)
		*out_esb_shift = s->esb_shift;

	mm_base = (uint64_t)s->esb_mmio + (1ull << s->esb_shift) * idx;

	if (s->flags & XIVE_SRC_EOI_PAGE1) {
		uint64_t p1off = 1ull << (s->esb_shift - 1);
		eoi_page = mm_base + p1off;
		trig_page = mm_base;
	} else {
		eoi_page = mm_base;
		if (!(s->flags & XIVE_SRC_STORE_EOI))
			trig_page = mm_base;
	}

	if (out_eoi_page)
		*out_eoi_page = eoi_page;
	if (out_trig_page)
		*out_trig_page = trig_page;
	if (out_src_chip)
		*out_src_chip = GIRQ_TO_CHIP(girq);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_get_irq_config(uint32_t girq,
					uint32_t *out_vp,
					uint8_t *out_prio,
					uint32_t *out_lirq)
{
	if (xive_get_eq_info(girq, out_vp, out_prio, out_lirq))
		return OPAL_SUCCESS;
	else
		return OPAL_PARAMETER;
}

static int64_t opal_xive_set_irq_config(uint32_t girq,
					uint32_t vp,
					uint8_t prio,
					uint32_t lirq)
{
	struct irq_source *is = irq_find_source(girq);
	struct xive_src *s = container_of(is, struct xive_src, is);

	/*
	 * WARNING: See comment in set_xive()
	 */

	/* Let XIVE configure the EQ */
	if (!xive_set_eq_info(girq, vp, prio, lirq))
		return OPAL_PARAMETER;

	/* Ensure it's enabled/disabled in the source controller */
	xive_update_irq_mask(s, girq - s->esb_base, prio == 0xff);

	return OPAL_SUCCESS;
}

static void xive_init_globals(void)
{
	uint32_t i;

	for (i = 0; i < 16; i++)
		xive_block_to_chip[i] = XIVE_INVALID_CHIP;
}

void init_xive(void)
{
	struct dt_node *np;
	struct proc_chip *chip;
	struct cpu_thread *cpu;
	bool first = true;

	/* Look for xive nodes and do basic inits */
	dt_for_each_compatible(dt_root, np, "ibm,power9-xive-x") {
		/* Initialize some global stuff */
		if (first)
			xive_init_globals();
		first = false;
		/* Create/initialize the xive instance */
		init_one_xive(np);
	}

	/* Some inits must be done after all xive have been created
	 * such as setting up the forwarding ports
	 */
	for_each_chip(chip) {
		if (chip->xive)
			late_init_one_xive(chip->xive);
	}

	/* Initialize XICS emulation per-cpu structures */
	for_each_cpu(cpu) {
		xive_init_cpu(cpu);
	}
	/* Add interrupts propertie to each CPU node */
	for_each_cpu(cpu) {
		if (cpu_is_thread0(cpu))
			xive_init_cpu_properties(cpu);
	}

	/* Calling boot CPU */
	xive_cpu_callin(this_cpu());

	/* Register XICS emulation calls */
	opal_register(OPAL_INT_GET_XIRR, opal_xive_get_xirr, 2);
	opal_register(OPAL_INT_SET_CPPR, opal_xive_set_cppr, 1);
	opal_register(OPAL_INT_EOI, opal_xive_eoi, 1);
	opal_register(OPAL_INT_SET_MFRR, opal_xive_set_mfrr, 2);

	/* Register XIVE exploitation calls */
	opal_register(OPAL_XIVE_RESET, opal_xive_reset, 1);
	opal_register(OPAL_XIVE_GET_IRQ_INFO, opal_xive_get_irq_info, 6);
	opal_register(OPAL_XIVE_GET_IRQ_CONFIG, opal_xive_get_irq_config, 4);
	opal_register(OPAL_XIVE_SET_IRQ_CONFIG, opal_xive_set_irq_config, 4);
}

