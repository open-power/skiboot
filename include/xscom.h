// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __XSCOM_H
#define __XSCOM_H

#include <stdint.h>
#include <processor.h>
#include <cpu.h>

/*
 * SCOM "partID" definitions:
 *
 * All Ids are 32-bits long, top nibble is reserved for the
 * 'type' field:
 *     0x0 = Processor Chip
 *     0x8 = Memory Buffer (Centaur) Chip
 *     0x4 = EX/Core Chiplet
 *
 * Processor Chip = Logical Fabric Id = PIR>>7
 *     0b0000.0000.0000.0000.0000.0000.00NN.NCCC
 *     N=Node, C=Chip
 * Centaur Chip = Associated Processor Chip with memory channel
 * appended and flag set
 *     0b1000.0000.0000.0000.0000.00NN.NCCC.MMMM
 *     N=Node, C=Chip, M=Memory Channel
 * Processor EX/Core chiplet = PIR >> 3 with flag set.
 * On P8:
 *     0b0100.0000.0000.0000.0000.00NN.NCCC.PPPP
 * On P9:
 *     0b0100.0000.0000.0000.0000.0NNN.CCCP.PPPP
 *     N=Node, C=Chip, P=Processor core
 */

/*
 * SCOM Address definition extracted from HWPs for documentation
 * purposes
 *
 * "Normal" (legacy) format
 *
 *            111111 11112222 22222233 33333333 44444444 44555555 55556666
 * 01234567 89012345 67890123 45678901 23456789 01234567 89012345 67890123
 * -------- -------- -------- -------- -------- -------- -------- --------
 * 00000000 00000000 00000000 00000000 0MCCCCCC ????PPPP 00LLLLLL LLLLLLLL
 *                                      ||          |    |
 *                                      ||          |    `-> Local Address*
 *                                      ||          |
 *                                      ||          `-> Port
 *                                      ||
 *                                      |`-> Chiplet ID**
 *                                      |
 *                                      `-> Multicast bit
 *
 *  * Local address is composed of "00" + 4-bit ring + 10-bit ID
 *    The 10-bit ID is usually 4-bit sat_id and 6-bit reg_id
 *
 * ** Chiplet ID turns into multicast operation type and group number
 *    if the multicast bit is set
 *
 * "Indirect" format
 *
 *
 *            111111 11112222 22222233 33333333 44444444 44555555 55556666
 * 01234567 89012345 67890123 45678901 23456789 01234567 89012345 67890123
 * -------- -------- -------- -------- -------- -------- -------- --------
 * 10000000 0000IIII IIIIIGGG GGGLLLLL 0MCCCCCC ????PPPP 00LLLLLL LLLLLLLL
 *              |         |      |      ||          |    |
 *              |         |      |      ||          |    `-> Local Address*
 *              |         |      |      ||          |
 *              |         |      |      ||          `-> Port
 *              |         |      |      ||
 *              |         |      |      |`-> Chiplet ID**
 *              |         |      |      |
 *              |         |      |      `-> Multicast bit
 *              |         |      |
 *              |         |      `-> Lane ID
 *              |         |
 *              |         `-> RX or TX Group ID
 *              |
 *              `-> Indirect Register Address
 *
 *  * Local address is composed of "00" + 4-bit ring + 4-bit sat_id + "111111"
 *
 * ** Chiplet ID turns into multicast operation type and group number
 *    if the multicast bit is set
 */

/*
 * Generate a local address from a given ring/satellite/offset
 * combination:
 *
 *     Ring    Satellite     offset
 *  +---------+---------+-------------+
 *  |    4    |    4    |     6       |
 *  +---------+---------+-------------+
 */
#define XSCOM_SAT(_r, _s, _o)	\
	(((_r) << 10) | ((_s) << 6) | (_o))

/*
 * Additional useful definitions for P8
 */
#define P8_EX_PCB_SLAVE_BASE	0x100F0000

#define XSCOM_ADDR_P8_EX_SLAVE(core, offset) \
     (P8_EX_PCB_SLAVE_BASE | (((core) & 0xF) << 24) | ((offset) & 0xFFFF))

#define XSCOM_ADDR_P8_EX(core, addr) \
		((((core) & 0xF) << 24) | (addr))

/*
 * Additional useful definitions for P9
 */

/*
 * An EQ is a quad. The Pervasive spec also uses the term "EP"
 * to refer to an EQ and it's two child EX chiplets, but
 * nothing else does
 */
#define XSCOM_ADDR_P9_EQ(core, addr) \
	(((((core) & 0x1c) + 0x40) << 22) | (addr))
#define XSCOM_ADDR_P9_EQ_SLAVE(core, addr) \
	XSCOM_ADDR_P9_EQ(core, (addr) | 0xf0000)

/* An EX is a pair of cores. They are accessed via their corresponding EQs
 * with bit 0x400 indicating which of the 2 EX to address
 */
#define XSCOM_ADDR_P9_EX(core, addr) \
	(XSCOM_ADDR_P9_EQ(core, addr | (((core) & 2) << 9)))

/* An EC is an individual core and has its own XSCOM addressing */
#define XSCOM_ADDR_P9_EC(core, addr) \
	(((((core) & 0x1F) + 0x20) << 24) | (addr))
#define XSCOM_ADDR_P9_EC_SLAVE(core, addr) \
	XSCOM_ADDR_P9_EC(core, (addr) | 0xf0000)


/* Definitions relating to indirect XSCOMs shared with centaur */
#define XSCOM_ADDR_IND_FLAG		PPC_BIT(0)
#define XSCOM_ADDR_IND_ADDR		PPC_BITMASK(12,31)
#define XSCOM_ADDR_IND_DATA		PPC_BITMASK(48,63)

#define XSCOM_DATA_IND_READ		PPC_BIT(0)
#define XSCOM_DATA_IND_COMPLETE		PPC_BIT(32)
#define XSCOM_DATA_IND_ERR		PPC_BITMASK(33,35)
#define XSCOM_DATA_IND_DATA		PPC_BITMASK(48,63)
#define XSCOM_DATA_IND_FORM1_DATA	PPC_BITMASK(12,63)

/* HB folks say: try 10 time for now */
#define XSCOM_IND_MAX_RETRIES		10

/* Max number of retries when XSCOM remains busy */
#define XSCOM_BUSY_MAX_RETRIES		3000

/* Max number of retries for xscom clearing recovery. */
#define XSCOM_CLEAR_MAX_RETRIES		10

/* Retry count after which to reset XSCOM, if still busy */
#define XSCOM_BUSY_RESET_THRESHOLD	1000

/*
 * Error handling:
 *
 * Error codes TBD, 0 = success
 */

/* Use only in select places where multiple SCOMs are time/latency sensitive */
extern void _xscom_lock(void);
extern int _xscom_read(uint32_t partid, uint64_t pcb_addr, uint64_t *val, bool take_lock);
extern int _xscom_write(uint32_t partid, uint64_t pcb_addr, uint64_t val, bool take_lock);
extern void _xscom_unlock(void);


/* Targeted SCOM access */
static inline int xscom_read(uint32_t partid, uint64_t pcb_addr, uint64_t *val)
{
	return _xscom_read(partid, pcb_addr, val, true);
}
static inline int xscom_write(uint32_t partid, uint64_t pcb_addr, uint64_t val) {
	return _xscom_write(partid, pcb_addr, val, true);
}
extern int xscom_write_mask(uint32_t partid, uint64_t pcb_addr, uint64_t val, uint64_t mask);

/* This chip SCOM access */
extern int xscom_readme(uint64_t pcb_addr, uint64_t *val);
extern int xscom_writeme(uint64_t pcb_addr, uint64_t val);
extern void xscom_init(void);

/* Mark XSCOM lock as being in console path */
extern void xscom_used_by_console(void);

/* Returns true if XSCOM can be used. Typically this returns false if
 * the current CPU holds the XSCOM lock (to avoid re-entrancy from error path).
 */
extern bool xscom_ok(void);

extern int64_t xscom_read_cfam_chipid(uint32_t partid, uint32_t *chip_id);
extern int64_t xscom_trigger_xstop(void);

#endif /* __XSCOM_H */
