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

#ifndef __LPC_H
#define __LPC_H

#include <opal.h>
#include <ccan/endian/endian.h>

/* Routines for accessing the LPC bus on Power8 */

extern void lpc_init(void);

/* Check for a default bus */
extern bool lpc_present(void);

/* Return of LPC is currently usable. This can be false if the caller
 * currently holds a lock that would make it unsafe, or the LPC bus
 * is known to be in some error condition (TBI).
 */
extern bool lpc_ok(void);

/* Handle the interrupt from LPC source */
extern void __attrconst lpc_interrupt(uint32_t chip_id);

/* Default bus accessors */
extern int64_t lpc_write(enum OpalLPCAddressType addr_type, uint32_t addr,
			 uint32_t data, uint32_t sz);
extern int64_t lpc_read(enum OpalLPCAddressType addr_type, uint32_t addr,
			uint32_t *data, uint32_t sz);

/* Mark LPC bus as used by console */
extern void lpc_used_by_console(void);

/*
 * Simplified big endian FW accessors
 */
static inline int64_t lpc_fw_read32(uint32_t *val, uint32_t addr)
{
	return lpc_read(OPAL_LPC_FW, addr, val, 4);
}

static inline int64_t lpc_fw_write32(uint32_t val, uint32_t addr)
{
	return lpc_write(OPAL_LPC_FW, addr, val, 4);
}


/*
 * Simplified Little Endian IO space accessors
 *
 * Note: We do *NOT* handle unaligned accesses
 */

static inline void lpc_outb(uint8_t data, uint32_t addr)
{
	lpc_write(OPAL_LPC_IO, addr, data, 1);
}

static inline uint8_t lpc_inb(uint32_t addr)
{
	uint32_t d32;
	int64_t rc = lpc_read(OPAL_LPC_IO, addr, &d32, 1);
	return (rc == OPAL_SUCCESS) ? d32 : 0xff;
}

static inline void lpc_outw(uint16_t data, uint32_t addr)
{
	lpc_write(OPAL_LPC_IO, addr, cpu_to_le16(data), 2);
}

static inline uint16_t lpc_inw(uint32_t addr)
{
	uint32_t d32;
	int64_t rc = lpc_read(OPAL_LPC_IO, addr, &d32, 2);
	return (rc == OPAL_SUCCESS) ? le16_to_cpu(d32) : 0xffff;
}

static inline void lpc_outl(uint32_t data, uint32_t addr)
{
	lpc_write(OPAL_LPC_IO, addr, cpu_to_le32(data), 4);
}

static inline uint32_t lpc_inl(uint32_t addr)
{
	uint32_t d32;
	int64_t rc = lpc_read(OPAL_LPC_IO, addr, &d32, 4);
	return (rc == OPAL_SUCCESS) ? le32_to_cpu(d32) : 0xffffffff;
}

#endif /* __LPC_H */
