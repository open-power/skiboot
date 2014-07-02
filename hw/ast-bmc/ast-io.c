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
 * Note about accesses to the AST2400 internal memory map:
 *
 * There are two ways to genrate accesses to the AHB bus of the AST2400
 * from the host. The LPC->AHB bridge and the iLPC->AHB bridge.
 *
 * LPC->AHB bridge
 * ---------------
 *
 * This bridge directly converts memory or firmware accesses using
 * a set of registers for establishing a remapping window. We prefer
 * using FW space as normal memory space is limited to byte accesses
 * to a fixed 256M window, while FW space allows us to use different
 * access sizes and to control the IDSEL bits which essentially enable
 * a full 4G addres space.
 *
 * The way FW accesses map onto AHB is controlled via two registers
 * in the BMC's LPC host controller:
 *
 * HICR7 at 0x1e789088 [31:16] : ADRBASE
 *                     [15:00] : HWMBASE
 *
 * HICR8 at 0x1e78908c [31:16] : ADRMASK
 *		       [15:00] : HWNCARE
 *
 * All decoding/remapping happens on the top 16 bits of the LPC address
 * named LPC_ADDR as follow:
 *
 *  - For decoding, LPC_ADDR bits are compared with HWMBASE if the
 *    corresponding bit in HWNCARE is 0.
 *
 *  - For remapping, the AHB address is constructed by taking bits
 *    from LPC_ADDR if the corresponding bit in ADRMASK is 0 or in
 *    ADRBASE if the corresponding bit in ADRMASK is 1
 *
 * Example of 2MB SPI flash, LPC 0xFCE00000~0xFCFFFFFF onto
 *                           AHB 0x30000000~0x301FFFFF (SPI flash)
 *
 * ADRBASE=0x3000 HWMBASE=0xFCE0
 * ADRMASK=0xFFE0 HWNCARE=0x001F
 *
 * This comes pre-configured by the BMC or HostBoot to access the PNOR
 * flash from IDSEL 0 as follow:
 *
 * ADRBASE=0x3000 HWMBASE=0x0e00
 * ADRMASK=0xfe00 HWNCARE=0x01ff 
 *
 * Which means mapping of   LPC 0x0e000000..0x0fffffff onto
 *                          AHB 0x30000000..0x31ffffff
 *
 * iLPC->AHB bridge
 * ---------------
 *
 * This bridge is hosted in the SuperIO part of the BMC and is
 * controlled by a series of byte-sized registers accessed indirectly
 * via IO ports 0x2e and 0x2f.
 *
 * Via these, byte by byte, we can construct an AHB address and
 * fill a data buffer to trigger a write cycle, or we can do a
 * read cycle and read back the data, byte after byte.
 *
 * This is fairly convoluted and slow but works regardless of what
 * mapping was established in the LPC->AHB bridge.
 *
 * For the time being, we use the iLPC->AHB for everything except
 * pnor accesses. In the long run, we will reconfigure the LPC->AHB
 * to provide more direct access to all of the BMC addres space but
 * we'll only do that after the boot script/program on the BMC is
 * updated to restore the bridge to a state compatible with the SBE
 * expectations on boot.
 */ 
 
#include <skiboot.h>
#include <lpc.h>
#include <lock.h>

#include "ast.h"

static struct lock bmc_sio_lock = LOCK_UNLOCKED;

/*
 * SuperIO indirect accesses
 */
static void bmc_sio_outb(uint8_t val, uint8_t reg)
{
	lpc_outb(reg, 0x2e);
	lpc_outb(val, 0x2f);
}

static uint8_t bmc_sio_inb(uint8_t reg)
{
	lpc_outb(reg, 0x2e);
	return lpc_inb(0x2f);
}

/*
 * AHB accesses via iLPC->AHB in SuperIO. Works on byteswapped
 * values (ie. Little Endian registers)
 */
static void bmc_sio_ahb_prep(uint32_t reg, uint8_t type)
{
	/* Address */
	bmc_sio_outb((reg >> 24) & 0xff, 0xf0);
	bmc_sio_outb((reg >> 16) & 0xff, 0xf1);
	bmc_sio_outb((reg >>  8) & 0xff, 0xf2);
	bmc_sio_outb((reg      ) & 0xff, 0xf3);

	/* bytes cycle type */
	bmc_sio_outb(type, 0xf8);
}

static void bmc_sio_ahb_writel(uint32_t val, uint32_t reg)
{
	lock(&bmc_sio_lock);

	bmc_sio_ahb_prep(reg, 2);

	/* Write data */
	bmc_sio_outb(val >> 24, 0xf4);
	bmc_sio_outb(val >> 16, 0xf5);
	bmc_sio_outb(val >>  8, 0xf6);
	bmc_sio_outb(val      , 0xf7);

	/* Trigger */
	bmc_sio_outb(0xcf, 0xfe);

	unlock(&bmc_sio_lock);
}

static uint32_t bmc_sio_ahb_readl(uint32_t reg)
{
	uint32_t val = 0;

	lock(&bmc_sio_lock);

	bmc_sio_ahb_prep(reg, 2);

	/* Trigger */	
	bmc_sio_inb(0xfe);

	/* Read results */
	val = (val << 8) | bmc_sio_inb(0xf4);
	val = (val << 8) | bmc_sio_inb(0xf5);
	val = (val << 8) | bmc_sio_inb(0xf6);
	val = (val << 8) | bmc_sio_inb(0xf7);

	unlock(&bmc_sio_lock);

	return val;
}

static void bmc_sio_ahb_init(void)
{
	/* Send SuperIO password */
	lpc_outb(0xa5, 0x2e);
	lpc_outb(0xa5, 0x2e);

	/* Select logical dev d */
	bmc_sio_outb(0x0d, 0x07);

	/* Enable iLPC->AHB */
	bmc_sio_outb(0x01, 0x30);

	/* We leave the SuperIO enabled and unlocked for
	 * subsequent accesses.
	 */
}

/*
 * External API
 *
 * We only support 4-byte accesses to all of AHB. We additionally
 * support 1-byte accesses to the flash area only.
 *
 * We could support all access sizes via iLPC but we don't need
 * that for now.
 */
#define PNOR_AHB_ADDR	0x30000000
#define PNOR_LPC_OFFSET	0x0e000000

void ast_ahb_writel(uint32_t val, uint32_t reg)
{
	/* For now, always use iLPC->AHB, it will byteswap */
	bmc_sio_ahb_writel(val, reg);
}

uint32_t ast_ahb_readl(uint32_t reg)
{
	/* For now, always use iLPC->AHB, it will byteswap */
	return bmc_sio_ahb_readl(reg);
}

int ast_copy_to_ahb(uint32_t reg, const void *src, uint32_t len)
{
	/* Check we don't cross IDSEL segments */
	if ((reg ^ (reg + len - 1)) >> 28)
		return -EINVAL;

	/* SPI flash, use LPC->AHB bridge */	
	if ((reg >> 28) == (PNOR_AHB_ADDR >> 28)) {
		uint32_t chunk, off = reg - PNOR_AHB_ADDR + PNOR_LPC_OFFSET;
		int64_t rc;

		while(len) {
			/* Chose access size */
			if (len > 3 && !(off & 3)) {
				rc = lpc_write(OPAL_LPC_FW, off,
					       *(uint32_t *)src, 4);
				chunk = 4;
			} else {
				rc = lpc_write(OPAL_LPC_FW, off,
					       *(uint8_t *)src, 1);
				chunk = 1;
			}
			if (rc) {
				prerror("AST_IO: lpc_write.sb failure %lld"
					" to FW 0x%08x\n", rc, off);
				return rc;
			}
			len -= chunk;
			off += chunk;
			src += chunk;
		}
		return 0;
	}

	/* Otherwise we don't do byte access (... yet)  */
	prerror("AST_IO: Attempted write bytes access to %08x\n", reg);
	return -EINVAL;
}

int ast_copy_from_ahb(void *dst, uint32_t reg, uint32_t len)
{
	/* Check we don't cross IDSEL segments */
	if ((reg ^ (reg + len - 1)) >> 28)
		return -EINVAL;

	/* SPI flash, use LPC->AHB bridge */
	if ((reg >> 28) == (PNOR_AHB_ADDR >> 28)) {
		uint32_t chunk, off = reg - PNOR_AHB_ADDR + PNOR_LPC_OFFSET;
		int64_t rc;

		while(len) {
			uint32_t dat;

			/* Chose access size */
			if (len > 3 && !(off & 3)) {
				rc = lpc_read(OPAL_LPC_FW, off, &dat, 4);
				if (!rc)
					*(uint32_t *)dst = dat;
				chunk = 4;
			} else {
				rc = lpc_read(OPAL_LPC_FW, off, &dat, 1);
				if (!rc)
					*(uint8_t *)dst = dat;
				chunk = 1;
			}
			if (rc) {
				prerror("AST_IO: lpc_read.sb failure %lld"
					" to FW 0x%08x\n", rc, off);
				return rc;
			}
			len -= chunk;
			off += chunk;
			dst += chunk;
		}
		return 0;
	}
	/* Otherwise we don't do byte access (... yet)  */
	prerror("AST_IO: Attempted read bytes access to %08x\n", reg);
	return -EINVAL;
}

void ast_io_init(void)
{
	/* Initialize iLPC->AHB bridge */
	bmc_sio_ahb_init();

	/* Configure the LPC->AHB bridge for PNOR access (just in case) */
	bmc_sio_ahb_writel(0x30000e00, LPC_HICR7);
	bmc_sio_ahb_writel(0xfe0001ff, LPC_HICR8);
	bmc_sio_ahb_writel(0x00000500, LPC_HICR6);
}

/* Setup SuperIO UART 1*/
void ast_setup_uart1(uint16_t io_base, uint8_t irq)
{
	/* Send SuperIO password */
	lpc_outb(0xa5, 0x2e);
	lpc_outb(0xa5, 0x2e);

	/* Select logical dev 2 */
	bmc_sio_outb(0x02, 0x07);

	/* Disable UART1 for configuration */
	bmc_sio_outb(0x01, 0x30);

	/* Configure base and interrupt */
	bmc_sio_outb(io_base >> 8, 0x60);
	bmc_sio_outb(io_base & 0xff, 0x61);
	bmc_sio_outb(irq, 0x70);
	bmc_sio_outb(0x01, 0x71); /* level low */

	/* Enable UART1 */
	bmc_sio_outb(0x01, 0x30);

	/* Re-lock SuperIO */
	lpc_outb(0xaa, 0x2e);
}
