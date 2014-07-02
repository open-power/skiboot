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
#ifndef __AST_H
#define __AST_H

/*
 * AHB bus registers
 */

/* SPI Flash controller #1 (BMC) */
#define BMC_SPI_FCTL_BASE	0x1E620000
#define BMC_SPI_FCTL_CTRL	(BMC_SPI_FCTL_BASE + 0x10)
#define BMC_FLASH_BASE		0x20000000

/* SPI Flash controller #2 (PNOR) */
#define PNOR_SPI_FCTL_BASE	0x1E630000
#define PNOR_SPI_FCTL_CONF	(PNOR_SPI_FCTL_BASE + 0x00)
#define PNOR_SPI_FCTL_CTRL	(PNOR_SPI_FCTL_BASE + 0x04)
#define PNOR_FLASH_BASE		0x30000000

/* LPC registers */
#define LPC_BASE		0x1e789000
#define LPC_HICR6		(LPC_BASE + 0x80)
#define LPC_HICR7		(LPC_BASE + 0x88)
#define LPC_HICR8		(LPC_BASE + 0x8c)

/*
 * AHB Accessors
 */
#ifndef __SKIBOOT__
#include "io.h"
#else

/*
 * Register accessors, return byteswapped values
 * (IE. LE registers)
 */
void ast_ahb_writel(uint32_t val, uint32_t reg);
uint32_t ast_ahb_readl(uint32_t reg);

/*
 * copy to/from accessors. Cannot cross IDSEL boundaries (256M)
 */
int ast_copy_to_ahb(uint32_t reg, const void *src, uint32_t len);
int ast_copy_from_ahb(void *dst, uint32_t reg, uint32_t len);

void ast_io_init(void);

/* UART init */
void ast_setup_uart1(uint16_t io_base, uint8_t irq);

#endif /* __SKIBOOT__ */

/*
 * SPI Flash controllers
 */
#define AST_SF_TYPE_PNOR	0
#define AST_SF_TYPE_BMC		1

struct spi_flash_ctrl;
int ast_sf_open(uint8_t type, struct spi_flash_ctrl **ctrl);
void ast_sf_close(struct spi_flash_ctrl *ctrl);


#endif /* __AST_H */
