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
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <libflash/libflash.h>
#include <libflash/libflash-priv.h>

#include "ast.h"

#ifndef __unused
#define __unused __attribute__((unused))
#endif

struct ast_sf_ctrl {
	/* We have 2 controllers, one for the BMC flash, one for the PNOR */
	uint8_t			type;

	/* Address and previous value of the ctrl register */
	uint32_t		ctl_reg;

	/* Control register value for normal commands */
	uint32_t		ctl_val;

	/* Control register value for (fast) reads */
	uint32_t		ctl_read_val;

	/* Address of the flash mapping */
	uint32_t		flash;

	/* Current 4b mode */
	bool			mode_4b;

	/* Callbacks */
	struct spi_flash_ctrl	ops;
};

static int ast_sf_start_cmd(struct ast_sf_ctrl *ct, uint8_t cmd)
{
	/* Switch to user mode, CE# dropped */
	ast_ahb_writel(ct->ctl_val | 7, ct->ctl_reg);

	/* user mode, CE# active */
	ast_ahb_writel(ct->ctl_val | 3, ct->ctl_reg);

	/* write cmd */
	return ast_copy_to_ahb(ct->flash, &cmd, 1);
}

static void ast_sf_end_cmd(struct ast_sf_ctrl *ct)
{
	/* clear CE# */
	ast_ahb_writel(ct->ctl_val | 7, ct->ctl_reg);

	/* Switch back to read mode */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
}

static int ast_sf_send_addr(struct ast_sf_ctrl *ct, uint32_t addr)
{
	const void *ap;

	/* Layout address MSB first in memory */
	addr = cpu_to_be32(addr);

	/* Send the right amount of bytes */
	ap = (char *)&addr;

	if (ct->mode_4b)
		return ast_copy_to_ahb(ct->flash, ap, 4);
	else
		return ast_copy_to_ahb(ct->flash, ap + 1, 3);
}

static int ast_sf_cmd_rd(struct spi_flash_ctrl *ctrl, uint8_t cmd,
			 bool has_addr, uint32_t addr, void *buffer,
			 uint32_t size)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);
	int rc;

	rc = ast_sf_start_cmd(ct, cmd);
	if (rc)
		goto bail;
	if (has_addr) {
		rc = ast_sf_send_addr(ct, addr);
		if (rc)
			goto bail;
	}
	if (buffer && size)
		rc = ast_copy_from_ahb(buffer, ct->flash, size);
 bail:
	ast_sf_end_cmd(ct);
	return rc;
}

static int ast_sf_cmd_wr(struct spi_flash_ctrl *ctrl, uint8_t cmd,
			 bool has_addr, uint32_t addr, const void *buffer,
			 uint32_t size)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);
	int rc;

	rc = ast_sf_start_cmd(ct, cmd);
	if (rc)
		goto bail;
	if (has_addr) {
		rc = ast_sf_send_addr(ct, addr);
		if (rc)
			goto bail;
	}
	if (buffer && size)
		rc = ast_copy_to_ahb(ct->flash, buffer, size);
 bail:
	ast_sf_end_cmd(ct);
	return rc;
}

static int ast_sf_set_4b(struct spi_flash_ctrl *ctrl, bool enable)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);

	if (ct->type != AST_SF_TYPE_PNOR)
		return enable ? FLASH_ERR_4B_NOT_SUPPORTED : 0;

	/*
	 * We update the "old" value as well since when quitting
	 * we don't restore the mode of the flash itself so we need
	 * to leave the controller in a compatible setup
	 */
	if (enable) {
		ct->ctl_val |= 0x2000;
		ct->ctl_read_val |= 0x2000;
	} else {
		ct->ctl_val &= ~0x2000;
		ct->ctl_read_val &= ~0x2000;
	}
	ct->mode_4b = enable;

	/* Update read mode */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	return 0;
}

static int ast_sf_read(struct spi_flash_ctrl *ctrl, uint32_t pos,
		       void *buf, uint32_t len)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);

	/*
	 * We are in read mode by default. We don't yet support fancy
	 * things like fast read or X2 mode
	 */
	return ast_copy_from_ahb(buf, ct->flash + pos, len);
}

static int ast_sf_setup(struct spi_flash_ctrl *ctrl, struct flash_info *info,
			uint32_t *tsize)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);	

	(void)tsize;

	/*
	 * Configure better timings and read mode for known
	 * flash chips
	 */
	switch(info->id) {		
	case 0xc22019: /* MX25L25635F */
	case 0xc2201a: /* MX66L51235F */
		/*
		 * Those Macronix chips support dual IO reads at 104Mhz
		 * with 8 dummy cycles so let's use HCLK/2 which is 96Mhz.
		 *
		 * We use DREAD (dual read) for now as it defaults to 8
		 * dummy cycles. Eventually we'd like to use 2READ (which
		 * also has the address using 2 IOs) but that defaults
		 * to 6 dummy cycles and we can only do a multiple of bytes
		 * (Note: I think that accounts for the dual IO so a byte is
		 * probably 4 clocks in that mode, but I need to dlb check).
		 *
		 * We can change the configuration of the flash so we can
		 * do that later, it's a bit more complex.
		 * 
		 * The CE# inactive width for reads must be 7ns, we set it
		 * to 2T which is about 10.4ns.
		 *
		 * For write and program it's 30ns so let's set the value
		 * for normal ops to 6T.
		 *
		 * Preserve the current 4b mode.
		 */
		ct->ctl_read_val = (ct->ctl_read_val & 0x2000) |
			(0x02 << 28) | /* Dual bit data only */
			(0x0e << 24) | /* CE# width 2T (b1110) */
			(0x3b << 16) | /* DREAD command */
			(0x07 <<  8) | /* HCLK/2 */
			(0x01 <<  6) | /* 1-byte dummy cycle */
			(0x01);	       /* fast read */

		/* Configure SPI flash read timing ? */

		/*
		 * For other commands and writes also increase the SPI clock
		 * to HCLK/2 since the chip supports up to 133Mhz and set
		 * CE# inactive to 6T
		 */
		ct->ctl_val = (ct->ctl_val & 0x2000) |
			(0x00 << 28) | /* Single bit */
			(0x0a << 24) | /* CE# width 6T (b1010) */
			(0x00 << 16) | /* no command */
			(0x07 <<  8) | /* HCLK/2 */
			(0x00 <<  6) | /* no dummy cycle */
			(0x00);	       /* normal read */

		/* Update chip with current read config */
		ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
		break;
	case 0xef4018: /* W25Q128BV */
		/*
		 * This Windbond chip support dual IO reads at 104Mhz
		 * with 8 dummy cycles so let's use HCLK/2.
		 *
		 * The CE# inactive width for reads must be 10ns, we set it
		 * to 3T which is about 15.6ns.
		 */
		ct->ctl_read_val =
			(0x02 << 28) | /* Dual bit data only */
			(0x0e << 24) | /* CE# width 2T (b1110) */
			(0x3b << 16) | /* DREAD command */
			(0x07 <<  8) | /* HCLK/2 */
			(0x01 <<  6) | /* 1-byte dummy cycle */
			(0x01);	       /* fast read */

		/* Configure SPI flash read timing ? */

		/*
		 * For other commands and writes also increase the SPI clock
		 * to HCLK/2 since the chip supports up to 133Mhz. CE# inactive
		 * for write and erase is 50ns so let's set it to 10T.
		 */
		ct->ctl_val =
			(0x00 << 28) | /* Single bit */
			(0x06 << 24) | /* CE# width 10T (b0110) */
			(0x00 << 16) | /* no command */
			(0x07 <<  8) | /* HCLK/2 */
			(0x00 <<  6) | /* no dummy cycle */
			(0x01);	       /* fast read */

		/* Update chip with current read config */
		ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
		break;
	}
	return 0;
}

static bool ast_sf_init_pnor(struct ast_sf_ctrl *ct)
{
	uint32_t reg;

	ct->ctl_reg = PNOR_SPI_FCTL_CTRL;
	ct->flash = PNOR_FLASH_BASE;

	/* Enable writing to the controller */
	reg = ast_ahb_readl(PNOR_SPI_FCTL_CONF);
	if (reg == 0xffffffff) {
		FL_ERR("AST_SF: Failed read from controller config\n");
		return false;
	}
	ast_ahb_writel(reg | 1, PNOR_SPI_FCTL_CONF);

	/*
	 * Snapshot control reg and sanitize it for our
	 * use, switching to 1-bit mode, clearing user
	 * mode if set, etc...
	 *
	 * Also configure SPI clock to something safe
	 * like HCLK/8 (24Mhz)
	 */
	ct->ctl_val = ast_ahb_readl(ct->ctl_reg);
	if (ct->ctl_val == 0xffffffff) {
		FL_ERR("AST_SF: Failed read from controller control\n");
		return false;
	}

	ct->ctl_val = (ct->ctl_val & 0x2000) |
		(0x00 << 28) | /* Single bit */
		(0x00 << 24) | /* CE# width 16T */
		(0x00 << 16) | /* no command */
		(0x04 <<  8) | /* HCLK/8 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* normal read */

	/* Initial read mode is default */
	ct->ctl_read_val = ct->ctl_val;

	/* Configure for read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	if (ct->ctl_val & 0x2000)
		ct->mode_4b = true;
	else
		ct->mode_4b = false;

	return true;
}

static bool ast_sf_init_bmc(struct ast_sf_ctrl *ct)
{
	ct->ctl_reg = BMC_SPI_FCTL_CTRL;
	ct->flash = BMC_FLASH_BASE;

	/*
	 * Snapshot control reg and sanitize it for our
	 * use, switching to 1-bit mode, clearing user
	 * mode if set, etc...
	 *
	 * Also configure SPI clock to something safe
	 * like HCLK/8 (24Mhz)
	 */
	ct->ctl_val =
		(0x00 << 28) | /* Single bit */
		(0x00 << 24) | /* CE# width 16T */
		(0x00 << 16) | /* no command */
		(0x04 <<  8) | /* HCLK/8 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* normal read */

	/* Initial read mode is default */
	ct->ctl_read_val = ct->ctl_val;

	/* Configure for read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	ct->mode_4b = false;

	return true;
}

int ast_sf_open(uint8_t type, struct spi_flash_ctrl **ctrl)
{
	struct ast_sf_ctrl *ct;

	if (type != AST_SF_TYPE_PNOR && type != AST_SF_TYPE_BMC)
		return -EINVAL;

	*ctrl = NULL;
	ct = malloc(sizeof(*ct));
	if (!ct) {
		FL_ERR("AST_SF: Failed to allocate\n");
		return -ENOMEM;
	}
	memset(ct, 0, sizeof(*ct));
	ct->type = type;
	ct->ops.cmd_wr = ast_sf_cmd_wr;
	ct->ops.cmd_rd = ast_sf_cmd_rd;
	ct->ops.set_4b = ast_sf_set_4b;
	ct->ops.read = ast_sf_read;
	ct->ops.setup = ast_sf_setup;

	if (type == AST_SF_TYPE_PNOR) {
		if (!ast_sf_init_pnor(ct))
			goto fail;
	} else {
		if (!ast_sf_init_bmc(ct))
			goto fail;
	}

	*ctrl = &ct->ops;

	return 0;
 fail:
	free(ct);
	return -EIO;
}

void ast_sf_close(struct spi_flash_ctrl *ctrl)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);

	/* Restore control reg to read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	/* Additional cleanup */
	if (ct->type == AST_SF_TYPE_PNOR) {
		uint32_t reg = ast_ahb_readl(PNOR_SPI_FCTL_CONF);
		if (reg != 0xffffffff)
			ast_ahb_writel(reg & ~1, PNOR_SPI_FCTL_CONF);
	}

	/* Free the whole lot */
	free(ct);
}

