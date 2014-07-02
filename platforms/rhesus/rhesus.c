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
#include <device.h>
#include <lpc.h>
#include <console.h>
#include <opal.h>
#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <sfc-ctrl.h>
#include <ec/config.h>
#include <ec/gpio.h>

/*
 * EC GPIO mapping
 */
#define RHESUS_RST_UCD90160_N	EC_GPIO_PORT_J, 3
#define RHESUS_FM_PWR_CYCLE_N	EC_GPIO_PORT_K, 2
#define RHESUS_EN_PWR_ON_SEQ	EC_GPIO_PORT_R, 1
#define RHESUS_BOARD_REVISION0	EC_GPIO_PORT_F, 3
#define RHESUS_BOARD_REVISION1	EC_GPIO_PORT_F, 2
#define RHESUS_BOARD_REVISION2	EC_GPIO_PORT_E, 5
#define RHESUS_BOARD_REVISION3	EC_GPIO_PORT_E, 4
#define RHESUS_BOARD_REVISION4	EC_GPIO_PORT_E, 1

static struct spi_flash_ctrl *pnor_ctrl;
static struct flash_chip *pnor_chip;
static struct ffs_handle *pnor_ffs;


/*
 * IO accessors for the EC driver
 */
void ec_outb(uint16_t addr, uint8_t data)
{
	lpc_outb(data, addr);
}

uint8_t ec_inb(uint16_t addr)
{
	return lpc_inb(addr);
}

static int rhesus_board_revision(void)
{
    int revision = 0, ret = 0, i = 0;

    static const struct {
        EcGpioPort port;
        uint8_t pin;
    } revision_gpios[] = {
        { RHESUS_BOARD_REVISION0 },
        { RHESUS_BOARD_REVISION1 },
        { RHESUS_BOARD_REVISION2 },
        { RHESUS_BOARD_REVISION3 },
        { RHESUS_BOARD_REVISION4 },
    };
    for (i = 0; i < sizeof(revision_gpios) / sizeof(revision_gpios[0]); ++i)
    {
        ret = ec_gpio_read(revision_gpios[i].port, revision_gpios[i].pin);
        if (ret < 0)
            return ret;
        revision <<= 1; revision |= ret;
    }

    return revision;
}

static int64_t rhesus_reboot(void)
{
    // TODO(rlippert): This should use EC_SYS_RST_N, but there is nothing to
    // deassert that at the moment.
    int ret = 0;
    ret = ec_gpio_set(RHESUS_FM_PWR_CYCLE_N, 0);
    if (ret < 0) {
        return ret;
    }

    ret = ec_gpio_setup(RHESUS_FM_PWR_CYCLE_N,
                        EC_GPIO_OUTPUT,
                        EC_GPIO_PULLUP_DISABLE);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int64_t rhesus_power_down(uint64_t request __unused)
{
    int ret = 0;
    ret = ec_gpio_set(RHESUS_EN_PWR_ON_SEQ, 0);
    if (ret < 0) {
        return ret;
    }

    ret = ec_gpio_setup(RHESUS_EN_PWR_ON_SEQ,
                        EC_GPIO_OUTPUT,
                        EC_GPIO_PULLUP_DISABLE);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int rhesus_pnor_init(void)
{
	uint32_t nv_part, nv_start, nv_size;
	int rc;

	/* Open controller, flash and ffs */
	rc = sfc_open(&pnor_ctrl);
	if (rc) {
		prerror("PLAT: Failed to open PNOR flash controller\n");
		goto fail;
	}
	rc = flash_init(pnor_ctrl, &pnor_chip);
	if (rc) {
		prerror("PLAT: Failed to open init PNOR driver\n");
		goto fail;
	}
	rc = ffs_open_flash(pnor_chip, 0, 0, &pnor_ffs);
	if (rc) {
		prerror("PLAT: Failed to parse FFS partition map\n");
		goto fail;
	}

	/*
	 * Grab NVRAM and initialize the flash_nvram module
	 *
	 * Note: Ignore actual size for now ... some images have
	 * it setup incorrectly.
	 */
	rc = ffs_lookup_part(pnor_ffs, "NVRAM", &nv_part);
	if (rc) {
		prerror("PLAT: No NVRAM partition in PNOR\n");
		return OPAL_HARDWARE;
	}
	rc = ffs_part_info(pnor_ffs, nv_part, NULL,
			   &nv_start, &nv_size, NULL);
	if (rc) {
		prerror("PLAT: Failed to get NVRAM partition info\n");
		return OPAL_HARDWARE;
	}
	flash_nvram_init(pnor_chip, nv_start, nv_size);

	return 0;
 fail:
	if (pnor_ffs)
		ffs_close(pnor_ffs);
	pnor_ffs = NULL;
	if (pnor_chip)
		flash_exit(pnor_chip);
	pnor_chip = NULL;
	if (pnor_ctrl)
		sfc_close(pnor_ctrl);
	pnor_ctrl = NULL;

	return rc;
}

static void rhesus_init(void)
{
	if (dummy_console_enabled())
		dummy_console_add_nodes();

	/* Initialize PNOR/NVRAM */
	rhesus_pnor_init();
}

static void rhesus_dt_fixup_uart(struct dt_node *lpc)
{
	/*
	 * The official OF ISA/LPC binding is a bit odd, it prefixes
	 * the unit address for IO with "i". It uses 2 cells, the first
	 * one indicating IO vs. Memory space (along with bits to
	 * represent aliasing).
	 *
	 * We pickup that binding and add to it "2" as a indication
	 * of FW space.
	 *
	 * TODO: Probe the UART instead if the LPC bus allows for it
	 */
	struct dt_node *uart;
	char namebuf[32];
#define UART_IO_BASE	0x3f8
#define UART_IO_COUNT	8

	sprintf(namebuf, "serial@i%x", UART_IO_BASE);
	uart = dt_new(lpc, namebuf);

	dt_add_property_cells(uart, "reg",
			      1, /* IO space */
			      UART_IO_BASE, UART_IO_COUNT);
	dt_add_property_strings(uart, "compatible",
				"ns16550",
				"pnpPNP,501");
	dt_add_property_cells(uart, "clock-frequency", 1843200);
	dt_add_property_cells(uart, "current-speed", 115200);

	/*
	 * This is needed by Linux for some obscure reasons,
	 * we'll eventually need to sanitize it but in the meantime
	 * let's make sure it's there
	 */
	dt_add_property_strings(uart, "device_type", "serial");

	/*
	 * Add interrupt. This simulates coming from HostBoot which
	 * does not know our interrupt numbering scheme. Instead, it
	 * just tells us which chip the interrupt is wired to, it will
	 * be the PSI "host error" interrupt of that chip. For now we
	 * assume the same chip as the LPC bus is on.
	 */
	dt_add_property_cells(uart, "ibm,irq-chip-id", dt_get_chip_id(lpc));
}

/*
 * This adds the legacy RTC device to the device-tree
 * for Linux to use
 */
static void rhesus_dt_fixup_rtc(struct dt_node *lpc)
{
	struct dt_node *rtc;

	/*
	 * Follows the structure expected by the kernel file
	 * arch/powerpc/sysdev/rtc_cmos_setup.c
	 */
	rtc = dt_new_addr(lpc, "rtc", EC_RTC_PORT_BASE);
	dt_add_property_string(rtc, "compatible", "pnpPNP,b00");
	dt_add_property_cells(rtc, "reg",
			      1, /* IO space */
			      EC_RTC_PORT_BASE,
			      /* 1 index/data pair per 128 bytes */
			      (EC_RTC_BLOCK_SIZE / 128) * 2);
}

static void rhesus_dt_fixup(void)
{
	struct dt_node *n, *primary_lpc = NULL;

	/* Find the primary LPC bus */
	dt_for_each_compatible(dt_root, n, "ibm,power8-lpc") {
		if (!primary_lpc || dt_has_node_property(n, "primary", NULL))
			primary_lpc = n;
		if (dt_has_node_property(n, "#address-cells", NULL))
			break;
	}

	if (!primary_lpc)
		return;

	rhesus_dt_fixup_rtc(primary_lpc);
	rhesus_dt_fixup_uart(primary_lpc);
}

static bool rhesus_probe(void)
{
	const char *model;
	int rev;

	if (!dt_node_is_compatible(dt_root, "ibm,powernv"))
		return false;

	model = dt_prop_get_def(dt_root, "model", NULL);
	if (!model || !(strstr(model, "rhesus") || strstr(model, "RHESUS")))
		return false;

	/* Grab board version from EC */
	rev = rhesus_board_revision();
	if (rev >= 0) {
		printf("Rhesus board rev %d\n", rev);
		dt_add_property_cells(dt_root, "revision-id", rev);
	} else
		prerror("Rhesus board revision not found !\n");

	/* Add missing bits of device-tree such as the UART */
	rhesus_dt_fixup();

	/*
	 * Setup UART and use it as console. For now, we
	 * don't expose the interrupt as we know it's not
	 * working properly yet
	 */
	uart_init(false);

	return true;
}

DECLARE_PLATFORM(rhesus) = {
	.name		= "Rhesus",
	.probe		= rhesus_probe,
	.init		= rhesus_init,
	.cec_power_down	= rhesus_power_down,
	.cec_reboot	= rhesus_reboot,
};
