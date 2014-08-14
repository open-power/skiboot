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
#include <console.h>
#include <psi.h>
#include <chip.h>
#include <xscom.h>
#include <ast.h>
#include <ipmi.h>

#include "bmc.h"

/* UART1 config */
#define UART_IO_BASE	0x3f8
#define UART_IO_COUNT	8
#define UART_LPC_IRQ	4

/* BT config */
#define BT_IO_BASE	0xe4
#define BT_IO_COUNT	3
#define BT_LPC_IRQ	10

static void palmetto_ext_irq(unsigned int chip_id __unused)
{
	uart_irq();
}

static void palmetto_init(void)
{
	/* Setup dummy console nodes */
	if (dummy_console_enabled())
		dummy_console_add_nodes();

	/* Initialize AHB accesses via AST2400 */
	ast_io_init();

	/* Initialize PNOR/NVRAM */
	pnor_init();
}

static void palmetto_fixup_dt_bt(struct dt_node *lpc)
{
	struct dt_node *bt;
	char namebuf[32];

	/* First check if the BT interface is already there */
	dt_for_each_child(lpc, bt) {
		if (dt_node_is_compatible(bt, "bt"))
			return;
	}

	sprintf(namebuf, "ipmi-bt@i%x", BT_IO_BASE);
	bt = dt_new(lpc, namebuf);

	dt_add_property_cells(bt, "reg",
			      1, /* IO space */
			      BT_IO_BASE, BT_IO_COUNT);
	dt_add_property_strings(bt, "compatible", "ipmi-bt");

	/* Mark it as reserved to avoid Linux trying to claim it */
	dt_add_property_strings(bt, "status", "reserved");
}

static void palmetto_fixup_dt_uart(struct dt_node *lpc)
{
	/*
	 * The official OF ISA/LPC binding is a bit odd, it prefixes
	 * the unit address for IO with "i". It uses 2 cells, the first
	 * one indicating IO vs. Memory space (along with bits to
	 * represent aliasing).
	 *
	 * We pickup that binding and add to it "2" as a indication
	 * of FW space.
	 */
	struct dt_node *uart;
	char namebuf[32];

	/* First check if the UART is already there */
	dt_for_each_child(lpc, uart) {
		if (dt_node_is_compatible(uart, "ns16550"))
			return;
	}

	/* Otherwise, add a node for it */
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

static void palmetto_fixup_dt(void)
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

	/* Fixup the UART, that might be missing from HB */
	palmetto_fixup_dt_uart(primary_lpc);

	palmetto_fixup_dt_bt(primary_lpc);

	/* Force the dummy console for now */
	force_dummy_console();
}

static void palmetto_fixup_psi_bar(void)
{
	struct proc_chip *chip = next_chip(NULL);
	uint64_t psibar;

	/* Read PSI BAR */
	if (xscom_read(chip->id, 0x201090A, &psibar)) {
		prerror("PLAT: Error reading PSI BAR\n");
		return;
	}
	/* Already configured, bail out */
	if (psibar & 1)
		return;

	/* Hard wire ... yuck */
	psibar = 0x3fffe80000001;

	printf("PLAT: Fixing up PSI BAR on chip %d BAR=%llx\n",
	       chip->id, psibar);

	/* Now write it */
	xscom_write(chip->id, 0x201090A, psibar);
}

static bool palmetto_probe(void)
{
	const char *model;

	if (!dt_node_is_compatible(dt_root, "ibm,powernv"))
		return false;

	/* Temporary ... eventually we'll get that in compatible */
	model = dt_prop_get_def(dt_root, "model", NULL);
	if ((!model || !strstr(model, "palmetto")) &&
	    (!dt_node_is_compatible(dt_root, "ibm,palmetto")))
		return false;

	/* Hostboot's device-tree isn't quite right yet */
	palmetto_fixup_dt();

	/* Hostboot forgets to populate the PSI BAR */
	palmetto_fixup_psi_bar();

	/* Send external interrupts to me */
	psi_set_external_irq_policy(EXTERNAL_IRQ_POLICY_SKIBOOT);

	/* Configure UART1 on SuperIO */
	ast_setup_uart1(UART_IO_BASE, UART_LPC_IRQ);

	/* Setup UART and use it as console with interrupts */
	uart_init(true);

	/* Setup IPMI */
	ipmi_init();

	return true;
}

static int64_t palmetto_ipmi_power_down(uint64_t request __unused)
{
	/* Request is:
	 *  0 = normal
	 *  1 = immediate
	 * When doing "shutdown -h now" from linux, we get a 0.
	 * However, I believe at that point we are ready to shut down,
	 * so unconditionally tell the BMC to immediately power us down.
	 */
	return ipmi_opal_chassis_control(IPMI_CHASSIS_PWR_DOWN);
}

static int64_t palmetto_ipmi_reboot(void)
{
	return ipmi_opal_chassis_control(IPMI_CHASSIS_PWR_CYCLE);
}

DECLARE_PLATFORM(palmetto) = {
	.name			= "Palmetto",
	.probe			= palmetto_probe,
	.init			= palmetto_init,
	.external_irq		= palmetto_ext_irq,
	.cec_power_down         = palmetto_ipmi_power_down,
	.cec_reboot             = palmetto_ipmi_reboot,
};

