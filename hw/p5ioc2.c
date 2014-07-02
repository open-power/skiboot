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
#include <p5ioc2.h>
#include <p5ioc2-regs.h>
#include <cec.h>
#include <gx.h>
#include <opal.h>
#include <interrupts.h>
#include <device.h>
#include <timebase.h>
#include <vpd.h>
#include <ccan/str/str.h>


static int64_t p5ioc2_set_tce_mem(struct io_hub *hub, uint64_t address,
				  uint64_t size)
{
	struct p5ioc2 *ioc = iohub_to_p5ioc2(hub);
	int64_t rc;

	printf("P5IOC2: set_tce_mem(0x%016llx size 0x%llx)\n",
	       address, size);

	/* The address passed must be naturally aligned */
	if (address && !is_pow2(size))
		return OPAL_PARAMETER;
	if (address & (size - 1))
		return OPAL_PARAMETER;

	ioc->tce_base = address;
	ioc->tce_size = size;

	rc = gx_configure_tce_bar(ioc->host_chip, ioc->gx_bus,
				  address, size);
	if (rc)
		return OPAL_INTERNAL_ERROR;
	return OPAL_SUCCESS;
}

static int64_t p5ioc2_get_diag_data(struct io_hub *hub __unused,
				   void *diag_buffer __unused,
				   uint64_t diag_buffer_len __unused)
{
	/* XXX Not yet implemented */
	return OPAL_UNSUPPORTED;
}

static const struct io_hub_ops p5ioc2_hub_ops = {
	.set_tce_mem	= p5ioc2_set_tce_mem,
	.get_diag_data	= p5ioc2_get_diag_data,
};

static void p5ioc2_inits(struct p5ioc2 *ioc)
{
	uint64_t val;
	unsigned int p, n;

	printf("P5IOC2: Initializing hub...\n");

	/*
	 * BML base inits
	 */
	/* mask off interrupt presentation timeout in FIRMC */
	out_be64(ioc->regs + (P5IOC2_FIRMC | P5IOC2_REG_OR),
		 0x0000080000000000);

	/* turn off display alter mode */
	out_be64(ioc->regs + (P5IOC2_CTL | P5IOC2_REG_AND),
		 0xffffff7fffffffff);

	/* setup hub and clustering interrupts BUIDs to 1 and 2 */
	out_be64(ioc->regs + P5IOC2_SBUID, 0x0001000200000000);

	/* setup old style MSI BUID (should be unused but set it up anyway) */
	out_be32(ioc->regs + P5IOC2_BUCO, 0xf);

	/* Set XIXO bit 0 needed for "enhanced" TCEs or else TCE
	 * fetches appear as normal memory reads on GX causing
	 * P7 to checkstop when a TCE DKill collides with them.
	 */
	out_be64(ioc->regs + P5IOC2_XIXO, in_be64(ioc->regs + P5IOC2_XIXO)
		 | P5IOC2_XIXO_ENH_TCE);

	/* Clear routing tables */
	for (n = 0; n < 16; n++) {
		for (p = 0; p < 8; p++)
			out_be64(ioc->regs + P5IOC2_TxRTE(p,n), 0);
	}
	for (n = 0; n < 32; n++)
		out_be64(ioc->regs + P5IOC2_BUIDRTE(n), 0);

	/*
	 * Setup routing. We use the same setup that pHyp appears
	 * to do (after inspecting the various registers with SCOM)
	 *
	 * We assume the BARs are already setup by the FSP such
	 * that BAR0 is 128G (8G region size) and BAR6 is
	 * 256M (16M region size).
	 *
	 * The routing is based on what pHyp and BML do, each Calgary
	 * get one slice of BAR6 and two slices of BAR0
	 */
	/* BAR 0 segments 0 & 1 -> CA0 */
	out_be64(ioc->regs + P5IOC2_TxRTE(0,0),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA0_RIO_ID);
	out_be64(ioc->regs + P5IOC2_TxRTE(0,1),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA0_RIO_ID);

	/* BAR 0 segments 2 & 3 -> CA1 */
	out_be64(ioc->regs + P5IOC2_TxRTE(0,2),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA1_RIO_ID);
	out_be64(ioc->regs + P5IOC2_TxRTE(0,3),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA1_RIO_ID);

	/* BAR 6 segments 0 -> CA0 */
	out_be64(ioc->regs + P5IOC2_TxRTE(6,0),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA0_RIO_ID);

	/* BAR 6 segments 1 -> CA0 */
	out_be64(ioc->regs + P5IOC2_TxRTE(6,1),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA1_RIO_ID);

	/*
	 * BUID routing, we send entries 1 to CA0 and 2 to CA1
	 * just like pHyp and make sure the base and mask are
	 * both clear in SID to we route the whole 512 block
	 */
	val = in_be64(ioc->regs + P5IOC2_SID);
	val = SETFIELD(P5IOC2_SID_BUID_BASE, val, 0);
	val = SETFIELD(P5IOC2_SID_BUID_MASK, val, 0);
	out_be64(ioc->regs + P5IOC2_SID, val);
	out_be64(ioc->regs + P5IOC2_BUIDRTE(1),
		 P5IOC2_BUIDRTE_VALID | P5IOC2_BUIDRTE_RR_RET |
		 P5IOC2_CA0_RIO_ID);
	out_be64(ioc->regs + P5IOC2_BUIDRTE(2),
		 P5IOC2_BUIDRTE_VALID | P5IOC2_BUIDRTE_RR_RET |
		 P5IOC2_CA1_RIO_ID);
}

static void p5ioc2_ca_init(struct p5ioc2 *ioc, int ca)
{
	void *regs = ca ? ioc->ca1_regs : ioc->ca0_regs;
	uint64_t val;

	printf("P5IOC2: Initializing Calgary %d...\n", ca);

	/* Setup device BUID */
	val = SETFIELD(CA_DEVBUID, 0ul, ca ? P5IOC2_CA1_BUID : P5IOC2_CA0_BUID);
	out_be32(regs + CA_DEVBUID, val);

	/* Setup HubID in TARm (and keep TCE clear, Linux will init that)
	 *
	 * BML and pHyp sets the values to 1 for CA0 and 4 for CA1. We
	 * keep the TAR valid bit clear as well.
	 */
	val = SETFIELD(CA_TAR_HUBID, 0ul, ca ? 4 : 1);
	val = SETFIELD(CA_TAR_ALTHUBID, val, ca ? 4 : 1);
	out_be64(regs + CA_TAR0, val);
	out_be64(regs + CA_TAR1, val);
	out_be64(regs + CA_TAR2, val);
	out_be64(regs + CA_TAR3, val);
	
	/* Bridge config register. We set it up to the same value as observed
	 * under pHyp on a Juno machine. The difference from the IPL value is
	 * that TCE buffers are enabled, discard timers are increased and
	 * we disable response status to avoid errors.
	 */
	//out_be64(regs + CA_CCR, 0x5045DDDED2000000);
	// disable memlimit:
	out_be64(regs + CA_CCR, 0x5005DDDED2000000);

	/* The system memory base/limit etc... setup will be done when the
	 * user enables TCE via OPAL calls
	 */
}

static void p5ioc2_create_hub(struct dt_node *np)
{
	struct p5ioc2 *ioc;
	unsigned int i, id, irq;
	char *path;

	/* Use the BUID extension as ID and add it to device-tree */
	id = dt_prop_get_u32(np, "ibm,buid-ext");
	path = dt_get_path(np);	
	printf("P5IOC2: Found at %s ID 0x%x\n", path, id);
	free(path);
	dt_add_property_cells(np, "ibm,opal-hubid", 0, id);

	/* Load VPD LID */
	vpd_iohub_load(np);

	ioc = zalloc(sizeof(struct p5ioc2));
	if (!ioc)
		return;
	ioc->hub.hub_id = id;
	ioc->hub.ops = &p5ioc2_hub_ops;
	ioc->dt_node = np;

	/* We assume SBAR == GX0 + some hard coded offset */
	ioc->regs = (void *)dt_get_address(np, 0, NULL);

	/* For debugging... */
	for (i = 0; i < 8; i++)
		printf("P5IOC2: BAR%d = 0x%016llx M=0x%16llx\n", i,
		       in_be64(ioc->regs + P5IOC2_BAR(i)),
		       in_be64(ioc->regs + P5IOC2_BARM(i)));

	ioc->host_chip = dt_get_chip_id(np);

	ioc->gx_bus = dt_prop_get_u32(np, "ibm,gx-index");

	/* Rather than reading the BARs in P5IOC2, we "know" that
	 * BAR6 matches GX BAR 1 and BAR0 matches GX BAR 2. This
	 * is a bit fishy but will work for the few machines this
	 * is intended to work on
	 */
	ioc->bar6 = dt_prop_get_u64(np, "ibm,gx-bar-1");
	ioc->bar0 = dt_prop_get_u64(np, "ibm,gx-bar-2");

	printf("DT BAR6 = 0x%016llx\n", ioc->bar6);
	printf("DT BAR0 = 0x%016llx\n", ioc->bar0);

	/* We setup the corresponding Calgary register bases and memory
	 * regions. Note: those cannot be used until the routing has
	 * been setup by inits
	 */
	ioc->ca0_regs = (void *)ioc->bar6 + P5IOC2_CA0_REG_OFFSET;
	ioc->ca1_regs = (void *)ioc->bar6 + P5IOC2_CA1_REG_OFFSET;
	ioc->ca0_mm_region = ioc->bar0 + P5IOC2_CA0_MM_OFFSET;
	ioc->ca1_mm_region = ioc->bar0 + P5IOC2_CA1_MM_OFFSET;

	/* Base of our BUIDs, will be refined later */
	ioc->buid_base = id << 9;

	/* Add interrupts: XXX These are the hub interrupts, we should add the
	 * calgary ones as well... but we don't handle any of them currently
	 * anyway.
	 */
	irq = (ioc->buid_base + 1) << 4;
	dt_add_property_cells(np, "interrupts", irq, irq + 1);
	dt_add_property_cells(np, "interrupt-base", irq);


	/* Now, we do the bulk of the inits */
	p5ioc2_inits(ioc);
	p5ioc2_ca_init(ioc, 0);
	p5ioc2_ca_init(ioc, 1);

	/* So how do we know what PHBs to create ? Let's try all of them
	 * and we'll see if that causes problems. TODO: Use VPD !
	 */
	for (i = 0; i < 4; i++)
		p5ioc2_phb_setup(ioc, &ioc->ca0_phbs[i], 0, i, true,
				 ioc->buid_base + P5IOC2_CA0_BUID + i + 1);
	for (i = 0; i < 4; i++)
		p5ioc2_phb_setup(ioc, &ioc->ca1_phbs[i], 1, i, true,
				 ioc->buid_base + P5IOC2_CA1_BUID + i + 1);

	/* Reset delay... synchronous, hope we never do that as a
	 * result of an OPAL callback. We shouldn't really need this
	 * here and may fold it in the generic slot init sequence but
	 * it's not like we care much about that p5ioc2 code...
	 *
	 * This is mostly to give devices a chance to settle after
	 * having lifted the reset pin on PCI-X.
	 */
	time_wait_ms(1000);

	printf("P5IOC2: Initialization complete\n");

	cec_register(&ioc->hub);
}

void probe_p5ioc2(void)
{
	struct dt_node *np;

	dt_for_each_compatible(dt_root, np, "ibm,p5ioc2")
		p5ioc2_create_hub(np);
}

