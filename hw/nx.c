/* Copyright 2013-2015 IBM Corp.
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
#include <io.h>
#include <cpu.h>
#include <nx.h>
#include <chip.h>
#include <xscom-p9-regs.h>
#include <phys-map.h>

static void p9_darn_init(void)
{
	struct dt_node *nx;
	struct proc_chip *chip;
	struct cpu_thread *c;
	uint64_t bar, default_bar;

	if (chip_quirk(QUIRK_NO_RNG))
		return;

	/*
	 * To allow the DARN instruction to function there must be at least
	 * one NX available in the system. Otherwise using DARN will result
	 * in a checkstop. I suppose we could mask the FIR...
	 */
	dt_for_each_compatible(dt_root, nx, "ibm,power9-nx")
		break;
	if (!nx) {
		assert(nx);
		return;
	}

	phys_map_get(dt_get_chip_id(nx), NX_RNG, 0, &default_bar, NULL);

	for_each_chip(chip) {
		/* is this NX enabled? */
		xscom_read(chip->id, P9X_NX_MMIO_BAR, &bar);
		if (!(bar & ~P9X_NX_MMIO_BAR_EN))
			bar = default_bar;

		for_each_available_core_in_chip(c, chip->id) {
			uint64_t addr;
			addr = XSCOM_ADDR_P9_EX(pir_to_core_id(c->pir),
						P9X_EX_NCU_DARN_BAR);
			xscom_write(chip->id, addr,
				    bar | P9X_EX_NCU_DARN_BAR_EN);
		}
	}
}

static void nx_init_one(struct dt_node *node)
{
	nx_create_rng_node(node);
	nx_create_crypto_node(node);
	nx_create_compress_node(node);
}

void nx_init(void)
{
	struct dt_node *node;

	dt_for_each_compatible(dt_root, node, "ibm,power-nx") {
		nx_init_one(node);
	}

	dt_for_each_compatible(dt_root, node, "ibm,power9-nx") {
		nx_init_one(node);
	}

	if (proc_gen == proc_gen_p9)
		p9_darn_init();
}
