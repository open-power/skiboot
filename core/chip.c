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
#include <chip.h>
#include <device.h>

static struct proc_chip *chips[MAX_CHIPS];

uint32_t pir_to_chip_id(uint32_t pir)
{
	if (proc_gen == proc_gen_p8)
		return P8_PIR2GCID(pir);
	else
		return P7_PIR2GCID(pir);
}

uint32_t pir_to_core_id(uint32_t pir)
{
	if (proc_gen == proc_gen_p8)
		return P8_PIR2COREID(pir);
	else
		return P7_PIR2COREID(pir);
}

uint32_t pir_to_thread_id(uint32_t pir)
{
	if (proc_gen == proc_gen_p8)
		return P8_PIR2THREADID(pir);
	else
		return P7_PIR2THREADID(pir);
}

struct proc_chip *next_chip(struct proc_chip *chip)
{
	unsigned int i;

	for (i = chip ? (chip->id + 1) : 0; i < MAX_CHIPS; i++)
		if (chips[i])
			return chips[i];
	return NULL;
}


struct proc_chip *get_chip(uint32_t chip_id)
{
	return chips[chip_id];
}

void init_chips(void)
{
	struct proc_chip *chip;
	struct dt_node *xn;

	/* We walk the chips based on xscom nodes in the tree */
	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		uint32_t id = dt_get_chip_id(xn);

		assert(id < MAX_CHIPS);

		chip = zalloc(sizeof(struct proc_chip));
		assert(chip);
		chip->id = id;
		chip->devnode = xn;
		chips[id] = chip;
		chip->dbob_id = dt_prop_get_u32_def(xn, "ibm,dbob-id",
						    0xffffffff);
		chip->pcid = dt_prop_get_u32_def(xn, "ibm,proc-chip-id",
						 0xffffffff);
	};
}
