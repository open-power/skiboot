/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <skiboot.h>
#include <i2c.h>
#include <opal.h>
#include <device.h>
#include <opal-msg.h>

static LIST_HEAD(i2c_bus_list);

/* Used to assign OPAL IDs */
static uint32_t i2c_next_bus;

void i2c_add_bus(struct i2c_bus *bus)
{
	bus->opal_id = ++i2c_next_bus;
	dt_add_property_cells(bus->dt_node, "ibm,opal-id", bus->opal_id);

	list_add_tail(&i2c_bus_list, &bus->link);
}

struct i2c_bus *i2c_find_bus_by_id(uint32_t opal_id)
{
	struct i2c_bus *bus;

	list_for_each(&i2c_bus_list, bus, link) {
		if (bus->opal_id == opal_id)
			return bus;
	}
	return NULL;
}

