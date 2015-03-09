/* Copyright 2013-2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <xscom.h>
#include <chip.h>
#include <sensor.h>
#include <dts.h>
#include <skiboot.h>
#include <opal-api.h>

/* Per core Digital Thermal Sensors */
#define EX_THERM_DTS_RESULT0	0x10050000
#define EX_THERM_DTS_RESULT1	0x10050001

/* Per core Digital Thermal Sensors control registers */
#define EX_THERM_MODE_REG	0x1005000F
#define EX_THERM_CONTROL_REG	0x10050012
#define EX_THERM_ERR_STATUS_REG	0x10050013

struct dts {
	uint8_t		valid;
	uint8_t		trip;
	int16_t		temp;
};


/* Therm mac result masking for DTS (result(0:15)
 *  0:3   - 0x0
 *  4:11  - Temperature in degrees C
 *  12:13 - trip bits: 00 - no trip; 01 - warning; 10 - critical; 11 - fatal
 *  14    - spare
 *  15    - valid
 */
static void dts_decode_one_dts(uint16_t raw, struct dts *dts)
{
	/*
	 * The value is both signed and unsigned :-) 0xff could be
	 * either 255C or -1C, so for now we treat this as unsigned
	 * which is sufficient for our purpose. We could try to be
	 * a bit smarter and treat it as signed for values between
	 * -10 and 0 and unsigned to 239 or something like that...
	 */
	dts->valid = raw & 1;
	if (dts->valid) {
		dts->temp = (raw >> 4) & 0xff;
		dts->trip = (raw >> 2) & 0x3;
	} else {
		dts->temp = 0;
		dts->trip = 0;
	}
}

/* Different sensor locations */
#define P8_CT_ZONE_LSU	0
#define P8_CT_ZONE_ISU	1
#define P8_CT_ZONE_FXU	2
#define P8_CT_ZONE_L3C	3
#define P8_CT_ZONES	4

/*
 * Returns the temperature as the max of all 4 zones and a global trip
 * attribute.
 */
static int dts_read_core_temp(uint32_t pir, struct dts *dts)
{
	int32_t chip_id = pir_to_chip_id(pir);
	int32_t core = pir_to_core_id(pir);
	uint64_t dts0, dts1;
	struct dts temps[P8_CT_ZONES];
	int i;
	int rc;

	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, EX_THERM_DTS_RESULT0),
			&dts0);
	if (rc)
		return rc;

	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, EX_THERM_DTS_RESULT1),
			&dts1);
	if (rc)
		return rc;

	dts_decode_one_dts(dts0 >> 48, &temps[P8_CT_ZONE_LSU]);
	dts_decode_one_dts(dts0 >> 32, &temps[P8_CT_ZONE_ISU]);
	dts_decode_one_dts(dts0 >> 16, &temps[P8_CT_ZONE_FXU]);
	dts_decode_one_dts(dts1 >> 48, &temps[P8_CT_ZONE_L3C]);

	for (i = 0; i < P8_CT_ZONES; i++) {
		int16_t t = temps[i].temp;

		if (!temps[i].valid)
			continue;

		/* keep the max temperature of all 4 sensors */
		if (t > dts->temp)
			dts->temp = t;

		dts->valid++;
		dts->trip |= temps[i].trip;
	}

	prlog(PR_TRACE, "DTS: Chip %x Core %x temp:%dC trip:%x\n",
	      chip_id, core, dts->temp, dts->trip);

	/*
	 * FIXME: The trip bits are always set ?! Just discard
	 * them for the moment until we understand why.
	 */
	dts->trip = 0;
	return 0;
}

/*
 * DTS sensor class ids. Only one for the moment: the core
 * temperature.
 */
enum sensor_dts_class {
	SENSOR_DTS_CORE_TEMP,
	/* To be continued */
};

/*
 * Attributes for the core temperature sensor
 */
enum {
	SENSOR_DTS_ATTR_TEMP_MAX,
	SENSOR_DTS_ATTR_TEMP_TRIP
};

int64_t dts_sensor_read(uint32_t sensor_hndl, uint32_t *sensor_data)
{
	uint8_t	attr = sensor_get_attr(sensor_hndl);
	uint32_t rid = sensor_get_rid(sensor_hndl);
	struct dts dts;
	int64_t rc;

	if (attr > SENSOR_DTS_ATTR_TEMP_TRIP)
		return OPAL_PARAMETER;

	memset(&dts, 0, sizeof(struct dts));

	switch (sensor_get_frc(sensor_hndl) & ~SENSOR_DTS) {
	case SENSOR_DTS_CORE_TEMP:
		rc = dts_read_core_temp(rid, &dts);
		break;
	default:
		rc = OPAL_PARAMETER;
		break;
	}
	if (rc)
		return rc;

	if (attr == SENSOR_DTS_ATTR_TEMP_MAX)
		*sensor_data = dts.temp;
	else if (attr == SENSOR_DTS_ATTR_TEMP_TRIP)
		*sensor_data = dts.trip;

	return 0;
}

bool dts_sensor_create_nodes(struct dt_node *sensors)
{
	uint8_t sensor_class = SENSOR_DTS_CORE_TEMP|SENSOR_DTS;

	struct proc_chip *chip;
	char name[64];

	/* build the device tree nodes :
	 *
	 *     sensors/core-temp@pir
	 *
	 * The core is identified by its PIR, is stored in the resource
	 * number of the sensor handler.
	 */
	for_each_chip(chip) {
		struct cpu_thread *c;

		for_each_available_core_in_chip(c, chip->id) {
			struct dt_node *node;
			uint32_t handler;

			snprintf(name, sizeof(name), "core-temp@%x", c->pir);

			handler = sensor_make_handler(sensor_class,
					c->pir, SENSOR_DTS_ATTR_TEMP_MAX);
			node = dt_new(sensors, name);
			dt_add_property_string(node, "compatible",
					       "ibm,opal-sensor");
			dt_add_property_cells(node, "sensor-data", handler);
			handler = sensor_make_handler(sensor_class,
					c->pir, SENSOR_DTS_ATTR_TEMP_TRIP);
			dt_add_property_cells(node, "sensor-status", handler);
			dt_add_property_string(node, "sensor-type", "temp");
			dt_add_property_cells(node, "ibm,pir", c->pir);
			dt_add_property_string(node, "label", "Core");
		}
	}

	return true;
}
