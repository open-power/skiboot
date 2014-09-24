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

#include <device.h>
#include <ipmi.h>
#include <opal.h>
#include <skiboot.h>
#include <string.h>

/* This field controls whether the sensor reading byte is written or left
 * unchanged according to the sensor */
#define IPMI_WRITE_SENSOR 0x01

#define FW_PROGRESS_SENSOR     0x0F

/* Ghetto. TODO: Do something smarter */
int16_t sensors[255];

struct set_sensor_req {
        u8 sensor;
        u8 operation;
        u8 reading[8];
};

int ipmi_set_fw_progress_sensor(uint8_t state)
{
       int fw_sensor_id = sensors[FW_PROGRESS_SENSOR];

        if (fw_sensor_id < 0) {
                prlog(PR_DEBUG, "SENSOR: fw progress set but not present\n");
                return OPAL_HARDWARE;
        }

        return ipmi_set_sensor(fw_sensor_id, &state, sizeof(state));
}

int ipmi_set_sensor(uint8_t sensor, uint8_t *reading, size_t len)
{
	struct ipmi_msg *msg;
	struct set_sensor_req request;

	if (!ipmi_present())
		return OPAL_CLOSED;

	if (len > 8) {
		prlog(PR_ERR, "IPMI: sensor setting length %zd invalid\n",
			      len);
		return OPAL_PARAMETER;
	}

	memset(&request, 0, sizeof(request));

	request.sensor = sensor;
	request.operation = IPMI_WRITE_SENSOR;
	memcpy(request.reading, reading, len);

	prlog(PR_INFO, "IPMI: setting sensor %02x to %02x ...\n",
			request.sensor, request.reading[0]);

	/* Send the minimial length message: header plus the reading bytes */
	msg = ipmi_mkmsg_simple(IPMI_SET_SENSOR_READING, &request, len + 2);
	if (!msg)
		return OPAL_HARDWARE;

	return ipmi_queue_msg(msg);
}

void ipmi_sensor_init(void)
{
	struct dt_node *n;
	const struct dt_property *type, *num;

	memset(sensors, -1, sizeof(sensors));

	dt_for_each_compatible(dt_root, n, "ibm,ipmi-sensor") {
		type = dt_find_property(n, "ipmi-sensor-type");
		if (!type) {
			prerror("IPMI: sensor doesn't have ipmi-sensor-type\n");
			continue;
		}

		num = dt_find_property(n, "reg");
		if (!num) {
			prerror("IPMI: sensor doesn't have reg property\n");
			continue;
		}
		sensors[(uint8_t)num->prop[0]] = type->prop[0];
	}
}
