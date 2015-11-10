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
/*
 */


/*
 * Design note:
 * This code will enable the 'powernv' to retrieve sensor related data from FSP
 * using SPCN passthru mailbox commands.
 *
 * The OPAL read sensor API in Sapphire is implemented as an 'asynchronous' read
 * call that returns after queuing the read request. A unique sensor-id is
 * expected as an argument for OPAL read call which has already been exported
 * to the device tree during fsp init. The sapphire code decodes this Id to
 * determine requested attribute and sensor.
 */

#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <device.h>
#include <spcn.h>
#include <opal-api.h>
#include <opal-msg.h>
#include <errorlog.h>
#include <sensor.h>

#define INVALID_DATA	((uint32_t)-1)

/* Entry size of PRS command modifiers */
#define PRS_STATUS_ENTRY_SZ	0x08
#define SENSOR_PARAM_ENTRY_SZ	0x10
#define SENSOR_DATA_ENTRY_SZ	0x08
#define PROC_JUNC_ENTRY_SZ	0x04

DEFINE_LOG_ENTRY(OPAL_RC_SENSOR_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_SENSOR,
			OPAL_MISC_SUBSYSTEM,
			OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT,
			OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SENSOR_READ, OPAL_PLATFORM_ERR_EVT, OPAL_SENSOR,
			OPAL_MISC_SUBSYSTEM, OPAL_INFO,
			OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SENSOR_ASYNC_COMPLETE, OPAL_PLATFORM_ERR_EVT,
			OPAL_SENSOR, OPAL_MISC_SUBSYSTEM, OPAL_INFO,
			OPAL_NA);

/* FSP response status codes */
enum {
	SP_RSP_STATUS_VALID_DATA = 0x00,
	SP_RSP_STATUS_INVALID_DATA = 0x22,
	SP_RSP_STATUS_SPCN_ERR = 0xA8,
	SP_RSP_STATUS_DMA_ERR = 0x24,
};

enum sensor_state {
	SENSOR_VALID_DATA,
	SENSOR_INVALID_DATA,
	SENSOR_SPCN_ERROR,
	SENSOR_DMA_ERROR,
	SENSOR_PERMANENT_ERROR,
	SENSOR_OPAL_ERROR,
};

enum spcn_attr {
	/* mod 0x01, 0x02 */
	SENSOR_PRESENT,
	SENSOR_FAULTED,
	SENSOR_AC_FAULTED,
	SENSOR_ON,
	SENSOR_ON_SUPPORTED,
	/* mod 0x10, 0x11 */
	SENSOR_THRS,
	SENSOR_LOCATION,
	/* mod 0x12, 0x13 */
	SENSOR_DATA,
	/* mod 0x1c */
	SENSOR_POWER,

	SENSOR_MAX,
};

/* Parsed sensor attributes, passed through OPAL */
struct opal_sensor_data {
	uint64_t	async_token;	/* Asynchronous token */
	uint32_t	*sensor_data;	/* Kernel pointer to copy data */
	enum spcn_attr	spcn_attr;	/* Modifier attribute */
	uint16_t	rid;		/* Sensor RID */
	uint8_t		frc;		/* Sensor resource class */
	uint32_t	mod_index;	/* Modifier index*/
	uint32_t	offset;		/* Offset in sensor buffer */
};

struct spcn_mod_attr {
	const char *name;
	enum spcn_attr val;
};

struct spcn_mod {
	uint8_t mod;		/* Modifier code */
	uint8_t entry_size;	/* Size of each entry in response buffer */
	uint16_t entry_count;	/* Number of entries */
	struct spcn_mod_attr *mod_attr;
};

static struct spcn_mod_attr prs_status_attrs[] = {
		{"present", SENSOR_PRESENT},
		{"faulted", SENSOR_FAULTED},
		{"ac-faulted", SENSOR_AC_FAULTED},
		{"on", SENSOR_ON},
		{"on-supported", SENSOR_ON_SUPPORTED}
};

static struct spcn_mod_attr sensor_param_attrs[] = {
		{"thrs", SENSOR_THRS},
		{"loc", SENSOR_LOCATION}
};

static struct spcn_mod_attr sensor_data_attrs[] = {
		{"data", SENSOR_DATA}
};

static struct spcn_mod_attr sensor_power_attrs[] = {
		{"power", SENSOR_POWER}
};

static struct spcn_mod spcn_mod_data[] = {
		{SPCN_MOD_PRS_STATUS_FIRST, PRS_STATUS_ENTRY_SZ, 0,
				prs_status_attrs},
		{SPCN_MOD_PRS_STATUS_SUBS, PRS_STATUS_ENTRY_SZ, 0,
				prs_status_attrs},
		{SPCN_MOD_SENSOR_PARAM_FIRST, SENSOR_PARAM_ENTRY_SZ, 0,
				sensor_param_attrs},
		{SPCN_MOD_SENSOR_PARAM_SUBS, SENSOR_PARAM_ENTRY_SZ, 0,
				sensor_param_attrs},
		{SPCN_MOD_SENSOR_DATA_FIRST, SENSOR_DATA_ENTRY_SZ, 0,
				sensor_data_attrs},
		{SPCN_MOD_SENSOR_DATA_SUBS, SENSOR_DATA_ENTRY_SZ, 0,
				sensor_data_attrs},
		/* TODO Support this modifier '0x14', if required */
		/* {SPCN_MOD_PROC_JUNC_TEMP, PROC_JUNC_ENTRY_SZ, 0, NULL}, */
		{SPCN_MOD_SENSOR_POWER, SENSOR_DATA_ENTRY_SZ, 0,
				sensor_power_attrs},
		{SPCN_MOD_LAST, 0xff, 0xffff, NULL}
};

/* Frame resource class (FRC) names */
static const char *frc_names[] = {
		/* 0x00 and 0x01 are reserved */
		NULL,
		NULL,
		"power-controller",
		"power-supply",
		"regulator",
		"cooling-fan",
		"cooling-controller",
		"battery-charger",
		"battery-pack",
		"amb-temp",
		"temp",
		"vrm",
		"riser-card",
		"io-backplane"
};

#define SENSOR_MAX_SIZE		0x00100000
static void *sensor_buffer = NULL;
static enum sensor_state sensor_state;
static bool prev_msg_consumed = true;
static struct lock sensor_lock;

/* Function prototypes */
static int64_t fsp_sensor_send_read_request(struct opal_sensor_data *attr);
static void queue_msg_for_delivery(int rc, struct opal_sensor_data *attr);


/*
 * Power Resource Status (PRS)
 * Command: 0x42
 *
 * Modifier: 0x01
 * --------------------------------------------------------------------------
 * |    0        1         2      3         4        5         6        7   |
 * --------------------------------------------------------------------------
 * |Frame resrc class|      PRID       |      SRC        |       Status     |
 * --------------------------------------------------------------------------
 *
 *
 * Modifier: 0x10
 * --------------------------------------------------------------------------
 * |    0        1         2      3         4        5         6        7   |
 * --------------------------------------------------------------------------
 * |Frame resrc class|      PRID       |            Sensor location         |
 * --------------------------------------------------------------------------
 * --------------------------------------------------------------------------
 * |    8        9         10      11         12   13          14    15     |
 * --------------------------------------------------------------------------
 * |    Reserved     |   Reserved      |   Threshold     |       Status     |
 * --------------------------------------------------------------------------
 *
 *
 * Modifier: 0x12
 * --------------------------------------------------------------------------
 * |    0        1         2      3         4        5         6        7   |
 * --------------------------------------------------------------------------
 * |Frame resrc class|      PRID      |   Sensor data    |       Status     |
 * --------------------------------------------------------------------------
 *
 *
 * Modifier: 0x14
 * --------------------------------------------------------------------------
 * |       0                 1                2                   3         |
 * --------------------------------------------------------------------------
 * |Enclosure Tj Avg | Chip Tj Avg    |    Reserved      |     Reserved     |
 * --------------------------------------------------------------------------
 */

static void fsp_sensor_process_data(struct opal_sensor_data *attr)
{
	uint8_t *sensor_buf_ptr = (uint8_t *)sensor_buffer;
	uint32_t sensor_data = INVALID_DATA;
	uint16_t sensor_mod_data[8];
	int count, i;
	uint8_t valid, nr_power;
	uint32_t power;

	for (count = 0; count < spcn_mod_data[attr->mod_index].entry_count;
			count++) {
		memcpy((void *)sensor_mod_data, sensor_buf_ptr,
				spcn_mod_data[attr->mod_index].entry_size);
		if (spcn_mod_data[attr->mod_index].mod == SPCN_MOD_PROC_JUNC_TEMP) {
			/* TODO Support this modifier '0x14', if required */

		} else if (spcn_mod_data[attr->mod_index].mod == SPCN_MOD_SENSOR_POWER) {
			valid = sensor_buf_ptr[0];
			if (valid & 0x80) {
				nr_power = valid & 0x0f;
				sensor_data = 0;
				for (i=0; i < nr_power; i++) {
					power = *(uint32_t *) &sensor_buf_ptr[2 + i * 5];
					prlog(PR_TRACE, "Power[%d]: %d mW\n",
					      i, power);
					sensor_data += power/1000;
				}
			} else {
				prlog(PR_TRACE, "Power Sensor data not valid\n");
			}
		} else if (sensor_mod_data[0] == attr->frc &&
				sensor_mod_data[1] == attr->rid) {
			switch (attr->spcn_attr) {
			/* modifier 0x01, 0x02 */
			case SENSOR_PRESENT:
				prlog(PR_TRACE,"Not exported to device tree\n");
				break;
			case SENSOR_FAULTED:
				sensor_data = sensor_mod_data[3] & 0x02;
				break;
			case SENSOR_AC_FAULTED:
			case SENSOR_ON:
			case SENSOR_ON_SUPPORTED:
				prlog(PR_TRACE,"Not exported to device tree\n");
				break;
			/* modifier 0x10, 0x11 */
			case SENSOR_THRS:
				sensor_data = sensor_mod_data[6];
				break;
			case SENSOR_LOCATION:
				prlog(PR_TRACE,"Not exported to device tree\n");
				break;
			/* modifier 0x12, 0x13 */
			case SENSOR_DATA:
				sensor_data = sensor_mod_data[2];
				break;
			default:
				break;
			}

			break;
		}

		sensor_buf_ptr += spcn_mod_data[attr->mod_index].entry_size;
	}

	*(attr->sensor_data) = sensor_data;
	if (sensor_data == INVALID_DATA)
		queue_msg_for_delivery(OPAL_PARTIAL, attr);
	else
		queue_msg_for_delivery(OPAL_SUCCESS, attr);
}

static int fsp_sensor_process_read(struct fsp_msg *resp_msg)
{
	uint8_t mbx_rsp_status;
	uint32_t size = 0;

	mbx_rsp_status = (resp_msg->word1 >> 8) & 0xff;
	switch (mbx_rsp_status) {
	case SP_RSP_STATUS_VALID_DATA:
		sensor_state = SENSOR_VALID_DATA;
		size = resp_msg->data.words[1] & 0xffff;
		break;
	case SP_RSP_STATUS_INVALID_DATA:
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
			"SENSOR: %s: Received invalid data\n", __func__);
		sensor_state = SENSOR_INVALID_DATA;
		break;
	case SP_RSP_STATUS_SPCN_ERR:
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
			"SENSOR: %s: Failure due to SPCN error\n", __func__);
		sensor_state = SENSOR_SPCN_ERROR;
		break;
	case SP_RSP_STATUS_DMA_ERR:
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
			"SENSOR: %s: Failure due to DMA error\n", __func__);
		sensor_state = SENSOR_DMA_ERROR;
		break;
	default:
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
			"SENSOR %s: Read failed, status:0x%02X\n",
					__func__, mbx_rsp_status);
		sensor_state = SENSOR_INVALID_DATA;
		break;
	}

	return size;
}

static void queue_msg_for_delivery(int rc, struct opal_sensor_data *attr)
{
	prlog(PR_INSANE, "%s: rc:%d, data:%d\n",
	      __func__, rc, *(attr->sensor_data));
	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
			attr->async_token, rc);
	spcn_mod_data[attr->mod_index].entry_count = 0;
	free(attr);
	prev_msg_consumed = true;
}

static void fsp_sensor_read_complete(struct fsp_msg *msg)
{
	struct opal_sensor_data *attr = msg->user_data;
	enum spcn_rsp_status status;
	int rc, size;

	prlog(PR_INSANE, "%s()\n", __func__);

	status = (msg->resp->data.words[1] >> 24) & 0xff;
	size = fsp_sensor_process_read(msg->resp);
	fsp_freemsg(msg);

	lock(&sensor_lock);
	if (sensor_state == SENSOR_VALID_DATA) {
		spcn_mod_data[attr->mod_index].entry_count += (size /
				spcn_mod_data[attr->mod_index].entry_size);
		attr->offset += size;
		/* Fetch the subsequent entries of the same modifier type */
		if (status == SPCN_RSP_STATUS_COND_SUCCESS) {
			switch (spcn_mod_data[attr->mod_index].mod) {
			case SPCN_MOD_PRS_STATUS_FIRST:
			case SPCN_MOD_SENSOR_PARAM_FIRST:
			case SPCN_MOD_SENSOR_DATA_FIRST:
				attr->mod_index++;
				spcn_mod_data[attr->mod_index].entry_count =
						spcn_mod_data[attr->mod_index - 1].
						entry_count;
				spcn_mod_data[attr->mod_index - 1].entry_count = 0;
				break;
			default:
				break;
			}

			rc = fsp_sensor_send_read_request(attr);
			if (rc != OPAL_ASYNC_COMPLETION)
				goto err;
		} else { /* Notify 'powernv' of read completion */
			fsp_sensor_process_data(attr);
		}
	} else {
		rc = OPAL_INTERNAL_ERROR;
		goto err;
	}
	unlock(&sensor_lock);
	return;
err:
	*(attr->sensor_data) = INVALID_DATA;
	queue_msg_for_delivery(rc, attr);
	unlock(&sensor_lock);
	log_simple_error(&e_info(OPAL_RC_SENSOR_ASYNC_COMPLETE),
		"SENSOR: %s: Failed to queue the "
		"read request to fsp\n", __func__);
}

static int64_t fsp_sensor_send_read_request(struct opal_sensor_data *attr)
{
	int rc;
	struct fsp_msg *msg;
	uint32_t align;
	uint32_t cmd_header;

	prlog(PR_INSANE, "Get the data for modifier [%d]\n",
	      spcn_mod_data[attr->mod_index].mod);

	if (spcn_mod_data[attr->mod_index].mod == SPCN_MOD_PROC_JUNC_TEMP) {
		/* TODO Support this modifier '0x14', if required */
		align = attr->offset % sizeof(uint32_t);
		if (align)
			attr->offset += (sizeof(uint32_t) - align);

		/* TODO Add 8 byte command data required for mod 0x14 */

		attr->offset += 8;

		cmd_header = spcn_mod_data[attr->mod_index].mod << 24 |
				SPCN_CMD_PRS << 16 | 0x0008;
	} else {
		cmd_header = spcn_mod_data[attr->mod_index].mod << 24 |
				SPCN_CMD_PRS << 16;
	}

	msg = fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
			SPCN_ADDR_MODE_CEC_NODE, cmd_header, 0,
			PSI_DMA_SENSOR_BUF + attr->offset);

	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ), "SENSOR: Failed "
				 "to allocate read message\n");
		return OPAL_INTERNAL_ERROR;
	}

	msg->user_data = attr;
	rc = fsp_queue_msg(msg, fsp_sensor_read_complete);
	if (rc) {
		fsp_freemsg(msg);
		msg = NULL;
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ), "SENSOR: Failed "
				 "to queue read message (%d)\n", rc);
		return OPAL_INTERNAL_ERROR;
	}

	return OPAL_ASYNC_COMPLETION;
}

static int64_t parse_sensor_id(uint32_t id, struct opal_sensor_data *attr)
{
	uint32_t mod, index;

	attr->spcn_attr = id >> 24;
	if (attr->spcn_attr >= SENSOR_MAX)
		return OPAL_PARAMETER;

	if (attr->spcn_attr <= SENSOR_ON_SUPPORTED)
		mod = SPCN_MOD_PRS_STATUS_FIRST;
	else if (attr->spcn_attr <= SENSOR_LOCATION)
		mod = SPCN_MOD_SENSOR_PARAM_FIRST;
	else if (attr->spcn_attr <= SENSOR_DATA)
		mod = SPCN_MOD_SENSOR_DATA_FIRST;
	else if (attr->spcn_attr <= SENSOR_POWER)
		mod = SPCN_MOD_SENSOR_POWER;
	else
		return OPAL_PARAMETER;

	for (index = 0; spcn_mod_data[index].mod != SPCN_MOD_LAST; index++) {
		if (spcn_mod_data[index].mod == mod)
			break;
	}

	attr->mod_index = index;
	attr->frc = (id >> 16) & 0xff;
	attr->rid = id & 0xffff;

	return 0;
}


int64_t fsp_opal_read_sensor(uint32_t sensor_hndl, int token,
		uint32_t *sensor_data)
{
	struct opal_sensor_data *attr;
	int64_t rc;

	prlog(PR_INSANE, "fsp_opal_read_sensor [%08x]\n", sensor_hndl);

	if (sensor_state == SENSOR_PERMANENT_ERROR) {
		rc = OPAL_HARDWARE;
		goto out;
	}

	if (!sensor_hndl) {
		rc = OPAL_PARAMETER;
		goto out;
	}

	lock(&sensor_lock);
	if (prev_msg_consumed) {
		attr = zalloc(sizeof(*attr));
		if (!attr) {
			log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
				"SENSOR: Failed to allocate memory\n");
			rc = OPAL_NO_MEM;
			goto out_lock;
		}

		/* Parse the sensor id and store them to the local structure */
		rc = parse_sensor_id(sensor_hndl, attr);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
				"SENSOR: %s: Failed to parse the sensor "
				"handle[0x%08x]\n", __func__, sensor_hndl);
			goto out_free;
		}
		/* Kernel buffer pointer to copy the data later when ready */
		attr->sensor_data = sensor_data;
		attr->async_token = token;

		rc = fsp_sensor_send_read_request(attr);
		if (rc != OPAL_ASYNC_COMPLETION) {
			log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
				"SENSOR: %s: Failed to queue the read "
					"request to fsp\n", __func__);
			goto out_free;
		}

		prev_msg_consumed = false;
	} else {
		rc = OPAL_BUSY_EVENT;
	}

	unlock(&sensor_lock);
	return rc;

out_free:
	free(attr);
out_lock:
	unlock(&sensor_lock);
out:
	return rc;
}


#define MAX_RIDS	64
#define MAX_NAME	64

static int get_index(uint16_t *prids, uint16_t rid)
{
	int index;

	for (index = 0; prids[index] && index < MAX_RIDS; index++)
		if (prids[index] == rid)
			return index;

	if (index == MAX_RIDS)
		return -1;

	prids[index] = rid;
	return index;
}

static void create_sensor_nodes(int index, uint16_t frc, uint16_t rid,
		uint16_t *prids, struct dt_node *sensors)
{
	char name[MAX_NAME];
	struct dt_node *fs_node;
	uint32_t value;
	int rid_index;

	switch (spcn_mod_data[index].mod) {
	case SPCN_MOD_PRS_STATUS_FIRST:
	case SPCN_MOD_PRS_STATUS_SUBS:
		switch (frc) {
		case SENSOR_FRC_POWER_SUPPLY:
		case SENSOR_FRC_COOLING_FAN:
			rid_index = get_index(prids, rid);
			if (rid_index < 0)
				break;
			snprintf(name, MAX_NAME, "%s#%d-%s", frc_names[frc],
					/* Start enumeration from 1 */
					rid_index + 1,
					spcn_mod_data[index].mod_attr[1].name);
			fs_node = dt_new(sensors, name);
			snprintf(name, MAX_NAME, "ibm,opal-sensor-%s",
					frc_names[frc]);
			dt_add_property_string(fs_node, "compatible", name);
			value = spcn_mod_data[index].mod_attr[1].val << 24 |
					(frc & 0xff) << 16 | rid;
			dt_add_property_cells(fs_node, "sensor-id", value);
			break;
		default:
			break;
		}
		break;
	case SPCN_MOD_SENSOR_PARAM_FIRST:
	case SPCN_MOD_SENSOR_PARAM_SUBS:
	case SPCN_MOD_SENSOR_DATA_FIRST:
	case SPCN_MOD_SENSOR_DATA_SUBS:
		switch (frc) {
		case SENSOR_FRC_POWER_SUPPLY:
		case SENSOR_FRC_COOLING_FAN:
		case SENSOR_FRC_AMB_TEMP:
			rid_index = get_index(prids, rid);
			if (rid_index < 0)
				break;
			snprintf(name, MAX_NAME, "%s#%d-%s", frc_names[frc],
					/* Start enumeration from 1 */
					rid_index + 1,
					spcn_mod_data[index].mod_attr[0].name);
			fs_node = dt_new(sensors, name);
			snprintf(name, MAX_NAME, "ibm,opal-sensor-%s",
					frc_names[frc]);
			dt_add_property_string(fs_node, "compatible", name);
			value = spcn_mod_data[index].mod_attr[0].val << 24 |
					(frc & 0xff) << 16 | rid;
			dt_add_property_cells(fs_node, "sensor-id", value);
			if (spcn_mod_data[index].mod == SPCN_MOD_SENSOR_DATA_FIRST &&
			    frc == SENSOR_FRC_AMB_TEMP)
				dt_add_property_string(fs_node, "label", "Ambient");

			break;
		default:
			break;
		}
		break;

	case SPCN_MOD_SENSOR_POWER:
		fs_node = dt_new(sensors, "power#1-data");
		dt_add_property_string(fs_node, "compatible", "ibm,opal-sensor-power");
		value = spcn_mod_data[index].mod_attr[0].val << 24;
		dt_add_property_cells(fs_node, "sensor-id", value);
		break;
	}
}

static void add_sensor_ids(struct dt_node *sensors)
{
	uint32_t MAX_FRC_NAMES = sizeof(frc_names) / sizeof(*frc_names);
	uint8_t *sensor_buf_ptr = (uint8_t *)sensor_buffer;
	uint16_t *prids[MAX_FRC_NAMES];
	uint16_t sensor_frc, power_rid;
	uint16_t sensor_mod_data[8];
	uint32_t index, count;

	for (index = 0; index < MAX_FRC_NAMES; index++)
		prids[index] = zalloc(MAX_RIDS * sizeof(**prids));

	for (index = 0; spcn_mod_data[index].mod != SPCN_MOD_LAST; index++) {
		if (spcn_mod_data[index].mod == SPCN_MOD_SENSOR_POWER) {
			create_sensor_nodes(index, 0, 0, 0, sensors);
			continue;
		}
		for (count = 0; count < spcn_mod_data[index].entry_count;
				count++) {
			if (spcn_mod_data[index].mod ==
					SPCN_MOD_PROC_JUNC_TEMP) {
				/* TODO Support this modifier '0x14', if
				 * required */
			} else {
				memcpy((void *)sensor_mod_data, sensor_buf_ptr,
						spcn_mod_data[index].entry_size);
				sensor_frc = sensor_mod_data[0];
				power_rid = sensor_mod_data[1];

				if (sensor_frc < MAX_FRC_NAMES &&
						frc_names[sensor_frc])
					create_sensor_nodes(index, sensor_frc,
							power_rid,
							prids[sensor_frc],
							sensors);
			}

			sensor_buf_ptr += spcn_mod_data[index].entry_size;
		}
	}

	for (index = 0; index < MAX_FRC_NAMES; index++)
		free(prids[index]);
}

static void add_opal_sensor_node(void)
{
	int index;

	if (!fsp_present())
		return;

	add_sensor_ids(sensor_node);

	/* Reset the entry count of each modifier */
	for (index = 0; spcn_mod_data[index].mod != SPCN_MOD_LAST;
			index++)
		spcn_mod_data[index].entry_count = 0;
}

void fsp_init_sensor(void)
{
	uint32_t cmd_header, align, size, psi_dma_offset = 0;
	enum spcn_rsp_status status;
	struct fsp_msg msg, resp;
	int index, rc;

	if (!fsp_present()) {
		sensor_state = SENSOR_PERMANENT_ERROR;
		return;
	}

	sensor_buffer = memalign(TCE_PSIZE, SENSOR_MAX_SIZE);
	if (!sensor_buffer) {
		log_simple_error(&e_info(OPAL_RC_SENSOR_INIT), "SENSOR: could "
				 "not allocate sensor_buffer!\n");
		return;
	}

	/* Map TCE */
	fsp_tce_map(PSI_DMA_SENSOR_BUF, sensor_buffer, PSI_DMA_SENSOR_BUF_SZ);

	msg.resp = &resp;

	/* Traverse using all the modifiers to know all the sensors available
	 * in the system */
	for (index = 0; spcn_mod_data[index].mod != SPCN_MOD_LAST &&
			sensor_state == SENSOR_VALID_DATA;) {
		prlog(PR_TRACE, "Get the data for modifier [%d]\n",
		      spcn_mod_data[index].mod);
		if (spcn_mod_data[index].mod == SPCN_MOD_PROC_JUNC_TEMP) {
			/* TODO Support this modifier 0x14, if required */
			align = psi_dma_offset % sizeof(uint32_t);
			if (align)
				psi_dma_offset += (sizeof(uint32_t) - align);

			/* TODO Add 8 byte command data required for mod 0x14 */
			psi_dma_offset += 8;

			cmd_header = spcn_mod_data[index].mod << 24 |
					SPCN_CMD_PRS << 16 | 0x0008;
		} else {
			cmd_header = spcn_mod_data[index].mod << 24 |
					SPCN_CMD_PRS << 16;
		}

		fsp_fillmsg(&msg, FSP_CMD_SPCN_PASSTHRU, 4,
				SPCN_ADDR_MODE_CEC_NODE, cmd_header, 0,
				PSI_DMA_SENSOR_BUF + psi_dma_offset);

		rc = fsp_sync_msg(&msg, false);
		if (rc >= 0) {
			status = (resp.data.words[1] >> 24) & 0xff;
			size = fsp_sensor_process_read(&resp);
			psi_dma_offset += size;
			spcn_mod_data[index].entry_count += (size /
					spcn_mod_data[index].entry_size);
		} else {
			sensor_state = SENSOR_PERMANENT_ERROR;
			break;
		}

		switch (spcn_mod_data[index].mod) {
		case SPCN_MOD_PRS_STATUS_FIRST:
		case SPCN_MOD_SENSOR_PARAM_FIRST:
		case SPCN_MOD_SENSOR_DATA_FIRST:
			if (status == SPCN_RSP_STATUS_COND_SUCCESS)
				index++;
			else
				index += 2;

			break;
		case SPCN_MOD_PRS_STATUS_SUBS:
		case SPCN_MOD_SENSOR_PARAM_SUBS:
		case SPCN_MOD_SENSOR_DATA_SUBS:
			if (status != SPCN_RSP_STATUS_COND_SUCCESS)
				index++;
			break;
		case SPCN_MOD_SENSOR_POWER:
			index++;
		default:
			break;
		}
	}

	if (sensor_state != SENSOR_VALID_DATA)
		sensor_state = SENSOR_PERMANENT_ERROR;
	else
		add_opal_sensor_node();
}
