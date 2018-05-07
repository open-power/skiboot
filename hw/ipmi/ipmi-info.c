/* Copyright 2018 IBM Corp.
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

#include <device.h>
#include <skiboot.h>
#include <stdlib.h>
#include <ipmi.h>
#include <mem_region-malloc.h>
#include <opal.h>
#include <timebase.h>

/*
 * Respones data from IPMI Get device ID command (As defined in
 * Section 20.1 Get Device ID Command - IPMI standard spec).
 */
struct ipmi_dev_id {
	uint8_t	dev_id;
	uint8_t	dev_revision;
	uint8_t	fw_rev1;
	uint8_t	fw_rev2;
	uint8_t	ipmi_ver;
	uint8_t	add_dev_support;
	uint8_t	manufactur_id[3];
	uint8_t	product_id[2];
	uint8_t	aux_fw_rev[4];
};
static struct ipmi_dev_id *ipmi_dev_id;

/* Got response from BMC? */
static bool bmc_info_waiting = false;
static bool bmc_info_valid = false;

/* This will free ipmi_dev_id structure */
void ipmi_dt_add_bmc_info(void)
{
	char buf[8];
	struct dt_node *dt_fw_version;

	while (bmc_info_waiting)
		time_wait_ms(5);

	if (!bmc_info_valid)
		return;

	dt_fw_version = dt_find_by_name(dt_root, "ibm,firmware-versions");
	if (!dt_fw_version) {
		free(ipmi_dev_id);
		return;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%x.%02x",
		 ipmi_dev_id->fw_rev1, ipmi_dev_id->fw_rev2);
	dt_add_property_string(dt_fw_version, "bmc-firmware-version", buf);

	free(ipmi_dev_id);
}

static void ipmi_get_bmc_info_resp(struct ipmi_msg *msg)
{
	bmc_info_waiting = false;

	if (msg->cc != IPMI_CC_NO_ERROR) {
		prlog(PR_ERR, "IPMI: IPMI_BMC_GET_DEVICE_ID cmd returned error"
		      " [rc : 0x%x]\n", msg->data[0]);
		return;
	}

	bmc_info_valid = true;
	memcpy(ipmi_dev_id, msg->data, msg->resp_size);
	ipmi_free_msg(msg);
}

int ipmi_get_bmc_info_request(void)
{
	int rc;
	struct ipmi_msg *msg;

	ipmi_dev_id = zalloc(sizeof(struct ipmi_dev_id));
	assert(ipmi_dev_id);

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_BMC_GET_DEVICE_ID,
			 ipmi_get_bmc_info_resp, NULL, NULL,
			 0, sizeof(struct ipmi_dev_id));
	if (!msg)
		return OPAL_NO_MEM;

	msg->error = ipmi_get_bmc_info_resp;
	prlog(PR_INFO, "IPMI: Requesting IPMI_BMC_GET_DEVICE_ID\n");
	rc = ipmi_queue_msg(msg);
	if (rc) {
		prlog(PR_ERR, "IPMI: Failed to queue IPMI_BMC_GET_DEVICE_ID\n");
		ipmi_free_msg(msg);
		return rc;
	}

	bmc_info_waiting = true;
	return rc;
}
