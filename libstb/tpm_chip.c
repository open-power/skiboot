/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
#include <string.h>

#include "status_codes.h"
#include "container.h"
#include "tpm_chip.h"
#include "drivers/tpm_i2c_nuvoton.h"

static struct list_head tpm_list = LIST_HEAD_INIT(tpm_list);

int tpm_register_chip(struct dt_node *node, struct tpm_dev *dev,
		       struct tpm_driver *driver)
{
	int i, rc;
	uint64_t sml_base;
	uint32_t sml_size;
	struct tpm_chip *tpm;

	i = 0;
	list_for_each(&tpm_list, tpm, link) {
		if (tpm->node == node) {
			/**
			 * @fwts-label TPMAlreadyRegistered
			 * @fwts-advice TPM node already registered. The same
			 * node is being registered twice or there is a
			 * tpm node duplicate in the device tree
			 */
			prlog(PR_WARNING, "TPM: tpm%d already registered\n",
			      tpm->id);
			return STB_ERROR;
		}
		i++;
	}

	tpm = (struct tpm_chip*) malloc(sizeof(struct tpm_chip));
	assert(tpm);
	tpm->id = i;

	/*
	 * Read event log info from the tpm device tree node. Both
	 * linux,sml-base and linux,sml-size properties are documented in
	 * 'doc/device-tree/tpm.rst'
	 */

	sml_base = dt_prop_get_u64_def(node, "linux,sml-base", 0);

	/* Check if sml-base is really 0 or it just doesn't exist */
	if (!sml_base &&
	    !dt_find_property(node, "linux,sml-base")) {
		/**
		 * @fwts-label TPMSmlBaseNotFound
		 * @fwts-advice linux,sml-base property not found. This
		 * indicates a Hostboot bug if the property really
		 * doesn't exist in the tpm node.
		 */
		prlog(PR_ERR, "TPM: linux,sml-base property not found "
		      "tpm node %p\n", node);
		goto disable;
	}

	sml_size = dt_prop_get_u32_def(node, "linux,sml-size", 0);

	if (!sml_size) {
		/**
		 * @fwts-label TPMSmlSizeNotFound
		 * @fwts-advice linux,sml-size property not found. This
		 * indicates a Hostboot bug if the property really
		 * doesn't exist in the tpm node.
		 */
		prlog(PR_ERR, "TPM: linux,sml-size property not found, "
		      "tpm node %p\n", node);
		goto disable;
	}

	/*
	 * Initialize the event log manager by walking through the log to identify
	 * what is the next free position in the log
	 */
	rc = TpmLogMgr_initializeUsingExistingLog(&tpm->logmgr,
					 (uint8_t*) sml_base, sml_size);

	if (rc) {
		/**
		 * @fwts-label TPMInitEventLogFailed
		 * @fwts-advice Hostboot creates and adds entries to the
		 * event log. The failed init function is part of hostboot,
		 * but the source code is shared with skiboot. If the hostboot
		 * TpmLogMgr code (or friends) has been updated, the changes
		 * need to be applied to skiboot as well.
		 */
		prlog(PR_ERR, "TPM: eventlog init failed: tpm%d rc=%d",
		      tpm->id, rc);
		goto disable;
	}

	tpm->enabled = true;
	tpm->node = node;
	tpm->dev = dev;
	tpm->driver = driver;

	list_add_tail(&tpm_list, &tpm->link);

	prlog(PR_NOTICE, "TPM: tpm%d registered: driver=%s felsz=%d\n",
	      tpm->id, tpm->driver->name, tpm->logmgr.logSize);

	return 0;

disable:
	dt_add_property_string(node, "status", "disabled");
	prlog(PR_NOTICE, "TPM: tpm node %p disabled\n", node);
	free(tpm);
	return STB_ERROR;
}

void tpm_init(void)
{
	if (!list_empty(&tpm_list)) {
		/**
		 * @fwts-label TPMAlreadyInitialized
		 * @fwts-advice TPM already initialized. Check if tpm is being
		 * initialized more than once.
		 */
		prlog(PR_WARNING, "TPM: tpm device(s) already initialized\n");
		return;
	}

	list_head_init(&tpm_list);

	/* tpm drivers supported */
	tpm_i2c_nuvoton_probe();

	if (list_empty(&tpm_list))
		/**
		 * @fwts-label TPMNotInitialized
		 * @fwts-advice No TPM chip has been initialized. We may not
		 * have a compatible tpm driver or there is no tpm node in the
		 * device tree with the expected bindings.
		 */
		prlog(PR_ERR, "TPM: no tpm chip has been initialized\n");

}

void tpm_cleanup(void)
{
	struct tpm_chip *tpm = NULL;

	tpm = list_pop(&tpm_list, struct tpm_chip, link);

	while (tpm) {
		/* deallocate memory */
		if (tpm->dev)
			free(tpm->dev);
		tpm->driver = NULL;
		free(tpm);
		tpm = list_pop(&tpm_list, struct tpm_chip, link);
	}

	list_head_init(&tpm_list);
}

void tpm_add_status_property(void) {
	struct tpm_chip *tpm;
	list_for_each(&tpm_list, tpm, link) {
		dt_add_property_string(tpm->node, "status",
				       tpm->enabled ? "okay" : "disabled");
	}
}
