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

static struct list_head tpm_list = LIST_HEAD_INIT(tpm_list);

int tpm_register_chip(struct dt_node *node, struct tpm_dev *dev,
		       struct tpm_driver *driver)
{
	int i;
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

	tpm->enabled = true;
	tpm->node = node;
	tpm->dev = dev;
	tpm->driver = driver;

	list_add_tail(&tpm_list, &tpm->link);

	prlog(PR_NOTICE, "TPM: tpm%d registered: driver=%s\n",
	      tpm->id, tpm->driver->name);

	return 0;
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
