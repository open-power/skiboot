/* Copyright 2013-2017 IBM Corp.
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

#ifndef pr_fmt
#define pr_fmt(fmt) "STB: " fmt
#endif

#include <skiboot.h>
#include <device.h>
#include <nvram.h>
#include "secureboot.h"
#include "trustedboot.h"
#include "tpm_chip.h"

static bool trusted_mode = false;

void trustedboot_init(void)
{
	struct dt_node *node;

	node = dt_find_by_path(dt_root, "/ibm,secureboot");
	if (!node) {
		prlog(PR_NOTICE, "trusted boot not supported\n");
		return;
	}

	if (!secureboot_is_compatible(node, NULL, NULL)) {
		/**
		 * @fwts-label TrustedBootNotCompatible
		 * @fwts-advice Compatible trustedboot driver not found. Probably,
		 * hostboot/mambo/skiboot has updated the
		 * /ibm,secureboot/compatible without adding a driver that
		 * supports it.
		 */
		prlog(PR_ERR, "trustedboot init FAILED, '%s' node not "
		      "compatible.\n", node->name);
		return;
	}

	if (nvram_query_eq("force-trusted-mode", "true")) {
		trusted_mode = true;
		prlog(PR_NOTICE, "trusted mode on (FORCED by nvram)\n");
	} else {
		trusted_mode = dt_has_node_property(node, "trusted-enabled", NULL);
		prlog(PR_NOTICE, "trusted mode %s\n",
		      trusted_mode ? "on" : "off");
	}

	if (!trusted_mode)
		return;
	cvc_init();
	tpm_init();
}
