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
#include "container.h"
#include "cvc.h"

static const void* hw_key_hash = NULL;
static size_t hw_key_hash_size;
static bool secure_mode = false;

static struct {
	enum secureboot_version version;
	const char *compat;
} secureboot_map[] = {
	{ IBM_SECUREBOOT_V1, "ibm,secureboot-v1" },
};

static void secureboot_enforce(void)
{
	/* Sanity check */
	if (!secure_mode)
		return;

	/*
	 * TODO: Ideally, the BMC should decide what security policy to apply
	 * (power off, reboot, switch PNOR sides, etc). We may need to provide
	 * extra info to BMC other than just abort.  Terminate Immediate
	 * Attention ? (TI)
	 */
	prlog(PR_EMERG, "enforcing secure mode ...\n");
	abort();
}

bool secureboot_is_compatible(struct dt_node *node, int *version, const char **compat)
{
	int i;

	if (!node)
		return false;

	for (i = 0; i < ARRAY_SIZE(secureboot_map); i++) {
		if (dt_node_is_compatible(node, secureboot_map[i].compat)) {
			if (version)
				*version = secureboot_map[i].version;
			if (compat)
				*compat = secureboot_map[i].compat;
			return true;
		}
	}
	return false;
}

void secureboot_init(void)
{
	struct dt_node *node;
	const char *hash_algo;
	const char *compat = NULL;
	int version;
	size_t size;

	node = dt_find_by_path(dt_root, "/ibm,secureboot");
	if (!node) {
		prlog(PR_NOTICE, "secure boot not supported\n");
		return;
	}

	if (!secureboot_is_compatible(node, &version, &compat)) {
		/**
		 * @fwts-label SecureBootNotCompatible
		 * @fwts-advice Compatible secureboot driver not found. Probably,
		 * hostboot/mambo/skiboot has updated the
		 * /ibm,secureboot/compatible without adding a driver that
		 * supports it.
		 */
		prlog(PR_ERR, "%s FAILED, /ibm,secureboot not compatible.\n",
		      __func__);
		return;
	}

	prlog(PR_NOTICE, "Found %s\n", compat);

	if (nvram_query_eq("force-secure-mode", "always")) {
		secure_mode = true;
		prlog(PR_NOTICE, "secure mode on (FORCED by nvram)\n");
	} else {
		secure_mode = dt_has_node_property(node, "secure-enabled", NULL);
		prlog(PR_NOTICE, "secure mode %s\n",
		      secure_mode ? "on" : "off");
	}

	if (!secure_mode)
		return;

	if (version == IBM_SECUREBOOT_V1) {
		hash_algo = dt_prop_get(node, "hash-algo");
		if (strcmp(hash_algo, "sha512")) {
			/**
			 * @fwts-label HashAlgoInvalid
			 * @fwts-advice Hash algorithm invalid, secureboot
			 * containers version 1 requires sha512. If you're
			 * running the latest POWER firmware, so probably there
			 * is a bug in the device tree received from hostboot.
			 */
			prlog(PR_EMERG, "secureboot init FAILED, hash-algo=%s "
			      "not supported\n", hash_algo);
			secureboot_enforce();
		}
		hw_key_hash_size = SHA512_DIGEST_LENGTH;
	} else {
		prlog(PR_ERR, "%s FAILED. /ibm,secureboot not supported",
		      __func__);
		secureboot_enforce();
	}

	hw_key_hash = dt_prop_get_def_size(node, "hw-key-hash", NULL, &size);
	if (!hw_key_hash) {
		prlog(PR_EMERG, "hw-key-hash not found\n");
		secureboot_enforce();
	}
	if (size != hw_key_hash_size) {
	       prlog(PR_EMERG, "hw_key-hash wrong size %zd (expected=%zd)\n",
		     size, hw_key_hash_size);
	       secureboot_enforce();
	}
	if (cvc_init())
		secureboot_enforce();
}
