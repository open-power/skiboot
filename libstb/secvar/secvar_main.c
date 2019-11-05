// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "SECVAR: " fmt
#endif

#include <stdlib.h>
#include <skiboot.h>
#include <opal.h>
#include "secvar.h"
#include "secvar_devtree.h"

struct list_head variable_bank;
struct list_head update_bank;

int secvar_enabled = 0;	// Set to 1 if secvar is supported
int secvar_ready = 0;	// Set to 1 when base secvar inits correctly

// To be filled in by platform.secvar_init
struct secvar_storage_driver secvar_storage = {0};
struct secvar_backend_driver secvar_backend = {0};


int secvar_main(struct secvar_storage_driver storage_driver,
               struct secvar_backend_driver backend_driver)
{
	int rc = OPAL_UNSUPPORTED;

	prlog(PR_INFO, "Secure variables are supported, initializing secvar\n");

	secvar_storage = storage_driver;
	secvar_backend = backend_driver;

	secvar_init_devnode(secvar_backend.compatible);

	secvar_enabled = 1;

	list_head_init(&variable_bank);
	list_head_init(&update_bank);

	rc = secvar_storage.store_init();
	if (rc)
		goto fail;

	// Failures here should indicate some kind of hardware problem
	rc = secvar_storage.load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	if (rc)
		goto fail;

	rc = secvar_storage.load_bank(&update_bank, SECVAR_UPDATE_BANK);
	if (rc)
		goto fail;

	// At this point, base secvar is functional. Rest is up to the backend
	secvar_ready = 1;
	secvar_set_status("okay");

	if (secvar_backend.pre_process)
		rc = secvar_backend.pre_process();

	// Process is required, error if it doesn't exist
	if (!secvar_backend.process)
		goto out;

	rc = secvar_backend.process();
		secvar_set_update_status(rc);
	if (rc == OPAL_SUCCESS) {
		rc = secvar_storage.write_bank(&variable_bank, SECVAR_VARIABLE_BANK);
		if (rc)
			goto out;

		rc = secvar_storage.write_bank(&update_bank, SECVAR_UPDATE_BANK);
		if (rc)
			goto out;
	}

	if (secvar_backend.post_process)
		rc = secvar_backend.post_process();
	if (rc)
		goto out;

	prlog(PR_INFO, "secvar initialized successfully\n");

	return OPAL_SUCCESS;
fail:
	secvar_set_status("fail");
out:
	prerror("secvar failed to initialize, rc = %04x\n", rc);
	return rc;
}
