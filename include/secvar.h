// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#ifndef _SECVAR_DRIVER_
#define _SECVAR_DRIVER_

#include <stdint.h>

struct secvar;

struct secvar_storage_driver {
	int (*load_bank)(struct list_head *bank, int section);
	int (*write_bank)(struct list_head *bank, int section);
	int (*store_init)(void);
	void (*lockdown)(void);
	uint64_t max_var_size;
};

struct secvar_backend_driver {
        int (*pre_process)(void);               // Perform any pre-processing stuff (e.g. determine secure boot state)
        int (*process)(void);                   // Process all updates
        int (*post_process)(void);              // Perform any post-processing stuff (e.g. derive/update variables)
        int (*validate)(struct secvar *var);    // Validate a single variable, return boolean
        const char *compatible;			// String to use for compatible in secvar node
};


int secvar_main(struct secvar_storage_driver, struct secvar_backend_driver);

#endif
