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

#ifndef __TPM_H
#define __TPM_H

#include <device.h>

struct tpm_dev {

	/* TPM bus id */
	int bus_id;

	/* TPM address in the bus */
	int xscom_base;
};

struct tpm_driver {

	/* Driver name */
	const char* name;

	/* Transmit the TPM command stored in buf to the tpm device */
	int (*transmit)(struct tpm_dev *dev, uint8_t* buf, size_t cmdlen,
			size_t *buflen);
};

struct tpm_chip {

	/* TPM chip id */
	int id;

	/* Indicates whether or not the device and log are functional */
	bool enabled;

	/* TPM device tree node */
	struct dt_node *node;

	/* TPM device handler */
	struct tpm_dev    *dev;

	/* TPM driver handler */
	struct tpm_driver *driver;

	struct list_node link;
};

/*
 * Register a tpm chip by binding the driver to dev.
 */
extern int tpm_register_chip(struct dt_node *node, struct tpm_dev *dev,
			     struct tpm_driver *driver);

/* Add status property to the TPM devices */
extern void tpm_add_status_property(void);

extern void tpm_init(void);
extern void tpm_cleanup(void);

#endif /* __TPM_H */
