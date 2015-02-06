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

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <opal.h>
#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <ast.h>

#include "astbmc.h"

static struct spi_flash_ctrl *pnor_ctrl;
static struct flash_chip *pnor_chip;
static struct ffs_handle *pnor_ffs;

int pnor_init(void)
{
	uint32_t nv_part, nv_start, nv_size;
	int rc;

	/* Open controller, flash and ffs */
	rc = ast_sf_open(AST_SF_TYPE_PNOR, &pnor_ctrl);
	if (rc) {
		prerror("PLAT: Failed to open PNOR flash controller\n");
		goto fail;
	}
	rc = flash_init(pnor_ctrl, &pnor_chip);
	if (rc) {
		prerror("PLAT: Failed to open init PNOR driver\n");
		goto fail;
	}
	rc = ffs_open_flash(pnor_chip, 0, 0, &pnor_ffs);
	if (rc) {
		prerror("PLAT: Failed to parse FFS partition map\n");
		goto fail;
	}

	/*
	 * Grab NVRAM and initialize the flash_nvram module
	 *
	 * Note: Ignore actual size for now ... some images have
	 * it setup incorrectly.
	 */
	rc = ffs_lookup_part(pnor_ffs, "NVRAM", &nv_part);
	if (rc) {
		prerror("PLAT: No NVRAM partition in PNOR\n");
		return OPAL_HARDWARE;
	}
	rc = ffs_part_info(pnor_ffs, nv_part, NULL,
			   &nv_start, &nv_size, NULL);
	if (rc) {
		prerror("PLAT: Failed to get NVRAM partition info\n");
		return OPAL_HARDWARE;
	}
	flash_nvram_init(pnor_chip, nv_start, nv_size);

	return 0;
 fail:
	if (pnor_ffs)
		ffs_close(pnor_ffs);
	pnor_ffs = NULL;
	if (pnor_chip)
		flash_exit(pnor_chip);
	pnor_chip = NULL;
	if (pnor_ctrl)
		ast_sf_close(pnor_ctrl);
	pnor_ctrl = NULL;

	return rc;
}

static const struct {
	enum resource_id id;
	char name[PART_NAME_MAX+1];
} part_name_map[] = {
	{ RESOURCE_ID_KERNEL, "KERNEL" },
	{ RESOURCE_ID_INITRAMFS, "ROOTFS" },
};

bool pnor_load_resource(enum resource_id id, void *buf, size_t *len)
{
	int i, rc, part_num, part_size, part_start;
	const char *name;

	if (!pnor_ffs || !pnor_chip)
		return false;

	for (i = 0, name = NULL; i < ARRAY_SIZE(part_name_map); i++) {
		if (part_name_map[i].id == id) {
			name = part_name_map[i].name;
			break;
		}
	}
	if (!name) {
		prerror("PLAT: Couldn't find partition for id %d\n", id);
		return false;
	}

	rc = ffs_lookup_part(pnor_ffs, name, &part_num);
	if (rc) {
		prerror("PLAT: No %s partition in PNOR\n", name);
		return false;
	}
	rc = ffs_part_info(pnor_ffs, part_num, NULL,
			   &part_start, &part_size, NULL);
	if (rc) {
		prerror("PLAT: Failed to get %s partition info\n", name);
		return false;
	}

	if (part_size > *len) {
		prerror("PLAT: %s image too large (%d > %zd)\n", name,
			part_size, *len);
		return false;
	}

	rc = flash_read(pnor_chip, part_start, buf, part_size);
	if (rc) {
		prerror("PLAT: failed to read %s partition\n", name);
		return false;
	}

	*len = part_size;

	return true;
}
