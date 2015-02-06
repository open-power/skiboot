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
#include <fsp.h>
#include <opal.h>
#include <opal-api.h>
#include <lock.h>
#include <device.h>
#include <platform.h>

static void *nvram_image;
static uint32_t nvram_size;
static bool nvram_ready;

static int64_t opal_read_nvram(uint64_t buffer, uint64_t size, uint64_t offset)
{
	if (!nvram_ready)
		return OPAL_HARDWARE;
	if (offset >= nvram_size || (offset + size) > nvram_size)
		return OPAL_PARAMETER;

	memcpy((void *)buffer, nvram_image + offset, size);
	return OPAL_SUCCESS;
}
opal_call(OPAL_READ_NVRAM, opal_read_nvram, 3);

static int64_t opal_write_nvram(uint64_t buffer, uint64_t size, uint64_t offset)
{
	if (!nvram_ready)
		return OPAL_HARDWARE;
	if (offset >= nvram_size || (offset + size) > nvram_size)
		return OPAL_PARAMETER;
	memcpy(nvram_image + offset, (void *)buffer, size);
	if (platform.nvram_write)
		platform.nvram_write(offset, nvram_image + offset, size);
	return OPAL_SUCCESS;
}
opal_call(OPAL_WRITE_NVRAM, opal_write_nvram, 3);

struct chrp_nvram_hdr {
	uint8_t		sig;
	uint8_t		cksum;
	uint16_t	len;
	char		name[12];
};

#define NVRAM_SIG_FW_PRIV	0x51
#define NVRAM_SIG_SYSTEM	0x70
#define NVRAM_SIG_FREE		0x7f

#define NVRAM_NAME_COMMON	"common"
#define NVRAM_NAME_FW_PRIV	"ibm,skiboot"
#define NVRAM_NAME_FREE		"wwwwwwwwwwww"

/* 64k should be enough, famous last words... */
#define NVRAM_SIZE_COMMON	0x10000

/* 4k should be enough, famous last words... */
#define NVRAM_SIZE_FW_PRIV	0x1000

static uint8_t chrp_nv_cksum(struct chrp_nvram_hdr *hdr)
{
	struct chrp_nvram_hdr h_copy = *hdr;
	uint8_t b_data, i_sum, c_sum;
	uint8_t *p = (uint8_t *)&h_copy;
	unsigned int nbytes = sizeof(h_copy);

	h_copy.cksum = 0;
	for (c_sum = 0; nbytes; nbytes--) {
		b_data = *(p++);
		i_sum = c_sum + b_data;
		if (i_sum < c_sum)
			i_sum++;
		c_sum = i_sum;
	}
	return c_sum;
}

static void nvram_format(void)
{
	struct chrp_nvram_hdr *h;
	unsigned int offset = 0;

	prerror("NVRAM: Re-initializing\n");
	memset(nvram_image, 0, nvram_size);

	/* Create private partition */
	h = nvram_image + offset;
	h->sig = NVRAM_SIG_FW_PRIV;
	h->len = NVRAM_SIZE_FW_PRIV >> 4;
	strcpy(h->name, NVRAM_NAME_FW_PRIV);
	h->cksum = chrp_nv_cksum(h);
	offset += NVRAM_SIZE_FW_PRIV;

	/* Create common partition */
	h = nvram_image + offset;
	h->sig = NVRAM_SIG_SYSTEM;
	h->len = NVRAM_SIZE_COMMON >> 4;
	strcpy(h->name, NVRAM_NAME_COMMON);
	h->cksum = chrp_nv_cksum(h);
	offset += NVRAM_SIZE_COMMON;

	/* Create free space partition */
	h = nvram_image + offset;
	h->sig = NVRAM_SIG_FREE;
	h->len = (nvram_size - offset) >> 4;
	strncpy(h->name, NVRAM_NAME_FREE, 12);
	h->cksum = chrp_nv_cksum(h);

	/* Write the whole thing back */
	if (platform.nvram_write)
		platform.nvram_write(0, nvram_image, nvram_size);
}

/*
 * Check that the nvram partition layout is sane and that it
 * contains our required partitions. If not, we re-format the
 * lot of it
 */
static void nvram_check(void)
{
	unsigned int offset = 0;
	bool found_common = false;
	bool found_skiboot = false;

	while (offset + sizeof(struct chrp_nvram_hdr) < nvram_size) {
		struct chrp_nvram_hdr *h = nvram_image + offset;

		if (chrp_nv_cksum(h) != h->cksum) {
			prerror("NVRAM: Partition at offset 0x%x"
				" has bad checksum\n", offset);
			goto failed;
		}
		if (h->len < 1) {
			prerror("NVRAM: Partition at offset 0x%x"
				" has incorrect 0 length\n", offset);
			goto failed;
		}

		if (h->sig == NVRAM_SIG_SYSTEM &&
		    strcmp(h->name, NVRAM_NAME_COMMON) == 0)
			found_common = true;

		if (h->sig == NVRAM_SIG_FW_PRIV &&
		    strcmp(h->name, NVRAM_NAME_FW_PRIV) == 0)
			found_skiboot = true;

		offset += h->len << 4;
		if (offset > nvram_size) {
			prerror("NVRAM: Partition at offset 0x%x"
				" extends beyond end of nvram !\n", offset);
			goto failed;
		}
	}
	if (!found_common) {
			prerror("NVRAM: Common partition not found !\n");
		goto failed;
	}
	if (!found_skiboot) {
			prerror("NVRAM: Skiboot private partition "
				"not found !\n");
		goto failed;
	}

	prerror("NVRAM: Layout appears sane\n");
	return;
 failed:
	nvram_format();
}

void nvram_read_complete(bool success)
{
	struct dt_node *np;

	/* Read not successful, error out and free the buffer */
	if (!success) {
		free(nvram_image);
		nvram_size = 0;
		return;
	}

	/* Check and maybe format nvram */
	nvram_check();

	/* Add nvram node */
	np = dt_new(opal_node, "nvram");
	dt_add_property_cells(np, "#bytes", nvram_size);
	dt_add_property_string(np, "compatible", "ibm,opal-nvram");

	/* Mark ready */
	nvram_ready = true;
}

void nvram_init(void)
{
	int rc;

	if (!platform.nvram_info)
		return;
	rc = platform.nvram_info(&nvram_size);
	if (rc) {
		prerror("NVRAM: Error %d retrieving nvram info\n", rc);
		return;
	}
	printf("NVRAM: Size is %d KB\n", nvram_size >> 10);
	if (nvram_size > 0x100000) {
		printf("NVRAM: Cropping to 1MB !\n");
		nvram_size = 0x100000;
	}

	/*
	 * We allocate the nvram image with 4k alignment to make the
	 * FSP backend job's easier
	 */
	nvram_image = memalign(0x1000, nvram_size);
	if (!nvram_image) {
		prerror("NVRAM: Failed to allocate nvram image\n");
		nvram_size = 0;
		return;
	}

	/* Read it in */
	rc = platform.nvram_start_read(nvram_image, 0, nvram_size);
	if (rc) {
		prerror("NVRAM: Failed to read NVRAM from FSP !\n");
		nvram_size = 0;
		free(nvram_image);
		return;
	}

	/*
	 * We'll get called back later (or recursively from
	 * nvram_start_read) in nvram_read_complete()
	 */
}
