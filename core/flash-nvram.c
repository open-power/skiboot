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
#include <platform.h>
#include <libflash/libflash.h>

static struct flash_chip *fl_nv_chip;
static uint32_t fl_nv_start, fl_nv_size;

static int flash_nvram_info(uint32_t *total_size)
{
	if (!fl_nv_chip)
		return OPAL_HARDWARE;
	*total_size = fl_nv_size;
	return OPAL_SUCCESS;
}

static int flash_nvram_start_read(void *dst, uint32_t src, uint32_t len)
{
	int rc;

	if ((src + len) > fl_nv_size) {
		prerror("FLASH_NVRAM: read out of bound (0x%x,0x%x)\n",
			src, len);
		return OPAL_PARAMETER;
	}
	rc = flash_read(fl_nv_chip, fl_nv_start + src, dst, len);
	if (rc)
		return rc;
	nvram_read_complete(true);
	return 0;
}

static int flash_nvram_write(uint32_t dst, void *src, uint32_t len)
{
	/* TODO: When we have async jobs for PRD, turn this into one */

	if ((dst + len) > fl_nv_size) {
		prerror("FLASH_NVRAM: write out of bound (0x%x,0x%x)\n",
			dst, len);
		return OPAL_PARAMETER;
	}
	return flash_smart_write(fl_nv_chip, fl_nv_start + dst, src, len);
}

int flash_nvram_init(struct flash_chip *chip, uint32_t start, uint32_t size)
{
	fl_nv_chip = chip;
	fl_nv_start = start;
	fl_nv_size = size;

	platform.nvram_info = flash_nvram_info;
	platform.nvram_start_read = flash_nvram_start_read;
	platform.nvram_write = flash_nvram_write;

	return 0;
}

