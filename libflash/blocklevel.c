/* Copyright 2013-2015 IBM Corp.
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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <libflash/errors.h>

#include "blocklevel.h"
#include "ecc.h"

#define PROT_REALLOC_NUM 25

/* This function returns tristate values.
 * 1  - The region is ECC protected
 * 0  - The region is not ECC protected
 * -1 - Partially protected
 */
static int ecc_protected(struct blocklevel_device *bl, uint32_t pos, uint32_t len)
{
	int i;

	/* Length of 0 is nonsensical so add 1 */
	if (len == 0)
		len = 1;

	for (i = 0; i < bl->ecc_prot.n_prot; i++) {
		/* Fits entirely within the range */
		if (bl->ecc_prot.prot[i].start <= pos && bl->ecc_prot.prot[i].start + bl->ecc_prot.prot[i].len >= pos + len)
			return 1;

		/*
		 * Since we merge regions on inserting we can be sure that a
		 * partial fit means that the non fitting region won't fit in another ecc
		 * region
		 */
		if ((bl->ecc_prot.prot[i].start >= pos && bl->ecc_prot.prot[i].start < pos + len) ||
		   (bl->ecc_prot.prot[i].start <= pos && bl->ecc_prot.prot[i].start + bl->ecc_prot.prot[i].len > pos))
			return -1;
	}
	return 0;
}

int blocklevel_read(struct blocklevel_device *bl, uint32_t pos, void *buf, uint32_t len)
{
	int rc;
	struct ecc64 *buffer;
	uint32_t ecc_len = ecc_buffer_size(len);

	if (!bl || !bl->read || !buf) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	if (!ecc_protected(bl, pos, len)) {
		return bl->read(bl, pos, buf, len);
	}

	buffer = malloc(ecc_len);
	if (!buffer) {
		errno = ENOMEM;
		return FLASH_ERR_MALLOC_FAILED;
	}

	rc = bl->read(bl, pos, buffer, ecc_len);
	if (rc)
		goto out;

	rc = memcpy_from_ecc(buf, buffer, len);

out:
	free(buffer);
	return rc;
}

int blocklevel_write(struct blocklevel_device *bl, uint32_t pos, const void *buf, uint32_t len)
{
	int rc;
	struct ecc64 *buffer;
	uint32_t ecc_len = ecc_buffer_size(len);

	if (!bl || !bl->write || !buf) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	if (!ecc_protected(bl, pos, len)) {
		return bl->write(bl, pos, buf, len);
	}

	buffer = malloc(ecc_len);
	if (!buffer) {
		errno = ENOMEM;
		return FLASH_ERR_MALLOC_FAILED;
	}

	if (memcpy_to_ecc(buffer, buf, len)) {
		errno = EBADF;
		rc = FLASH_ERR_ECC_INVALID;
		goto out;
	}
	rc = bl->write(bl, pos, buffer, ecc_len);
out:
	free(buffer);
	return rc;
}

int blocklevel_erase(struct blocklevel_device *bl, uint32_t pos, uint32_t len)
{
	if (!bl || !bl->erase) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	/* Programmer may be making a horrible mistake without knowing it */
	if (len & bl->erase_mask) {
		fprintf(stderr, "blocklevel_erase: len (0x%08x) is not erase block (0x%08x) aligned\n",
				len, bl->erase_mask + 1);
		return FLASH_ERR_ERASE_BOUNDARY;
	}

	return bl->erase(bl, pos, len);
}

int blocklevel_get_info(struct blocklevel_device *bl, const char **name, uint32_t *total_size,
		uint32_t *erase_granule)
{
	int rc;

	if (!bl || !bl->get_info) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	rc = bl->get_info(bl, name, total_size, erase_granule);

	/* Check the validity of what we are being told */
	if (erase_granule && *erase_granule != bl->erase_mask + 1)
		fprintf(stderr, "blocklevel_get_info: WARNING: erase_granule (0x%08x) and erase_mask"
				" (0x%08x) don't match\n", *erase_granule, bl->erase_mask + 1);

	return rc;
}

int blocklevel_smart_write(struct blocklevel_device *bl, uint32_t pos, const void *buf, uint32_t len)
{
	uint32_t erase_size;
	const void *write_buf = buf;
	void *write_buf_start = NULL;
	void *erase_buf;
	int rc = 0;

	if (!write_buf || !bl) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	if (!(bl->flags & WRITE_NEED_ERASE))
		return blocklevel_write(bl, pos, buf, len);

	rc = blocklevel_get_info(bl, NULL, NULL, &erase_size);
	if (rc)
		return rc;

	if (ecc_protected(bl, pos, len)) {
		len = ecc_buffer_size(len);

		write_buf_start = malloc(len);
		if (!write_buf_start) {
			errno = ENOMEM;
			return FLASH_ERR_MALLOC_FAILED;
		}

		if (memcpy_to_ecc(write_buf_start, buf, ecc_buffer_size_minus_ecc(len))) {
			free(write_buf_start);
			errno = EBADF;
			return FLASH_ERR_ECC_INVALID;
		}
		write_buf = write_buf_start;
	}

	erase_buf = malloc(erase_size);
	if (!erase_buf) {
		errno = ENOMEM;
		rc = FLASH_ERR_MALLOC_FAILED;
		goto out;
	}

	while (len > 0) {
		uint32_t erase_block = pos & ~(erase_size - 1);
		uint32_t block_offset = pos & (erase_size - 1);
		uint32_t size = erase_size > len ? len : erase_size;

		rc = bl->read(bl, erase_block, erase_buf, erase_size);
		if (rc)
			goto out;

		if (memcmp(erase_buf + block_offset, write_buf, size) != 0) {
			memcpy(erase_buf + block_offset, write_buf, size);
			rc = bl->write(bl, erase_block, erase_buf + block_offset, size);
			if (rc)
				goto out;
		}

		len -= size;
		pos += size;
		write_buf += size;
	}

out:
	free(write_buf_start);
	free(erase_buf);
	return rc;
}

static int insert_bl_prot_range(struct blocklevel_range *ranges, struct bl_prot_range range)
{
	struct bl_prot_range *new_ranges;
	struct bl_prot_range *old_ranges = ranges->prot;
	int i, count = ranges->n_prot;

	/* Try to merge into an existing range */
	for (i = 0; i < count; i++) {
		if (!(range.start + range.len == old_ranges[i].start ||
			  old_ranges[i].start + old_ranges[i].len == range.start))
			continue;

		if (range.start + range.len == old_ranges[i].start)
			old_ranges[i].start = range.start;

		old_ranges[i].len += range.len;

		/*
		 * Check the inserted range isn't wedged between two ranges, if it
		 * is, merge aswell
		 */
		i++;
		if (i < count && range.start + range.len == old_ranges[i].start) {
			old_ranges[i - 1].len += old_ranges[i].len;

			for (; i + 1 < count; i++)
				old_ranges[i] = old_ranges[i + 1];
			ranges->n_prot--;
		}

		return 0;
	}

	if (ranges->n_prot == ranges->total_prot) {
		new_ranges = realloc(ranges->prot, sizeof(range) * ((ranges->n_prot) + PROT_REALLOC_NUM));
		if (new_ranges)
			ranges->total_prot += PROT_REALLOC_NUM;
	} else {
		new_ranges = old_ranges;
	}
	if (new_ranges) {
		memcpy(new_ranges + ranges->n_prot, &range, sizeof(range));
		ranges->prot = new_ranges;
		ranges->n_prot++;
	}

	return !new_ranges;
}

int blocklevel_ecc_protect(struct blocklevel_device *bl, uint32_t start, uint32_t len)
{
	/*
	 * Could implement this at hardware level by having an accessor to the
	 * backend in struct blocklevel_device and as a result do nothing at
	 * this level (although probably not for ecc!)
	 */
	struct bl_prot_range range = { .start = start, .len = len };

	/*
	 * Refuse to add regions that are already protected or are partially
	 * protected
	 */
	if (len < BYTES_PER_ECC || ecc_protected(bl, start, len))
		return -1;
	return insert_bl_prot_range(&bl->ecc_prot, range);
}
