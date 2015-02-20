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
/*
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ecc.h>

#include <ccan/endian/endian.h>

#include "libffs.h"

enum ffs_type {
	ffs_type_flash,
	ffs_type_image,
};

struct ffs_handle {
	struct ffs_hdr		hdr;	/* Converted header */
	enum ffs_type		type;
	struct flash_chip	*chip;
	uint32_t		flash_offset;
	uint32_t		max_size;
	void			*cache;
	uint32_t		cached_size;
};

static uint32_t ffs_checksum(void* data, size_t size)
{
	uint32_t i, csum = 0;

	for (i = csum = 0; i < (size/4); i++)
		csum ^= ((uint32_t *)data)[i];
	return csum;
}

static int ffs_check_convert_header(struct ffs_hdr *dst, struct ffs_hdr *src)
{
	dst->magic = be32_to_cpu(src->magic);
	if (dst->magic != FFS_MAGIC)
		return FFS_ERR_BAD_MAGIC;
	dst->version = be32_to_cpu(src->version);
	if (dst->version != FFS_VERSION_1)
		return FFS_ERR_BAD_VERSION;
	if (ffs_checksum(src, FFS_HDR_SIZE) != 0)
		return FFS_ERR_BAD_CKSUM;
	dst->size = be32_to_cpu(src->size);
	dst->entry_size = be32_to_cpu(src->entry_size);
	dst->entry_count = be32_to_cpu(src->entry_count);
	dst->block_size = be32_to_cpu(src->block_size);
	dst->block_count = be32_to_cpu(src->block_count);

	return 0;
}

int ffs_open_flash(struct flash_chip *chip, uint32_t offset,
		   uint32_t max_size, struct ffs_handle **ffs)
{
	struct ffs_hdr hdr;
	struct ffs_handle *f;
	uint32_t fl_size, erase_size;
	int rc;

	if (!ffs)
		return FLASH_ERR_PARM_ERROR;
	*ffs = NULL;

	/* Grab some info about our flash chip */
	rc = flash_get_info(chip, NULL, &fl_size, &erase_size);
	if (rc) {
		FL_ERR("FFS: Error %d retrieving flash info\n", rc);
		return rc;
	}
	if ((offset + max_size) < offset)
		return FLASH_ERR_PARM_ERROR;
	if ((offset + max_size) > fl_size)
		return FLASH_ERR_PARM_ERROR;

	/* Read flash header */
	rc = flash_read(chip, offset, &hdr, sizeof(hdr));
	if (rc) {
		FL_ERR("FFS: Error %d reading flash header\n", rc);
		return rc;
	}

	/* Allocate ffs_handle structure and start populating */
	f = malloc(sizeof(*f));
	if (!f)
		return FLASH_ERR_MALLOC_FAILED;
	memset(f, 0, sizeof(*f));
	f->type = ffs_type_flash;
	f->flash_offset = offset;
	f->max_size = max_size ? max_size : (fl_size - offset);
	f->chip = chip;

	/* Convert and check flash header */
	rc = ffs_check_convert_header(&f->hdr, &hdr);
	if (rc) {
		FL_ERR("FFS: Error %d checking flash header\n", rc);
		free(f);
		return rc;
	}

	/*
	 * Decide how much of the image to grab to get the whole
	 * partition map.
	 */
	f->cached_size = f->hdr.block_size * f->hdr.size;
	FL_DBG("FFS: Partition map size: 0x%x\n", f->cached_size);

	/* Align to erase size */
	f->cached_size |= (erase_size - 1);
	f->cached_size &= ~(erase_size - 1);
	FL_DBG("FFS:         Aligned to: 0x%x\n", f->cached_size);

	/* Allocate cache */
	f->cache = malloc(f->cached_size);
	if (!f->cache) {
		free(f);
		return FLASH_ERR_MALLOC_FAILED;
	}

	/* Read the cached map */
	rc = flash_read(chip, offset, f->cache, f->cached_size);
	if (rc) {
		FL_ERR("FFS: Error %d reading flash partition map\n", rc);
		free(f);
	}
	if (rc == 0)
		*ffs = f;
	return rc;
}

#if 0 /* XXX TODO: For FW updates so we can copy nvram around */
int ffs_open_image(void *image, uint32_t size, uint32_t offset,
		   struct ffs_handle **ffs)
{
}
#endif

void ffs_close(struct ffs_handle *ffs)
{
	if (ffs->cache)
		free(ffs->cache);
	free(ffs);
}

static struct ffs_entry *ffs_get_part(struct ffs_handle *ffs, uint32_t index,
				      uint32_t *out_offset)
{
	uint32_t esize = ffs->hdr.entry_size;
	uint32_t offset = FFS_HDR_SIZE + index * esize;

	if (index > ffs->hdr.entry_count)
		return NULL;
	if (out_offset)
		*out_offset = offset;
	return (struct ffs_entry *)(ffs->cache + offset);
}

static int ffs_check_convert_entry(struct ffs_entry *dst, struct ffs_entry *src)
{
	if (ffs_checksum(src, FFS_ENTRY_SIZE) != 0)
		return FFS_ERR_BAD_CKSUM;
	memcpy(dst->name, src->name, sizeof(dst->name));
	dst->base = be32_to_cpu(src->base);
	dst->size = be32_to_cpu(src->size);
	dst->pid = be32_to_cpu(src->pid);
	dst->id = be32_to_cpu(src->id);
	dst->type = be32_to_cpu(src->type);
	dst->flags = be32_to_cpu(src->flags);
	dst->actual = be32_to_cpu(src->actual);
	dst->user.datainteg = be16_to_cpu(src->user.datainteg);

	return 0;
}

int ffs_lookup_part(struct ffs_handle *ffs, const char *name,
		    uint32_t *part_idx)
{
	struct ffs_entry ent;
	uint32_t i;
	int rc;

	/* Lookup the requested partition */
	for (i = 0; i < ffs->hdr.entry_count; i++) {
		struct ffs_entry *src_ent  = ffs_get_part(ffs, i, NULL);
		rc = ffs_check_convert_entry(&ent, src_ent);
		if (rc) {
			FL_ERR("FFS: Bad entry %d in partition map\n", i);
			continue;
		}
		if (!strncmp(name, ent.name, sizeof(ent.name)))
			break;
	}
	if (i >= ffs->hdr.entry_count)
		return FFS_ERR_PART_NOT_FOUND;
	if (part_idx)
		*part_idx = i;
	return 0;
}

int ffs_part_info(struct ffs_handle *ffs, uint32_t part_idx,
		  char **name, uint32_t *start,
		  uint32_t *total_size, uint32_t *act_size, bool *ecc)
{
	struct ffs_entry *raw_ent;
	struct ffs_entry ent;
	char *n;
	int rc;

	if (part_idx >= ffs->hdr.entry_count)
		return FFS_ERR_PART_NOT_FOUND;

	raw_ent = ffs_get_part(ffs, part_idx, NULL);
	if (!raw_ent)
		return FFS_ERR_PART_NOT_FOUND;

	rc = ffs_check_convert_entry(&ent, raw_ent);
	if (rc) {
		FL_ERR("FFS: Bad entry %d in partition map\n", part_idx);
		return rc;
	}
	if (start)
		*start = ent.base * ffs->hdr.block_size;
	if (total_size)
		*total_size = ent.size * ffs->hdr.block_size;
	if (act_size)
		*act_size = ent.actual;
	if (ecc)
		*ecc = ((ent.user.datainteg & FFS_ENRY_INTEG_ECC) != 0);

	if (name) {
		n = malloc(PART_NAME_MAX + 1);
		memset(n, 0, PART_NAME_MAX + 1);
		strncpy(n, ent.name, PART_NAME_MAX);
		*name = n;
	}
	return 0;
}

int ffs_update_act_size(struct ffs_handle *ffs, uint32_t part_idx,
			uint32_t act_size)
{
	struct ffs_entry *ent;
	uint32_t offset;

	if (part_idx >= ffs->hdr.entry_count) {
		FL_DBG("FFS: Entry out of bound\n");
		return FFS_ERR_PART_NOT_FOUND;
	}

	ent = ffs_get_part(ffs, part_idx, &offset);
	if (!ent) {
		FL_DBG("FFS: Entry not found\n");
		return FFS_ERR_PART_NOT_FOUND;
	}
	FL_DBG("FFS: part index %d at offset 0x%08x\n",
	       part_idx, offset);

	/*
	 * NOTE: We are accessing the unconverted ffs_entry from the PNOR here
	 * (since we are going to write it back) so we need to be endian safe.
	 */
	if (ent->actual == cpu_to_be32(act_size)) {
		FL_DBG("FFS: ent->actual alrady matches: 0x%08x==0x%08x\n",
		       cpu_to_be32(act_size), ent->actual);
		return 0;
	}
	ent->actual = cpu_to_be32(act_size);
	ent->checksum = ffs_checksum(ent, FFS_ENTRY_SIZE_CSUM);
	if (!ffs->chip)
		return 0;
	return flash_smart_write(ffs->chip, offset, ent, FFS_ENTRY_SIZE);
}

#define COPY_BUFFER_LENGTH 4096

/*
 * This provides a wrapper around flash_read on ECCed data
 * len is length of data without ECC attached
 */
int ffs_flash_read(struct flash_chip *c, uint32_t pos, void *buf, uint32_t len,
		   bool ecc)
{
	uint64_t *bufecc;
	uint32_t copylen;
	int rc;
	uint8_t ret;

	if (!ecc)
		return flash_read(c, pos, buf, len);

	/* Copy the buffer in chunks */
	bufecc = malloc(ECC_BUFFER_SIZE(COPY_BUFFER_LENGTH));
	if (!bufecc)
		return FLASH_ERR_MALLOC_FAILED;

	while (len > 0) {
		/* What's left to copy? */
		copylen = MIN(len, COPY_BUFFER_LENGTH);

		/* Read ECCed data from flash */
		rc = flash_read(c, pos, bufecc, ECC_BUFFER_SIZE(copylen));
		if (rc)
			goto err;

		/* Extract data from ECCed data */
		ret = eccmemcpy(buf, bufecc, copylen);
		if (ret == UE) {
			rc = FLASH_ERR_ECC_INVALID;
			goto err;
		}

		/* Update for next copy */
		len -= copylen;
		buf = (uint8_t *)buf + copylen;
		pos += ECC_BUFFER_SIZE(copylen);
	}

	return 0;

err:
	free(bufecc);
	return rc;
}
