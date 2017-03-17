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
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef __SKIBOOT__
#include <sys/types.h>
#include <unistd.h>
#else
static void *calloc(size_t num, size_t size)
{
	void *ptr = malloc(num * size);
	if (ptr)
		memset(ptr, 0, num * size);
	return ptr;
}
#endif

#include "ffs.h"

#define __unused __attribute__((unused))

struct ffs_handle {
	struct ffs_hdr		hdr;	/* Converted header */
	uint32_t		toc_offset;
	uint32_t		max_size;
	/* The converted header knows how big this is */
	struct __ffs_hdr *cache;
	struct blocklevel_device *bl;
};

static uint32_t ffs_checksum(void* data, size_t size)
{
	uint32_t i, csum = 0;

	for (i = csum = 0; i < (size/4); i++)
		csum ^= ((uint32_t *)data)[i];
	return csum;
}

/* Helper functions for typesafety and size safety */
static uint32_t ffs_hdr_checksum(struct __ffs_hdr *hdr)
{
	return ffs_checksum(hdr, sizeof(struct __ffs_hdr));
}

static uint32_t ffs_entry_checksum(struct __ffs_entry *ent)
{
	return ffs_checksum(ent, sizeof(struct __ffs_entry));
}

__unused static int ffs_num_entries(struct ffs_hdr *hdr)
{
	struct ffs_entry *ent;
	int num_entries = 0;
	list_for_each(&hdr->entries, ent, list)
		num_entries++;
	if (num_entries == 0)
		FL_DBG("%s returned zero!\n", __func__);
	return num_entries;
}

__unused static size_t ffs_hdr_raw_size(int num_entries)
{
	return sizeof(struct __ffs_hdr) + num_entries * sizeof(struct __ffs_entry);
}

static int ffs_check_convert_header(struct ffs_hdr *dst, struct __ffs_hdr *src)
{
	if (be32_to_cpu(src->magic) != FFS_MAGIC)
		return FFS_ERR_BAD_MAGIC;
	dst->version = be32_to_cpu(src->version);
	if (dst->version != FFS_VERSION_1)
		return FFS_ERR_BAD_VERSION;
	if (ffs_hdr_checksum(src) != 0)
		return FFS_ERR_BAD_CKSUM;
	if (be32_to_cpu(src->entry_size) != sizeof(struct __ffs_entry))
		return FFS_ERR_BAD_SIZE;
	if ((be32_to_cpu(src->entry_size) * be32_to_cpu(src->entry_count)) >
			(be32_to_cpu(src->block_size) * be32_to_cpu(src->size)))
		return FLASH_ERR_PARM_ERROR;

	dst->block_size = be32_to_cpu(src->block_size);
	dst->size = be32_to_cpu(src->size) * dst->block_size;
	dst->block_count = be32_to_cpu(src->block_count);

	return 0;
}

static int ffs_entry_user_to_flash(struct __ffs_entry_user *dst,
		struct ffs_entry_user *src)
{
	memset(dst, 0, sizeof(struct __ffs_entry_user));
	dst->datainteg = cpu_to_be16(src->datainteg);
	dst->vercheck = src->vercheck;
	dst->miscflags = src->miscflags;

	return 0;
}

static int ffs_entry_user_to_cpu(struct ffs_entry_user *dst,
		struct __ffs_entry_user *src)
{
	memset(dst, 0, sizeof(struct ffs_entry_user));
	dst->datainteg = be16_to_cpu(src->datainteg);
	dst->vercheck = src->vercheck;
	dst->miscflags = src->miscflags;

	return 0;
}

static int ffs_entry_to_flash(struct ffs_hdr *hdr,
		struct __ffs_entry *dst, struct ffs_entry *src)
{
	int rc, index = 1; /* On flash indexes start at 1 */
	struct ffs_entry *ent = NULL;

	if (!hdr || !dst || !src)
		return -1;

	list_for_each(&hdr->entries, ent, list) {
		if (ent == src)
			break;
		index++;
	}

	if (!ent)
		return FFS_ERR_PART_NOT_FOUND;

	memcpy(dst->name, src->name, sizeof(dst->name));
	dst->name[FFS_PART_NAME_MAX] = '\0';
	dst->base = cpu_to_be32(src->base / hdr->block_size);
	dst->size = cpu_to_be32(src->size / hdr->block_size);
	dst->pid = cpu_to_be32(src->pid);
	dst->id = cpu_to_be32(index);
	dst->type = cpu_to_be32(src->type); /* TODO: Check that it is valid? */
	dst->flags = cpu_to_be32(src->flags);
	dst->actual = cpu_to_be32(src->actual);
	rc = ffs_entry_user_to_flash(&dst->user, &src->user);
	dst->checksum = ffs_entry_checksum(dst);

	return rc;
}

static int ffs_entry_to_cpu(struct ffs_hdr *hdr,
		struct ffs_entry *dst, struct __ffs_entry *src)
{
	int rc;

	if (ffs_entry_checksum(src) != 0)
		return FFS_ERR_BAD_CKSUM;

	memcpy(dst->name, src->name, sizeof(dst->name));
	dst->name[FFS_PART_NAME_MAX] = '\0';
	dst->base = be32_to_cpu(src->base) * hdr->block_size;
	dst->size = be32_to_cpu(src->size) * hdr->block_size;
	dst->actual = be32_to_cpu(src->actual);
	dst->pid = be32_to_cpu(src->pid);
	dst->type = be32_to_cpu(src->type); /* TODO: Check that it is valid? */
	dst->flags = be32_to_cpu(src->flags);
	rc = ffs_entry_user_to_cpu(&dst->user, &src->user);

	return rc;
}

static struct ffs_entry *ffs_get_part(struct ffs_handle *ffs, uint32_t index)
{
	int i = 0;
	struct ffs_entry *ent = NULL;

	list_for_each(&ffs->hdr.entries, ent, list)
		if (i++ == index)
			break;

	return ent;
}

bool has_ecc(struct ffs_entry *ent)
{
	return ((ent->user.datainteg & FFS_ENRY_INTEG_ECC) != 0);
}

int ffs_init(uint32_t offset, uint32_t max_size, struct blocklevel_device *bl,
		struct ffs_handle **ffs, bool mark_ecc)
{
	struct __ffs_hdr blank_hdr;
	struct __ffs_hdr raw_hdr;
	struct ffs_handle *f;
	uint64_t total_size;
	int rc, i;

	if (!ffs || !bl)
		return FLASH_ERR_PARM_ERROR;
	*ffs = NULL;

	rc = blocklevel_get_info(bl, NULL, &total_size, NULL);
	if (rc) {
		FL_ERR("FFS: Error %d retrieving flash info\n", rc);
		return rc;
	}
	if (total_size > UINT_MAX)
		return FLASH_ERR_VERIFY_FAILURE;
	if ((offset + max_size) < offset)
		return FLASH_ERR_PARM_ERROR;

	if ((max_size > total_size))
		return FLASH_ERR_PARM_ERROR;

	/* Read flash header */
	rc = blocklevel_read(bl, offset, &raw_hdr, sizeof(raw_hdr));
	if (rc) {
		FL_ERR("FFS: Error %d reading flash header\n", rc);
		return rc;
	}

	/*
	 * Flash controllers can get deconfigured or otherwise upset, when this
	 * happens they return all 0xFF bytes.
	 * An __ffs_hdr consisting of all 0xFF cannot be valid and it would be
	 * nice to drop a hint to the user to help with debugging. This will
	 * help quickly differentiate between flash corruption and standard
	 * type 'reading from the wrong place' errors vs controller errors or
	 * reading erased data.
	 */
	memset(&blank_hdr, UINT_MAX, sizeof(struct __ffs_hdr));
	if (memcmp(&blank_hdr, &raw_hdr, sizeof(struct __ffs_hdr)) == 0) {
		FL_ERR("FFS: Reading the flash has returned all 0xFF.\n");
		FL_ERR("     Are you reading erased flash?\n");
		FL_ERR("     Is something else using the flash controller?\n");
		return FLASH_ERR_BAD_READ;
	}

	/* Allocate ffs_handle structure and start populating */
	f = calloc(1, sizeof(*f));
	if (!f)
		return FLASH_ERR_MALLOC_FAILED;

	f->toc_offset = offset;
	f->max_size = max_size;
	f->bl = bl;

	/* Convert and check flash header */
	rc = ffs_check_convert_header(&f->hdr, &raw_hdr);
	if (rc) {
		FL_INF("FFS: Flash header not found. Code: %d\n", rc);
		goto out;
	}

	/* Check header is sane */
	if ((f->hdr.block_count * f->hdr.block_size) > max_size) {
		rc = FLASH_ERR_PARM_ERROR;
		FL_ERR("FFS: Flash header exceeds max flash size\n");
		goto out;
	}

	/*
	 * Grab the entire partition header
	 */
	/* Check for overflow or a silly size */
	if (!f->hdr.size || f->hdr.size % f->hdr.block_size != 0) {
		rc = FLASH_ERR_MALLOC_FAILED;
		FL_ERR("FFS: Cache size overflow (0x%x * 0x%x)\n",
				f->hdr.block_size, f->hdr.size);
		goto out;
	}

	FL_DBG("FFS: Partition map size: 0x%x\n", f->hdr.size);

	/* Allocate cache */
	f->cache = malloc(f->hdr.size);
	if (!f->cache) {
		rc = FLASH_ERR_MALLOC_FAILED;
		goto out;
	}

	/* Read the cached map */
	rc = blocklevel_read(bl, offset, f->cache, f->hdr.size);
	if (rc) {
		FL_ERR("FFS: Error %d reading flash partition map\n", rc);
		goto out;
	}

	list_head_init(&f->hdr.entries);
	for (i = 0; i < be32_to_cpu(raw_hdr.entry_count); i++) {
		struct ffs_entry *ent = calloc(1, sizeof(struct ffs_entry));
		if (!ent) {
			rc = FLASH_ERR_MALLOC_FAILED;
			goto out;
		}

		list_add_tail(&f->hdr.entries, &ent->list);
		rc = ffs_entry_to_cpu(&f->hdr, ent, &f->cache->entries[i]);
		if (rc)
			goto out;

		if (mark_ecc && has_ecc(ent)) {
			rc = blocklevel_ecc_protect(bl, ent->base, ent->size);
			if (rc) {
				FL_ERR("Failed to blocklevel_ecc_protect(0x%08x, 0x%08x)\n",
				       ent->base, ent->size);
				goto out;
			}
		}
	}

out:
	if (rc == 0)
		*ffs = f;
	else
		ffs_close(f);

	return rc;
}

void ffs_close(struct ffs_handle *ffs)
{
	struct ffs_entry *ent, *next;

	list_for_each_safe(&ffs->hdr.entries, ent, next, list) {
		list_del(&ent->list);
		free(ent);
	}

	if (ffs->cache)
		free(ffs->cache);

	free(ffs);
}

int ffs_lookup_part(struct ffs_handle *ffs, const char *name,
		    uint32_t *part_idx)
{
	int i = 0;
	struct ffs_entry *ent = NULL;

	list_for_each(&ffs->hdr.entries, ent, list) {
		if (!strncmp(name, ent->name, sizeof(ent->name)))
			break;
		i++;
	}

	if (part_idx)
		*part_idx = i;
	return ent ? 0 : FFS_ERR_PART_NOT_FOUND;
}

int ffs_part_info(struct ffs_handle *ffs, uint32_t part_idx,
		  char **name, uint32_t *start,
		  uint32_t *total_size, uint32_t *act_size, bool *ecc)
{
	struct ffs_entry *ent;
	char *n;

	ent = ffs_get_part(ffs, part_idx);
	if (!ent)
		return FFS_ERR_PART_NOT_FOUND;

	if (start)
		*start = ent->base;
	if (total_size)
		*total_size = ent->size;
	if (act_size)
		*act_size = ent->actual;
	if (ecc)
		*ecc = has_ecc(ent);

	if (name) {
		n = calloc(1, FFS_PART_NAME_MAX + 1);
		if (!n)
			return FLASH_ERR_MALLOC_FAILED;
		strncpy(n, ent->name, FFS_PART_NAME_MAX);
		*name = n;
	}
	return 0;
}

/*
 * There are quite a few ways one might consider two ffs_handles to be the
 * same. For the purposes of this function we are trying to detect a fairly
 * specific scenario:
 * Consecutive calls to ffs_next_side() may succeed but have gone circular.
 * It is possible that the OTHER_SIDE partition in one TOC actually points
 * back to the TOC to first ffs_handle.
 * This function compares for this case, therefore the requirements are
 * simple, the underlying blocklevel_devices must be the same along with
 * the toc_offset and the max_size.
 */
bool ffs_equal(struct ffs_handle *one, struct ffs_handle *two)
{
	return (!one && !two) || (one && two && one->bl == two->bl
		&& one->toc_offset == two->toc_offset
		&& one->max_size == two->max_size);
}

int ffs_next_side(struct ffs_handle *ffs, struct ffs_handle **new_ffs,
		bool mark_ecc)
{
	int rc;
	uint32_t index, offset, max_size;

	if (!ffs || !new_ffs)
		return FLASH_ERR_PARM_ERROR;

	*new_ffs = NULL;

	rc = ffs_lookup_part(ffs, "OTHER_SIDE", &index);
	if (rc)
		return rc;

	rc = ffs_part_info(ffs, index, NULL, &offset, &max_size, NULL, NULL);
	if (rc)
		return rc;

	return ffs_init(offset, max_size, ffs->bl, new_ffs, mark_ecc);
}

int ffs_update_act_size(struct ffs_handle *ffs, uint32_t part_idx,
			uint32_t act_size)
{
	struct ffs_entry *ent;
	struct __ffs_entry raw_ent;
	uint32_t offset;
	int rc;

	ent = ffs_get_part(ffs, part_idx);
	if (!ent) {
		FL_DBG("FFS: Entry not found\n");
		return FFS_ERR_PART_NOT_FOUND;
	}
	offset = ent->base;
	FL_DBG("FFS: part index %d at offset 0x%08x\n",
	       part_idx, offset);

	if (ent->actual == act_size) {
		FL_DBG("FFS: ent->actual alrady matches: 0x%08x==0x%08x\n",
		       act_size, ent->actual);
		return 0;
	}
	ent->actual = act_size;

	rc = ffs_entry_to_flash(&ffs->hdr, &raw_ent, ent);
	if (rc)
		return rc;

	return blocklevel_smart_write(ffs->bl, offset, &raw_ent, sizeof(struct __ffs_entry));
}

