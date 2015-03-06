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
#include <lock.h>
#include <opal.h>
#include <opal-msg.h>
#include <opal-api.h>
#include <device.h>
#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <ecc.h>

struct flash {
	bool			registered;
	bool			busy;
	struct flash_chip	*chip;
	uint32_t		size;
	uint32_t		block_size;
};

#define MAX_FLASH 1
static struct flash flashes[MAX_FLASH];
static struct flash *system_flash;

/* Using a single lock as we only have one flash at present. */
static struct lock flash_lock;

/* nvram-on-flash support */
static struct flash *nvram_flash;
static u32 nvram_offset, nvram_size;

bool flash_reserve(void)
{
	bool rc = false;

	if (!try_lock(&flash_lock))
		return false;

	if (!system_flash->busy) {
		system_flash->busy = true;
		rc = true;
	}
	unlock(&flash_lock);

	return rc;
}

void flash_release(void)
{
	lock(&flash_lock);
	system_flash->busy = false;
	unlock(&flash_lock);
}

static int flash_nvram_info(uint32_t *total_size)
{
	int rc;

	lock(&flash_lock);
	if (!nvram_flash) {
		rc = OPAL_HARDWARE;
	} else if (nvram_flash->busy) {
		rc = OPAL_BUSY;
	} else {
		*total_size = nvram_size;
		rc = OPAL_SUCCESS;
	}
	unlock(&flash_lock);

	return rc;
}

static int flash_nvram_start_read(void *dst, uint32_t src, uint32_t len)
{
	int rc;

	if (!try_lock(&flash_lock))
		return OPAL_BUSY;

	if (!nvram_flash) {
		rc = OPAL_HARDWARE;
		goto out;
	}

	if (nvram_flash->busy) {
		rc = OPAL_BUSY;
		goto out;
	}

	if ((src + len) > nvram_size) {
		prerror("FLASH_NVRAM: read out of bound (0x%x,0x%x)\n",
			src, len);
		rc = OPAL_PARAMETER;
		goto out;
	}

	rc = flash_read(nvram_flash->chip, nvram_offset + src, dst, len);

out:
	unlock(&flash_lock);
	if (!rc)
		nvram_read_complete(true);
	return rc;
}

static int flash_nvram_write(uint32_t dst, void *src, uint32_t len)
{
	int rc;

	if (!try_lock(&flash_lock))
		return OPAL_BUSY;

	if (nvram_flash->busy) {
		rc = OPAL_BUSY;
		goto out;
	}

	/* TODO: When we have async jobs for PRD, turn this into one */

	if ((dst + len) > nvram_size) {
		prerror("FLASH_NVRAM: write out of bound (0x%x,0x%x)\n",
			dst, len);
		rc = OPAL_PARAMETER;
		goto out;
	}
	rc = flash_smart_write(nvram_flash->chip, nvram_offset + dst, src, len);

out:
	unlock(&flash_lock);
	return rc;
}

static int flash_nvram_probe(struct flash *flash, struct ffs_handle *ffs)
{
	uint32_t start, size, part;
	int rc;

	prlog(PR_INFO, "FLASH: probing for NVRAM\n");

	rc = ffs_lookup_part(ffs, "NVRAM", &part);
	if (rc) {
		prlog(PR_WARNING, "FLASH: no NVRAM partition found\n");
		return OPAL_HARDWARE;
	}

	rc = ffs_part_info(ffs, part, NULL,
			   &start, &size, NULL, NULL);
	if (rc) {
		prlog(PR_ERR, "FLASH: Can't parse ffs info for NVRAM\n");
		return OPAL_HARDWARE;
	}

	nvram_flash = flash;
	nvram_offset = start;
	nvram_size = size;

	platform.nvram_info = flash_nvram_info;
	platform.nvram_start_read = flash_nvram_start_read;
	platform.nvram_write = flash_nvram_write;

	return 0;
}

/* core flash support */

static void flash_add_dt_partition_node(struct dt_node *flash_node, char *name,
		uint32_t start, uint32_t size)
{
	struct dt_node *part_node;

	part_node = dt_new_addr(flash_node, "partition", start);
	dt_add_property_cells(part_node, "reg", start, size);
	if (name && strlen(name))
		dt_add_property_strings(part_node, "label", name);
}

static struct dt_node *flash_add_dt_node(struct flash *flash, int id,
		struct ffs_handle *ffs)
{
	struct dt_node *flash_node;
	int i;

	flash_node = dt_new_addr(opal_node, "flash", id);
	dt_add_property_strings(flash_node, "compatible", "ibm,opal-flash");
	dt_add_property_cells(flash_node, "ibm,opal-id", id);
	dt_add_property_cells(flash_node, "reg", 0, flash->size);
	dt_add_property_cells(flash_node, "ibm,flash-block-size",
			flash->block_size);

	/* we fix to 32-bits */
	dt_add_property_cells(flash_node, "#address-cells", 1);
	dt_add_property_cells(flash_node, "#size-cells", 1);

	if (!ffs)
		return flash_node;

	for (i = 0; ; i++) {
		uint32_t start, size;
		char *name;
		int rc;

		rc = ffs_part_info(ffs, i, &name, &start, NULL, &size, NULL);
		if (rc)
			break;

		flash_add_dt_partition_node(flash_node, name, start, size);
	}

	return flash_node;
}

static void setup_system_flash(struct flash *flash, struct dt_node *node,
		const char *name, struct ffs_handle *ffs)
{
	char *path;

	if (system_flash) {
		prlog(PR_WARNING, "FLASH: attempted to register a second "
				"system flash device %s\n", name);
		return;
	}

	if (!ffs) {
		prlog(PR_WARNING, "FLASH: attempted to register system flash "
				"%s, wwhich has no partition info\n", name);
		return;
	}

	system_flash = flash;
	path = dt_get_path(node);
	dt_add_property_string(dt_chosen, "ibm,system-flash", path);
	free(path);

	prlog(PR_INFO, "FLASH: registered system flash device %s\n", name);

	flash_nvram_probe(flash, ffs);
}

int flash_register(struct flash_chip *chip, bool is_system_flash)
{
	uint32_t size, block_size;
	struct ffs_handle *ffs;
	struct dt_node *node;
	struct flash *flash;
	const char *name;
	unsigned int i;
	int rc;

	rc = flash_get_info(chip, &name, &size, &block_size);
	if (rc)
		return rc;

	prlog(PR_INFO, "FLASH: registering flash device %s "
			"(size 0x%x, blocksize 0x%x)\n",
			name ?: "(unnamed)", size, block_size);

	lock(&flash_lock);
	for (i = 0; i < ARRAY_SIZE(flashes); i++) {
		if (flashes[i].registered)
			continue;

		flash = &flashes[i];
		flash->registered = true;
		flash->busy = false;
		flash->chip = chip;
		flash->size = size;
		flash->block_size = block_size;
		break;
	}

	if (!flash) {
		unlock(&flash_lock);
		prlog(PR_ERR, "FLASH: No flash slots available\n");
		return OPAL_RESOURCE;
	}

	rc = ffs_open_flash(chip, 0, flash->size, &ffs);
	if (rc) {
		prlog(PR_WARNING, "FLASH: No ffs info; "
				"using raw device only\n");
		ffs = NULL;
	}

	node = flash_add_dt_node(flash, i, ffs);

	if (is_system_flash)
		setup_system_flash(flash, node, name, ffs);

	if (ffs)
		ffs_close(ffs);

	unlock(&flash_lock);

	return OPAL_SUCCESS;
}

enum flash_op {
	FLASH_OP_READ,
	FLASH_OP_WRITE,
	FLASH_OP_ERASE,
};

static int64_t opal_flash_op(enum flash_op op, uint64_t id, uint64_t offset,
		uint64_t buf, uint64_t size, uint64_t token)
{
	struct flash *flash;
	int rc;

	if (id >= ARRAY_SIZE(flashes))
		return OPAL_PARAMETER;

	if (!try_lock(&flash_lock))
		return OPAL_BUSY;

	flash = &flashes[id];

	if (flash->busy) {
		rc = OPAL_BUSY;
		goto err;
	}

	if (!flash->registered) {
		rc = OPAL_PARAMETER;
		goto err;
	}

	if (size >= flash->size || offset >= flash->size
			|| offset + size >= flash->size) {
		rc = OPAL_PARAMETER;
		goto err;
	}

	switch (op) {
	case FLASH_OP_READ:
		rc = flash_read(flash->chip, offset, (void *)buf, size);
		break;
	case FLASH_OP_WRITE:
		rc = flash_write(flash->chip, offset, (void *)buf, size, false);
		break;
	case FLASH_OP_ERASE:
		rc = flash_erase(flash->chip, offset, size);
		break;
	default:
		assert(0);
	}

	if (rc) {
		rc = OPAL_HARDWARE;
		goto err;
	}

	unlock(&flash_lock);

	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL, token, rc);
	return OPAL_ASYNC_COMPLETION;

err:
	unlock(&flash_lock);
	return rc;
}

static int64_t opal_flash_read(uint64_t id, uint64_t offset, uint64_t buf,
		uint64_t size, uint64_t token)
{
	return opal_flash_op(FLASH_OP_READ, id, offset, buf, size, token);
}

static int64_t opal_flash_write(uint64_t id, uint64_t offset, uint64_t buf,
		uint64_t size, uint64_t token)
{
	return opal_flash_op(FLASH_OP_WRITE, id, offset, buf, size, token);
}

static int64_t opal_flash_erase(uint64_t id, uint64_t offset, uint64_t size,
		uint64_t token)
{
	return opal_flash_op(FLASH_OP_ERASE, id, offset, 0L, size, token);
}

opal_call(OPAL_FLASH_READ, opal_flash_read, 5);
opal_call(OPAL_FLASH_WRITE, opal_flash_write, 5);
opal_call(OPAL_FLASH_ERASE, opal_flash_erase, 4);

/* flash resource API */
static struct {
	enum resource_id	id;
	uint32_t		subid;
	char			name[PART_NAME_MAX+1];
} part_name_map[] = {
	{ RESOURCE_ID_KERNEL,	RESOURCE_SUBID_NONE,		"BOOTKERNEL" },
	{ RESOURCE_ID_INITRAMFS,RESOURCE_SUBID_NONE,		"ROOTFS" },
	{ RESOURCE_ID_CAPP,	RESOURCE_SUBID_SUPPORTED,	"CAPP" },
};

/* This mimics the hostboot SBE format */
#define FLASH_SUBPART_ALIGNMENT 0x1000
#define FLASH_SUBPART_HEADER_SIZE FLASH_SUBPART_ALIGNMENT

struct flash_hostboot_toc {
	be32 ec;
	be32 offset; /* From start of header.  4K aligned */
	be32 size;
};
#define FLASH_HOSTBOOT_TOC_MAX_ENTRIES ((FLASH_SUBPART_HEADER_SIZE - 8) \
		/sizeof(struct flash_hostboot_toc))

struct flash_hostboot_header {
	char eyecatcher[4];
	be32 version;
	struct flash_hostboot_toc toc[FLASH_HOSTBOOT_TOC_MAX_ENTRIES];
};

/* start and total size include ECC */
static int flash_find_subpartition(struct flash_chip *chip, uint32_t subid,
				   uint32_t *start, uint32_t *total_size,
				   bool *ecc)
{
	struct flash_hostboot_header *header;
	char eyecatcher[5];
	uint32_t i, partsize;
	int rc;

	header = malloc(FLASH_SUBPART_HEADER_SIZE);
	if (!header)
		return false;

	/* Get raw partition size without ECC */
	partsize = *total_size;
	if (ecc)
		partsize = BUFFER_SIZE_MINUS_ECC(*total_size);

	/* Get the TOC */
	rc = flash_read_corrected(chip, *start, header,
			FLASH_SUBPART_HEADER_SIZE, ecc);
	if (rc) {
		prerror("FLASH: flash subpartition TOC read failed %i\n", rc);
		goto end;
	}

	/* Perform sanity */
	i = be32_to_cpu(header->version);
	if (i != 1) {
		prerror("FLASH: flash subpartition TOC version unknown %i\n", i);
		rc = OPAL_RESOURCE;
		goto end;
	}
	/* NULL terminate eyecatcher */
	strncpy(eyecatcher, header->eyecatcher, 4);
	eyecatcher[4] = 0;
	prlog(PR_DEBUG, "FLASH: flash subpartition eyecatcher %s\n",
			eyecatcher);

	rc = OPAL_RESOURCE;
	for (i = 0; i< FLASH_HOSTBOOT_TOC_MAX_ENTRIES; i++) {
		uint32_t ec, offset, size;

		ec = be32_to_cpu(header->toc[i].ec);
		offset = be32_to_cpu(header->toc[i].offset);
		size = be32_to_cpu(header->toc[i].size);
		/* Check for null terminating entry */
		if (!ec && !offset && !size) {
			prerror("FLASH: flash subpartition not found.\n");
			goto end;
		}

		if (ec != subid)
			continue;

		/* Sanity check the offset and size. */
		if (offset + size > partsize) {
			prerror("FLASH: flash subpartition too big: %i\n", i);
			goto end;
		}
		if (!size) {
			prerror("FLASH: flash subpartition zero size: %i\n", i);
			goto end;
		}
		if (offset < FLASH_SUBPART_HEADER_SIZE) {
			prerror("FLASH: flash subpartition "
					"offset too small: %i\n", i);
			goto end;
		}

		prlog(PR_DEBUG, "FLASH: flash found subpartition: "
				"%i size: %i offset %i\n",
				i, size, offset);

		/*
		 * Adjust the start and size.  The start location in the needs
		 * to account for ecc but the size doesn't.
		 */
		*start += offset;
		*total_size = size;
		if (ecc) {
			*start += ECC_SIZE(offset);
			*total_size += ECC_SIZE(size);
		}
		rc = 0;
		goto end;
	}

end:
	free(header);
	return rc;
}

/*
 * load a resource from FLASH
 * buf and len shouldn't account for ECC even if partition is ECCed.
 */
bool flash_load_resource(enum resource_id id, uint32_t subid,
		void *buf, size_t *len)
{
	int i, rc, part_num, part_size, part_start, size;
	struct ffs_handle *ffs;
	struct flash *flash;
	const char *name;
	bool status, ecc;

	status = false;

	lock(&flash_lock);

	if (!system_flash)
		goto out_unlock;

	flash = system_flash;

	if (flash->busy)
		goto out_unlock;

	for (i = 0, name = NULL; i < ARRAY_SIZE(part_name_map); i++) {
		if (part_name_map[i].id == id) {
			name = part_name_map[i].name;
			break;
		}
	}
	if (!name) {
		prerror("FLASH: Couldn't find partition for id %d\n", id);
		goto out_unlock;
	}
	/*
	 * If partition doesn't have a subindex but the caller specifies one,
	 * we fail.  eg. kernel partition doesn't have a subindex
	 */
	if ((part_name_map[i].subid == RESOURCE_SUBID_NONE) &&
	    (subid != RESOURCE_SUBID_NONE)) {
		prerror("PLAT: Partition %s doesn't have subindex\n", name);
		return false;
	}

	rc = ffs_open_flash(flash->chip, 0, flash->size, &ffs);
	if (rc) {
		prerror("FLASH: Can't open ffs handle\n");
		goto out_unlock;
	}

	rc = ffs_lookup_part(ffs, name, &part_num);
	if (rc) {
		prerror("FLASH: No %s partition\n", name);
		goto out_free_ffs;
	}
	rc = ffs_part_info(ffs, part_num, NULL,
			   &part_start, &part_size, NULL, &ecc);
	if (rc) {
		prerror("FLASH: Failed to get %s partition info\n", name);
		goto out_free_ffs;
	}
	prlog(PR_DEBUG,"FLASH: %s partition %s ECC\n",
	      name, ecc  ? "has" : "doesn't have");

	/*
	 * part_start/size are raw pointers into the partition.
	 *  ie. they will account for ECC if included.
	 */

	/* Find the sub partition if required */
	if (subid != RESOURCE_SUBID_NONE) {
		rc = flash_find_subpartition(flash->chip, subid, &part_start,
					     &part_size, &ecc);
		if (rc)
			goto out_free_ffs;
	}

	/* Work out what the final size of buffer will be without ECC */
	size = part_size;
	if (ecc) {
		if ECC_BUFFER_SIZE_CHECK(part_size) {
			prerror("FLASH: %s image invalid size for ECC %d\n",
				name, part_size);
			goto out_free_ffs;
		}
		size = BUFFER_SIZE_MINUS_ECC(part_size);
	}

	if (size > *len) {
		prerror("FLASH: %s image too large (%d > %zd)\n", name,
			part_size, *len);
		goto out_free_ffs;
	}

	rc = flash_read_corrected(flash->chip, part_start, buf, size, ecc);
	if (rc) {
		prerror("FLASH: failed to read %s partition\n", name);
		goto out_free_ffs;
	}

	*len = size;
	status = true;

out_free_ffs:
	ffs_close(ffs);
out_unlock:
	unlock(&flash_lock);
	return status;
}
