// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <endian.h>
#include <lock.h>
#include <opal-api.h>
#include <libflash/errors.h>
#include <libflash/ffs.h>
#include "pldm.h"

/*
 * This struct is used to map a PNOR sections.
 * The content is deriving from the hb_lid_ids PLDM BIOS Attribute.
 */
struct pldm_lid {
	struct list_node	list;
	uint32_t		start;
	uint32_t		handle;
	uint32_t		length;
	char			name[FFS_PART_NAME_MAX + 1];
	char			id[FFS_PART_NAME_MAX + 1];
};

static LIST_HEAD(lid_files);

#define MEGABYTE (1024*1024)

/*
 * When using PLDM for PNOR Resource Provider operations,
 * reserve 32 MB of VMM address space per section.
 * Note that all of this space may not actually be used by each section.
 */
#define VMM_SIZE_RESERVED_PER_SECTION (32 * MEGABYTE)

/*
 * Print the attributes of lid files.
 */
static void print_lid_files_attr(void)
{
	struct pldm_lid *lid = NULL;

	list_for_each(&lid_files, lid, list)
		prlog(PR_NOTICE, "name: %s, id: %s, handle: %d, length: 0x%x, start: 0x%x\n",
				 lid->name, lid->id, lid->handle, lid->length, lid->start);
}

/*
 * Return the number of lid files.
 */
static uint32_t get_lids_count(void)
{
	struct pldm_lid *lid = NULL;
	uint32_t count = 0;

	list_for_each(&lid_files, lid, list)
		count++;

	return count;
}

/*
 * parse the "hb_lid_ids" string
 * <ATTR_a>=<lid_id_1>,<ATTR_b>=<lid_id_2>
 */
static int parse_hb_lid_ids_string(char *str)
{
	struct pldm_lid *lid, *tmp;
	const char *pp = "=";
	char *attr, *attr_end;
	int rc, count = 1;
	char *lid_id;

	for (char *p = strtok(str, ","); p != NULL; p = strtok(NULL, ",")) {
		lid = zalloc(sizeof(struct pldm_lid));
		if (!lid) {
			prlog(PR_ERR, "Error allocating pldm_lid structure\n");
			rc = OPAL_NO_MEM;
			goto err;
		}

		/* parse the string <attr>=<lid_id> */
		attr = p;
		while ((*pp != *p) && (*p != '\0'))
			p++;

		attr_end = p;
		lid_id = ++p;
		*attr_end = '\0';

		strcpy(lid->name, attr);
		strcpy(lid->id, lid_id);

		/* reserve 32 MB of VMM address space per section.
		 * Address 0x0 -> 0x2000000:   'fake' header flash
		 * Address 0x2000000 -> 0x4000000: lid id 1
		 * Address 0x4000000 -> 0x6000000: lid id 2
		 * ....
		 */
		lid->start = VMM_SIZE_RESERVED_PER_SECTION * count;

		/* handle and length */
		rc = pldm_find_file_handle_by_lid_id(lid->id,
						     &lid->handle,
						     &lid->length);
		/* OPAL_PARAMETER means that lid_id is present in hb_lid_ids,
		 * but we don't have any file attribute information in the
		 * file table, so continue on the next item.
		 */
		if ((rc) && (rc != OPAL_PARAMETER))
			goto err;

		if (lid->length > VMM_SIZE_RESERVED_PER_SECTION) {
			prlog(PR_ERR, "file length (0x%x) > virtual size reserved per "
				      "section (0x%x)\n",
				      lid->length, VMM_SIZE_RESERVED_PER_SECTION);
			rc = OPAL_RESOURCE;
			goto err;
		}

		/* add new member in the global list */
		list_add_tail(&lid_files, &lid->list);

		count++;
	}

	return OPAL_SUCCESS;

err:
	/* free all lid entries */
	list_for_each_safe(&lid_files, lid, tmp, list)
		free(lid);

	return rc;
}

/*
 * Parse the "hb_lid_ids" string from bios tables and complete
 * the global list of lid files.
 */
static int lid_ids_to_vaddr_mapping(void)
{
	char *lid_ids_string = NULL;
	int rc;

	/* get lid ids string from bios tables */
	rc = pldm_bios_get_lids_id(&lid_ids_string);
	if (rc)
		goto out;

	/* parse the "hb_lid_ids" string */
	rc = parse_hb_lid_ids_string(lid_ids_string);

out:
	if (lid_ids_string)
		free(lid_ids_string);

	return rc;
}

int pldm_lid_files_init(struct blocklevel_device **bl)
{
	uint32_t lid_files_count;
	int rc;

	if (!bl)
		return FLASH_ERR_PARM_ERROR;

	*bl = NULL;

	/* convert lid ids data to pnor structure */
	rc = lid_ids_to_vaddr_mapping();
	if (rc)
		goto err;

	lid_files_count = get_lids_count();

	prlog(PR_NOTICE, "Number of lid files: %d\n", lid_files_count);
	print_lid_files_attr();

	return OPAL_SUCCESS;

err:
	return rc;
}
