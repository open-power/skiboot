/* Copyright 2013-2016 IBM Corp.
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
#include <opal-api.h>

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

int flash_subpart_info(void *part_header, uint32_t part_size, uint32_t subid,
		       uint32_t *offset, uint32_t *size)
{
	struct flash_hostboot_header *header;
	char eyecatcher[5];
	uint32_t i, ec;

	if (!part_header || !offset || !size) {
		prlog(PR_ERR, "FLASH: invalid parameters: "
		      "ph %p of %p sz %p\n", part_header, offset, size);
		return OPAL_PARAMETER;
	}

	header = (struct flash_hostboot_header*) part_header;

	/* Perform sanity */
	i = be32_to_cpu(header->version);
	if (i != 1) {
		prerror("FLASH: flash subpartition TOC version unknown %i\n", i);
		goto end;
	}

	/* NULL terminate eyecatcher */
	strncpy(eyecatcher, header->eyecatcher, 4);
	eyecatcher[4] = '\0';
	prlog(PR_DEBUG, "FLASH: flash subpartition eyecatcher %s\n",
			eyecatcher);

	for (i = 0; i < FLASH_HOSTBOOT_TOC_MAX_ENTRIES; i++) {

		ec = be32_to_cpu(header->toc[i].ec);
		*offset = be32_to_cpu(header->toc[i].offset);
		*size = be32_to_cpu(header->toc[i].size);

		/* Check for null terminating entry */
		if (!ec && !*offset && !*size) {
			prerror("FLASH: flash subpartition not found.\n");
			goto end;
		}

		if (ec != subid)
			continue;

		/* Sanity check the offset and size. */
		if (*offset + *size > part_size) {
			prerror("FLASH: flash subpartition too big: %i\n", i);
			goto end;
		}
		if (!*size) {
			prerror("FLASH: flash subpartition zero size: %i\n", i);
			goto end;
		}
		if (*offset < FLASH_SUBPART_HEADER_SIZE) {
			prerror("FLASH: flash subpartition "
					"offset too small: %i\n", i);
			goto end;
		}

		prlog(PR_DEBUG, "FLASH: flash found subpartition: "
				"%i size: %i offset %i\n",
				i, *size, *offset);

		return OPAL_SUCCESS;
	}
end:
	*size = 0;
	*offset = 0;
	return OPAL_RESOURCE;
}
