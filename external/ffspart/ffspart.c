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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <libflash/blocklevel.h>
#include <common/arch_flash.h>

/*
 * Flags:
 *  - E: ECC for this part
 */

/*
 * TODO FIXME
 * Max line theoretical max size:
 *  - name: 15 chars = 15
 *  - base: 0xffffffff = 10
 *  - size: 0xffffffff = 10
 *  - flag: E = 1
 *
 *  36 + 3 separators = 39
 *  Plus \n 40
 *  Lets do 50.
 */
#define MAX_LINE 100
#define SEPARATOR ','

/* Full version number (possibly includes gitid). */
extern const char version[];

static void print_version(void)
{
	printf("Open-Power FFS format tool %s\n", version);
}

static void print_help(const char *pname)
{
	print_version();
	printf("Usage: %s [options] -s size -c num -i layout_file -p pnor_file ...\n\n", pname);
	printf(" Options:\n");
	printf("\t-s, --block_size=size\n");
	printf("\t\tSize (in hex with leading 0x) of the blocks on the flash in bytes\n\n");
	printf("\t-c, --block_count=num\n");
	printf("\t\tNumber of blocks on the flash\n\n");
	printf("\t-i, --input=file\n");
	printf("\t\tFile containing the required partition data\n\n");
	printf("\t-p, --pnor=file\n");
	printf("\t\tOutput file to write data\n\n");
}

int main(int argc, char *argv[])
{
	const char *pname = argv[0];
	struct blocklevel_device *bl = NULL;
	uint32_t block_size = 0, block_count = 0;
	bool bad_input = false;
	char *pnor = NULL, *input = NULL;
	struct ffs_hdr *new_hdr;
	FILE *in_file;
	char line[MAX_LINE];
	int rc;

	while(1) {
		struct option long_opts[] = {
			{"block_size",	required_argument,	NULL,	's'},
			{"block_count",	required_argument,	NULL,	'c'},
			{"debug",	no_argument,	NULL,	'g'},
			{"input",	required_argument,	NULL,	'i'},
			{"pnor",	required_argument,	NULL,	'p'},
			{NULL,	0,	0, 0}
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "c:gi:p:s:", long_opts, &oidx);
		if (c == EOF)
			break;
		switch(c) {
		case 'c':
			block_count = strtoul(optarg, NULL, 0);
			break;
		case 'g':
			libflash_debug = true;
			break;
		case 'i':
			input = strdup(optarg);
			break;
		case 'p':
			pnor = strdup(optarg);
			break;
		case 's':
			block_size = strtoul(optarg, NULL, 0);
			break;
		default:
			exit(1);
		}
	}

	if (!block_size || !block_count || !input || !pnor)
		bad_input = true;

	if (bad_input) {
		print_help(pname);
		rc = 1;
		goto out;
	}

	rc = ffs_hdr_new(block_size, block_count, &new_hdr);
	if (rc) {
		if (rc == FFS_ERR_BAD_SIZE) {
			/* Well this check is a tad redudant now */
			fprintf(stderr, "Bad parametres passed to libffs\n");
		} else {
			fprintf(stderr, "Error %d initialising new TOC\n", rc);
		}
		goto out;
	}

	in_file = fopen(input, "r");
	if (!in_file) {
		rc = errno;
		fprintf(stderr, "Couldn't open your input file %s because %s\n", input, strerror(errno));
		goto out_free_hdr;
	}

	rc = arch_flash_init(&bl, pnor, true);
	if (rc) {
		fprintf(stderr, "Couldn't initialise architecture flash structures\n");
		goto out_close_f;
	}

	/*
	 * 'Erase' the file, make it all 0xFF
	 * TODO: Add sparse option and don't do this.
	 */
	rc = blocklevel_erase(bl, 0, block_size * block_count);
	if (rc) {
		fprintf(stderr, "Couldn't erase file\n");
		goto out_close_bl;
	}

	while (fgets(line, MAX_LINE, in_file) != NULL) {
		struct ffs_entry *new_entry;
		struct ffs_entry_user user = { 0 };
		char *pos, *old_pos;
		char *name, *endptr;
		uint32_t pbase, psize, pactual = 0;

		/* Inline comments in input file */
		if (line[0] == '#')
			continue;

		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		pos = strchr(line, SEPARATOR);
		if (!pos) {
			fprintf(stderr, "Invalid input file format: Couldn't find name\n");
			rc = -1;
			goto out_close_bl;
		}
		*pos = '\0';
		name = line;
		/* There is discussion to be had as to if we should bail here */
		if (pos - line > FFS_PART_NAME_MAX)
			fprintf(stderr, "WARNING: Long partition '%s' name will get truncated\n",
					line);

		pos++;
		old_pos = pos;
		pos = strchr(pos, SEPARATOR);
		if (!pos) {
			fprintf(stderr, "Invalid input file format: Couldn't find base\n");
			rc = -1;
			goto out_close_bl;
		}
		*pos = '\0';
		pbase = strtoul(old_pos, &endptr, 0);
		if (*endptr != '\0') {
			fprintf(stderr, "Invalid input file format: Couldn't parse "
					"'%s' partition base address\n", name);
			rc = -1;
			goto out_close_bl;
		}

		pos++;
		old_pos = pos;
		pos = strchr(pos, SEPARATOR);
		if (!pos) {
			fprintf(stderr, "Invalid input file format: Couldn't find size\n");
			rc = -1;
			goto out_close_bl;
		}
		*pos = '\0';
		psize = strtoul(old_pos, &endptr, 0);
		if (*endptr != '\0') {
			fprintf(stderr, "Invalid input file format: Couldn't parse "
					"'%s' partition length\n", name);
			rc = -1;
			goto out_close_bl;
		}

		pos++;
		while (*pos != '\0' && *pos != SEPARATOR) {
			switch (*pos) {
			case 'E':
				user.datainteg |= FFS_ENRY_INTEG_ECC;
				break;
			case 'L':
				user.vercheck |= FFS_VERCHECK_SHA512V;
				break;
			case 'I':
				user.vercheck |= FFS_VERCHECK_SHA512EC;
				break;
			case 'P':
				user.miscflags |= FFS_MISCFLAGS_PRESERVED;
				break;
			case 'R':
				user.miscflags |= FFS_MISCFLAGS_READONLY;
				break;
			case 'F':
				user.miscflags |= FFS_MISCFLAGS_REPROVISION;
				break;
			case 'V':
				user.miscflags |= FFS_MISCFLAGS_VOLATILE;
				break;
			case 'C':
				user.miscflags |= FFS_MISCFLAGS_CLEARECC;
				break;
			/* Not sure these are valid */
			case 'B':
				user.miscflags |= FFS_MISCFLAGS_BACKUP;
				break;
			default:
				fprintf(stderr, "Unknown flag '%c'\n", *pos);
				rc = -1;
				goto out_close_bl;
			}
			pos++;
		}

		printf("Adding '%s' 0x%08x, 0x%08x\n", name, pbase, psize);
		rc = ffs_entry_new(name, pbase, psize, &new_entry);
		if (rc) {
			fprintf(stderr, "Invalid entry '%s' 0x%08x for 0x%08x\n",
					name, pbase, psize);
			goto out_close_bl;
		}

		rc = ffs_entry_user_set(new_entry, &user);
		if (rc) {
			fprintf(stderr, "Invalid flag passed to ffs_entry_user_set\n");
			goto out_while;
		}

		rc = ffs_entry_add(new_hdr, new_entry);
		if (rc) {
			fprintf(stderr, "Couldn't add entry '%s' 0x%08x for 0x%08x\n",
					name, pbase, psize);
			goto out_while;
		}

		if (*pos != '\0') {
			struct stat data_stat;
			int data_fd;
			uint8_t *data_ptr;
			char *data_fname = pos + 1;

			data_fd = open(data_fname, O_RDONLY);
			if (data_fd == -1) {
				fprintf(stderr, "Couldn't open data file for partition '%s' (filename: %s)\n",
						name, data_fname);
				rc = -1;
				goto out_while;
			}

			if (fstat(data_fd, &data_stat) == -1) {
				fprintf(stderr, "Couldn't stat data file for partition '%s': %s\n",
						name, strerror(errno));
				rc = -1;
				goto out_if;
			}
			pactual = data_stat.st_size;

			/*
			 * Sanity check that the file isn't too large for
			 * partition
			 */
			if (pactual > psize) {
				fprintf(stderr, "Data file for partition '%s' is too large\n",
						name);
				rc = -1;
				goto out_if;
			}

			data_ptr = mmap(NULL, pactual, PROT_READ, MAP_SHARED, data_fd, 0);
			if (!data_ptr) {
				fprintf(stderr, "Couldn't mmap data file for partition '%s': %s\n",
						name, strerror(errno));
				rc = -1;
				goto out_if;
			}

			rc = blocklevel_write(bl, pbase, data_ptr, pactual);
			if (rc)
				fprintf(stderr, "Couldn't write data file for partition '%s' to pnor file:"
					    " %s\n", name, strerror(errno));

			munmap(data_ptr, pactual);
out_if:
			close(data_fd);
			if (rc)
				goto out_while;
			/*
			 * TODO: Update the actual size within the partition table.
			 */
		}

		continue;
out_while:
		free(new_entry);
		goto out_close_bl;
	}

	rc = ffs_hdr_finalise(bl, new_hdr);
	if (rc)
		fprintf(stderr, "Failed to write out TOC values\n");

out_close_bl:
	arch_flash_close(bl, pnor);
out_close_f:
	fclose(in_file);
out_free_hdr:
	ffs_hdr_free(new_hdr);
out:
	free(input);
	free(pnor);
	return rc;
}
