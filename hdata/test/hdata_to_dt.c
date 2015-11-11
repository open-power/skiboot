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
/* Given a hdata dump, output the device tree. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include <interrupts.h>

struct dt_node *opal_node;

/* Our actual map. */
static void *spira_heap;
static off_t spira_heap_size;
static uint64_t base_addr;

/* Override ntuple_addr. */
#define ntuple_addr ntuple_addr
struct spira_ntuple;
static void *ntuple_addr(const struct spira_ntuple *n);

/* Stuff which core expects. */
#define __this_cpu ((struct cpu_thread *)NULL)
#define zalloc(expr) calloc(1, (expr))

/* Don't include processor-specific stuff. */
#define __PROCESSOR_H
#define PVR_TYPE(_pvr)	_pvr

/* PVR definitions */
#define PVR_TYPE_P7	0x003f
#define PVR_TYPE_P7P	0x004a
#define PVR_TYPE_P8E	0x004b
#define PVR_TYPE_P8	0x004d
#define PVR_TYPE_P8NVL	0x004c

#define SPR_PVR		0x11f	/* RO: Processor version register */

#define __CPU_H
struct cpu_thread {
	uint32_t			pir;
};

struct cpu_thread __boot_cpu, *boot_cpu = &__boot_cpu;
static unsigned long fake_pvr_type = PVR_TYPE_P7;

static inline unsigned long mfspr(unsigned int spr)
{
	assert(spr == SPR_PVR);
	return fake_pvr_type;
}

struct dt_node *add_ics_node(void)
{
	return NULL;
}

#include <config.h>
#include <bitutils.h>

/* Your pointers won't be correct, that's OK. */
#define spira_check_ptr(ptr, file, line) ((ptr) != NULL)

#include "../cpu-common.c"
#include "../fsp.c"
#include "../hdif.c"
#include "../iohub.c"
#include "../memory.c"
#include "../paca.c"
#include "../pcia.c"
#include "../spira.c"
#include "../vpd.c"
#include "../vpd-common.c"
#include "../slca.c"
#include "../hostservices.c"
#include "../../core/vpd.c"
#include "../../core/device.c"
#include "../../core/chip.c"

#include <err.h>

char __rodata_start[1], __rodata_end[1];

enum proc_gen proc_gen = proc_gen_p7;

static void *ntuple_addr(const struct spira_ntuple *n)
{
	uint64_t addr = be64_to_cpu(n->addr);
	if (n->addr == 0)
		return NULL;
	assert(addr >= base_addr);
	assert(addr < base_addr + spira_heap_size);
	return spira_heap + ((unsigned long)addr - base_addr);
}

static void indent_num(unsigned indent)
{
	unsigned int i;

	for (i = 0; i < indent; i++)
		putc(' ', stdout);
}

static void dump_val(unsigned indent, const void *prop, size_t size)
{
	size_t i;
	int width = 78 - indent;

	for (i = 0; i < size; i++) {
		printf("%02x", ((unsigned char *)prop)[i]);
		width-=2;
		if(width < 2) {
			printf("\n");
			indent_num(indent);
			width = 80 - indent;
		}
	}
}

/* Make sure valgrind knows these are undefined bytes. */
static void undefined_bytes(void *p, size_t len)
{
	void *undef = malloc(len);
	memcpy(p, undef, len);
	free(undef);
}

static void dump_dt(const struct dt_node *root, unsigned indent)
{
	const struct dt_node *i;
	const struct dt_property *p;

	list_for_each(&root->properties, p, list) {
		indent_num(indent);
		printf("prop: %s size: %zu val: ", p->name, p->len);
		dump_val(indent, p->prop, p->len);
		printf("\n");
	}

	list_for_each(&root->children, i, list)
		dump_dt(i, indent + 2);
}

int main(int argc, char *argv[])
{
	int fd, r;
	bool verbose = false, quiet = false;

	while (argv[1]) {
		if (strcmp(argv[1], "-v") == 0) {
			verbose = true;
			argv++;
			argc--;
		} else if (strcmp(argv[1], "-q") == 0) {
			quiet = true;
			argv++;
			argc--;
		} else
			break;
	}

	if (argc != 3)
		errx(1, "Usage: hdata [-v|-q] <spira-dump> <heap-dump>");

	/* Copy in spira dump (assumes little has changed!). */
	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		err(1, "opening %s", argv[1]);
	r = read(fd, &spira, sizeof(spira));
	if (r < sizeof(spira.hdr))
		err(1, "reading %s gave %i", argv[1], r);
	if (verbose)
		printf("verbose: read spira %u bytes\n", r);
	close(fd);

	undefined_bytes((void *)&spira + r, sizeof(spira) - r);

	base_addr = be64_to_cpu(spira.ntuples.heap.addr);
	if (!base_addr)
		errx(1, "Invalid base addr");
	if (verbose)
		printf("verbose: map.base_addr = %llx\n", (long long)base_addr);

	fd = open(argv[2], O_RDONLY);
	if (fd < 0)
		err(1, "opening %s", argv[2]);
	spira_heap_size = lseek(fd, 0, SEEK_END);
	if (spira_heap_size < 0)
		err(1, "lseek on %s", argv[2]);
	spira_heap = mmap(NULL, spira_heap_size, PROT_READ, MAP_SHARED, fd, 0);
	if (spira_heap == MAP_FAILED)
		err(1, "mmaping %s", argv[3]);
	if (verbose)
		printf("verbose: mapped %zu at %p\n",
		       spira_heap_size, spira_heap);
	close(fd);

	if (quiet) {
		fclose(stdout);
		fclose(stderr);
	}

	parse_hdat(false, 0);

	if (!quiet)
		dump_dt(dt_root, 0);

	dt_free(dt_root);
	return 0;
}
