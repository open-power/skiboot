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

#ifndef __MEMORY_REGION
#define __MEMORY_REGION
#include <ccan/list/list.h>
#include <stdint.h>

enum mem_region_type {
	/* ranges allocatable by mem_alloc: this will be most of memory */
	REGION_SKIBOOT_HEAP,

	/* ranges used explicitly for skiboot, but not allocatable. eg .text */
	REGION_SKIBOOT_FIRMWARE,

	/* ranges reserved, possibly before skiboot init, eg HW framebuffer */
	REGION_RESERVED,

	/* ranges available for the OS, created by mem_region_release_unused */
	REGION_OS,
};

/* An area of physical memory. */
struct mem_region {
	struct list_node list;
	const char *name;
	uint64_t start, len;
	struct dt_node *mem_node;
	enum mem_region_type type;
	struct list_head free_list;
};

extern struct lock mem_region_lock;
void *mem_alloc(struct mem_region *region, size_t size, size_t align,
		const char *location);
void mem_free(struct mem_region *region, void *mem,
	      const char *location);
bool mem_resize(struct mem_region *region, void *mem, size_t len,
		const char *location);
size_t mem_size(const struct mem_region *region, const void *ptr);
bool mem_check(const struct mem_region *region);
void mem_region_release_unused(void);

/* Specifically for working on the heap. */
extern struct mem_region skiboot_heap;

void mem_region_init(void);

void mem_region_add_dt_reserved(void);

/* Mark memory as reserved */
void mem_reserve(const char *name, uint64_t start, uint64_t len);

struct mem_region *find_mem_region(const char *name);

#endif /* __MEMORY_REGION */
