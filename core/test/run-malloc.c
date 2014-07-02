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

#include <config.h>

#define BITS_PER_LONG (sizeof(long) * 8)

/* Don't include this, it's PPC-specific */
#define __CPU_H
static unsigned int cpu_max_pir = 1;
struct cpu_thread {
	unsigned int			chip_id;
};

#include <skiboot.h>

#define is_rodata(p) true

#include "../mem_region.c"
#include "../malloc.c"
#include "../device.c"

#include "mem_region-malloc.h"

#define TEST_HEAP_ORDER 12
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

struct dt_node *dt_root;

void lock(struct lock *l)
{
	assert(!l->lock_val);
	l->lock_val = 1;
}

void unlock(struct lock *l)
{
	assert(l->lock_val);
	l->lock_val = 0;
}

static bool heap_empty(void)
{
	const struct alloc_hdr *h = region_start(&skiboot_heap);
	return h->num_longs == skiboot_heap.len / sizeof(long);
}

int main(void)
{
	char test_heap[TEST_HEAP_SIZE], *p, *p2, *p3, *p4;
	size_t i;

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (unsigned long)test_heap;
	skiboot_heap.len = TEST_HEAP_SIZE;

	/* Allocations of various sizes. */
	for (i = 0; i < TEST_HEAP_ORDER; i++) {
		p = malloc(1ULL << i);
		assert(p);
		assert(p > (char *)test_heap);
		assert(p + (1ULL << i) <= (char *)test_heap + TEST_HEAP_SIZE);
		assert(!mem_region_lock.lock_val);
		free(p);
		assert(!mem_region_lock.lock_val);
		assert(heap_empty());
	}

	/* Realloc as malloc. */
	mem_region_lock.lock_val = 0;
	p = realloc(NULL, 100);
	assert(p);
	assert(!mem_region_lock.lock_val);

	/* Realloc as free. */
	p = realloc(p, 0);
	assert(!p);
	assert(!mem_region_lock.lock_val);
	assert(heap_empty());

	/* Realloc longer. */
	p = realloc(NULL, 100);
	assert(p);
	assert(!mem_region_lock.lock_val);
	p2 = realloc(p, 200);
	assert(p2 == p);
	assert(!mem_region_lock.lock_val);
	free(p);
	assert(!mem_region_lock.lock_val);
	assert(heap_empty());

	/* Realloc shorter. */
	mem_region_lock.lock_val = 0;
	p = realloc(NULL, 100);
	assert(!mem_region_lock.lock_val);
	assert(p);
	p2 = realloc(p, 1);
	assert(!mem_region_lock.lock_val);
	assert(p2 == p);
	free(p);
	assert(!mem_region_lock.lock_val);
	assert(heap_empty());

	/* Realloc with move. */
	p2 = malloc(TEST_HEAP_SIZE - 64 - sizeof(struct alloc_hdr)*2);
	assert(p2);
	p = malloc(64);
	assert(p);
	free(p2);

	p2 = realloc(p, 128);
	assert(p2 != p);
	free(p2);
	assert(heap_empty());
	assert(!mem_region_lock.lock_val);

	/* Reproduce bug BZ109128/SW257364 */
	p = malloc(100);
	p2 = malloc(100);
	p3 = malloc(100);
	p4 = malloc(100);
	free(p2);
	realloc(p,216);
	free(p3);
	free(p);
	free(p4);
	assert(heap_empty());
	assert(!mem_region_lock.lock_val);

	return 0;
}
