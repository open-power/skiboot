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
/* Wrappers for malloc, et. al. */
#include <mem_region.h>
#include <lock.h>
#include <string.h>
#include <mem_region-malloc.h>

#define DEFAULT_ALIGN __alignof__(long)

void *__memalign(size_t blocksize, size_t bytes, const char *location)
{
	void *p;

	lock(&mem_region_lock);
	p = mem_alloc(&skiboot_heap, bytes, blocksize, location);
	unlock(&mem_region_lock);

	return p;
}

void *__malloc(size_t bytes, const char *location)
{
	return __memalign(DEFAULT_ALIGN, bytes, location);
}

void __free(void *p, const char *location)
{
	lock(&mem_region_lock);
	mem_free(&skiboot_heap, p, location);
	unlock(&mem_region_lock);
}

void *__realloc(void *ptr, size_t size, const char *location)
{
	void *newptr;

	/* Two classic malloc corner cases. */
	if (!size) {
		__free(ptr, location);
		return NULL;
	}
	if (!ptr)
		return __malloc(size, location);

	lock(&mem_region_lock);
	if (mem_resize(&skiboot_heap, ptr, size, location)) {
		newptr = ptr;
	} else {
		newptr = mem_alloc(&skiboot_heap, size, DEFAULT_ALIGN,
				   location);
		if (newptr) {
			size_t copy = mem_size(&skiboot_heap, ptr);
			if (copy > size)
				copy = size;
			memcpy(newptr, ptr, copy);
			mem_free(&skiboot_heap, ptr, location);
		}
	}
	unlock(&mem_region_lock);
	return newptr;
}

void *__zalloc(size_t bytes, const char *location)
{
	void *p = __malloc(bytes, location);

	if (p)
		memset(p, 0, bytes);
	return p;
}
