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

/* Override this for testing. */
#define is_rodata(p) fake_is_rodata(p)

char __rodata_start[16];
#define __rodata_end (__rodata_start + sizeof(__rodata_start))

static inline bool fake_is_rodata(const void *p)
{
	return ((char *)p >= __rodata_start && (char *)p < __rodata_end);
}

#define zalloc(bytes) calloc((bytes), 1)

#include "../device.c"
#include "../../ccan/list/list.c" /* For list_check */
#include <assert.h>

int main(void)
{
	struct dt_node *root, *c1, *c2, *gc1, *gc2, *gc3, *ggc1, *i;
	const struct dt_property *p;
	struct dt_property *p2;
	unsigned int n;

	root = dt_new_root("root");
	assert(!list_top(&root->properties, struct dt_property, list));
	c1 = dt_new(root, "c1");
	assert(!list_top(&c1->properties, struct dt_property, list));
	c2 = dt_new(root, "c2");
	assert(!list_top(&c2->properties, struct dt_property, list));
	gc1 = dt_new(c1, "gc1");
	assert(!list_top(&gc1->properties, struct dt_property, list));
	gc2 = dt_new(c1, "gc2");
	assert(!list_top(&gc2->properties, struct dt_property, list));
	gc3 = dt_new(c1, "gc3");
	assert(!list_top(&gc3->properties, struct dt_property, list));
	ggc1 = dt_new(gc1, "ggc1");
	assert(!list_top(&ggc1->properties, struct dt_property, list));

	for (n = 0, i = dt_first(root); i; i = dt_next(root, i), n++) {
		assert(!list_top(&i->properties, struct dt_property, list));
		dt_add_property_cells(i, "visited", 1);
	}
	assert(n == 6);

	for (n = 0, i = dt_first(root); i; i = dt_next(root, i), n++) {
		p = list_top(&i->properties, struct dt_property, list);
		assert(strcmp(p->name, "visited") == 0);
		assert(p->len == sizeof(u32));
		assert(fdt32_to_cpu(*(u32 *)p->prop) == 1);
	}
	assert(n == 6);

	dt_add_property_cells(c1, "some-property", 1, 2, 3);
	p = dt_find_property(c1, "some-property");
	assert(p);
	assert(strcmp(p->name, "some-property") == 0);
	assert(p->len == sizeof(u32) * 3);
	assert(fdt32_to_cpu(*(u32 *)p->prop) == 1);
	assert(fdt32_to_cpu(*((u32 *)p->prop + 1)) == 2);
	assert(fdt32_to_cpu(*((u32 *)p->prop + 2)) == 3);

	/* Test freeing a single node */
	assert(!list_empty(&gc1->children));
	dt_free(ggc1);
	assert(list_empty(&gc1->children));

	/* Test rodata logic. */
	assert(!is_rodata("hello"));
	assert(is_rodata(__rodata_start));
	strcpy(__rodata_start, "name");
	ggc1 = dt_new(root, __rodata_start);
	assert(ggc1->name == __rodata_start);

	/* Test string node. */
	dt_add_property_string(ggc1, "somestring", "someval");
	assert(dt_has_node_property(ggc1, "somestring", "someval"));
	assert(!dt_has_node_property(ggc1, "somestrin", "someval"));
	assert(!dt_has_node_property(ggc1, "somestring", "someva"));
	assert(!dt_has_node_property(ggc1, "somestring", "somevale"));

	/* Test resizing property. */
	p = p2 = __dt_find_property(c1, "some-property");
	assert(p);
	n = p2->len;
	while (p2 == p) {
		n *= 2;
		dt_resize_property(&p2, n);
	}

	assert(dt_find_property(c1, "some-property") == p2);
	list_check(&c1->properties, "properties after resizing");

	dt_del_property(c1, p2);
	list_check(&c1->properties, "properties after delete");

	/* No leaks for valgrind! */
	dt_free(root);
	return 0;
}
