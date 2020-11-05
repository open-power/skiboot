// SPDX-License-Identifier: Apache-2.0
/* Copyright 2020 IBM Corp. */

#define pr_fmt(fmt) "DEBUG: " fmt

#include <cpu.h>
#include <opal.h>
#include <opal-debug.h>

static LIST_HEAD(opal_debug_handlers);
static uint64_t opal_debug_index;

/* This would need some locking */
struct opal_debug *opal_debug_create(const char *name, struct dt_node *node,
				     void* private, const struct opal_debug_ops *ops)
{
	const char *compat = ops->compat ? ops->compat : "ibm,opal-debug";
	struct opal_debug *d;

	d = zalloc(sizeof(*d));
	if (!d) {
		prlog(PR_ERR, "Failed to allocate debug handler!\n");
		return NULL;
	}

	d->id = opal_debug_index;
	d->name = name;
	d->private = private;
	d->ops = ops;

	d->node = dt_new_addr(node, "debug", opal_debug_index);
	dt_add_property_cells(d->node, "reg", opal_debug_index);
	dt_add_property_string(d->node, "compatible", compat);
	dt_add_property_string(d->node, "label", d->name);

	list_add_tail(&opal_debug_handlers, &d->link);

	opal_debug_index++;

	return d;
}

static struct opal_debug *opal_debug_find(uint64_t id)
{
	struct opal_debug *d;

	list_for_each(&opal_debug_handlers, d, link) {
		if (d->id == id)
			return d;
	}
	return NULL;
}
static int64_t opal_debug_read(uint64_t id, uint64_t buf, uint64_t size)
{
	struct opal_debug *d;

	if (id >= opal_debug_index)
		return OPAL_PARAMETER;

	if (!opal_addr_valid((void *)buf) || !size)
		return OPAL_PARAMETER;

	d = opal_debug_find(id);
	if (!d) {
		prlog(PR_ERR, "No debug handler %lld!\n", id);
		return OPAL_INTERNAL_ERROR;
	}

	if (!d->ops->read)
		return OPAL_UNSUPPORTED;

	return d->ops->read(d, (void *)buf, size);
}
opal_call(OPAL_DEBUG_READ, opal_debug_read, 3);

static int64_t opal_debug_write(uint64_t id, uint64_t buf, uint64_t size)
{
	struct opal_debug *d;

	if (id >= opal_debug_index)
		return OPAL_PARAMETER;

	if (!opal_addr_valid((void *)buf) || !size)
		return OPAL_PARAMETER;

	d = opal_debug_find(id);
	if (!d) {
		prlog(PR_ERR, "No debug handler %lld!\n", id);
		return OPAL_INTERNAL_ERROR;
	}

	if (!d->ops->write)
		return OPAL_UNSUPPORTED;

	return d->ops->write(d, (void *)buf, size);
}
opal_call(OPAL_DEBUG_WRITE, opal_debug_write, 3);
