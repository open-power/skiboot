// SPDX-License-Identifier: Apache-2.0
/* Copyright 2020 IBM Corp. */

#ifndef __OPAL_DEBUG_H
#define __OPAL_DEBUG_H

struct opal_debug;

struct opal_debug_ops {
	const char *compat;
	int  (*read)(struct opal_debug *d, void *buf, uint64_t size);
	int  (*write)(struct opal_debug *d, void *buf, uint64_t size);
};

struct opal_debug {
	struct list_node link;
	uint64_t id;
	struct dt_node *node;
	const char *name;
	void *private;
	const struct opal_debug_ops *ops;
};

struct opal_debug *opal_debug_create(const char *name, struct dt_node *node,
			     void* private, const struct opal_debug_ops *ops);

#endif
