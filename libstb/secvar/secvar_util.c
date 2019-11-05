// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "SECVAR: " fmt
#endif

#include <stdlib.h>
#include <string.h>
#include <skiboot.h>
#include <opal.h>
#include "secvar.h"

void clear_bank_list(struct list_head *bank)
{
	struct secvar_node *node, *next;

	if (!bank)
		return;

	list_for_each_safe(bank, node, next, link) {
		list_del(&node->link);

		if (node->var)
			free(node->var);
		free(node);
	}
}

struct secvar_node *alloc_secvar(uint64_t size)
{
	struct secvar_node *ret;

	ret = zalloc(sizeof(struct secvar_node));
	if (!ret)
		return NULL;

	ret->var = zalloc(sizeof(struct secvar) + size);
	if (!ret->var) {
		free(ret);
		return NULL;
	}

	ret->size = size;

	return ret;
}

int realloc_secvar(struct secvar_node *node, uint64_t size)
{
	void *tmp;

	if (node->size >= size)
		return 0;

	tmp = zalloc(sizeof(struct secvar) + size);
	if (!tmp)
		return -1;

	memcpy(tmp, node->var, sizeof(struct secvar) + node->size);
	free(node->var);
	node->var = tmp;

	return 0;
}

struct secvar_node *find_secvar(const char *key, uint64_t key_len, struct list_head *bank)
{
	struct secvar_node *node = NULL;

	list_for_each(bank, node, link) {
		// Prevent matching shorter key subsets / bail early
		if (key_len != node->var->key_len)
			continue;
		if (!memcmp(key, node->var->key, key_len))
			return node;
	}

	return NULL;
}

int is_key_empty(const char *key, uint64_t key_len)
{
	int i;
	for (i = 0; i < key_len; i++) {
		if (key[i] != 0)
			return 0;
	}

	return 1;
}

int list_length(struct list_head *bank)
{
	int ret = 0;
	struct secvar_node *node;

	list_for_each(bank, node, link)
		ret++;

	return ret;
}
