// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "SECVAR_API: " fmt
#endif

#include <opal.h>
#include "secvar.h"


static int64_t opal_secvar_get(const char *key, uint64_t key_len, void *data, uint64_t *data_size)
{
	struct secvar_node *node;
	int64_t rc = OPAL_SUCCESS;

	if (!secvar_enabled)
		return OPAL_UNSUPPORTED;
	if (!secvar_ready)
		return OPAL_RESOURCE;
	if (!key)
		return OPAL_PARAMETER;
	if (key_len == 0)
		return OPAL_PARAMETER;
	// Data size must be set, data is optional for size query
	if (!data_size)
		return OPAL_PARAMETER;

	node = find_secvar(key, key_len, &variable_bank);
	if (!node)
		return OPAL_EMPTY; // Variable not found, bail early

	if (!data)
		rc = OPAL_SUCCESS;
	else if (*data_size < node->var->data_size)
		rc = OPAL_PARTIAL;
	else
		memcpy(data, node->var->data, node->var->data_size);

	*data_size = node->var->data_size;

	return rc;
}
opal_call(OPAL_SECVAR_GET, opal_secvar_get, 4);


static int64_t opal_secvar_get_next(char *key, uint64_t *key_len, uint64_t key_buf_size)
{
	struct secvar_node *node;

	if (!secvar_enabled)
		return OPAL_UNSUPPORTED;
	if (!secvar_ready)
		return OPAL_RESOURCE;
	if (!key_len)
		return OPAL_PARAMETER;
	if (key_buf_size == 0)
		return OPAL_PARAMETER;
	if (*key_len > SECVAR_MAX_KEY_LEN)
		return OPAL_PARAMETER;
	if (*key_len > key_buf_size)
		return OPAL_PARAMETER;
	if (!key)
		return OPAL_PARAMETER;

	if (!is_key_empty(key, *key_len)) {
		node = find_secvar(key, *key_len, &variable_bank);
		if (!node)
			return OPAL_PARAMETER;

		node = list_next(&variable_bank, node, link);
	} else {
		node = list_top(&variable_bank, struct secvar_node, link);
	}

	if (!node)
		return OPAL_EMPTY;

	if (key_buf_size < node->var->key_len) {
		*key_len = node->var->key_len;
		return OPAL_PARTIAL;
	}

	*key_len = node->var->key_len;
	memcpy(key, node->var->key, node->var->key_len);

	return OPAL_SUCCESS;
}
opal_call(OPAL_SECVAR_GET_NEXT, opal_secvar_get_next, 3);


static int64_t opal_secvar_enqueue_update(const char *key, uint64_t key_len, void *data, uint64_t data_size)
{
	struct secvar_node *node;

	if (!secvar_enabled)
		return OPAL_UNSUPPORTED;
	if (!secvar_ready)
		return OPAL_RESOURCE;
	if (!secvar_storage.write_bank)
		return OPAL_HARDWARE;
	if (!key)
		return OPAL_PARAMETER;
	if (key_len == 0)
		return OPAL_PARAMETER;
	if (key_len > SECVAR_MAX_KEY_LEN)
		return OPAL_PARAMETER;
	if ((!data) && (data_size != 0))
		return OPAL_PARAMETER;
	if (data_size > secvar_storage.max_var_size)
		return OPAL_PARAMETER;

	// Key should not be empty
	if (is_key_empty(key, key_len))
		return OPAL_PARAMETER;

	node = find_secvar(key, key_len, &update_bank);

	// Unstage an update
	if (data_size == 0) {
		if (!node)
			return OPAL_EMPTY;

		if (node->var)
			free(node->var);
		list_del(&node->link);
		free(node);
		goto out;
	}

	if (node) {
		list_del(&node->link);
		// Realloc var if too small
		if (node->size < data_size) {
			if (realloc_secvar(node, data_size))
				return OPAL_NO_MEM;
		} else {
			memset(node->var, 0x00, sizeof(struct secvar) + node->var->data_size);
		}
	} else {
		node = alloc_secvar(data_size);
		if (!node)
			return OPAL_NO_MEM;
	}

	memcpy(node->var->key, key, key_len);
	node->var->key_len = key_len;
	memcpy(node->var->data, data, data_size);
	node->var->data_size = data_size;

	list_add_tail(&update_bank, &node->link);

out:
	if (secvar_storage.write_bank(&update_bank, SECVAR_UPDATE_BANK))
		return OPAL_HARDWARE;
	else
		return OPAL_SUCCESS;
}
opal_call(OPAL_SECVAR_ENQUEUE_UPDATE, opal_secvar_enqueue_update, 4);
