// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef _SECVAR_H_
#define _SECVAR_H_

#include <ccan/list/list.h>
#include <stdint.h>
#include <secvar.h>

#define SECVAR_MAX_KEY_LEN		1024

enum {
	SECVAR_VARIABLE_BANK,
	SECVAR_UPDATE_BANK,
};


struct secvar_node {
	struct list_node link;
	struct secvar *var;
	uint64_t flags;		// Flag for how *var should be stored
	uint64_t size;		// How much space was allocated for data
};

#define SECVAR_FLAG_VOLATILE		0x1 // Instructs storage driver to ignore variable on writes
#define SECVAR_FLAG_SECURE_STORAGE	0x2 // Hint for storage driver to select storage location

struct secvar {
	uint64_t key_len;
	uint64_t data_size;
	char key[SECVAR_MAX_KEY_LEN];
	char data[0];
};


extern struct list_head variable_bank;
extern struct list_head update_bank;
extern int secvar_enabled;
extern int secvar_ready;
extern struct secvar_storage_driver secvar_storage;
extern struct secvar_backend_driver secvar_backend;

// Helper functions
void clear_bank_list(struct list_head *bank);
int copy_bank_list(struct list_head *dst, struct list_head *src);
struct secvar_node *alloc_secvar(uint64_t size);
struct secvar_node *new_secvar(const char *key, uint64_t key_len,
			       const char *data, uint64_t data_size,
			       uint64_t flags);
int realloc_secvar(struct secvar_node *node, uint64_t size);
void dealloc_secvar(struct secvar_node *node);
struct secvar_node *find_secvar(const char *key, uint64_t key_len, struct list_head *bank);
int is_key_empty(const char *key, uint64_t key_len);
int list_length(struct list_head *bank);

#endif
