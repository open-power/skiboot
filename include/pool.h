#ifndef __POOL_H
#define __POOL_H

#include <ccan/list/list.h>
#include <stddef.h>

struct pool {
	void *buf;
	size_t obj_size;
	struct list_head free_list;
	int free_count;
	int reserved;
};

enum pool_priority {POOL_NORMAL, POOL_HIGH};

void* pool_get(struct pool *pool, enum pool_priority priority);
void pool_free_object(struct pool *pool, void *obj);
int pool_init(struct pool *pool, size_t obj_size, int count, int reserved);

#endif /* __POOL_H */
