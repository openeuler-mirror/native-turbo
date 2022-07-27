/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _DFE_HASHMAP_H
#define _DFE_HASHMAP_H

#include <stdint.h>

#include "dfe_common.h"

typedef uint32_t (*dfe_hash_func)(void *key);

typedef struct {
	dfe_hash_func hash_func;
	uint32_t nr;
} dfe_hashmap_t;

dfe_hashmap_t *dfe_hashmap_new();

void dfe_hashmap_free(dfe_hashmap_t *map);

uint32_t dfe_hashmap_size(dfe_hashmap_t *map);

int dfe_hashmap_insert(dfe_hashmap_t *map, char *key, void *data);

void *dfe_hashmap_find(dfe_hashmap_t *map, char *key);

#endif /* _DFE_HASHMAP_H */
