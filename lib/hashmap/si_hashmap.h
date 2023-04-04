/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _SI_HASHMAP_H
#define _SI_HASHMAP_H

#include <stdint.h>

#include "si_common.h"

typedef uint32_t (*si_hash_func)(void *key);

typedef struct {
	si_hash_func hash_func;
	uint32_t nr;
} si_hashmap_t;

si_hashmap_t *si_hashmap_new();

void si_hashmap_free(si_hashmap_t *map);

uint32_t si_hashmap_size(si_hashmap_t *map);

int si_hashmap_insert(si_hashmap_t *map, char *key, void *data);

void *si_hashmap_find(si_hashmap_t *map, char *key);

#endif /* _SI_HASHMAP_H */
