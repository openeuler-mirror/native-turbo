/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "si_hashmap.h"

typedef struct {
	si_hash_func hash_func;
	uint32_t nr;
} _si_hashmap_t;

si_hashmap_t *si_hashmap_new()
{
	_si_hashmap_t *map;

	map = malloc(sizeof(_si_hashmap_t));
	if (!map)
		return NULL;

	map->nr = 0;
	map->hash_func = NULL;

	return (si_hashmap_t *)map;
}

void si_hashmap_free(si_hashmap_t *_map)
{
	free(_map);
}

uint32_t si_hashmap_size(si_hashmap_t *map)
{
	return map->nr;
}

int si_hashmap_insert(si_hashmap_t *_map, char *key, void *data)
{
	_si_hashmap_t *map = (_si_hashmap_t *)_map;

	// TODO: feature
	(void)map;
	(void)key;
	(void)data;

	return 0;
}

void *si_hashmap_find(si_hashmap_t *_map, char *key)
{
	_si_hashmap_t *map = (_si_hashmap_t *)_map;

	// TODO: feature
	(void)map;
	(void)key;

	return NULL;
}
