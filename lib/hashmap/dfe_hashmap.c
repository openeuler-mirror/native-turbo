/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dfe_hashmap.h"

typedef struct {
	dfe_hash_func hash_func;
	uint32_t nr;
} _dfe_hashmap_t;

dfe_hashmap_t *dfe_hashmap_new()
{
	_dfe_hashmap_t *map;

	map = malloc(sizeof(_dfe_hashmap_t));
	if (!map)
		return NULL;

	map->nr = 0;
	map->hash_func = NULL;

	return (dfe_hashmap_t *)map;
}

void dfe_hashmap_free(dfe_hashmap_t *_map)
{
	free(_map);
}

uint32_t dfe_hashmap_size(dfe_hashmap_t *map)
{
	return map->nr;
}

int dfe_hashmap_insert(dfe_hashmap_t *_map, char *key, void *data)
{
	_dfe_hashmap_t *map = (_dfe_hashmap_t *)_map;

	// TODO
	(void)map;
	(void)key;
	(void)data;

	return 0;
}

void *dfe_hashmap_find(dfe_hashmap_t *_map, char *key)
{
	_dfe_hashmap_t *map = (_dfe_hashmap_t *)_map;

	// TODO
	(void)map;
	(void)key;

	return NULL;
}
