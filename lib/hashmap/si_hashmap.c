// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
//
// native-turbo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "si_hashmap.h"

typedef struct {
	si_hash_func hash_func;
	uint32_t nr;
} _si_hashmap_t;

si_hashmap_t *si_hashmap_new(void)
{
	_si_hashmap_t *map;

	map = malloc(sizeof(_si_hashmap_t));
	if (!map) {
		return NULL;
	}

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
