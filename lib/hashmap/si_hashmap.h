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

#ifndef _SI_HASHMAP_H
#define _SI_HASHMAP_H

#include <stdint.h>

#include "si_common.h"

typedef uint32_t (*si_hash_func)(void *key);

typedef struct {
	si_hash_func hash_func;
	uint32_t nr;
} si_hashmap_t;

si_hashmap_t *si_hashmap_new(void);

void si_hashmap_free(si_hashmap_t *_map);

uint32_t si_hashmap_size(si_hashmap_t *map);

int si_hashmap_insert(si_hashmap_t *_map, char *key, void *data);

void *si_hashmap_find(si_hashmap_t *map, char *key);

#endif /* _SI_HASHMAP_H */
