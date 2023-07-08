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

#include "si_array.h"

typedef struct {
	void *data;
	uint32_t len;
	uint32_t eltm_capacity;
	uint32_t eltm_size;
} _si_array_t;

#define si_array_eltm_len(arr, len) ((uint32_t)(arr)->eltm_size * (len))
#define si_array_eltm_pos(arr, i) ((arr)->data + si_array_eltm_len((arr), (i)))

#define DEFAULT_ARRAY_CAP 32
// define max element size is 512M
#define MAX_ELEMENT_SIZE 536870912 

si_array_t *si_array_new(uint32_t elem_size)
{
	_si_array_t *arr;

	if (elem_size == 0 || elem_size > MAX_ELEMENT_SIZE) {
		return NULL;
	}

	// TODO: bug, check MAX size

	arr = malloc(sizeof(_si_array_t));
	if (!arr) {
		return NULL;
	}
	arr->data = malloc(elem_size * DEFAULT_ARRAY_CAP);
	arr->len = 0;
	arr->eltm_capacity = DEFAULT_ARRAY_CAP;
	arr->eltm_size = elem_size;

	return (si_array_t *)arr;
}

void si_array_free(si_array_t *_arr)
{
	_si_array_t *arr = (_si_array_t *)_arr;

	free(arr->data);
	free(arr);
}

static void si_array_maybe_expand(_si_array_t *arr, uint32_t elem_nr)
{
	uint32_t need_len;
	void *tmp;

	// TODO: bug, check MAX size

	need_len = arr->len + elem_nr;
	if (need_len <= arr->eltm_capacity) {
		return;
	}

	need_len = max(need_len, arr->eltm_capacity * 2);
	// realloc arr->data, arr->data shoulw point to the same location
	tmp = realloc(arr->data, si_array_eltm_len(arr, need_len));
	arr->data = tmp;
	arr->eltm_capacity = need_len;
}

int si_array_append_vals(si_array_t *_arr, void *data, uint32_t elem_nr)
{
	_si_array_t *arr = (_si_array_t *)_arr;

	if (!arr || (elem_nr == 0)) {
		return -1;
	}

	si_array_maybe_expand(arr, elem_nr);

	int data_len = si_array_eltm_len(arr, elem_nr);
	memcpy(si_array_eltm_pos(arr, arr->len), data, data_len);
	arr->len += elem_nr;

	return 0;
}

void si_array_sort(si_array_t *_arr, si_cmp_func cmp_func)
{
	_si_array_t *arr = (_si_array_t *)_arr;

	if (arr->len == 0) {
		return;
	}

	qsort(arr->data, arr->len, arr->eltm_size, cmp_func);
}

si_array_t *si_array_new_strings(void)
{
	return si_array_new(sizeof(char *));
}

void si_array_free_strings(si_array_t *_arr)
{
	si_array_free(_arr);
}

int si_array_append_strings(si_array_t *_arr, char *item)
{
	return si_array_append(_arr, &item);
}

bool si_array_in_strings(si_array_t *_arr, char *item)
{
	int len = _arr->len;
	char **string_arr = _arr->data;
	char *string_item = NULL;

	for (int i = 0; i < len; i++) {
		string_item = string_arr[i];
		if (strcmp(string_item, item) == 0) {
			return true;
		}
	}

	return false;
}

int si_array_append_strings_uniq(si_array_t *_arr, char *item)
{
	if (si_array_in_strings(_arr, item) == true) {
		return -1;
	}
	return si_array_append(_arr, &item);
}

void si_array_foreach_strings(si_array_t *_arr, si_foreach_func foreach_func, void *pridata)
{
	_si_array_t *arr = (_si_array_t *)_arr;

	if (arr->len == 0) {
		return;
	}

	int len = _arr->len;
	char **string_arr = _arr->data;
	char *string_item = NULL;

	for (int i = 0; i < len; i++) {
		string_item = string_arr[i];
		if (foreach_func(string_item, pridata) != 0) {
			return;
		}
	}
}
