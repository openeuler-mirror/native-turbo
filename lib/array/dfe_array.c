/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dfe_array.h"

typedef struct {
	void *data;
	uint32_t len;
	uint32_t eltm_capacity;
	uint32_t eltm_size;
} _dfe_array_t;

#define dfe_array_eltm_len(arr, len) ((uint32_t)(arr)->eltm_size * (len))
#define dfe_array_eltm_pos(arr, i) ((arr)->data + dfe_array_eltm_len((arr), (i)))

#define DEFAULT_ARRAY_CAP 32

dfe_array_t *dfe_array_new(uint32_t elem_size)
{
	_dfe_array_t *arr;

	if (elem_size == 0)
		return NULL;

	// TODO: check MAX size

	arr = malloc(sizeof(_dfe_array_t));
	if (!arr)
		return NULL;
	arr->data = malloc(elem_size * DEFAULT_ARRAY_CAP);
	arr->len = 0;
	arr->eltm_capacity = DEFAULT_ARRAY_CAP;
	arr->eltm_size = elem_size;

	return (dfe_array_t *)arr;
}

void dfe_array_free(dfe_array_t *_arr)
{
	_dfe_array_t *arr = (_dfe_array_t *)_arr;

	free(arr->data);
	free(arr);
}

static void dfe_array_maybe_expand(_dfe_array_t *arr, uint32_t elem_nr)
{
	uint32_t need_len;
	void *tmp;

	// TODO: check MAX size

	need_len = arr->len + elem_nr;
	if (need_len <= arr->eltm_capacity)
		return;

	need_len = max(need_len, arr->eltm_capacity * 2);
	tmp = realloc(arr->data, dfe_array_eltm_len(arr, need_len));
	arr->data = tmp;
	arr->eltm_capacity = need_len;
}

int dfe_array_append_vals(dfe_array_t *_arr, void *data, uint32_t elem_nr)
{
	_dfe_array_t *arr = (_dfe_array_t *)_arr;

	if (!arr || (elem_nr == 0))
		return -1;

	dfe_array_maybe_expand(arr, elem_nr);

	int data_len = dfe_array_eltm_len(arr, elem_nr);
	memcpy(dfe_array_eltm_pos(arr, arr->len), data, data_len);
	arr->len += elem_nr;

	return 0;
}

void dfe_array_sort(dfe_array_t *_arr, dfe_cmp_func cmp_func)
{
	_dfe_array_t *arr = (_dfe_array_t *)_arr;

	if (arr->len == 0)
		return;

	qsort(arr->data, arr->len, arr->eltm_size, cmp_func);
}
