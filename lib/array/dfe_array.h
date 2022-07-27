/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _DFE_ARRAY_H
#define _DFE_ARRAY_H

#include <stdint.h>

#include "dfe_common.h"

typedef struct {
	void *data;
	uint32_t len;
} dfe_array_t;

#define dfe_array_index(a, t, i) (((t *)(void *)(a)->data)[(i)])

dfe_array_t *dfe_array_new(uint32_t elem_size);
void dfe_array_free(dfe_array_t *arr);

int dfe_array_append_vals(dfe_array_t *arr, void *data, uint32_t elem_size);

static inline int dfe_array_append(dfe_array_t *arr, void *data)
{
	return dfe_array_append_vals(arr, data, 1);
}

void dfe_array_sort(dfe_array_t *arr, dfe_cmp_func cmp_func);

#endif /* _DFE_ARRAY_H */
