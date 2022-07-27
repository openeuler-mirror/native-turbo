/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <dfe_array.h>
#include <dfe_test.h>

static int test_dfe_array_append()
{
	dfe_array_t *arr;
	int i;
	int tmp;

	arr = dfe_array_new(sizeof(int));
	for (i = 0; i < 10000; i++)
		dfe_array_append(arr, &i);

	for (i = 0; i < 10000; i++) {
		tmp = ((int *)arr->data)[i];
		TEST_ASSERT(tmp == i, "arr data[i] fail");

		tmp = dfe_array_index(arr, int, i);
		TEST_ASSERT(tmp == i, "dfe_array_index fail");
	}

	dfe_array_free(arr);
	return 0;
}

static int test_dfe_array_sort()
{
	//
	return 0;
}

int main(void)
{
	test_dfe_array_append();
	test_dfe_array_sort();

	return 0;
}
