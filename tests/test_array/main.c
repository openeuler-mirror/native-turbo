/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <si_array.h>
#include <si_test.h>

static int test_si_array_append()
{
	si_array_t *arr;
	int i;
	int tmp;

	arr = si_array_new(sizeof(int));
	for (i = 0; i < 10000; i++)
		si_array_append(arr, &i);

	for (i = 0; i < 10000; i++) {
		tmp = ((int *)arr->data)[i];
		TEST_ASSERT(tmp == i, "arr data[i] fail");

		tmp = si_array_append(arr, &i);
		TEST_ASSERT(tmp == i, "si_array_append fail");
	}

	si_array_free(arr);
	return 0;
}

static int test_si_array_sort()
{
	//
	return 0;
}

int main(void)
{
	test_si_array_append();
	test_si_array_sort();

	return 0;
}
