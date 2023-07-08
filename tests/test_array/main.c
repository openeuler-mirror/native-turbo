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
