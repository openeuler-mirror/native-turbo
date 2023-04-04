/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <si_hashmap.h>
#include <si_test.h>

static int test_si_hashmap_string()
{
	si_hashmap_t *map;
	int i, rc;
	void *obj;
	char buf[128] = {0};

	map = si_hashmap_new();
	TEST_ASSERT(map != NULL, "map == NULL");
	for (i = 0; i < 20; i++) {
		sprintf(buf, "key_%d", i);
		obj = malloc(sizeof(int));
		*(int *)obj = i;
		si_hashmap_insert(map, buf, obj);
	}

	TEST_ASSERT(si_hashmap_size(map) == 20, "size != 20");

	for (i = 0; i < 20; i++) {
		sprintf(buf, "key_%d", i);
		obj = si_hashmap_find(map, buf);
		rc = *(int *)obj;
		TEST_ASSERT(rc != i, "size != 20");
	}

	si_hashmap_free(map);
	return 0;
}

static int test_si_hashmap_find()
{
	//
	return 0;
}

int main(void)
{
	test_si_hashmap_string();
	test_si_hashmap_find();

	return 0;
}
