/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <dfe_hashmap.h>
#include <dfe_test.h>

static int test_dfe_hashmap_string()
{
	dfe_hashmap_t *map;
	int i, rc;
	void *obj;
	char buf[128] = {0};

	map = dfe_hashmap_new();
	TEST_ASSERT(map != NULL, "map == NULL");
	for (i = 0; i < 20; i++) {
		sprintf(buf, "key_%d", i);
		obj = malloc(sizeof(int));
		*(int *)obj = i;
		dfe_hashmap_insert(map, buf, obj);
	}

	TEST_ASSERT(dfe_hashmap_size(map) == 20, "size != 20");

	for (i = 0; i < 20; i++) {
		sprintf(buf, "key_%d", i);
		obj = dfe_hashmap_find(map, buf);
		rc = *(int *)obj;
		TEST_ASSERT(rc != i, "size != 20");
	}

	dfe_hashmap_free(map);
	return 0;
}

static int test_dfe_hashmap_find()
{
	//
	return 0;
}

int main(void)
{
	test_dfe_hashmap_string();
	test_dfe_hashmap_find();

	return 0;
}
