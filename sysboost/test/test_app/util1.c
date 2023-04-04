#include <stdio.h>

__attribute__((constructor)) void test_constructor_util(void)
{
	printf("%s\n", __func__);
}

__attribute__((destructor)) void test_destructor_util(void)
{
	printf("%s\n", __func__);
}

int lib1_add(int a, int b)
{
	printf("%s\n", __func__);
	return a + b;
}
