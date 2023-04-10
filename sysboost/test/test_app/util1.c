#include <stdio.h>

__attribute__((constructor)) void constructor_in_lib1(void)
{
	printf("... %s\n", __func__);
}

__attribute__((destructor)) void destructor_in_lib1(void)
{
	printf("... %s\n", __func__);
}

int lib1_add(int a, int b)
{
	printf("... %s\n", __func__);
	return a + b;
}
