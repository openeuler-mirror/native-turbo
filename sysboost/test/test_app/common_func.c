#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int run_b(int a, int b)
{
	printf("call local ELF func %d\n", 123);

	return a + b;
}
