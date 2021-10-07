#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int run_b(int a, int b);

int g_count = 1;

int main(void)
{

	run_b(1, 2);

	sleep(g_count);

	return 0;
}

