#include <stdio.h>

// __thread int g_thread_lib21 = 5;
// __thread int g_thread_lib22 = 6;

int lib2_add(int a, int b)
{
	// return g_thread_lib21 + g_thread_lib22 + a + b;
	return a + b;
}
