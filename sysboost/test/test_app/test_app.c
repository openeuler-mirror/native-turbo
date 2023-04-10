#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int lib1_add(int a, int b);
extern int lib2_add(int a, int b);

extern int run_b(int a, int b);

int g_count = 1;
__thread int g_thread_count;
__thread int g_thread_count2 = 2;
__thread const int g_thread_count3 = 3;

void *thread1(void *junk)
{
	(void)junk;
	printf("test_thread_var: thread1 g_thread_count2 %d\n", g_thread_count2);
	return NULL;
}

void test_pthread(void)
{
	// pthread_t t_a;

	// pthread_create(&t_a, NULL, thread1, (void*)NULL);
	// printf("test_pthread\n");
	// pthread_join(t_a, NULL);
}

void test_switch(void)
{
	printf("test_switch: ");
	switch (g_thread_count2) {
	case 0:
		printf("case 0\n");
		break;
	case 1:
		printf("case 1\n");
		break;
	case 2:
		printf("case 2\n");
		break;
	case 3:
		printf("case 3\n");
		break;
	case 4:
		printf("case 4\n");
		break;
	default:
		printf("case default\n");
		break;
	}
}

void test_global_var(void)
{
	printf("test_global_var: g_count %d\n", g_count);
}

void test_thread_var(void)
{
	printf("test_thread_var: thread0 g_thread_count %d\n", g_thread_count);
	g_thread_count2 = g_thread_count2 + g_thread_count3;
	printf("test_thread_var: thread0 g_thread_count2 %d, g_thread_count3 %d\n", g_thread_count2, g_thread_count3);

	// test thread var in lib
	printf("test_thread_var: lib2_add=%d\n", lib2_add(1, 2));
}

void test_lib(void)
{
	printf("test_lib: lib1_add = %d\n", lib1_add(1, 2));
}

void test_local_ELF_func(void)
{
	printf("test_local_ELF_func: ");
	run_b(1, 2);
}

// TODO: constructor func for new elf will do again, but old elf just once
void test_dlsym_from_lib(void)
{
	void *handle;
	int (*add_func)(int, int);
	char *error;

	handle = dlopen("./libutil1.so", RTLD_NOW);
	if (!handle) {
		fprintf(stderr, "%s\n", dlerror());
		return;
	}
	dlerror();

	// lookup function from lib
	add_func = dlsym(handle, "lib1_add");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s\n", error);
		return;
	}

	printf("test_dlsym_from_lib: %d\n", add_func(1, 2));
	dlclose(handle);
}

void test_dlsym_any(void)
{
	int (*add_func)(int, int);
	char *error;

	// lookup function from anywhere
	add_func = dlsym(RTLD_DEFAULT, "lib1_add");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s\n", error);
		return;
	}

	printf("test_dlsym_any: %d\n", add_func(1, 2));
}

void test_dlsym(void)
{
	test_dlsym_any();
	test_dlsym_from_lib();
}

__attribute__((constructor)) void constructor_in_main_elf(void)
{
	printf("... %s\n", __func__);
}

__attribute__((destructor)) void destructor_in_main_elf(void)
{
	printf("... %s\n", __func__);
}

void test_IFUNC(void)
{
	char dest[1024] = {0};
	char src[1024] = {0};

	src[0] = 'c';

	// memmove memchr memset strlen memcpy

	// __memmove_generic
	memmove(dest + 10, dest, 512);
	if (dest[10] == 'x')
		printf("%s: error\n", __func__);

	// __memchr_generic
	void *p = memchr(src, 'a', sizeof(src));
	if (p == (void *)1UL)
		printf("%s: error\n", __func__);

	// __memset_kunpeng
	memset(dest, 0, sizeof(dest));

	// __strlen_asimd
	int i = strlen(src);
	if (i == 500)
		printf("%s: error\n", __func__);

	// __memcpy_generic
	memcpy(dest, src, sizeof(dest));
	if (dest[10] == 'x')
		printf("%s: error\n", __func__);
}

#define TEST_DLSYM_FLAG (1 << 0)

int main(int argc, char *argv[])
{
	// arg0 is program name, parameter is from arg1
	int cur_arg = 1;
	unsigned long test_flag = 0;

	if (cur_arg < argc && strcmp(argv[cur_arg], "-dlsym") == 0) {
		test_flag |= TEST_DLSYM_FLAG;
	}

	test_switch();

	test_global_var();
	test_thread_var();
	test_pthread();

	test_local_ELF_func();
	test_lib();

	if (test_flag & TEST_DLSYM_FLAG) {
		test_dlsym();
	}

	test_IFUNC();

	return 0;
}
