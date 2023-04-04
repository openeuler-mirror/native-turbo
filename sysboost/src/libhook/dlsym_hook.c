/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <dlfcn.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define MAIN_ELF_HANDLE ((void *)-4095)

// so path list
// put addr when merge so, change .data
char *___g_so_path_list = (char *)0xDEAD;

static bool is_so_in_merge_elf(const char *filename)
{
	// count ... path ... path ...
	char tmp[PATH_MAX];
	int count = *(int *)___g_so_path_list;
	char *ret;

	if (filename == NULL) {
		return false;
	}

	ret = realpath(filename, tmp);
	if (!ret)
		printf("get realpath fail: %s\n", filename);
	char *so_path = ___g_so_path_list + sizeof(int);
	for (int i = 0; i < count; i++) {
		printf("is_so_in_merge_elf: %s -- %s\n", so_path, tmp);
		if (strcmp(so_path, tmp) == 0) {
			return true;
		}
		int len = strlen(so_path);
		so_path = so_path + (len + 1);
	}

	return false;
}

void *___dlopen(const char *filename, int flags)
{
	if (is_so_in_merge_elf(filename)) {

		return MAIN_ELF_HANDLE;
	}

	return dlopen(filename, flags);
}

int ___dlclose(void *handle)
{
	if (handle == MAIN_ELF_HANDLE) {
		return 0;
	}

	return dlclose(handle);
}

void *___dlsym(void *handle, const char *symbol)
{
	if (handle == MAIN_ELF_HANDLE) {
		handle = RTLD_DEFAULT;
	}

	return dlsym(handle, symbol);
}
