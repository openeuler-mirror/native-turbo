/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <dlfcn.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <si_common.h>

#define MAIN_ELF_HANDLE ((void *)-4095)

// ELF lib file name list, libs can not have same name
// first 4 Byte is count, left space is strings
// modify .got var point to poit real addr when merge lib.so
// init MAGIC NUM for debug, here no need reserve more space
char ___g_so_path_list[8] = {'D', 'E', 'A', 'D'};

static bool is_so_in_merge_elf(const char *filename)
{
	const char *tmp = NULL;
	int count = *(int *)___g_so_path_list;

	if (filename == NULL) {
		return false;
	}

	tmp = si_basename(filename);
	char *so_path = ___g_so_path_list + sizeof(int);
	for (int i = 0; i < count; i++) {
		if (strcmp(so_path, tmp) == 0) {
			return true;
		}
		int len = strlen(so_path);
		so_path = so_path + (len + 1);
	}

	return false;
}

void *__hook_dlopen(const char *filename, int flags)
{
	if (is_so_in_merge_elf(filename)) {
		return MAIN_ELF_HANDLE;
	}

	return dlopen(filename, flags);
}

int __hook_dlclose(void *handle)
{
	if (handle == MAIN_ELF_HANDLE) {
		return 0;
	}

	return dlclose(handle);
}

void *__hook_dlsym(void *handle, const char *symbol)
{
	if (handle == MAIN_ELF_HANDLE) {
		handle = RTLD_DEFAULT;
	}

	return dlsym(handle, symbol);
}
