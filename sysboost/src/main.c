/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf_read_elf.h"
#include "link_elf.h"
#include "si_debug.h"
#include "si_log.h"

#define LIBHOOK "libhook.so"

int main(int argc, char *argv[])
{
	// TODO modify simple app's init and fini's first functions.
	char tmp[PATH_MAX];
	elf_link_t *elf_link = elf_link_new();
	int cur_arg;
	char *str_ret;

	if (!elf_link) {
		SI_LOG_INFO("malloc fail\n");
		return -1;
	}

	if (argc == 1) {
		SI_LOG_INFO("nothing to do\n");
		return -1;
	}

	// arg0 is program name, parameter is from arg1
	cur_arg = 1;

	if (strcmp(argv[cur_arg], "-debug") == 0) {
		si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
		cur_arg++;
	} else {
		si_log_set_global_level(SI_LOG_LEVEL_INFO);
	}

	// -static parameter is used to determine whether static file generated
	if (strcmp(argv[cur_arg], "-static") == 0) {
		elf_link->dynamic_link = false;
		elf_link->direct_call_optimize = true;
		cur_arg++;
		SI_LOG_INFO("static mode\n");
	}

	for (int i = cur_arg; i < argc; i++) {
		str_ret = realpath(argv[i], tmp);
		if (!str_ret)
			si_panic("get realpath fail: %s\n", argv[i]);
		int ret = elf_link_add_infile(elf_link, tmp);
		if (ret != 0) {
			return ret;
		}
		if (strcmp(LIBHOOK, si_basename(tmp)) == 0) {
			elf_link->hook_func = true;
			SI_LOG_DEBUG("hook func\n");
		}
	}

	elf_link_write(elf_link);
	SI_LOG_INFO("OK\n");

	return 0;
}
