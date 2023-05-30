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
#include "elf_link_elf.h"
#include "si_debug.h"
#include "si_log.h"
#include "elf_hugepage.h"

int main(int argc, char *argv[])
{
	char tmp[PATH_MAX];
	elf_link_t *elf_link = elf_link_new();
	int cur_arg;
	char *str_ret;

	if (!elf_link) {
		SI_LOG_ERR("malloc fail\n");
		return -1;
	}

	if (argc == 1) {
		SI_LOG_ERR("nothing to do\n");
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

	if ((strcmp(argv[cur_arg], "-set") == 0) || (strcmp(argv[cur_arg], "-unset") == 0)) {
		if (cur_arg + 1 >= argc) {
			SI_LOG_ERR("need file path\n");
			return -1;
		}
		str_ret = realpath(argv[cur_arg + 1], tmp);
		if (!str_ret) {
			SI_LOG_ERR("get realpath fail: %s\n", argv[cur_arg + 1]);
			return -1;
		}

		bool state = true;
		if ((strcmp(argv[cur_arg], "-unset") == 0)) {
			state = false;
		}

		return elf_set_aot(tmp, state);
	}

	// -static parameter is used to determine whether static file generated
	if (strcmp(argv[cur_arg], "-static") == 0) {
		elf_link_set_mode(elf_link, ELF_LINK_STATIC);
		cur_arg++;
		SI_LOG_INFO("static mode\n");
	} else if (strcmp(argv[cur_arg], "-static-nolibc") == 0) {
		elf_link_set_mode(elf_link, ELF_LINK_STATIC_NOLIBC);
		cur_arg++;
		SI_LOG_INFO("static-nolibc mode\n");
	}

	for (int i = cur_arg; i < argc; i++) {
		if (*argv[i] == '\0') {
			continue;
		}

		str_ret = realpath(argv[i], tmp);
		if (!str_ret) {
			SI_LOG_ERR("get realpath fail: %s\n", argv[i]);
			return -1;
		}
		elf_file_t *ef = elf_link_add_infile(elf_link, tmp);
		if (ef == NULL) {
			SI_LOG_ERR("add link file fail: %s\n", tmp);
			return -1;
		}
	}

	elf_link_write(elf_link);
	SI_LOG_INFO("OK\n");

	return 0;
}
