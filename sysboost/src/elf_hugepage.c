/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf_link_common.h"
#include "si_debug.h"
#include "si_log.h"

#ifndef PF_HUGEPAGE
#define PF_HUGEPAGE (0x01000000)
#endif

#ifndef EF_AARCH64_AOT
#define EF_AARCH64_AOT      (0x00010000U)
#endif

#ifndef EF_AARCH64_HUGEPAGE
#define EF_AARCH64_HUGEPAGE (0x00020000U)
#endif

#ifdef __aarch64__
#define OS_SPECIFIC_FLAG_AOT EF_AARCH64_AOT
#define OS_SPECIFIC_FLAG_HUGEPAGE EF_AARCH64_HUGEPAGE
#else
// TODO: feature, for x86
#define OS_SPECIFIC_FLAG_AOT EF_AARCH64_AOT
#define OS_SPECIFIC_FLAG_HUGEPAGE EF_AARCH64_HUGEPAGE
#endif
#define OS_SPECIFIC_MASK (0xffffffffU ^ OS_SPECIFIC_FLAG_AOT ^ OS_SPECIFIC_FLAG_HUGEPAGE)

void _elf_set_aot(elf_file_t *ef, bool state)
{
	if (state) {
		ef->hdr->e_flags |= OS_SPECIFIC_FLAG_AOT;
		ef->hdr->e_flags |= OS_SPECIFIC_FLAG_HUGEPAGE;
	} else {
		ef->hdr->e_flags &= OS_SPECIFIC_MASK;
	}
}

void elf_set_hugepage(elf_link_t *elf_link)
{
	int i, exec_only = 1;
	elf_file_t *ef = &elf_link->out_ef;
	int count = ef->hdr->e_phnum;
	Elf64_Phdr *phdr = (Elf64_Phdr *)ef->hdr_Phdr;

	for (i = 0; i < count; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			if (exec_only && !(phdr[i].p_flags & PF_X))
				continue;
			phdr[i].p_flags |= PF_HUGEPAGE;
		}
	}

	_elf_set_aot(ef, true);
}

int elf_set_aot(char *path, bool state)
{
	elf_file_t *ef = malloc(sizeof(elf_file_t));
	if (ef == NULL) {
		SI_LOG_ERR("malloc fail\n");
		return -1;
	}

	int ret = elf_read_file(path, ef, false);
	if (ret != 0) {
		return -1;
	}

	_elf_set_aot(ef, state);

	close(ef->fd);
	// This process is a oneshot process. The release of variable ef depends
	// on the process exit.
	return 0;
}
