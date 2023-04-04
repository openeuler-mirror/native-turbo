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

#ifndef PF_HUGEPAGE
#define PF_HUGEPAGE (0x01000000)
#endif

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
}
