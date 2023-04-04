/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "elf_link_common.h"
#include <si_debug.h>
#include <si_log.h>

static void check_bss_addr(elf_file_t *out_ef)
{
	// in kernel, bss addr = data segment + filesize
	Elf64_Shdr *sec = elf_find_section_by_name(out_ef, ".bss");
	Elf64_Phdr *p = out_ef->data_Phdr;

	if (sec->sh_addr != (p->p_paddr + p->p_filesz)) {
		si_panic(".bss addr wrong\n");
	}
}

static void check_data_section_addr(elf_file_t *out_ef)
{
	Elf64_Shdr *sec = elf_find_section_by_name(out_ef, ".data");

	// .data section addr align 2M
	if (sec->sh_addr % ELF_SEGMENT_ALIGN != 0) {
		si_panic(".data addr wrong\n");
	}

	// GNU_RELRO end align 2M
	Elf64_Phdr *p = out_ef->relro_Phdr;
	if ((p->p_paddr + p->p_memsz) % ELF_SEGMENT_ALIGN != 0) {
		si_panic("GNU_RELRO end addr wrong\n");
	}
}

void elf_check_elf(elf_link_t *elf_link)
{
	elf_file_t *out_ef = &elf_link->out_ef;
	check_bss_addr(out_ef);
	check_data_section_addr(out_ef);
}
