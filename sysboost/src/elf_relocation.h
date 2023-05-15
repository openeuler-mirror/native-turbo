/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _ELF_RELOCATION_H
#define _ELF_RELOCATION_H

#include "elf_link_common.h"

void modify_rela_dyn(elf_link_t *elf_link);
void modify_got(elf_link_t *elf_link);
void modify_local_call(elf_link_t *elf_link);

int modify_local_call_rela(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela);
void modify_rela_plt(elf_link_t *elf_link, si_array_t *arr);
void modify_plt_got(elf_link_t *elf_link);
void correct_stop_libc_atexit(elf_link_t *elf_link);
void replace_malloc(elf_link_t *elf_link);

#endif /* _ELF_RELOCATION_H */
