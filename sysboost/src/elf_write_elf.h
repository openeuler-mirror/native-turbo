/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _ELF_WRITE_ELF_H
#define _ELF_WRITE_ELF_H

#include <elf.h>
#include <stdbool.h>

#include "elf_link_common.h"

void elf_modify_file_zero(elf_link_t *elf_link, unsigned long offset, unsigned long len);
void elf_modify_section_zero(elf_link_t *elf_link, char *secname);

void *write_elf_file(elf_link_t *elf_link, void *src, unsigned int len);
void *write_elf_file_zero(elf_link_t *elf_link, unsigned int len);
void *write_elf_file_section(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, Elf64_Shdr *dst_sec);

unsigned int elf_align_file(elf_link_t *elf_link, unsigned int align);
unsigned int elf_align_file_segment(elf_link_t *elf_link);
unsigned int elf_align_file_section(elf_link_t *elf_link, Elf64_Shdr *sec, bool is_align_file_offset);

int create_elf_file(char *file_name, elf_file_t *elf_file);
void truncate_elf_file(elf_link_t *elf_link);

#endif /* _ELF_WRITE_ELF_H */
