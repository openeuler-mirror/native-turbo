/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _ELF_HUGEPAGE_H
#define _ELF_HUGEPAGE_H

#include "elf_link_common.h"

void elf_set_hugepage(elf_link_t *elf_link);
int elf_set_aot(char *path, bool state);

#endif /* _ELF_HUGEPAGE_H */
