/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _ELF_READ_ELF_H
#define _ELF_READ_ELF_H

#include <elf.h>
#include <stdbool.h>

#define NEED_CLEAR_RELA (-2)

typedef struct {
	Elf64_Ehdr *hdr;
	Elf64_Phdr *segments;

	Elf64_Shdr *sechdrs;
	Elf64_Shdr *shstrtab_sec;
	Elf64_Shdr *symtab_sec;
	Elf64_Shdr *dynsym_sec;
	Elf64_Shdr *dynstr_sec;

	Elf64_Shdr *rel;

	Elf64_Phdr *hdr_Phdr;
	Elf64_Phdr *text_Phdr;
	Elf64_Phdr *rodata_Phdr;
	Elf64_Phdr *data_Phdr;
	Elf64_Phdr *dynamic_Phdr;
	Elf64_Phdr *frame_Phdr;
	Elf64_Phdr *relro_Phdr;
	Elf64_Phdr *tls_Phdr;

	char *shstrtab_data;
	char *strtab_data;
	char *dynstr_data;

	int fd;
	char *file_name;
	char *build_id;
} elf_file_t;

static inline char *elf_get_section_name(const elf_file_t *ef, const Elf64_Shdr *sec)
{
	return ef->shstrtab_data + sec->sh_name;
}

static inline char *elf_get_dynsym_name(elf_file_t *ef, Elf64_Sym *sym)
{
	return ef->dynstr_data + sym->st_name;
}

static inline char *elf_get_symbol_name(elf_file_t *ef, Elf64_Sym *sym)
{
	if (ELF64_ST_TYPE(sym->st_info) == STT_SECTION) {
		Elf64_Shdr *sec = &ef->sechdrs[sym->st_shndx];
		return elf_get_section_name(ef, sec);
	}

	return ef->strtab_data + sym->st_name;
}

static inline Elf64_Sym *elf_get_symtab_by_rela(elf_file_t *ef, Elf64_Rela *rela)
{
	return (Elf64_Sym *)((void *)ef->hdr + ef->symtab_sec->sh_offset) + ELF64_R_SYM(rela->r_info);
}

static inline Elf64_Sym *elf_get_dynsym_by_rela(elf_file_t *ef, Elf64_Rela *rela)
{
	return (Elf64_Sym *)((void *)ef->hdr + ef->dynsym_sec->sh_offset) + ELF64_R_SYM(rela->r_info);
}

unsigned long elf_va_to_offset(elf_file_t *ef, unsigned long va);
int elf_find_func_range_by_name(elf_file_t *ef, const char *func_name,
				unsigned long *start, unsigned long *end);

// symbol
unsigned elf_find_symbol_index_by_name(elf_file_t *ef, const char *name);
Elf64_Sym *elf_find_symbol_by_name(elf_file_t *ef, const char *sym_name);
bool elf_is_same_symbol_name(const char *a, const char *b);
char *get_sym_name_dynsym(elf_file_t *ef, unsigned int index);
int find_dynsym_index_by_name(elf_file_t *ef, const char *name, bool clear);

// section
Elf64_Shdr *elf_find_section_by_tls_offset(elf_file_t *ef, unsigned long obj_tls_offset);
Elf64_Shdr *elf_find_section_by_name(elf_file_t *ef, const char *sec_name);
Elf64_Shdr *elf_find_section_by_addr(elf_file_t *ef, unsigned long addr);
typedef bool (*section_filter_func)(const elf_file_t *ef, const Elf64_Shdr *sec);
bool elf_is_relro_section(const elf_file_t *ef, const Elf64_Shdr *sechdr);
bool text_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool rodata_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool got_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool rwdata_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool bss_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool elf_is_debug_section(elf_file_t *ef, Elf64_Shdr *sechdr);
bool elf_is_same_area(const elf_file_t *ef, const Elf64_Shdr *a, const Elf64_Shdr *b);

// ELF
void elf_parse_hdr(elf_file_t *ef);
int elf_read_file(char *file_name, elf_file_t *elf, bool is_readonly);

// debug
void elf_show_dynsym(elf_file_t *ef);
void elf_show_sections(elf_file_t *ef);
void elf_show_segments(elf_file_t *ef);

#endif /* _ELF_READ_ELF_H */
