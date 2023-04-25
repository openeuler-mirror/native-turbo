/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _ELF_LINK_COMMON_H
#define _ELF_LINK_COMMON_H

#include <stdbool.h>
#include <string.h>

#include "elf_read_elf.h"
#include "si_array.h"
#include "si_common.h"

#define ELF_SEGMENT_ALIGN (0x200000)

#define SKIP_ONE_RELA (1)
#define SKIP_TWO_RELA (2)
#define SKIP_THREE_RELA (3)

#define MAX_ELF_FILE 512
#define MAX_ELF_SECTION 128

#define LIBHOOK "libhook.so"

typedef struct {
	elf_file_t in_efs[MAX_ELF_FILE];
	elf_file_t out_ef;
	unsigned int in_ef_nr;

	elf_file_t vdso_ef;

	Elf64_Shdr tmp_sechdrs_buf[MAX_ELF_SECTION];

	si_array_t *sec_mapping_arr;
	si_array_t *obj_mapping_arr;

	si_array_t *rela_plt_arr;
	si_array_t *rela_dyn_arr;

	// direct symbol mapping
	si_array_t *symbol_mapping_arr;

	unsigned int next_mem_addr;
	unsigned int next_file_offset;

	bool delete_symbol_version;
	bool direct_call_optimize;
	bool direct_vdso_optimize;
	bool dynamic_link;
	// use libhook func to hook libc
	bool hook_func;
	unsigned long so_path_struct;
} elf_link_t;

typedef struct {
	char *symbol_name;
	unsigned long symbol_addr;
} elf_symbol_mapping_t;

typedef struct {
	elf_file_t *src_ef;
	Elf64_Shdr *src_sec;
	Elf64_Shdr *dst_sec;
	unsigned long dst_mem_addr;
	unsigned long dst_file_offset;
} elf_sec_mapping_t;

typedef struct {
	elf_file_t *src_ef;
	Elf64_Shdr *src_sec;
	void *src_obj;
	void *dst_obj;
} elf_obj_mapping_t;

// no use .plt, so clear .plt .rela.plt
static inline bool is_direct_call_optimize(elf_link_t *elf_link)
{
	return elf_link->direct_call_optimize;
}

static inline bool is_direct_vdso_optimize(elf_link_t *elf_link)
{
	return elf_link->direct_vdso_optimize;
}

static inline elf_file_t *get_template_ef(elf_link_t *elf_link)
{
	// use first ef as template
	return &elf_link->in_efs[0];
}

static inline elf_file_t *get_main_ef(elf_link_t *elf_link)
{
	if (elf_link->dynamic_link == true) {
		return &elf_link->in_efs[0];
	}

	// static mode use second ef as main ef, which contains main function we need.
	return &elf_link->in_efs[1];
}

static inline int elf_read_s32(elf_file_t *ef, unsigned long offset)
{
	void *addr = ((void *)ef->hdr + (unsigned long)offset);
	return *(int *)addr;
}

static inline int elf_read_s32_va(elf_file_t *ef, unsigned long va)
{
	return elf_read_s32(ef, elf_va_to_offset(ef, va));
}

static inline unsigned elf_read_u32(elf_file_t *ef, unsigned long offset)
{
	void *addr = ((void *)ef->hdr + (unsigned long)offset);
	return *(unsigned *)addr;
}

static inline unsigned elf_read_u32_va(elf_file_t *ef, unsigned long va)
{
	return elf_read_u32(ef, elf_va_to_offset(ef, va));
}

static inline unsigned long elf_read_u64(elf_file_t *ef, unsigned long addr_)
{
	void *addr = ((void *)ef->hdr + (unsigned long)addr_);
	return *(unsigned long *)addr;
}

static inline void elf_write_u64(elf_file_t *ef, unsigned long addr_, unsigned long value)
{
	unsigned long *addr = ((void *)ef->hdr + (unsigned long)addr_);
	*addr = value;
}

static inline void elf_write_u32(elf_file_t *ef, unsigned long addr_, unsigned value)
{
	unsigned *addr = ((void *)ef->hdr + (unsigned long)addr_);
	*addr = value;
}

static inline void elf_write_value(elf_file_t *ef, unsigned long addr_, void *val, unsigned int len)
{
	void *addr = ((void *)ef->hdr + (unsigned long)addr_);
	memcpy(addr, val, len);
}

static inline void modify_elf_file(elf_link_t *elf_link, unsigned long loc, void *val, int len)
{
	void *dst = (void *)elf_link->out_ef.hdr + loc;
	memcpy(dst, val, len);
}

bool is_gnu_weak_symbol(Elf64_Sym *sym);

unsigned long get_new_offset_by_old_offset(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long offset);
unsigned long get_new_addr_by_old_addr(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long addr);
unsigned long _get_new_elf_addr(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long addr);
int get_new_section_index(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int sec_index);
unsigned long get_new_name_offset(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Shdr *src_sec, unsigned long offset);

char *elf_get_tmp_section_name(elf_link_t *elf_link, Elf64_Shdr *shdr);
Elf64_Shdr *find_tmp_section_by_name(elf_link_t *elf_link, const char *sec_name);
Elf64_Shdr *find_tmp_section_by_src(elf_link_t *elf_link, Elf64_Shdr *shdr);

unsigned long find_sym_old_addr(elf_file_t *ef, char *sym_name);
unsigned long get_new_addr_by_sym(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym);
unsigned long get_new_addr_by_dynsym(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym);

int get_new_sym_index_no_clear(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index);
int get_new_sym_index(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index);

void show_sec_mapping(elf_link_t *elf_link);
void append_sec_mapping(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, Elf64_Shdr *dst_sec);
void append_obj_mapping(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, void *src_obj, void *dst_obj);
elf_obj_mapping_t *elf_get_mapping_by_dst(elf_link_t *elf_link, void *dst_obj);
elf_sec_mapping_t *elf_find_sec_mapping_by_dst(elf_link_t *elf_link, void *dst);
elf_sec_mapping_t *elf_find_sec_mapping_by_srcsec(elf_link_t *elf_link, Elf64_Shdr *src_sec);

void append_symbol_mapping(elf_link_t *elf_link, char *symbol_name, unsigned long symbol_addr);
unsigned long get_new_addr_by_symbol_mapping(elf_link_t *elf_link, char *symbol_name);
void init_vdso_symbol_addr(elf_link_t *elf_link);

unsigned long elf_get_new_tls_offset(elf_link_t *elf_link, elf_file_t *ef, unsigned long obj_tls_offset);

#endif /* _ELF_LINK_COMMON_H */
