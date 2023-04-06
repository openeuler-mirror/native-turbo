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
#include "si_common.h"
#include "si_debug.h"
#include "si_log.h"

void show_sec_mapping(elf_link_t *elf_link)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;

	SI_LOG_INFO("dst_addr  dst_off   dst_sec_addr         src_sec_addr         src_sec_name         src_file             *src_sec          *dst_sec\n");
	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];
		char *name = elf_get_section_name(sec_rel->src_ef, sec_rel->src_sec);
		const char *fname = si_basename(sec_rel->src_ef->file_name);
		SI_LOG_INFO("%08lx  %08lx  %08lx - %08lx  %08lx - %08lx  %-20s %-20s %016lx  %016lx\n",
			    sec_rel->dst_mem_addr, sec_rel->dst_file_offset,
			    sec_rel->dst_sec->sh_addr, sec_rel->dst_sec->sh_addr + sec_rel->dst_sec->sh_size,
			    sec_rel->src_sec->sh_addr, sec_rel->src_sec->sh_addr + sec_rel->src_sec->sh_size,
			    name, fname, (unsigned long)sec_rel->src_sec, (unsigned long)sec_rel->dst_sec);
	}
}

// if sec not SHF_ALLOC, has no addr, get_new_name_offset will use that sec
void append_sec_mapping(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, Elf64_Shdr *dst_sec)
{
	elf_sec_mapping_t sec_rel = {0};

	sec_rel.src_ef = ef;
	sec_rel.src_sec = sec;
	sec_rel.dst_sec = dst_sec;
	sec_rel.dst_mem_addr = (unsigned long)elf_link->next_mem_addr;
	sec_rel.dst_file_offset = (unsigned long)elf_link->next_file_offset;
	si_array_append(elf_link->sec_mapping_arr, &sec_rel);

	char *name = elf_get_section_name(ef, sec);
	SI_LOG_DEBUG("add section map: %-20s dst_file_offset 0x%08lx dst_addr 0x%08lx src_addr 0x%08lx\n",
		     name, sec_rel.dst_file_offset, dst_sec->sh_addr, sec->sh_addr);
}

elf_sec_mapping_t *elf_find_sec_mapping_by_srcsec(elf_link_t *elf_link, Elf64_Shdr *src_sec)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;

	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];
		if (sec_rel->src_sec != src_sec) {
			continue;
		}
		return sec_rel;
	}

	return NULL;
}

int get_new_section_index(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int sec_index)
{
	elf_sec_mapping_t *sec_rel = NULL;

	if (sec_index == 0) {
		return 0;
	}

	Elf64_Shdr *src_sec = &src_ef->sechdrs[sec_index];

	sec_rel = elf_find_sec_mapping_by_srcsec(elf_link, src_sec);
	if (sec_rel == NULL) {
		// some sec is no need in out ELF
		return 0;
		// char *name = elf_get_section_name(src_ef, src_sec);
		// printf("elf_find_sec_mapping_by_srcsec fail: file %s name %s src_sec %lx\n", src_ef->file_name, name, (unsigned long)src_sec);
		// show_sec_mapping(elf_link);
		// si_panic("elf_find_sec_mapping_by_srcsec fail");
	}

	return sec_rel->dst_sec - elf_link->out_ef.sechdrs;
}

elf_sec_mapping_t *elf_find_sec_mapping_by_dst(elf_link_t *elf_link, void *_dst_offset)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;
	unsigned long dst_offset = _dst_offset - (void *)elf_link->out_ef.hdr;

	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];

		// bss is no memory space, so out elf offset no need
		if (sec_rel->src_sec->sh_type == SHT_NOBITS) {
			continue;
		}

		if (dst_offset >= sec_rel->dst_file_offset && dst_offset < sec_rel->dst_file_offset + sec_rel->src_sec->sh_size) {
			return sec_rel;
		}
	}

	// section can not be NULL
	si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
	show_sec_mapping(elf_link);
	si_panic("section can not be NULL, dst_offset: %lx\n", dst_offset);
	return NULL;
}

void append_obj_mapping(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, void *src_obj, void *dst_obj)
{
	elf_obj_mapping_t obj_mapping = {0};

	obj_mapping.src_ef = ef;
	obj_mapping.src_sec = sec;
	obj_mapping.src_obj = src_obj;
	obj_mapping.dst_obj = dst_obj;
	si_array_append(elf_link->obj_mapping_arr, &obj_mapping);
}

static elf_obj_mapping_t *elf_get_mapping_by_src(elf_link_t *elf_link, void *src_obj)
{
	int len = elf_link->obj_mapping_arr->len;
	elf_obj_mapping_t *obj_mappings = elf_link->obj_mapping_arr->data;
	elf_obj_mapping_t *obj_mapping = NULL;

	for (int i = 0; i < len; i++) {
		obj_mapping = &obj_mappings[i];
		if (obj_mapping->src_obj != src_obj) {
			continue;
		}
		return obj_mapping;
	}

	return NULL;
}

elf_obj_mapping_t *elf_get_mapping_by_dst(elf_link_t *elf_link, void *dst_obj)
{
	int len = elf_link->obj_mapping_arr->len;
	elf_obj_mapping_t *obj_mappings = elf_link->obj_mapping_arr->data;
	elf_obj_mapping_t *obj_mapping = NULL;

	for (int i = 0; i < len; i++) {
		obj_mapping = &obj_mappings[i];
		if (obj_mapping->dst_obj != dst_obj) {
			continue;
		}
		return obj_mapping;
	}

	return NULL;
}

static void *elf_get_mapping_dst_obj(elf_link_t *elf_link, void *src_obj)
{
	elf_obj_mapping_t *obj_mapping = elf_get_mapping_by_src(elf_link, src_obj);
	if (obj_mapping == NULL) {
		return NULL;
	}

	return obj_mapping->dst_obj;
}

char *elf_get_tmp_section_name(elf_link_t *elf_link, Elf64_Shdr *shdr)
{
	// sh_name maybe not change, use old elf string
	elf_obj_mapping_t *obj_mapping = elf_get_mapping_by_dst(elf_link, shdr);

	return obj_mapping->src_ef->shstrtab_data + ((Elf64_Shdr *)obj_mapping->src_obj)->sh_name;
}

Elf64_Shdr *find_tmp_section_by_src(elf_link_t *elf_link, Elf64_Shdr *shdr)
{
	return (Elf64_Shdr *)elf_get_mapping_dst_obj(elf_link, shdr);
}

Elf64_Shdr *find_tmp_section_by_name(elf_link_t *elf_link, const char *sec_name)
{
	Elf64_Shdr *sechdrs = elf_link->out_ef.sechdrs;
	unsigned int shnum = elf_link->out_ef.hdr->e_shnum;
	unsigned int i;
	Elf64_Shdr *shdr = NULL;
	char *name = NULL;

	for (i = 1; i < shnum; i++) {
		shdr = &sechdrs[i];
		name = elf_get_tmp_section_name(elf_link, shdr);
		if (strcmp(name, sec_name) == 0) {
			return shdr;
		}
	}

	return NULL;
}

// addr != offset from RELRO segment
unsigned long _get_new_elf_addr(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long addr)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;
	elf_sec_mapping_t *end_sec_rel = NULL;
	bool found = false;
	unsigned long tmp = 0;

	// rela will point to ELF header, first section not map, so sec_rels[0] is section[1]
	if (addr < src_ef->sechdrs[1].sh_addr) {
		return addr;
	}

	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];
		if (sec_rel->src_ef != src_ef) {
			continue;
		}
		if (addr < sec_rel->src_sec->sh_addr || addr > sec_rel->src_sec->sh_addr + sec_rel->src_sec->sh_size) {
			continue;
		}
		if (addr == sec_rel->src_sec->sh_addr + sec_rel->src_sec->sh_size) {
			end_sec_rel = sec_rel;
			continue;
		}
		// section like .symtab has no addr
		if (!(sec_rel->src_sec->sh_flags & SHF_ALLOC)) {
			continue;
		}
		// .tbss has the same offset as .init_array, e.g.
		//   [22] .tbss             NOBITS           00000000007ffd18  005ffd18
		//        0000000000000004  0000000000000000 WAT       0     0     4
		//   [23] .init_array       INIT_ARRAY       00000000007ffd18  005ffd18
		//        0000000000000010  0000000000000008  WA       0     0     8
		// check the combination of SHT_NOBITS and SHF_TLS
		if ((sec_rel->src_sec->sh_type == SHT_NOBITS) && (sec_rel->src_sec->sh_flags & SHF_TLS))
			continue;
		found = true;
		break;
	}

	// _end symbol
	if (!found && end_sec_rel != NULL) {
		sec_rel = end_sec_rel;
		found = true;
	}

	if (found) {
		// out elf must be pic
		tmp = (addr - sec_rel->src_sec->sh_addr) + (unsigned long)sec_rel->dst_mem_addr;
		if (sec_rel->src_sec->sh_addr == 0) {
			si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
			show_sec_mapping(elf_link);
			SI_LOG_DEBUG("dst_file_offset %lx  dst_sec->sh_offset %lx  dst_sec->sh_addr %lx  src_sec->sh_addr %lx\n",
				     sec_rel->dst_file_offset, sec_rel->dst_sec->sh_offset, sec_rel->dst_sec->sh_addr, sec_rel->src_sec->sh_addr);
			si_panic("%s %lx %lx\n", src_ef->file_name, addr, tmp);
		}
		return tmp;
	}

	return -1;
}

unsigned long get_new_addr_by_old_addr(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long addr)
{
	unsigned long ret = _get_new_elf_addr(elf_link, src_ef, addr);
	SI_LOG_DEBUG("get addr: %s %lx %lx\n", src_ef->file_name, addr, ret);
	if (ret != (unsigned long)-1) {
		return ret;
	}

	// something wrong had happen
	si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
	show_sec_mapping(elf_link);
	si_panic("get addr fail: %s %lx %lx\n", src_ef->file_name, addr, ret);
	return -1;
}

unsigned long get_new_offset_by_old_offset(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long offset)
{
	// addr != offset after RELRO segment
	return get_new_addr_by_old_addr(elf_link, src_ef, offset);
}

static unsigned long _get_ifunc_new_addr(elf_link_t *elf_link, char *sym_name);

static unsigned long find_sym_new_addr(elf_link_t *elf_link, char *sym_name)
{
	int count = elf_link->in_ef_nr;
	elf_file_t *ef = NULL;
	Elf64_Sym *sym = NULL;

	// pubilc func sym is in dynsym
	for (int i = 0; i < count; i++) {
		ef = &elf_link->in_efs[i];
		int sym_count = ef->dynsym_sec->sh_size / sizeof(Elf64_Sym);
		Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->dynsym_sec->sh_offset);
		for (int j = 0; j < sym_count; j++) {
			sym = &syms[j];
			char *name = elf_get_dynsym_name(ef, sym);
			if (elf_is_same_symbol_name(sym_name, name) && sym->st_shndx != SHN_UNDEF)
				goto out;
		}
	}

	// static mode some func no in dynsym, find from symtab
	for (int i = 0; i < count; i++) {
		ef = &elf_link->in_efs[i];
		int sym_count = ef->symtab_sec->sh_size / sizeof(Elf64_Sym);
		Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->symtab_sec->sh_offset);
		for (int j = 0; j < sym_count; j++) {
			sym = &syms[j];
			char *name = elf_get_symbol_name(ef, sym);
			if (elf_is_same_symbol_name(sym_name, name) && sym->st_shndx != SHN_UNDEF)
				goto out;
		}
	}

	if (elf_link->dynamic_link == false)
		si_panic("not found symbol %s\n", sym_name);

out:
	if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC)
		return _get_ifunc_new_addr(elf_link, sym_name);

	return get_new_addr_by_old_addr(elf_link, ef, sym->st_value);
}

static char *ifunc_mapping[][2] = {
    {"memmove", "__memmove_generic"},
    {"memchr", "__memchr_generic"},
    {"__memchr", "__memchr_generic"},
    {"memset", "__memset_kunpeng"},
    {"strlen", "__strlen_asimd"},
    {"__strlen", "__strlen_asimd"},
    {"memcpy", "__memcpy_generic"},
};
#define IFUNC_MAPPING_LEN (sizeof(ifunc_mapping) / sizeof(ifunc_mapping[0]))
static unsigned long _get_ifunc_new_addr(elf_link_t *elf_link, char *sym_name)
{
	// TODO: use ifunc return value
	// only support for 1620
	SI_LOG_DEBUG("ifunc to real func %s\n", sym_name);

	for (unsigned i = 0; i < IFUNC_MAPPING_LEN; i++) {
		if (elf_is_same_symbol_name(sym_name, ifunc_mapping[i][0]))
			return find_sym_new_addr(elf_link, ifunc_mapping[i][1]);
	}

	si_panic("ifunc %s is not known\n", sym_name);
	return 0;
}

unsigned long find_sym_old_addr(elf_file_t *ef, char *sym_name)
{
	int sym_count = ef->symtab_sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->symtab_sec->sh_offset);
	for (int j = 0; j < sym_count; j++) {
		Elf64_Sym *sym = &syms[j];
		char *name = elf_get_symbol_name(ef, sym);
		if (elf_is_same_symbol_name(sym_name, name) && sym->st_shndx != SHN_UNDEF) {
			return sym->st_value;
		}
	}
	si_panic("can not find sym, %s\n", sym_name);
	return 0;
}

bool is_gnu_weak_symbol(Elf64_Sym *sym)
{
	// IN normal ELF
	// 5: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.17 (3)
	if ((ELF64_ST_BIND(sym->st_info) == STB_WEAK) && (sym->st_shndx == SHN_UNDEF)) {
		return true;
	}
	// IN libc ELF
	// 3441: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND _ITM_registerTMCloneTable
	if ((ELF64_ST_TYPE(sym->st_info) == STT_NOTYPE) && (sym->st_shndx == SHN_UNDEF)) {
		return true;
	}

	return false;
}

static unsigned long _get_new_addr_by_sym(elf_link_t *elf_link, elf_file_t *ef,
					  Elf64_Sym *sym, bool is_dynsym)
{
	char *sym_name = NULL;
	if (is_dynsym) {
		sym_name = elf_get_dynsym_name(ef, sym);
	} else {
		sym_name = elf_get_symbol_name(ef, sym);
	}

	// jump hook func, in libhook do not hook it, use real func
	if (elf_link->hook_func && (strcmp(LIBHOOK, si_basename(ef->file_name)) != 0)) {
		if (elf_is_same_symbol_name(sym_name, "dlopen")) {
			sym_name = "___dlopen";
		} else if (elf_is_same_symbol_name(sym_name, "dlclose")) {
			sym_name = "___dlclose";
		} else if (elf_is_same_symbol_name(sym_name, "dlsym")) {
			sym_name = "___dlsym";
		}
	}

	// WEAK func is used by GNU debug, libc do not have that func
	if (is_gnu_weak_symbol(sym) == true) {
		return 0;
	}

	if (is_direct_call_optimize(elf_link) == true) {
		// IFUNC find real function
		if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
			return _get_ifunc_new_addr(elf_link, sym_name);
		}
	}

	// When the shndx != SHN_UNDEF, the symbol in this ELF.
	if (sym->st_shndx != SHN_UNDEF) {
		return get_new_addr_by_old_addr(elf_link, ef, sym->st_value);
	}

	// find sym in other merge ELF
	return find_sym_new_addr(elf_link, sym_name);
}

unsigned long get_new_addr_by_sym(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym)
{
	return _get_new_addr_by_sym(elf_link, ef, sym, false);
}

unsigned long get_new_addr_by_dynsym(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym)
{
	return _get_new_addr_by_sym(elf_link, ef, sym, true);
}

unsigned long elf_get_new_tls_offset(elf_link_t *elf_link, elf_file_t *ef, unsigned long obj_tls_offset)
{
	// STT_TLS symbol st_value is offset to TLS segment begin
	Elf64_Shdr *obj_tls_sec = elf_find_section_by_tls_offset(ef, obj_tls_offset);
	elf_sec_mapping_t *map_tls = elf_find_sec_mapping_by_srcsec(elf_link, obj_tls_sec);
	// obj old addr
	unsigned long obj_addr = obj_tls_offset + ef->tls_Phdr->p_paddr;
	unsigned long obj_sec_offset = obj_addr - obj_tls_sec->sh_addr;
	// .tbss not in old file, can not use get_new_elf_addr
	obj_addr = map_tls->dst_file_offset + obj_sec_offset;

	return obj_addr - elf_link->out_ef.tls_Phdr->p_paddr;
}

// after merge .dynstr or .strtab
unsigned long get_new_name_offset(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Shdr *src_sec, unsigned long offset)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;
	unsigned long tmp = 0;

	// printf("get_new_name_offset: %s\n", ((char *)src_ef->hdr) + src_sec->sh_offset + offset);

	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];
		if (sec_rel->src_ef != src_ef || sec_rel->src_sec != src_sec) {
			continue;
		}
		// offset in merge section
		tmp = (unsigned long)sec_rel->dst_file_offset - sec_rel->dst_sec->sh_offset;
		tmp = tmp + offset;
		return tmp;
	}

	si_panic("get_new_name_offset fail\n");
	return 0;
}

int get_new_sym_index_no_clear(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index)
{
	if (old_index == 0)
		return 0;

	const char *name = get_sym_name_dynsym(src_ef, old_index);

	return find_dynsym_index_by_name(&elf_link->out_ef, name, false);
}

int get_new_sym_index(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index)
{
	if (old_index == 0)
		return 0;

	const char *name = get_sym_name_dynsym(src_ef, old_index);

	return find_dynsym_index_by_name(&elf_link->out_ef, name, true);
}
