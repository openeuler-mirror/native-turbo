/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf_link_common.h"
#include "elf_relocation.h"
#include "si_debug.h"
#include "si_log.h"

#define BYTES_NOP1 0x90

#define INDIRECT_CALL_INSN_OP_SIZE 2

#define CALL_INSN_SIZE 5
#define CALL_INSN_OPCODE 0xE8

#define JMP32_INSN_SIZE 5
#define JMP32_INSN_OPCODE 0xE9

#define MAX_INSN_OFFSET 2147483647L
#define MIN_INSN_OFFSET -2147483648L

static char *special_dynsyms[] = {
    "_ITM_deregisterTMCloneTable",
    "__cxa_finalize",
    "__gmon_start__",
    "_ITM_registerTMCloneTable",
};
#define SPECIAL_DYNSYMS_LEN (sizeof(special_dynsyms) / sizeof(special_dynsyms[0]))
static bool is_dynsym_valid(Elf64_Sym *sym, const char *name)
{
	// some special symbols are ok even if they are undefined, skip them
	for (unsigned i = 0; i < SPECIAL_DYNSYMS_LEN; i++) {
		if (!strcmp(name, special_dynsyms[i]))
			return true;
	}

	if (sym->st_shndx == SHN_UNDEF)
		return false;

	return true;
}

static int find_dynsym_index_by_name(elf_file_t *ef, const char *name, bool clear)
{
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->dynsym_sec->sh_offset);
	int count = ef->dynsym_sec->sh_size / sizeof(Elf64_Sym);
	int found_index = -1;

	Elf64_Sym *sym = NULL;
	char *sym_name = NULL;
	for (int i = 0; i < count; i++) {
		sym = &syms[i];
		sym_name = elf_get_dynsym_name(ef, sym);
		if (strcmp(sym_name, name) == 0) {
			if (clear && sym->st_shndx != 0) {
				return NEED_CLEAR_RELA;
			}
			found_index = i;
			break;
		}
	}

	if (found_index == -1)
		si_panic("fail\n");

	if (is_dynsym_valid(sym, sym_name) == false) {
		si_panic("%s is UND\n", sym_name);
	}

	return found_index;
}

char *get_sym_name_dynsym(elf_file_t *ef, unsigned int index)
{
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->dynsym_sec->sh_offset);
	return elf_get_dynsym_name(ef, &syms[index]);
}

int get_new_sym_index_no_clear(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index)
{
	const char *name = get_sym_name_dynsym(src_ef, old_index);

	return find_dynsym_index_by_name(&elf_link->out_ef, name, false);
}

int get_new_sym_index(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index)
{
	const char *name = get_sym_name_dynsym(src_ef, old_index);

	return find_dynsym_index_by_name(&elf_link->out_ef, name, true);
}

static void modify_local_call_sec(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec)
{
	char *name = NULL;
	int len = sec->sh_size / sec->sh_entsize;
	Elf64_Rela *relas = (void *)ef->hdr + sec->sh_offset;
	Elf64_Rela *rela = NULL;
	int ret = 0;

	name = elf_get_section_name(ef, sec);
	SI_LOG_DEBUG("modify_local_call_sec: sec %s\n", name);

	for (int i = 0; i < len; i++) {
		rela = &relas[i];
		ret = modify_local_call_rela(elf_link, ef, rela);
		if (ret > 0) {
			// retrun value tell skip num
			i += ret;
		}
	}
}

static bool is_rela_for_A(elf_file_t *ef, Elf64_Shdr *sec)
{
	Elf64_Shdr *target_sec = NULL;

	if (sec->sh_flags & SHF_ALLOC) {
		return false;
	}
	if (sec->sh_info == 0) {
		return false;
	}
	target_sec = &ef->sechdrs[sec->sh_info];
	if (target_sec->sh_flags & SHF_ALLOC) {
		return true;
	}

	return false;
}

static void modify_local_call_ef(elf_link_t *elf_link, elf_file_t *ef)
{
	Elf64_Shdr *sechdrs = ef->sechdrs;
	unsigned int shnum = ef->hdr->e_shnum;
	unsigned int i;
	Elf64_Shdr *sec = NULL;

	for (i = 1; i < shnum; i++) {
		sec = &sechdrs[i];
		// rela sec is not alloc and sh_info is alloc sec, .rela.text
		// sh_info for SHT_SYMTAB is the first non-local symbol index
		if (sechdrs[i].sh_type != SHT_RELA || !is_rela_for_A(ef, sec)) {
			continue;
		}

		modify_local_call_sec(elf_link, ef, sec);
	}
}

void modify_local_call(elf_link_t *elf_link)
{
	elf_file_t *ef;
	int count = elf_link->in_ef_nr;

	for (int i = 0; i < count; i++) {
		ef = &elf_link->in_efs[i];
		modify_local_call_ef(elf_link, ef);
	}
}

// The __stack_chk_guard and __stack_chk_fail symbols are normally supplied by a GCC library called libssp
// we can not change code to direct access the symbol, some code use 2 insn to point symbol, the adrp insn may be shared
static void modify_rela_to_RELATIVE(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Rela *src_rela, Elf64_Rela *dst_rela)
{
	// some symbol do not export in .dynsym, change to R_AARCH64_RELATIVE
	Elf64_Sym *sym = elf_get_dynsym_by_rela(src_ef, src_rela);
	dst_rela->r_addend = get_new_addr_by_dynsym(elf_link, src_ef, sym);
	dst_rela->r_info = ELF64_R_INFO(0, ELF64_R_TYPE(R_AARCH64_RELATIVE));
	// offset modify by caller
}

void modify_rela_dyn_item(elf_link_t *elf_link, elf_obj_mapping_t *obj_rel)
{
	Elf64_Rela *src_rela = NULL;
	Elf64_Rela *dst_rela = NULL;
	int type;
	unsigned int old_index;
	int new_index;

	src_rela = obj_rel->src_obj;
	dst_rela = obj_rel->dst_obj;

	// modify offset
	dst_rela->r_offset = get_new_addr_by_old_addr(elf_link, obj_rel->src_ef, src_rela->r_offset);

	// modify index or relative addr
	type = ELF64_R_TYPE(src_rela->r_info);
	switch (type) {
	case R_X86_64_GLOB_DAT:
		// set addr of so path list
		if (elf_link->hook_func) {
			// .rela.dyn
			// 00000000007fffe0  0000000f00000006 R_X86_64_GLOB_DAT      0000000000800008 ___g_so_path_list + 0
			new_index = ELF64_R_SYM(dst_rela->r_info);
			const char *sym_name = get_sym_name_dynsym(&elf_link->out_ef, new_index);
			if (strcmp(sym_name, "___g_so_path_list") != 0) {
				return;
			}

			// when ELF load, real addr will set
			dst_rela->r_info = ELF64_R_INFO(new_index, ELF64_R_TYPE(R_X86_64_RELATIVE));
			dst_rela->r_addend = (unsigned long)elf_link->so_path_struct;
		}
		break;
	case R_X86_64_RELATIVE:
	case R_AARCH64_RELATIVE:
		dst_rela->r_addend = get_new_addr_by_old_addr(elf_link, obj_rel->src_ef, src_rela->r_addend);
		break;
	case R_AARCH64_ABS64:
		new_index = get_new_sym_index_no_clear(elf_link, obj_rel->src_ef, ELF64_R_SYM(src_rela->r_info));
		dst_rela->r_info = ELF64_R_INFO(new_index, ELF64_R_TYPE(src_rela->r_info));
		break;
	case R_AARCH64_GLOB_DAT:
		// some symbol do not export in .dynsym, change to R_AARCH64_RELATIVE
		modify_rela_to_RELATIVE(elf_link, obj_rel->src_ef, src_rela, dst_rela);
		break;
	case R_AARCH64_TLS_TPREL:
		old_index = ELF64_R_SYM(src_rela->r_info);
		new_index = 0;
		if (old_index)
			new_index = get_new_sym_index_no_clear(elf_link, obj_rel->src_ef, old_index);
		dst_rela->r_info = ELF64_R_INFO(new_index, ELF64_R_TYPE(src_rela->r_info));
		dst_rela->r_addend = src_rela->r_addend;
		break;
	case R_AARCH64_COPY:
		// Variables in the bss section, some from glibc, some declared by the application
		// Redefined in the template file temporarily, so skip here
	case R_AARCH64_NONE:
		/* nothing need to do */
		break;
	default:
		si_panic("error not supported modify_rela_dyn type\n");
	}
}

// .rela.dyn
void modify_rela_dyn(elf_link_t *elf_link)
{
	int len = elf_link->rela_dyn_arr->len;
	elf_obj_mapping_t *obj_rels = elf_link->rela_dyn_arr->data;
	elf_obj_mapping_t *obj_rel = NULL;

	for (int i = 0; i < len; i++) {
		obj_rel = &obj_rels[i];
		modify_rela_dyn_item(elf_link, obj_rel);
	}
}

void modify_got(elf_link_t *elf_link)
{
	Elf64_Shdr *got_sec = find_tmp_section_by_name(elf_link, ".got");
	Elf64_Shdr *find_sec = find_tmp_section_by_name(elf_link, ".dynamic");
	void *got_addr = NULL;

	// got[0] is .dynamic addr
	// TODO: aarch64 got[0] is zero when link
	got_addr = ((void *)elf_link->out_ef.hdr) + got_sec->sh_offset;
	if (elf_link->dynamic_link) {
		*(unsigned long *)got_addr = find_sec->sh_addr;
	}

	// modify _GLOBAL_OFFSET_TABLE_ point value, offset .dynamic to ELF header
	// _GLOBAL_OFFSET_TABLE_[0] used by _dl_relocate_static_pie to get link_map->l_addr
	//   2006: 00000000003ffbd8     0 OBJECT  LOCAL  DEFAULT  ABS _GLOBAL_OFFSET_TABLE_
	elf_file_t *template_ef = get_template_ef(elf_link);
	Elf64_Sym *sym = elf_find_symbol_by_name(template_ef, "_GLOBAL_OFFSET_TABLE_");
	unsigned long new_addr = get_new_addr_by_old_addr(elf_link, template_ef, sym->st_value);
	elf_file_t *out_ef = &elf_link->out_ef;
	elf_write_u64(out_ef, new_addr, find_sec->sh_addr);

	// modify .rela.plt
	modify_rela_plt(elf_link, elf_link->rela_plt_arr);

	// modify .plt.got
	modify_plt_got(elf_link);
}
