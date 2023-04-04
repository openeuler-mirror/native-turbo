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
#include "si_debug.h"

#define BYTES_NOP1 0x90

#define INDIRECT_CALL_INSN_OP_SIZE 2

#define CALL_INSN_SIZE 5
#define CALL_INSN_OPCODE 0xE8

#define JMP32_INSN_SIZE 5
#define JMP32_INSN_OPCODE 0xE9

#define MAX_INSN_OFFSET 2147483647L
#define MIN_INSN_OFFSET -2147483648L

#define POKE_MAX_OPCODE_SIZE 10

union text_poke_insn {
	unsigned char text[POKE_MAX_OPCODE_SIZE];
	struct {
		unsigned char opcode;
		int disp;
	} __attribute__((packed));
};

#define THREAD_VAR_INSN_OP_SIZE 12
#define THREAD_VAR_INSN_SIZE 16

union thread_var_insn {
	unsigned char text[THREAD_VAR_INSN_SIZE];
	struct {
		unsigned char opcode[THREAD_VAR_INSN_OP_SIZE];
		int offset;
	} __attribute__((packed));
};

static void modify_insn_offset(elf_link_t *elf_link, unsigned long loc, unsigned long sym_addr, int addend)
{
	int val = (long)sym_addr - (long)loc + addend;
	modify_elf_file(elf_link, loc, &val, sizeof(int));
}

static void elf_write_jmp_addr(elf_file_t *ef, unsigned long addr_, unsigned long sym_addr_)
{
	// relative jump has 4 Byte value, calculate from end of insn
	int val = sym_addr_ - addr_ - 4;
	int *addr = ((void *)ef->hdr + (unsigned long)addr_);
	*addr = val;
}

static int modify_insn_direct_jmp(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	unsigned long loc = get_new_addr_by_old_addr(elf_link, ef, rela->r_offset);
	unsigned long sym_addr = get_new_addr_by_sym(elf_link, ef, sym);
	if (sym_addr == 0) {
		return -1;
	}
	long disp = (long)sym_addr - (long)(loc - INDIRECT_CALL_INSN_OP_SIZE + CALL_INSN_SIZE);
	if ((disp > MAX_INSN_OFFSET) || (disp < MIN_INSN_OFFSET)) {
		return -1;
	}

	union text_poke_insn *insn;
	insn = (union text_poke_insn *)((void *)elf_link->out_ef.hdr + loc - INDIRECT_CALL_INSN_OP_SIZE);
	// ff 15 00 00 00 00       callq  *0x00(%rip)
	if ((insn->text[0] != 0xff) || (insn->text[1] != 0x15)) {
		return -1;
	}
	insn->opcode = CALL_INSN_OPCODE;
	insn->disp = disp;
	insn->text[5] = BYTES_NOP1;

	return 0;
}

static int get_new_tls_insn_offset(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym)
{
	unsigned long obj_tls_offset = elf_get_new_tls_offset(elf_link, ef, sym->st_value);
	elf_file_t *out_ef = &elf_link->out_ef;
	Elf64_Phdr *p = out_ef->tls_Phdr;
	unsigned long obj_addr = obj_tls_offset + p->p_paddr;

	return -(int)(p->p_paddr + p->p_memsz - obj_addr);
}

static void modify_tls_insn_use_fs(elf_link_t *elf_link, unsigned long loc, int offset_in_insn)
{
	union thread_var_insn *insn;
	insn = (union thread_var_insn *)((void *)elf_link->out_ef.hdr + loc);
	insn->opcode[0] = 0x64;
	insn->opcode[1] = 0x48;
	insn->opcode[2] = 0x8b;
	insn->opcode[3] = 0x04;
	insn->opcode[4] = 0x25;
	insn->opcode[5] = 0x00;
	insn->opcode[6] = 0x00;
	insn->opcode[7] = 0x00;
	insn->opcode[8] = 0x00;
	insn->opcode[9] = 0x48;
	insn->opcode[10] = 0x8d;
	insn->opcode[11] = 0x80;
	insn->offset = offset_in_insn;
}

static void modify_tls_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// TLS (thread local storage) use two rela
	// first insn point to got, have 16 Byte struct, modid and offset
	// second insn call __tls_get_addr to get thread var addr
	// 66 48 8d 3d c6 fe 5f 00    data16 lea 0x5ffec6(%rip),%rdi        <g_thread_lib2>
	// 66 66 48 e8 06 ff ff ff    data16 data16 rex.W call 200030       <__tls_get_addr@plt>
	// in the template ELF modid is zero, use fs to optimize insn, skip this and next rela
	// fs is percpu point to TLS end addr
	// 64 48 8b 04 25 00 00       mov    %fs:0x0,%rax         R_X86_64_TLSGD, st_value is offset to TLS area
	// 00 00
	// 48 8d 80 fc ff ff ff       lea    -0x4(%rax),%rax      R_X86_64_PLT32

	unsigned long loc;

	// .rela.dyn R_X86_64_DTPOFF64 sym->st_value is offset from .tdata begin
	// .rela.text R_X86_64_TLSGD sym->st_value is offset from .tdata begin
	// new insn offset
	int offset_in_insn = get_new_tls_insn_offset(elf_link, ef, sym);
	// thread var have 16 Byte insn space, rela offset is 4 Byte from insn begin
	loc = get_new_offset_by_old_offset(elf_link, ef, rela->r_offset) - 4;
	modify_tls_insn_use_fs(elf_link, loc, offset_in_insn);
}

// string symbol may have some name, change offset use insn direct value
static void modify_insn_data_offset(elf_link_t *elf_link, elf_file_t *ef, unsigned long loc, int addend)
{
	int offset_in_insn = elf_read_s32_va(ef, loc);
	// obj old addr
	unsigned long obj_addr = offset_in_insn + loc - addend;
	// new addr
	obj_addr = get_new_addr_by_old_addr(elf_link, ef, obj_addr);
	loc = get_new_addr_by_old_addr(elf_link, ef, loc);

	modify_insn_offset(elf_link, loc, obj_addr, addend);
}

static void modify_insn_func_offset(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// This is where to make the change
	unsigned long loc = get_new_addr_by_old_addr(elf_link, ef, rela->r_offset);
	unsigned long sym_addr = get_new_addr_by_sym(elf_link, ef, sym);

	if (sym_addr == 0) {
		// symbol is in other ELF, change offset
		modify_insn_data_offset(elf_link, ef, rela->r_offset, rela->r_addend);
		return;
	}
	int val = (long)sym_addr - (long)loc + rela->r_addend;
	modify_elf_file(elf_link, loc, &val, sizeof(int));
}

// retrun value tell skip num
int modify_local_call_rela(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela)
{
	Elf64_Sym *sym = NULL;
	int ret = 0;

	sym = (Elf64_Sym *)((void *)ef->hdr + ef->symtab_sec->sh_offset) + ELF64_R_SYM(rela->r_info);

	switch (ELF64_R_TYPE(rela->r_info)) {
	case R_X86_64_NONE:
		break;
	case R_X86_64_TLSGD:
		// TLS (thread local storage) use two rela
		// first insn point to got, have 16 Byte struct, modid and offset
		// second insn call __tls_get_addr to get thread var addr
		// 66 48 8d 3d c6 fe 5f 00    data16 lea 0x5ffec6(%rip),%rdi        <g_thread_lib2>
		// 66 66 48 e8 06 ff ff ff    data16 data16 rex.W call 200030       <__tls_get_addr@plt>
		// in the template ELF modid is zero, use fs to optimize insn, skip this and next rela
		// fs is percpu point to TLS end addr
		// mov    %fs:0x0,%rax         R_X86_64_TLSGD, st_value is offset to TLS area
		// lea    -0x4(%rax),%rax      R_X86_64_PLT32
		modify_tls_insn(elf_link, ef, rela, sym);
		return SKIP_ONE_RELA;
	case R_X86_64_TLSLD:
		// 48 8d 3d d3 e0 c9 00    lea    0xc9e0d3(%rip),%rdi        # 13ff498 <.got>   R_X86_64_TLSLD
		// e8 e6 0c ea ff          callq  6020b0 <__tls_get_addr@plt>                   R_X86_64_PLT32
		// 48 8b 80 00 00 00 00    mov    0x0(%rax),%rax                                R_X86_64_DTPOFF32
		// this time just modify immediate data
		// TODO: change insn to use fs
		modify_insn_data_offset(elf_link, ef, rela->r_offset, rela->r_addend);
		return SKIP_TWO_RELA;
	case R_X86_64_DTPOFF32:
		// insn may move by optimize
		// this insn is offset to TLS block begin, no need change
		break;
	case R_X86_64_PLT32:
		// call func in plt, change to direct jump
		// e8 74 ff ff ff          call   200070 <lib1_add@plt>
		// jmp and ret, change direct value
		// e9 ee fc ff ff          jmp    200040 <printf@plt>
		if (sym->st_shndx == SHN_UNDEF) {
			modify_insn_func_offset(elf_link, ef, rela, sym);
		}
		// local func call used offset in same sectioni, do nothing
		// e8 4d 02 00 00          call   200330 <run_b>
		break;
	case R_X86_64_GOTPCRELX:
		// call func use got, change to direct jump
		// ff 15 00 00 00 00       callq  *0x00(%rip)
		ret = modify_insn_direct_jmp(elf_link, ef, rela, sym);
		if (ret == 0)
			break;

		// data var, just change offset
		// 48 83 3d d2 fe 5f 00    cmpq   $0x0,0x5ffed2(%rip)
		modify_insn_data_offset(elf_link, ef, rela->r_offset, rela->r_addend);
		break;
	case R_X86_64_PC32:
		// STT_FUNC no need reloc
		if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC)
			break;
		// data is use offset, STT_OBJECT
		// global var, change insn offset
		// lea    0x5fff75(%rip),%rax
		// TODO: direct mov, do not use lea
		fallthrough;
	case R_X86_64_GOTPCREL:
	case R_X86_64_REX_GOTPCRELX:
		// TODO: sym may not exist, change data offset
		modify_insn_data_offset(elf_link, ef, rela->r_offset, rela->r_addend);
		break;
	case R_X86_64_64:
		// direct value, data is already write
		break;
	default:
		SI_LOG_INFO("modify_local_call_rela: invalid type %2d r_offset %016lx r_addend %016lx sym_index %4d",
			    (int)ELF64_R_TYPE(rela->r_info), rela->r_offset, rela->r_addend, (int)ELF64_R_SYM(rela->r_info));
		SI_LOG_INFO(" st_value %016lx\n", sym->st_value);
		si_panic("invalid type\n");
		return -1;
	}

	return 0;
}

void modify_rela_plt(elf_link_t *elf_link, si_array_t *arr)
{
	int len = arr->len;
	elf_obj_mapping_t *obj_rels = arr->data;
	elf_obj_mapping_t *obj_rel = NULL;
	Elf64_Rela *src_rela = NULL;
	Elf64_Rela *dst_rela = NULL;
	elf_file_t *out_ef = &elf_link->out_ef;
	Elf64_Shdr *find_sec = find_tmp_section_by_name(elf_link, ".plt");

	for (int i = 0; i < len; i++) {
		obj_rel = &obj_rels[i];
		src_rela = obj_rel->src_obj;
		dst_rela = obj_rel->dst_obj;

		// old sym index to new index of .dynsym
		unsigned int old_index = ELF64_R_SYM(src_rela->r_info);
		int new_index = get_new_sym_index(elf_link, obj_rel->src_ef, old_index);
		// func in this ELF need clear rela
		if (new_index == NEED_CLEAR_RELA) {
			(void)memset(dst_rela, 0, sizeof(*dst_rela));
			continue;
		}
		dst_rela->r_info = ELF64_R_INFO(new_index, ELF64_R_TYPE(src_rela->r_info));

		// old got addr to new addr
		dst_rela->r_offset = get_new_addr_by_old_addr(elf_link, obj_rel->src_ef, src_rela->r_offset);

		// got[n+2] is plt next insn
		unsigned long old_plt_addr = elf_read_u64(out_ef, (unsigned long)dst_rela->r_offset);
		unsigned long new_plt_addr = get_new_addr_by_old_addr(elf_link, obj_rel->src_ef, old_plt_addr);
		elf_write_u64(out_ef, (unsigned long)dst_rela->r_offset, new_plt_addr);

		// ff 25 82 ff 5f 00       jmp    *0x5fff82(%rip)
		// 68 00 00 00 00          pushq  $0x0
		// e9 e0 ff ff ff          jmpq   200020 <.plt>
		// change jmp insn offset to new
		modify_insn_offset(elf_link, new_plt_addr - 4, (unsigned long)dst_rela->r_offset, -4);
		// change sym index, pushq has 1 Byte cmd
		// index of .rela.plt
		elf_write_value(out_ef, new_plt_addr + 1, &i, sizeof(unsigned int));
		// relative jump to begin of .plt
		// pushq has 5 Byte, jmpq has 1 Byte cmd
		elf_write_jmp_addr(out_ef, new_plt_addr + 6, find_sec->sh_offset);
	}
}

void modify_plt_got(elf_link_t *elf_link)
{
	// no rela for .plt.got, do this by scan insn
	// every ELF have .plt.got secsion, just modify first one
	elf_file_t *ef = get_template_ef(elf_link);

	// ff 25 82 ff 5f 00       jmp    *0x5fff82(%rip)        # 7ffff8 <__cxa_finalize>
	Elf64_Shdr *sec = elf_find_section_by_name(ef, ".plt.got");
	if (!sec)
		return;
	unsigned long loc = sec->sh_offset;

	// insn have 2 op code, direct value have 4 Byte
	loc = loc + 2;
	modify_insn_data_offset(elf_link, ef, loc, -4);
}
