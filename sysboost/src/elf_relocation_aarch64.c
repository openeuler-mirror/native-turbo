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
#include "elf_write_elf.h"
#include "si_debug.h"
#include "si_log.h"

#define unlikely(x) __builtin_expect((x), 0)

#define ARM64_INSN_LEN (4)
#define BIAS 0x10

// B
// Branch causes an unconditional branch to a label at a PC-relative offset, with a hint that this is not a subroutine call or return.
// Format
// |31|30|29|28|27|26|25|24|23|22 21|20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0|
// |0 |0 |0 |1 |0 |1 |                             imm26                                 |
// BL
// Branch with Link branches to a PC-relative offset, setting the register X30 to PC+4. It provides a hint that this is a subroutine call.
// Format
// |31|30|29|28|27|26|25|24|23|22 21|20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0|
// |1 |0 |0 |1 |0 |1 |                             imm26                                 |
static int sign_extend_32(int value, int len)
{
	int shift = 32 - len;
	value <<= shift;
	value >>= shift;
	return value;
}

#define IMM_LEN_BRANCH 26
#define IMM_MASK_BRANCH ((1UL << IMM_LEN_BRANCH) - 1)
#define OPCODE_MASK_BRANCH (0x3FUL << IMM_LEN_BRANCH)
#define OPCODE_CALL26 (0x25UL << IMM_LEN_BRANCH)

static unsigned get_branch_addr(unsigned binary, unsigned offset)
{
	unsigned imm = binary & IMM_MASK_BRANCH;
	imm = sign_extend_32(imm, IMM_LEN_BRANCH);
	return (imm << 2) + offset;
}

static unsigned gen_branch_binary(unsigned binary, unsigned addr, unsigned offset)
{
	unsigned opcode = binary & OPCODE_MASK_BRANCH;
	return opcode | (((addr - offset) >> 2) & IMM_MASK_BRANCH);
}

// Form PC-relative address to 4KB page adds an immediate value that is shifted left by 12 bits, to the PC value to form a PC-relative address, with
// the bottom 12 bits masked out, and writes the result to the destination register.
// Format
// |31|30|29|28|27|26|25|24|23|22 21|20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5|4 3 2 1 0|
// |1 |immlo|1 |0 |0 |0 |0 |                       immhi                       |    Rd   |
#define IMM_HI_SHIFT 5
#define IMM_HI_LEN 19
#define IMM_HI_MASK ((1UL << IMM_HI_LEN) - 1)
#define IMM_LO_SHIFT 29
#define IMM_LO_LEN 2
#define IMM_LO_MASK ((1UL << IMM_LO_LEN) - 1)
#define PAGE_SHIFT 12
#define PAGE_MASK (~((1UL << PAGE_SHIFT) - 1))
#define OPCODE_ADRP (0x9UL << 28)
#define OPCODE_ADRP_MASK (0x9FUL << 24)
#define REG_LEN 5U
#define ADRP_RD_MASK ((1U << REG_LEN) - 1)

static unsigned get_adrp_Rd(unsigned binary)
{
	return (binary & ADRP_RD_MASK);
}

static unsigned get_adrp_addr(unsigned binary, unsigned long offset)
{
	unsigned imm_hi = (binary >> IMM_HI_SHIFT) & IMM_HI_MASK;
	unsigned imm_lo = (binary >> IMM_LO_SHIFT) & IMM_LO_MASK;
	unsigned imm = (imm_hi << IMM_LO_LEN) + imm_lo;
	offset &= PAGE_MASK;
	return (imm << PAGE_SHIFT) + offset;
}

static unsigned gen_adrp_binary(unsigned obj_addr, unsigned insn_offset, unsigned binary)
{
	obj_addr &= PAGE_MASK;
	insn_offset &= PAGE_MASK;
	// we have negative values
	int imm = obj_addr - insn_offset;
	imm >>= PAGE_SHIFT;
	unsigned imm_hi = ((imm >> IMM_LO_LEN) & IMM_HI_MASK) << IMM_HI_SHIFT;
	unsigned imm_lo = (imm & IMM_LO_MASK) << IMM_LO_SHIFT;
	imm = imm_hi | imm_lo;
	return OPCODE_ADRP | imm | (binary & ADRP_RD_MASK);
}

static inline bool is_adrp_instruction(unsigned binary)
{
	return ((binary & OPCODE_ADRP_MASK) == OPCODE_ADRP);
}

// STRB (immediate)
// |31|30|29|28|27|26|25|24|23|22|21 20 19 18 17 16 15 14 13 12 11 10|9 8 7 6 5|4 3 2 1 0|
// |0 |0 |1 |1 |1 |0 |0 |1 |0 |0 |              imm12                |    Rn   |    Rt   |
// the positive immediate byte offset is in the range 0 to 4095, defaulting to 0 and encoded in the "imm12" field
//
// STR (immediate)
// 64-bit (size == 11)
// |31|30|29|28|27|26|25|24|23|22|21 20 19 18 17 16 15 14 13 12 11 10|9 8 7 6 5|4 3 2 1 0|
// |1 |x |1 |1 |1 |0 |0 |1 |0 |0 |              imm12                |    Rn   |    Rt   |
// |size |                 | opc |
// For the 64-bit variant: the positive immediate byte offset is a multiple of 8 in the range 0 to 32760, defaulting to 0
// and encoded in the "imm12" field as <pimm>/8.
//
// LDRB (immediate)
// |31|30|29|28|27|26|25|24|23|22|21 20 19 18 17 16 15 14 13 12 11 10|9 8 7 6 5|4 3 2 1 0|
// |0 |0 |1 |1 |1 |0 |0 |1 |0 |1 |              imm12                |    Rn   |    Rt   |
// the positive immediate byte offset, in the range 0 to 4095, defaulting to 0 and encoded in the "imm12" field
//
// LDR (immediate)
// 64-bit (size == 11)
// |31|30|29|28|27|26|25|24|23|22|21 20 19 18 17 16 15 14 13 12 11 10|9 8 7 6 5|4 3 2 1 0|
// |1 |x |1 |1 |1 |0 |0 |1 |0 |1 |              imm12                |    Rn   |    Rt   |
// |size |                 | opc |
// For the 64-bit variant: the positive immediate byte offset is a multiple of 8 in the range 0 to 32760, defaulting to 0
// and encoded in the "imm12" field as <pimm>/8.

#define REG_LEN_LDST (REG_LEN * 2)
#define IMM_LEN_LDST 12
#define IMM_MASK_LDST (((1UL << IMM_LEN_LDST) - 1) << REG_LEN_LDST)
#define OPCODE_LDR_64 (0x3E5U << 22)
#define OPCODE_LDR_32 (0x2E5U << 22)
#define OPCODE_LDR_16 (0x1E7U << 22)
#define OPCODE_STR_64 (0b1111100100U << 22)
#define OPCODE_STR_32 (0b1011100100U << 22)
#define OPCODE_LDRB (0xE5U << 22)
#define OPCODE_STRB (0xE4U << 22)
#define OPCODE_LDST_MASK (0x3FFU << 22)
#define ADDR_SHIFT_64 3
#define IN_PAGE ((1UL << PAGE_SHIFT) - 1)
#define LDR_RN_MASK ((1U << REG_LEN) - 1)

static unsigned get_ldr_Rn(unsigned binary)
{
	return ((binary >> REG_LEN) & LDR_RN_MASK);
}

static unsigned get_ldr_addr(unsigned binary)
{
	unsigned opcode = binary & OPCODE_LDST_MASK;
	if (opcode != OPCODE_LDR_64 && opcode != OPCODE_STR_64 && opcode != OPCODE_LDRB && opcode != OPCODE_STRB) {
		si_panic("this LD/ST is not unsigned 64bit mode, opcode %x binary %x\n", opcode, binary);
		return 0;
	}
	if (opcode == OPCODE_STRB || opcode == OPCODE_LDRB)
		return ((binary & IMM_MASK_LDST) >> REG_LEN_LDST);
	return ((binary & IMM_MASK_LDST) >> REG_LEN_LDST) << ADDR_SHIFT_64;
}

// Sometimes obj_addr need to restrict to one page
static unsigned gen_ldst_binary_inpage(unsigned obj_addr, unsigned binary)
{
	obj_addr &= IN_PAGE;
	unsigned opcode = binary & OPCODE_LDST_MASK;
	if (opcode == OPCODE_LDR_64 || opcode == OPCODE_STR_64) {
		obj_addr >>= 3;
	} else if (opcode == OPCODE_LDR_32 || opcode == OPCODE_STR_32) {
		obj_addr >>= 2;
	} else if (opcode == OPCODE_LDR_16) {
		// the insn is ldrsh
		obj_addr >>= 1;
	} else {
		si_panic("this insn is not LD/ST, opcode %x binary %x\n", opcode, binary);
	}
	return (binary & ~IMM_MASK_LDST) | (obj_addr << REG_LEN_LDST);
}

// Add (immediate) adds a register value and an optionally-shifted immediate value, and writes the result to the destination register.
// Format
// |31|30|29|28|27|26|25|24|23 22|21 20 19 18 17 16 15 14 13 12 11 10|9 8 7 6 5|4 3 2 1 0|
// |sf|0 |0 |1 |0 |0 |0 |1 |shift|                imm12              |    Rn   |    Rd   |
// 32-bit (sf == 0), 64-bit (sf == 1)
// case shift of
// when '00' imm = ZeroExtend(imm12, datasize);
// when '01' imm = ZeroExtend(imm12:Zeros(12), datasize);
// when '10' SEE "ADDG, SUBG";
// when '11' ReservedValue();
#define IMM_LEN_ADD 12
#define OPCODE_ADD (0x91UL << 24)
#define OPCODE_ADD_MASK (0xFFUL << 24)
#define SHIFT_LEN_ADD 2
#define SHIFT_OFFSET_ADD 22
#define REG_LEN_ADD (REG_LEN * 2)
#define REG_MASK_ADD ((1UL << REG_LEN_ADD) - 1)
#define IMM_MASK_ADD ((1UL << IMM_LEN_ADD) - 1)
#define SHIFT_MASK_ADD ((1UL << SHIFT_LEN_ADD) - 1)

static unsigned gen_add_binary(unsigned addr, unsigned binary)
{
	if (addr >= IN_PAGE) {
		si_panic("gen_add_binary: addr is more than 4K\n");
	}
	return OPCODE_ADD | (binary & (SHIFT_MASK_ADD << SHIFT_OFFSET_ADD)) | (addr << REG_LEN_ADD) | (binary & REG_MASK_ADD);
}

// Move wide with keep moves an optionally-shifted 16-bit immediate value into a register, keeping other bits unchanged.
// Format
// |31|30|29|28|27|26|25|24|23|22 21|20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5|4 3 2 1 0|
// |sf|1 |1 |1 |0 |0 |1 |0 |1 | hw  |                    imm16                 |    Rd   |
// 32-bit (sf == 0), 64-bit (sf == 1)
#define MOVK_IMM_LEN 16
#define MOVK_IMM_MASK ((1UL << MOVZ_IMM_LEN) - 1)
#define OPCODE_MOVK (0x1E5UL << 23)
#define OPCODE_MOVK_MASK (0x1FFUL << 23)
#define REG_MASK_MOVK ((1UL << REG_LEN) - 1)
#define MOVK_IMM_MAX ((1UL << MOVK_IMM_LEN) - 1)

static unsigned gen_movk_addr(unsigned addr, unsigned binary)
{
	// The 16-digit immediate value should range from 0 to 65535
	if (addr > MOVK_IMM_MAX)
		return addr;
	return OPCODE_MOVK | (addr << REG_LEN) | (binary & REG_MASK_MOVK);
}

// Move wide with zero moves an optionally-shifted 16-bit immediate value to a register.
// Format
// |31|30|29|28|27|26|25|24|23|22 21|20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5|4 3 2 1 0|
// |sf|1 |0 |1 |0 |0 |1 |0 |1 | hw  |                    imm16                 |    Rd   |
// 32-bit (sf == 0), 64-bit (sf == 1)
#define OPCODE_MOVZ (0x1A5UL << 23)
#define OPCODE_MOVZ_MASK (0x1FFUL << 23)
static inline bool is_movz_instruction(unsigned binary)
{
	if ((binary & OPCODE_MOVZ_MASK) != OPCODE_MOVZ)
		return false;
	return true;
}

static unsigned long get_adrp_ldr_new_data_addr(elf_link_t *elf_link, elf_file_t *ef, unsigned long old_insn_addr)
{
	unsigned old_insn_raw = elf_read_u32(ef, old_insn_addr);
	unsigned long old_got_data_addr = get_adrp_addr(old_insn_raw, old_insn_addr);
	// next insn have immediate value
	unsigned old_insn_raw2 = elf_read_u32(ef, old_insn_addr + ARM64_INSN_LEN);
	SI_LOG_DEBUG("old_insn_addr %x  old_insn_raw %x  old_insn_raw2 %x\n", old_insn_addr, old_insn_raw, old_insn_raw2);
	old_got_data_addr += get_ldr_addr(old_insn_raw2);

	unsigned long new_got_data_addr = get_new_addr_by_old_addr(elf_link, ef, old_got_data_addr);
	return new_got_data_addr;
}

static void modify_adrp_ldr_tls(elf_link_t *elf_link, unsigned long insn_addr, unsigned long obj_addr)
{
	// change 4 insn to template ELF, in template ELF no need modid offset
	unsigned new_insn_raw = gen_adrp_binary(obj_addr, insn_addr, 0xf0001fe0U);
	elf_write_u32(&elf_link->out_ef, insn_addr, new_insn_raw);

	new_insn_raw = gen_ldst_binary_inpage(obj_addr, 0xf947f400U);
	elf_write_u32(&elf_link->out_ef, insn_addr + ARM64_INSN_LEN, new_insn_raw);
	elf_write_u32(&elf_link->out_ef, insn_addr + ARM64_INSN_LEN * 2, 0xd503201fU);
	elf_write_u32(&elf_link->out_ef, insn_addr + ARM64_INSN_LEN * 3, 0xd503201fU);
}

static void modify_adrp_ldr_tls_ie(elf_link_t *elf_link, unsigned long insn_addr, unsigned long obj_addr,
				   elf_file_t *ef, unsigned long old_insn_addr)
{
	// change 2 insn
	// use elf_read_u32 to get adrp binary
	unsigned binary = elf_read_u32(ef, old_insn_addr);
	unsigned new_insn_raw = gen_adrp_binary(obj_addr, insn_addr, binary);
	elf_write_u32(&elf_link->out_ef, insn_addr, new_insn_raw);

	// use elf_read_u32 to get ldr binary
	binary = elf_read_u32(ef, old_insn_addr + ARM64_INSN_LEN);
	new_insn_raw = gen_ldst_binary_inpage(obj_addr, binary);
	elf_write_u32(&elf_link->out_ef, insn_addr + ARM64_INSN_LEN, new_insn_raw);
}

static void modify_mov_tls_ie(elf_link_t *elf_link, unsigned long insn_addr, unsigned long obj_addr,
			      elf_file_t *ef, unsigned long old_insn_addr)
{
	// 1st insn don't need to change, there is 2nd insn
	unsigned binary = elf_read_u32(ef, old_insn_addr + ARM64_INSN_LEN);
	unsigned new_insn_raw = gen_movk_addr(obj_addr, binary);
	elf_write_u32(&elf_link->out_ef, insn_addr + ARM64_INSN_LEN, new_insn_raw);
}

static void modify_tls_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// TLS (thread local storage) use 4 rela
	// in template ELF, .got have 8 Byte, is offset + 0x10, tpidr_el0 is TLS first addr
	// adrp and ldr is point to .got data
	// .text
	// a20:   d53bd041        mrs     x1, tpidr_el0
	// a2c:   f0001fe0        adrp    x0, 3ff000 <__FRAME_END__+0x3fdf64>
	// a30:   f947f400        ldr     x0, [x0, #4072]                                 0x3ff000 + 4072 = 3fffe8
	// a34:   d503201f        nop
	// a38:   d503201f        nop
	// a3c:   b8606821        ldr     w1, [x1, x0]
	// .rela.text
	// 000000000a2c  007400000232 R_AARCH64_TLSDESC 0000000000000004 g_thread_count2 + 0
	// 000000000a30  007400000233 R_AARCH64_TLSDESC 0000000000000004 g_thread_count2 + 0
	// 000000000a34  007400000234 R_AARCH64_TLSDESC 0000000000000004 g_thread_count2 + 0
	// 000000000a38  007400000239 R_AARCH64_TLSDESC 0000000000000004 g_thread_count2 + 0
	// in other ELF, .got have 16 Byte, is _dl_tlsdesc_return and offset
	// 6a4:   d53bd042        mrs     x2, tpidr_el0
	// 6b0:   f0001fe0        adrp    x0, 3ff000 <__FRAME_END__+0x3fe830>
	// 6b4:   f947e404        ldr     x4, [x0, #4040]                                 0x3ff000 + 4040 = 3fffc8   *0x3fffc8
	// 6b8:   913f2000        add     x0, x0, #0xfc8                                  0x3fffc8 as first arg
	// 6bc:   d63f0080        blr     x4                                              _dl_tlsdesc_return
	// 6c0:   8b000044        add     x4, x2, x0
	// 6c4:   f0001fe0        adrp    x0, 3ff000 <__FRAME_END__+0x3fe830>
	// 6c8:   f947dc05        ldr     x5, [x0, #4024]                                 3fffb8
	// 6cc:   913ee000        add     x0, x0, #0xfb8
	// 6d0:   d63f00a0        blr     x5
	// 6d4:   b8606842        ldr     w2, [x2, x0]

	unsigned long new_got_data_addr = get_adrp_ldr_new_data_addr(elf_link, ef, rela->r_offset);
	unsigned long new_insn_addr = get_new_addr_by_old_addr(elf_link, ef, rela->r_offset);
	modify_adrp_ldr_tls(elf_link, new_insn_addr, new_got_data_addr);

	// other ELF, set offset to got, offset has a 0x10 bias
	unsigned int offset_in_insn = elf_get_new_tls_offset(elf_link, ef, sym->st_value) + BIAS;
	elf_write_u32(&elf_link->out_ef, new_got_data_addr, offset_in_insn);
}

static void modify_tls_ie(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// if symbol name is __libc_errno
	// 7990:       90001fc0        adrp    x0, 3ff000 <tunable_list+0x730>
	// 7994:       f9470400        ldr     x0, [x0, #3592]
	// 7998:       d53bd041        mrs     x1, tpidr_el0
	// 799c:       b8606820        ldr     w0, [x1, x0]
	// 000000000002b130  00001f320000021d R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 0000000000000010 __libc_errno + 0
	// 000000000002b134  00001f320000021e R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC 0000000000000010 __libc_errno + 0
	// if symbol name is .LANCHOR2
	// 896c:       d53bd055        mrs     x21, tpidr_el0
	// 8970:       d2a00016        movz    x22, #0x0, lsl #16 // x22 = 0 + #0x0 * 16
	// 8974:       f2800716        movk    x22, #0x38 // x22 = x22 + #0x38
	// ...
	// 8990:       f8766ab7        ldr     x23, [x21, x22]
	// 0000000000008970  000000d50000021d R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 0000000000000028 .LANCHOR2 + 0
	// 0000000000008974  000000d50000021e R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC 0000000000000028 .LANCHOR2 + 0

	unsigned long new_got_data_addr, new_insn_addr;
	unsigned binary = elf_read_u32(ef, rela->r_offset);
	if (is_adrp_instruction(binary)) {
		// Only need to modify the immediate value
		new_got_data_addr = get_adrp_ldr_new_data_addr(elf_link, ef, rela->r_offset);
		new_insn_addr = get_new_addr_by_old_addr(elf_link, ef, rela->r_offset);
		modify_adrp_ldr_tls_ie(elf_link, new_insn_addr, new_got_data_addr, ef, rela->r_offset);
		// Change TLS‘s offset, and module id don’t need to change
		unsigned int offset_in_insn = elf_get_new_tls_offset(elf_link, ef, sym->st_value) + BIAS;
		elf_write_u32(&elf_link->out_ef, new_got_data_addr, offset_in_insn);
	} else if (is_movz_instruction(binary)) {
		// No need to go through the .got section, but the variable name is reused.
		// The memory in .got section is not updated after the combination, so the values in this area may be incorrect
		new_got_data_addr = elf_get_new_tls_offset(elf_link, ef, sym->st_value + rela->r_addend) + BIAS;
		new_insn_addr = get_new_addr_by_old_addr(elf_link, ef, rela->r_offset);
		modify_mov_tls_ie(elf_link, new_insn_addr, new_got_data_addr, ef, rela->r_offset);
	} else
		si_panic("modify_tls_ie find other symbol!\n");
}

static void fix_special_symbol_new_addr(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym, unsigned long *new_addr)
{
	// template ELF .init_array is merge last one
	// __init_array_start need set begin of .init_array addr
	// __init_array_end need set end of .init_array addr
	char *name = elf_get_symbol_name(ef, sym);
	if (elf_is_same_symbol_name(name, "__init_array_start")) {
		Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, ".init_array");
		*new_addr = sec->sh_addr;
		SI_LOG_DEBUG("%s new addr %lx\n", name, *new_addr);
		return;
	}
	if (elf_is_same_symbol_name(name, "__init_array_end")) {
		Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, ".init_array");
		*new_addr = sec->sh_addr + sec->sh_size;
		SI_LOG_DEBUG("%s new addr %lx\n", name, *new_addr);
		return;
	}
	if (elf_is_same_symbol_name(name, "__fini_array_start")) {
		Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, ".fini_array");
		*new_addr = sec->sh_addr;
		SI_LOG_DEBUG("%s new addr %lx\n", name, *new_addr);
		return;
	}
	if (elf_is_same_symbol_name(name, "__fini_array_end")) {
		Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, ".fini_array");
		*new_addr = sec->sh_addr + sec->sh_size;
		SI_LOG_DEBUG("%s new addr %lx\n", name, *new_addr);
		return;
	}
}

// modify_new_adrp, always change imm of adrp with keeping the offset unchanged
// Example:
// 7610:       90001fc1        adrp    x1, 3ff000 <tunable_list+0x730>
// 0000000000007610  000008b300000113 R_AARCH64_ADR_PREL_PG_HI21 00000000003ff4c0 __libc_stack_end + 0
// Ensure new __libc_stack_end and old __libc_stack_end has page alignment when merging
//
// For certain situations:
// 00000000000076f8  00000a0700000113 R_AARCH64_ADR_PREL_PG_HI21 0000000000406cb0 _dl_hwcap2 + 0
// 0000000000007708  00000a070000011e R_AARCH64_LDST64_ABS_LO12_NC 0000000000406cb0 _dl_hwcap2 + 0
// 0000000000007750  00000a070000011e R_AARCH64_LDST64_ABS_LO12_NC 0000000000406cb0 _dl_hwcap2 + 0
//
// 76f8:       f0001ff8        adrp    x24, 406000 <__pthread_keys+0x3410>
// 7708:       f9465b01        ldr     x1, [x24, #3248]
// 7750:       f9465b01        ldr     x1, [x24, #3248]
// Ensure the new_symbol = old_symbol + integer page, all relative compilations do not need to be recalculated
//
// 000000000000790c  000006cb00000113 R_AARCH64_ADR_PREL_PG_HI21 0000000000000000 __ehdr_start + 0
// 0000000000007910  000006cb00000115 R_AARCH64_ADD_ABS_LO12_NC 0000000000000000 __ehdr_start + 0
//
// 790c:       b0ffffc1        adrp    x1, 0 <_nl_current_LC_CTYPE>
// 7910:       91000021        add     x1, x1, #0x0
// if type is R_AARCH64_ADR_PREL_PG_HI21, sym->st_value + rela->r_addend = 0 and imm = 0
//
// 00000000000074d8  0000072100000137 R_AARCH64_ADR_GOT_PAGE 0000000000000000 __cxa_finalize + 0
// 00000000000074dc  0000072100000138 R_AARCH64_LD64_GOT_LO12_NC 0000000000000000 __cxa_finalize + 0
//
// 74d8:       90001fc0        adrp    x0, 3ff000 <tunable_list+0x730>
// 74dc:       f9465c00        ldr     x0, [x0, #3256]
//
// 0000000000007704  0000081700000113 R_AARCH64_ADR_PREL_PG_HI21 00000000003ffbd0 _GLOBAL_OFFSET_TABLE_ + 0
// 0000000000007724  0000074700000139 R_AARCH64_LD64_GOTPAGE_LO15 0000000000000000 __rela_iplt_start + 0
// 0000000000007728  0000071b00000139 R_AARCH64_LD64_GOTPAGE_LO15 0000000000000000 __rela_iplt_end + 0
//
// 7704:       90001fda        adrp    x26, 3ff000 <tunable_list+0x730>
// 7724:       f9469742        ldr     x2, [x26, #3368]
// 7728:       f9465756        ldr     x22, [x26, #3240]
// If type is R_AARCH64_ADR_GOT_PAGE or R_AARCH64_ADR_PREL_PG_HI21 with _GLOBAL_OFFSET_TABLE_, and that means
// getting the address of the symbol from the .got, so only R_AARCH64_ADR_GOT_PAGE is processed.
//
// 00000000000006dc  0000005d00000137 R_AARCH64_ADR_GOT_PAGE 0000000000000680 main + 0
// 00000000000006e0  0000005d00000138 R_AARCH64_LD64_GOT_LO12_NC 0000000000000680 main + 0
//
// 6dc:   f0001fe0        adrp    x0, 3ff000 <__FRAME_END__+0x3fe720>
// 6e0:   f947f800        ldr     x0, [x0, #4080]
// In dynamic executable file, R_AARCH64_ADR_GOT_PAGE with address isn't 0, special treatment
static void modify_new_adrp(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	unsigned long old_sym_addr, new_sym_addr;
	int r_type = ELF64_R_TYPE(rela->r_info);
	unsigned long old_offset = rela->r_offset;
	unsigned old_insn = elf_read_u32_va(ef, old_offset);
	if (r_type == R_AARCH64_ADR_GOT_PAGE) {
		old_sym_addr = get_adrp_addr(old_insn, old_offset);
		/* make sure old_sym_addr locate in .got */
		sym = elf_find_symbol_by_name(ef, "_GLOBAL_OFFSET_TABLE_");
		if (old_sym_addr < sym->st_value)
			old_sym_addr = sym->st_value;
	} else {
		old_sym_addr = sym->st_value + rela->r_addend;
	}
	new_sym_addr = get_new_addr_by_old_addr(elf_link, ef, old_sym_addr);

	fix_special_symbol_new_addr(elf_link, ef, sym, &new_sym_addr);

	unsigned long new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	elf_file_t *out_ef = &elf_link->out_ef;
	// Generate a new insn based on the new immediate value
	unsigned new_insn = gen_adrp_binary(new_sym_addr, new_offset, old_insn);
	// Write new insn
	elf_write_u32(out_ef, new_offset, new_insn);

	SI_LOG_DEBUG("offset %lx->%lx\n", old_offset, new_offset);
}

// Check whether the addr is in the sec.
static bool is_addr_in_section(unsigned long addr, elf_file_t *ef, char *sec_name)
{
	Elf64_Shdr *sec = elf_find_section_by_name(ef, sec_name);
	if (!sec)
		return false;

	if (addr >= sec->sh_addr && addr < (sec->sh_addr + sec->sh_size))
		return true;
	return false;
}

// _DYNAMI is in .dynamic
// 0000000000012cfc  000006b800000115 R_AARCH64_ADD_ABS_LO12_NC 00000000003ff9d8 _DYNAMIC + 0
//  1720: 00000000003ff9d8     0 OBJECT  LOCAL  DEFAULT  ABS _DYNAMI
// sym in .data.rel.ro
// 000000000001294c  0000001600000113 R_AARCH64_ADR_PREL_PG_HI21 00000000003fce30 .data.rel.ro + 1aa0
// 0000000000012950  0000001600000115 R_AARCH64_ADD_ABS_LO12_NC 00000000003fce30 .data.rel.ro + 1aa0
//    22: 00000000003fce30     0 SECTION LOCAL  DEFAULT   30 .data.rel.ro
// sym in .data.rel.ro
// 0000000000007730  000009e200000113 R_AARCH64_ADR_PREL_PG_HI21 00000000003ff4a0 _dl_random + 0
// 000000000000773c  000009e20000011e R_AARCH64_LDST64_ABS_LO12_NC 00000000003ff4a0 _dl_random + 0
//  2530: 00000000003ff4a0     8 OBJECT  GLOBAL HIDDEN    30 _dl_random
// 2nd rela is not real addr, sym point to .data.rel.ro, when R_AARCH64_LD64_GOTPAGE_LO15 do not do this func
// 00000000000120fc  000007d600000113 R_AARCH64_ADR_PREL_PG_HI21 00000000003ffbd8 _GLOBAL_OFFSET_TABLE_ + 0
// 00000000000121c0  0000092900000139 R_AARCH64_LD64_GOTPAGE_LO15 00000000003fe8c0 __rseq_offset + 0
//  2345: 00000000003fe8c0     8 OBJECT  GLOBAL DEFAULT   30 __rseq_offset
static char *unaligned_sections[] = {
    ".data.rel.ro",
    ".dynamic",
    ".init_array",
    ".fini_array",
};
#define UNALIGNED_SECTIONS_LEN (sizeof(unaligned_sections) / sizeof(unaligned_sections[0]))
bool is_special_symbol_redirection(elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// .data.rel.ro and .dynamic are not aligned
	// if symbol in .data.rel.ro and .dynamic, we need to modify the offset in ld/st or add
	// Some elf files may not contain segments A or B
	unsigned long old_sym_addr = sym->st_value + rela->r_addend;
	for (unsigned i = 0; i < UNALIGNED_SECTIONS_LEN; i++) {
		if (is_addr_in_section(old_sym_addr, ef, unaligned_sections[i]))
			return true;
	}

	return false;
}

bool is_gmon_start_symbol(elf_file_t *ef, Elf64_Sym *sym)
{
	//   2086: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND __gmon_start__
	if (sym->st_shndx != SHN_UNDEF)
		return false;

	char *name = elf_get_symbol_name(ef, sym);
	if (elf_is_same_symbol_name(name, "__gmon_start__")) {
		return true;
	}
	return false;
}

bool is_ehdr_start_symbol(elf_file_t *ef, Elf64_Sym *sym)
{
	// 1689: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    1 __ehdr_start
	char *name = elf_get_symbol_name(ef, sym);
	if (elf_is_same_symbol_name(name, "__ehdr_start")) {
		return true;
	}
	return false;
}

static void modify_new_special_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	unsigned long old_offset = rela->r_offset;
	unsigned long old_insn = elf_read_u32_va(ef, old_offset);
	unsigned long old_addr = sym->st_value + rela->r_addend;
	unsigned long new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	unsigned long new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);

	fix_special_symbol_new_addr(elf_link, ef, sym, &new_addr);

	SI_LOG_DEBUG("offset %lx->%lx addr %lx->%lx\n", old_offset, new_offset, old_addr, new_addr);

	unsigned opcode = old_insn & OPCODE_LDST_MASK;
	unsigned long new_insn = 0;
	switch (opcode) {
	case OPCODE_LDR_64:
	case OPCODE_LDR_32:
	case OPCODE_STR_64:
	case OPCODE_STR_32:
		new_insn = gen_ldst_binary_inpage(new_addr, old_insn);
		break;

	case OPCODE_ADD:
		new_addr &= ~(PAGE_MASK);
		new_insn = gen_add_binary(new_addr, old_insn);
		break;

	default:
		si_panic("unsupported opcode 0x%lx\n", opcode);
		break;
	}
	elf_file_t *out_ef = &elf_link->out_ef;
	elf_write_u32(out_ef, new_offset, new_insn);
}

// adrp and 2nd insn is compose to tell a symbol addr
// rela of adrp and 2nd insn, sometime has point diff symbol, so we need keep text and data offset in PAGE
// 2nd insn is no need to change, just modify adrp imm
// text | rodata | relro | got | data | bss
// check is there symbol PAGE addr and INPAGE addr is point two area
static void check_two_rela_insn_addr(elf_link_t *elf_link, elf_file_t *ef,
				     Elf64_Rela *rela, Elf64_Sym *sym)
{
	// if sym->st_value not zero, adrp can get addr, no need check
	// case 1: two rela point same sym
	//    739c:       90000000        adrp    x0, 7000 <__abi_tag+0x6ddc>
	//    73a0:       910ed000        add     x0, x0, #0x3b4
	// 000000000000739c  0000000a00000113 R_AARCH64_ADR_PREL_PG_HI21 0000000000007180 .text + 234
	// 00000000000073a0  0000000a00000115 R_AARCH64_ADD_ABS_LO12_NC 0000000000007180 .text + 234
	//    10: 0000000000007180     0 SECTION LOCAL  DEFAULT   11 .text
	// case 2: two rela point diff sym, first rela is point right addr
	// 1f820:       90001f01        adrp    x1, 3ff000 <tunable_list+0x730>
	// 1f824:       f946ec21        ldr     x1, [x1, #3544]
	// 000000000001f820  000007d600000113 R_AARCH64_ADR_PREL_PG_HI21 00000000003ffbd8 _GLOBAL_OFFSET_TABLE_ + 0
	// 000000000001f824  0000098200000139 R_AARCH64_LD64_GOTPAGE_LO15 0000000000406d68 _dl_aarch64_cpu_features + 0
	// 2006: 00000000003ffbd8     0 OBJECT  LOCAL  DEFAULT  ABS _GLOBAL_OFFSET_TABLE_
	// 2434: 0000000000406d68    16 OBJECT  GLOBAL HIDDEN    43 _dl_aarch64_cpu_features
	unsigned long old_obj_addr = sym->st_value + rela->r_addend;
	if (old_obj_addr != 0) {
		return;
	}

	// if symbol UND and R_AARCH64_ADR_GOT_PAGE, *symbol is in .got, adrp can get _GLOBAL_OFFSET_TABLE_ addr PAGE, so no need check
	// 54120:       f0001d54        adrp    x20, 3ff000 <tunable_list+0x730>
	// 54138:       f9463281        ldr     x1, [x20, #3168]
	// 0000000000054120  000006cc00000137 R_AARCH64_ADR_GOT_PAGE 0000000000000000 __pthread_key_create + 0
	// 0000000000054138  000006cc00000138 R_AARCH64_LD64_GOT_LO12_NC 0000000000000000 __pthread_key_create + 0
	// 1740: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND __pthread_key_create
	if (ELF64_R_TYPE(rela->r_info) == R_AARCH64_ADR_GOT_PAGE) {
		return;
	}

	// __ehdr_start is ELF header, this symbol real addr is 0
	// 788c:       b0ffffc1        adrp    x1, 0 <_nl_current_LC_CTYPE>
	// 7890:       91000021        add     x1, x1, #0x0
	// 000000000000788c  0000069900000113 R_AARCH64_ADR_PREL_PG_HI21 0000000000000000 __ehdr_start + 0
	// 0000000000007890  0000069900000115 R_AARCH64_ADD_ABS_LO12_NC 0000000000000000 __ehdr_start + 0
	// 1689: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    1 __ehdr_start
	if (is_ehdr_start_symbol(ef, sym) == true) {
		return;
	}

	// other sym not .got
	/*unsigned long old_obj_addr_page = old_obj_addr & PAGE_MASK;
	unsigned long new_obj_addr = get_new_elf_addr(elf_link, ef, old_obj_addr);
	unsigned long new_obj_addr_page = get_new_elf_addr(elf_link, ef, old_obj_addr_page);

	elf_file_t *out_ef = &elf_link->out_ef;
	Elf64_Shdr *a = elf_find_section_by_addr(out_ef, new_obj_addr);
	Elf64_Shdr *b = elf_find_section_by_addr(out_ef, new_obj_addr_page);
	if (a == NULL || b == NULL || elf_is_same_area(out_ef, a, b) == false) {
		si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
		show_sec_mapping(elf_link);
		si_panic("check_two_rela_insn_addr fail: old_obj_addr %lx new_obj_addr %lx old_obj_addr_page %lx new_obj_addr_page %lx rela->r_offset %08lx\n",
			 old_obj_addr, new_obj_addr, old_obj_addr_page, new_obj_addr_page, rela->r_offset);
	}*/
	(void)elf_link;
	si_panic("check_two_rela_insn_addr fail: rela->r_offset %08lx\n", rela->r_offset);
}

static void modify_branch_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// For most cases, like this:
	// 0000000000008c68  000009620000011b R_AARCH64_CALL26       0000000000012440 __mbrlen + 0
	// 0000000000009650  00000cc60000011a R_AARCH64_JUMP26       0000000000009660 __sigjmp_save + 0
	// Some symbols are not defined, and no affects, so skip them.
	// For example,
	// 0000000000008fdc  00000a510000011b R_AARCH64_CALL26       0000000000000000 __pthread_initialize_minimal + 0
	// 0000000000000000	0 NOTYPE  LOCAL  DEFAULT  UND __pthread_initialize_minimal
	unsigned long old_insn = 0, old_sym_addr = 0, old_offset = 0;
	unsigned long new_insn = 0, new_sym_addr = 0, new_offset = 0;
	elf_file_t *out_ef = &elf_link->out_ef;

	if (is_gmon_start_symbol(ef, sym)) {
		// __gmon_start__ rela offset point nop, do nothing
		return;
	}

	old_offset = rela->r_offset;
	old_insn = elf_read_u32_va(ef, old_offset);

	// For static ELF, the symbol that type is IFUNC need special treatment
	if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
		new_sym_addr = get_new_addr_by_sym(elf_link, ef, sym);
		goto out;
	} else if (sym->st_value) {
		old_sym_addr = sym->st_value + rela->r_addend;
		new_sym_addr = get_new_addr_by_old_addr(elf_link, ef, old_sym_addr);
	} else {
		new_sym_addr = get_new_addr_by_sym(elf_link, ef, sym);
	}

	// WEAK func is used by GNU debug, libc do not have that func
	if (is_gnu_weak_symbol(sym) == true) {
		goto out;
	}

	char *name = elf_get_symbol_name(ef, sym);
	if (unlikely(elf_is_same_symbol_name(name, "main"))) {
		elf_file_t *main_ef = get_main_ef(elf_link);
		old_sym_addr = find_sym_old_addr(main_ef, "main");
		new_sym_addr = get_new_addr_by_old_addr(elf_link, main_ef, old_sym_addr);
		goto out;
	}

	// Here is an inelegant optimization for bash that cancels all resource release procedures in the
	// exit process, and directly calls the _Exit function to end the process.
	if (!elf_link->dynamic_link && unlikely(elf_is_same_symbol_name(name, "exit"))) {
		elf_file_t *template_ef = get_template_ef(elf_link);
		old_sym_addr = find_sym_old_addr(template_ef, "_exit");
		new_sym_addr = get_new_addr_by_old_addr(elf_link, template_ef, old_sym_addr);
		goto out;
	}

	// get old addr from insn
	if (!new_sym_addr) {
		old_sym_addr = get_branch_addr(old_insn, old_offset);
		new_sym_addr = get_new_addr_by_old_addr(elf_link, ef, old_sym_addr);
	}

out:
	new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	new_insn = gen_branch_binary(old_insn, new_sym_addr, new_offset);
	elf_write_u32(out_ef, new_offset, new_insn);
	SI_LOG_DEBUG("offset %lx->%lx addr %lx->%lx\n", old_offset, new_offset, old_sym_addr, new_sym_addr);
}

int modify_local_call_rela(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela)
{
	Elf64_Sym *sym = NULL;
	unsigned long old_addr = 0, new_addr = 0, binary;
	unsigned long old_offset = rela->r_offset;
	unsigned long new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	elf_file_t *out_ef = &elf_link->out_ef;
	int r_type = ELF64_R_TYPE(rela->r_info);

	sym = elf_get_symtab_by_rela(ef, rela);

	switch (r_type) {
	case R_AARCH64_PREL32:
		// sym.value + added = offset + (PC-relative 32-bit)
		old_addr = sym->st_value + rela->r_addend;
		new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
		// negative number less than 32 bit
		binary = new_addr - new_offset;
		elf_write_u32(out_ef, new_offset, binary);
		break;
	case R_AARCH64_NONE:
		// sym->st_value = 0, rela->r_addend = 0
		return 0;
	case R_AARCH64_TLSDESC_ADR_PAGE21:
		// TLS (thread local storage) use 4 rela
		modify_tls_insn(elf_link, ef, rela, sym);
		return SKIP_THREE_RELA;
	case R_AARCH64_ABS64:
		old_addr = sym->st_value + rela->r_addend;
		new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
		if (new_addr == -1UL) {
			SI_LOG_INFO("ABS64: addr is missing\n");
			si_panic("ABS64: addr is missing\n");
			return -1;
		}
		SI_LOG_DEBUG("change offset %lx->%lx content %lx->%lx\n", old_offset, new_offset, old_addr, new_addr);
		elf_write_u64(out_ef, new_offset, new_addr);
		return 0;
	case R_AARCH64_CONDBR19:
		// PC-rel. cond. br. imm. from 20:2
		// relative imm19 no need change, jump in a func, +-1M
		// b5fff9c0        cbnz    x0, 4afc0
		old_addr = sym->st_value + rela->r_addend;
		new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
		if ((new_offset - new_addr) > 0x100000) {
			SI_LOG_ERR("R_AARCH64_CONDBR19 imm19 too big, offset: %lx addr: %lx\n", new_offset, new_addr);
			return -1;
		}
		return 0;
	case R_AARCH64_CALL26:
	case R_AARCH64_JUMP26:
		modify_branch_insn(elf_link, ef, rela, sym);
		return 0;
	case R_AARCH64_ADR_GOT_PAGE:
	case R_AARCH64_ADR_PREL_PG_HI21:
		modify_new_adrp(elf_link, ef, rela, sym);
		check_two_rela_insn_addr(elf_link, ef, rela, sym);
		return 0;
	case R_AARCH64_ADD_ABS_LO12_NC:
	case R_AARCH64_LDST64_ABS_LO12_NC:
	case R_AARCH64_LDST32_ABS_LO12_NC:
	case R_AARCH64_LDST16_ABS_LO12_NC:
	case R_AARCH64_LDST8_ABS_LO12_NC:
		if (is_special_symbol_redirection(ef, rela, sym))
			modify_new_special_insn(elf_link, ef, rela, sym);
		return 0;
	case R_AARCH64_LD64_GOT_LO12_NC:
	case R_AARCH64_LD64_GOTPAGE_LO15:
		// if a symbol in dynamic or data.rel.ro, but it is needed to find address by got, should skip it
		return 0;
	case R_AARCH64_TLSLE_ADD_TPREL_HI12:
		return 0;
	case R_AARCH64_TLSLE_ADD_TPREL_LO12_NC:
		// 000000000000a298  000000d600000225 R_AARCH64_TLSLE_ADD_TPREL_HI12 0000000000000028 .LANCHOR4 + 0
		// 000000000000a29c  000000d600000227 R_AARCH64_TLSLE_ADD_TPREL_LO12_NC 0000000000000028 .LANCHOR4 + 0
		//    a298:       914002a3        add     x3, x21, #0x0, lsl #12
		//    a29c:       9100e063        add     x3, x3, #0x38
		// These 2 insns means add a range 16M imm
		new_addr = elf_get_new_tls_offset(elf_link, ef, sym->st_value + rela->r_addend) + BIAS;
		if ((long)new_addr >= (1L << 12) || (long)new_addr < 0)
			si_panic("R_AARCH64_TLSLE_ADD_TPREL_HI12: error, new_addr 0x%lx out of bound\n", new_addr);
		// if offset more than 4k, we don't take it
		new_addr &= (~PAGE_MASK);
		binary = elf_read_u32_va(ef, old_offset);
		binary = gen_add_binary(new_addr, binary);
		elf_write_u32(out_ef, new_offset, binary);
		SI_LOG_DEBUG("add offset %lx->%lx addr %lx\n", old_offset, new_offset, new_addr);
		break;
	case R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
		// adrp	x0, 3ff000  R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21
		// ldr	x0, [x0, <offset>]  R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC
		// movz	x22, #0x0, lsl #16  R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21
		// movk	x22, #0x38  R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC
		modify_tls_ie(elf_link, ef, rela, sym);
		return SKIP_ONE_RELA;
	default:
		si_panic("invalid type %d\n", (int)ELF64_R_TYPE(rela->r_info));
		return -1;
	}

	return 0;
}

#define INST_LEN_BYTE 4
void modify_plt_jump(elf_link_t *elf_link, elf_file_t *ef, unsigned long old_offset)
{
	// 0000000000007100 <.plt>:
	//    7100:       a9bf7bf0        stp     x16, x30, [sp, #-16]!
	//    7104:       90001fd0        adrp    x16, 3ff000 <tunable_list+0x730>
	//    7108:       f945ca11        ldr     x17, [x16, #2960]
	//    710c:       912e4210        add     x16, x16, #0xb90
	//    7110:       d61f0220        br      x17
	//    7114:       d503201f        nop
	//    7118:       d503201f        nop
	//    711c:       d503201f        nop
	//
	// 0000000000007120 <*ABS*+0x1f760@plt>:
	//    7120:       90001fd0        adrp    x16, 3ff000 <tunable_list+0x730>
	//    7124:       f945ce11        ldr     x17, [x16, #2968]
	//    7128:       912e6210        add     x16, x16, #0xb98
	//    712c:       d61f0220        br      x17
	unsigned old_adrp_insn, old_ldr_insn, old_addr, new_insn, new_addr, new_offset;
	elf_file_t *out_ef = &elf_link->out_ef;
	// address of the old .got section is adrp imm + ldr imm - 10
	old_adrp_insn = elf_read_u32_va(ef, old_offset);
	old_addr = get_adrp_addr(old_adrp_insn, old_offset);
	old_ldr_insn = elf_read_u32_va(ef, old_offset + INST_LEN_BYTE);
	old_addr += get_ldr_addr(old_ldr_insn);
	new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr) - BIAS;
	new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	// adrp	x16, <.got page>
	new_insn = gen_adrp_binary(new_addr, new_offset, old_adrp_insn);
	elf_write_u32(out_ef, new_offset, new_insn);
	SI_LOG_DEBUG("plt jump at %lx\n", new_offset);
}

static void modify_plt_section(elf_link_t *elf_link, elf_file_t *ef, unsigned long old_offset)
{
	Elf64_Shdr *old_rela_plt_sec = elf_find_section_by_name(ef, ".rela.plt");
	Elf64_Rela *old_rela_entry = (Elf64_Rela *)((char *)ef->hdr + old_rela_plt_sec->sh_offset);
	int count = old_rela_plt_sec->sh_size / old_rela_plt_sec->sh_entsize;

	// modify .plt stub
	old_offset += INST_LEN_BYTE;
	modify_plt_jump(elf_link, ef, old_offset);
	old_offset += INST_LEN_BYTE * 7;
	// modify func@plt stubs
	for (int i = 0; i < count; ++i, ++old_rela_entry) {
		switch (ELF64_R_TYPE(old_rela_entry->r_info)) {
		case R_AARCH64_JUMP_SLOT:
		case R_AARCH64_IRELATIVE:
			modify_plt_jump(elf_link, ef, old_offset);
			old_offset += INST_LEN_BYTE * 4;
			break;
		case R_AARCH64_TLSDESC:
			if (ELF64_R_SYM(old_rela_entry->r_info)) {
				// no plt stub for local tls
			} else {
				si_panic("unsupported plt tls entry\n");
			}
			break;
		default:
			si_panic("unsupported plt entry, %ld\n", ELF64_R_TYPE(old_rela_entry->r_info));
			break;
		}
	}
}

static void clear_plt_and_rela_plt(elf_link_t *elf_link)
{
	elf_file_t *ef = NULL;
	int in_ef_nr = elf_link->in_ef_nr;

	// out ELF .plt is rename
	for (int i = 0; i < in_ef_nr; i++) {
		ef = &elf_link->in_efs[i];

		Elf64_Shdr *old_sec = elf_find_section_by_name(ef, ".plt");
		unsigned long new_offset = get_new_offset_by_old_offset(elf_link, ef, old_sec->sh_offset);
		elf_modify_file_zero(elf_link, new_offset, old_sec->sh_size);
	}

	// .rela.plt section is already delete
}

void modify_rela_plt(elf_link_t *elf_link, si_array_t *arr)
{
	int len = arr->len;
	elf_obj_mapping_t *obj_rels = arr->data;
	Elf64_Sym *sym = NULL;

	SI_LOG_DEBUG("modify_rela_plt: \n");

	// no use .plt, so clear .plt .rela.plt
	if (is_direct_call_optimize(elf_link) == true) {
		clear_plt_and_rela_plt(elf_link);
		return;
	}

	for (int i = 0; i < len; i++) {
		elf_obj_mapping_t *obj_rel = &obj_rels[i];
		Elf64_Rela *src_rela = obj_rel->src_obj;
		Elf64_Rela *dst_rela = obj_rel->dst_obj;
		int type = ELF64_R_TYPE(src_rela->r_info);
		int new_index = 0;

		if (elf_link->dynamic_link) {
			unsigned old_index = ELF64_R_SYM(src_rela->r_info);
			new_index = get_new_sym_index(elf_link, obj_rel->src_ef, old_index);
		}
		if (new_index == NEED_CLEAR_RELA) {
			memset(dst_rela, 0, sizeof(Elf64_Rela));
			continue;
		}

		dst_rela->r_info = ELF64_R_INFO(new_index, type);
		dst_rela->r_offset = get_new_addr_by_old_addr(elf_link, obj_rel->src_ef, src_rela->r_offset);

		switch (type) {
		case R_AARCH64_IRELATIVE:
			// R_AARCH64_IRELATIVE  STT_GNU_IFUNC relocation
			// 00000000003ffba0  0000000000000408 R_AARCH64_IRELATIVE                       1f820
			dst_rela->r_addend = get_new_addr_by_old_addr(elf_link, obj_rel->src_ef, src_rela->r_addend);
			break;
		case R_AARCH64_JUMP_SLOT:
			// 00000000003fffc8  0000000800000402 R_AARCH64_JUMP_SLOT    0000000000000000 puts@GLIBC_2.17 + 0
			sym = elf_get_dynsym_by_rela(obj_rel->src_ef, src_rela);
			dst_rela->r_addend = get_new_addr_by_dynsym(elf_link, obj_rel->src_ef, sym);
			break;
		default:
			si_panic("unsupported .rela.plt %ld\n", type);
			break;
		}
	}

	Elf64_Shdr *old_plt;
	elf_file_t *in_ef;
	unsigned long old_offset;
	for (int i = 0; i < (int)elf_link->in_ef_nr; ++i) {
		in_ef = &elf_link->in_efs[i];
		old_plt = elf_find_section_by_name(in_ef, ".plt");
		old_offset = old_plt->sh_addr;
		modify_plt_section(elf_link, in_ef, old_offset);
	}
}

void modify_plt_got(elf_link_t *elf_link)
{
	(void)elf_link;
}

void correct_stop_libc_atexit(elf_link_t *elf_link)
{
	elf_file_t *template_ef = get_template_ef(elf_link);
	elf_file_t *out_ef = &elf_link->out_ef;

	/* find __run_exit_handlers() range first */
	unsigned long start, end;
	int ret = elf_find_func_range_by_name(template_ef, "__run_exit_handlers",
					      &start, &end);
	if (ret)
		si_panic("%s: elf_find_func_range_by_name fail\n", __func__);

	/* find ldr with __stop___libc_atexit rela in __run_exit_handlers() */
	Elf64_Shdr *sec = elf_find_section_by_name(template_ef, ".rela.text");
	Elf64_Rela *relas = ((void *)template_ef->hdr) + sec->sh_offset;
	unsigned len = sec->sh_size / sec->sh_entsize;
	unsigned sym_id = elf_find_symbol_index_by_name(template_ef, "__stop___libc_atexit");

	unsigned long old_ldr_addr = 0;
	for (unsigned i = 0; i < len; i++) {
		Elf64_Rela *rela = &relas[i];
		unsigned cur_sym_id = ELF64_R_SYM(rela->r_info);
		if (sym_id != cur_sym_id)
			continue;
		if (rela->r_offset < start || rela->r_offset >= end)
			continue;
		if (old_ldr_addr)
			si_panic("%s, found 2 __stop___libc_atexit symbols\n", __func__);
		old_ldr_addr = rela->r_offset;
	}
	if (!old_ldr_addr)
		si_panic("%s, didn't find __stop___libc_atexit symbol\n", __func__);
	unsigned binary = elf_read_u32(template_ef, old_ldr_addr);
	unsigned ldr_Rn = get_ldr_Rn(binary);

	/* find adrp matching with ldr above in __run_exit_handlers() */
	unsigned long old_adrp_addr = 0;
	for (unsigned long addr = start; addr < end; addr += ARM64_INSN_LEN) {
		binary = elf_read_u32(template_ef, addr);
		if (!is_adrp_instruction(binary))
			continue;
		unsigned adrp_Rd = get_adrp_Rd(binary);
		if (adrp_Rd != ldr_Rn)
			continue;
		if (old_adrp_addr)
			si_panic("%s, found 2 matched adrp in __run_exit_handlers()\n", __func__);
		old_adrp_addr = addr;
	}
	if (!old_adrp_addr)
		si_panic("%s, didn't find matched adrp in __run_exit_handlers()\n", __func__);

	/* compute got addr from ldr and adrp in out_ef */
	unsigned long new_adrp_addr = get_new_addr_by_old_addr(elf_link, template_ef, old_adrp_addr);
	unsigned long new_ldr_addr = get_new_addr_by_old_addr(elf_link, template_ef, old_ldr_addr);
	binary = elf_read_u32(out_ef, new_adrp_addr);
	unsigned long got_addr = get_adrp_addr(binary, new_adrp_addr);
	binary = elf_read_u32(out_ef, new_ldr_addr);
	got_addr += get_ldr_addr(binary);

	/* find corresponding rela entry in out_ef */
	sec = elf_find_section_by_name(out_ef, ".rela.dyn");
	relas = ((void *)out_ef->hdr) + sec->sh_offset;
	len = sec->sh_size / sec->sh_entsize;

	bool found = false;
	for (unsigned i = 0; i < len; i++) {
		Elf64_Rela *rela = &relas[i];
		if (rela->r_offset != got_addr)
			continue;
		Elf64_Sym *sym = elf_find_symbol_by_name(out_ef, "__stop___libc_atexit");
		rela->r_addend = sym->st_value;
		SI_LOG_DEBUG("change .rela.dyn 0x%lx's value to 0x%lx\n",
			     rela->r_offset, sym->st_value);
		found = true;
	}
	if (!found)
		si_panic("didn't find corresponding rela entry in .rela.dyn\n");
}

/*
void replace_symbol(elf_link_t *elf_link, char *old_sym_name, char *new_sym_name)
{
	unsigned long target_addr = find_sym_new_addr(elf_link, get_main_ef(elf_link), new_sym_name);
	unsigned long origin_addr =
		find_sym_new_addr(elf_link, get_template_ef(elf_link), old_sym_name);

	elf_file_t *out_ef = get_out_ef(elf_link);
	Elf64_Shdr *sec_text = elf_find_section_by_name(out_ef, ".text");
	Elf64_Off text_offset = sec_text->sh_offset;
	Elf64_Off text_end = text_offset + sec_text->sh_size;

	for (Elf64_Off cur_offset = text_offset; cur_offset < text_end; cur_offset += ARM64_INSN_LEN) {
		unsigned binary = elf_read_u32(out_ef, cur_offset);
		unsigned long cur_addr = get_branch_addr(binary, cur_offset);
		if (cur_addr != origin_addr)
			continue;
		unsigned new_binary = gen_branch_binary(binary, target_addr, cur_offset);
		elf_write_u32(out_ef, cur_offset, new_binary);
	}
}
*/

void replace_malloc(elf_link_t *elf_link)
{
	if (strcmp("bash.rto", si_basename(elf_link->out_ef.file_name)) != 0) {
		return;
	}

	//replace_symbol(elf_link, "__malloc", "malloc");
	//replace_symbol(elf_link, "__free", "free");
}
