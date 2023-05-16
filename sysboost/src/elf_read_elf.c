/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

#include "elf_read_elf.h"
#include "si_common.h"
#include <si_debug.h>
#include <si_log.h>

#ifdef __aarch64__
#define LOCAL_RUNNING_ARCH EM_AARCH64
#else
#define LOCAL_RUNNING_ARCH EM_X86_64
#endif

#define DEBUG_SEC_PRE_NAME ".debug_"
#define BUILD_ID_LEN 40

// cmp symbol name without sym version
bool elf_is_same_symbol_name(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return false;

	while (*a != '\0' && *a != '@' && *b != '\0' && *b != '@') {
		if (*a != *b)
			return false;

		a++;
		b++;
	}

	if (*a != '\0' && *a != '@')
		return false;
	if (*b != '\0' && *b != '@')
		return false;

	return true;
}

int find_dynsym_index_by_name(elf_file_t *ef, const char *name, bool clear)
{
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->dynsym_sec->sh_offset);
	int count = ef->dynsym_sec->sh_size / sizeof(Elf64_Sym);
	int found_index = -1;

	Elf64_Sym *sym = NULL;
	char *sym_name = NULL;
	for (int i = 0; i < count; i++) {
		sym = &syms[i];
		sym_name = elf_get_dynsym_name(ef, sym);
		if (elf_is_same_symbol_name(sym_name, name)) {
			if (clear && sym->st_shndx != 0) {
				return NEED_CLEAR_RELA;
			}
			found_index = i;
			break;
		}
	}

	if (found_index == -1)
		si_panic("fail\n");

	return found_index;
}

char *get_sym_name_dynsym(elf_file_t *ef, unsigned int index)
{
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->dynsym_sec->sh_offset);
	return elf_get_dynsym_name(ef, &syms[index]);
}

int elf_find_func_range_by_name(elf_file_t *ef, const char *func_name,
				unsigned long *start, unsigned long *end)
{
	Elf64_Sym *sym = elf_find_symbol_by_name(ef, func_name);
	if (!sym)
		return -1;
	*start = sym->st_value;

	Elf64_Shdr *sec = ef->symtab_sec;
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + sec->sh_offset);
	unsigned count = sec->sh_size / sizeof(Elf64_Sym);

	*end = ~0UL;
	for (unsigned i = 0; i < count; i++) {
		Elf64_Sym *sym = &syms[i];
		if (sym->st_value <= *start)
			continue;
		if (sym->st_value < *end)
			*end = sym->st_value;
	}
	if (*end == ~0UL)
		return -1;
	return 0;
}

unsigned elf_find_symbol_index_by_name(elf_file_t *ef, const char *name)
{
	Elf64_Shdr *sec = ef->symtab_sec;
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + sec->sh_offset);
	int count = sec->sh_size / sizeof(Elf64_Sym);

	for (int i = 0; i < count; i++) {
		Elf64_Sym *sym = &syms[i];
		char *sym_name = elf_get_symbol_name(ef, sym);
		SI_LOG_DEBUG("%s %s\n", name, sym_name);
		if (elf_is_same_symbol_name(sym_name, name))
			return i;
	}

	si_panic("%s fail %s\n", __func__, name);
	return ~0U; /* unreachable */
}

Elf64_Sym *elf_find_symbol_by_name(elf_file_t *ef, const char *name)
{
	Elf64_Shdr *sec = ef->symtab_sec;
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + sec->sh_offset);
	unsigned i = elf_find_symbol_index_by_name(ef, name);
	return &syms[i];
}

unsigned long elf_va_to_offset(elf_file_t *ef, unsigned long va)
{
	Elf64_Shdr *sechdrs = ef->sechdrs;
	unsigned int shnum = ef->hdr->e_shnum;
	unsigned int i;
	Elf64_Shdr *shdr = NULL;

	for (i = 1; i < shnum; i++) {
		shdr = &sechdrs[i];
		// virtual addr is only used by ALLOC section
		if (!(shdr->sh_flags & SHF_ALLOC)) {
			continue;
		}
		if ((va >= shdr->sh_addr) && (va < shdr->sh_addr + shdr->sh_size)) {
			return (va - shdr->sh_addr) + shdr->sh_offset;
		}
	}

	return -1;
}

Elf64_Shdr *elf_find_section_by_addr(elf_file_t *ef, unsigned long addr)
{
	Elf64_Shdr *sechdrs = ef->sechdrs;
	int shnum = ef->hdr->e_shnum;
	Elf64_Shdr *sec = NULL;

	for (int i = 1; i < shnum; i++) {
		sec = &sechdrs[i];
		if (!(sec->sh_flags & SHF_ALLOC)) {
			continue;
		}
		if (addr < sec->sh_addr || addr >= sec->sh_addr + sec->sh_size) {
			continue;
		}
		return sec;
	}

	return NULL;
}

Elf64_Shdr *elf_find_section_by_tls_offset(elf_file_t *ef, unsigned long obj_tls_offset)
{
	unsigned long addr = obj_tls_offset + ef->tls_Phdr->p_paddr;

	Elf64_Shdr *sec = elf_find_section_by_addr(ef, addr);
	if (!(sec->sh_flags & SHF_TLS)) {
		si_panic("elf_find_section_by_tls_offset fail\n");
		return NULL;
	}

	return sec;
}

Elf64_Shdr *elf_find_section_by_name(elf_file_t *ef, const char *sec_name)
{
	Elf64_Shdr *sechdrs = ef->sechdrs;
	char *secstrings = ef->shstrtab_data;
	unsigned int shnum = ef->hdr->e_shnum;
	unsigned int i;
	Elf64_Shdr *shdr = NULL;
	char *name = NULL;

	for (i = 1; i < shnum; i++) {
		shdr = &sechdrs[i];
		name = secstrings + shdr->sh_name;
		if (strcmp(name, sec_name) == 0) {
			return shdr;
		}
	}

	return NULL;
}

bool elf_is_relro_section(const elf_file_t *ef, const Elf64_Shdr *sechdr)
{
	unsigned int start = ef->relro_Phdr->p_paddr;
	unsigned int end = start + ef->relro_Phdr->p_memsz;

	if ((sechdr->sh_addr >= start) && (sechdr->sh_addr + sechdr->sh_size <= end)) {
		return true;
	}

	return false;
}

bool text_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec)
{
	(void)ef;
	if (!(sec->sh_flags & SHF_EXECINSTR)) {
		return false;
	}
	return true;
}

bool rodata_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec)
{
	(void)ef;
	if (sec->sh_type != SHT_PROGBITS) {
		return false;
	}
	if (!(sec->sh_flags & SHF_ALLOC)) {
		return false;
	}
	if (sec->sh_flags & SHF_WRITE) {
		return false;
	}
	if (sec->sh_flags & SHF_EXECINSTR) {
		return false;
	}
	if (sec->sh_flags & SHF_INFO_LINK) {
		return false;
	}
	return true;
}

bool got_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec)
{
	char *name = elf_get_section_name(ef, sec);
	if (strcmp(name, ".got") == 0) {
		return true;
	}
	return false;
}

bool rwdata_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec)
{
	(void)ef;

	// is WA and not in GNU_RELRO
	if (!(sec->sh_flags & SHF_ALLOC)) {
		return false;
	}
	if (!(sec->sh_flags & SHF_WRITE)) {
		return false;
	}
	if (elf_is_relro_section(ef, sec) == true) {
		return false;
	}
	// not include .bss
	if (sec->sh_type != SHT_PROGBITS) {
		return false;
	}

	return true;
}

bool bss_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec)
{
	(void)ef;

	// is WA and not in GNU_RELRO
	if (!(sec->sh_flags & SHF_ALLOC)) {
		return false;
	}
	if (!(sec->sh_flags & SHF_WRITE)) {
		return false;
	}
	if (elf_is_relro_section(ef, sec) == true) {
		return false;
	}
	// .bss
	if (sec->sh_type != SHT_NOBITS) {
		return false;
	}

	return true;
}

bool elf_is_debug_section(elf_file_t *ef, Elf64_Shdr *sechdr)
{
	char *name = NULL;

	name = ef->shstrtab_data + sechdr->sh_name;
	if (strncmp(name, DEBUG_SEC_PRE_NAME, sizeof(DEBUG_SEC_PRE_NAME) - 1) == 0) {
		return true;
	}

	return false;
}

// text | rodata | got | data | bss
bool elf_is_same_area(const elf_file_t *ef, const Elf64_Shdr *a, const Elf64_Shdr *b)
{
	if (text_section_filter(ef, a) && text_section_filter(ef, b)) {
		return true;
	}
	if (rodata_section_filter(ef, a) && rodata_section_filter(ef, b)) {
		return true;
	}
	if (got_section_filter(ef, a) && got_section_filter(ef, b)) {
		return true;
	}
	if (rwdata_section_filter(ef, a) && rwdata_section_filter(ef, b)) {
		return true;
	}
	if (bss_section_filter(ef, a) && bss_section_filter(ef, b)) {
		return true;
	}

	return false;
}

void read_elf_sections(elf_file_t *ef)
{
	unsigned int i;
	unsigned int index_str;
	Elf64_Ehdr *hdr = ef->hdr;
	Elf64_Shdr *sechdrs = NULL;
	Elf64_Shdr *strhdr;
	Elf64_Nhdr *nhdr = (Elf64_Nhdr *)(hdr + sechdrs->sh_offset);

	// sechdrs addr caller set when tmp writer
	if (ef->sechdrs == NULL) {
		sechdrs = (Elf64_Shdr *)((char *)hdr + hdr->e_shoff);
		ef->sechdrs = sechdrs;
	} else {
		sechdrs = ef->sechdrs;
	}

	// session header name string table
	strhdr = &sechdrs[hdr->e_shstrndx];
	ef->shstrtab_sec = strhdr;
	if (ef->shstrtab_data == NULL) {
		ef->shstrtab_data = (char *)hdr + strhdr->sh_offset;
	}

	// .symtab
	for (i = 1; i < hdr->e_shnum; i++) {
		if (sechdrs[i].sh_type == SHT_SYMTAB) {
			ef->symtab_sec = &sechdrs[i];
			if (ef->strtab_data == NULL) {
				index_str = sechdrs[i].sh_link;
				ef->strtab_data = (char *)hdr + sechdrs[index_str].sh_offset;
			}
			continue;
		} else if (sechdrs[i].sh_type == SHT_DYNSYM) {
			ef->dynsym_sec = &sechdrs[i];
			index_str = sechdrs[i].sh_link;
			ef->dynstr_sec = &sechdrs[index_str];
			ef->dynstr_data = (char *)hdr + sechdrs[index_str].sh_offset;
		} else if (strcmp(elf_get_section_name(ef, &sechdrs[i]), ".note.gnu.build-id") == 0) {
			nhdr = (Elf64_Nhdr *)(hdr + sechdrs[i].sh_offset);
			ef->build_id = (char *)(hdr + sechdrs[i].sh_offset + sizeof(Elf64_Nhdr) + nhdr->n_namesz);
		}
	}
}

/*
x86_64 has 4 LOAD
aarch64 has 2 LOAD
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x000230 0x000230 R   0x8
  INTERP         0x000270 0x0000000000000270 0x0000000000000270 0x00001b 0x00001b R   0x1
      [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x0017b8 0x0017b8 R E 0x200000
  LOAD           0x1ffca8 0x00000000003ffca8 0x00000000003ffca8 0x000370 0x000378 RW  0x200000
  DYNAMIC        0x1ffcd0 0x00000000003ffcd0 0x00000000003ffcd0 0x000220 0x000220 RW  0x8
  NOTE           0x00028c 0x000000000000028c 0x000000000000028c 0x000044 0x000044 R   0x4
  TLS            0x1ffca8 0x00000000003ffca8 0x00000000003ffca8 0x000008 0x00000c R   0x4
  GNU_EH_FRAME   0x001458 0x0000000000001458 0x0000000000001458 0x0000ac 0x0000ac R   0x4
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x1ffca8 0x00000000003ffca8 0x00000000003ffca8 0x000358 0x000358 R   0x1
*/
void read_elf_phdr(elf_file_t *ef)
{
	int i;
	char *load_addr;
	Elf64_Phdr *elf_ppnt, *elf_phdata;

	load_addr = (void *)ef->hdr;
	elf_phdata = (Elf64_Phdr *)(load_addr + ef->hdr->e_phoff);
	ef->segments = elf_phdata;
	for (i = 0, elf_ppnt = elf_phdata; i < ef->hdr->e_phnum; i++, elf_ppnt++) {
		if (elf_ppnt->p_type == PT_LOAD) {
			if (ef->hdr_Phdr == NULL) {
				ef->hdr_Phdr = elf_ppnt;
			}
			if (elf_ppnt->p_flags & PF_X) {
				ef->text_Phdr = elf_ppnt;
			} else if (elf_ppnt->p_flags & PF_W) {
				ef->data_Phdr = elf_ppnt;
			} else if (ef->hdr_Phdr != NULL) {
				// last R segment is rodata
				ef->rodata_Phdr = elf_ppnt;
			}
			continue;
		} else if (elf_ppnt->p_type == PT_DYNAMIC) {
			ef->dynamic_Phdr = elf_ppnt;
		} else if (elf_ppnt->p_type == PT_GNU_EH_FRAME) {
			ef->frame_Phdr = elf_ppnt;
		} else if (elf_ppnt->p_type == PT_GNU_RELRO) {
			ef->relro_Phdr = elf_ppnt;
		} else if (elf_ppnt->p_type == PT_TLS) {
			ef->tls_Phdr = elf_ppnt;
		}
	}
}

void elf_parse_hdr(elf_file_t *ef)
{
	read_elf_sections(ef);
	read_elf_phdr(ef);
}

static int read_elf_info(int fd, elf_file_t *ef, bool is_readonly)
{
	int ret;
	void *buf;

	ret = lseek(fd, 0, SEEK_END);
	int prot = PROT_READ;
	int flags = MAP_PRIVATE;
	if (is_readonly == false) {
		prot |= PROT_WRITE;
		flags = MAP_SHARED;
	}
	buf = mmap(0, ret, prot, flags, fd, 0);
	ef->length = ret;
	SI_LOG_DEBUG("ELF len %d, buf addr 0x%08lx\n", ret, (unsigned long)buf);

	ef->hdr = (Elf64_Ehdr *)buf;
	elf_parse_hdr(ef);

	return 0;
}

static int _elf_read_file(char *file_name, elf_file_t *ef, bool is_readonly)
{
	int fd = -1;
	int ret = 0;
	int flags = O_RDONLY;

	if (is_readonly == false)
		flags = O_RDWR;

	fd = open(file_name, flags);
	if (fd == -1) {
		SI_LOG_ERR("open %s fail\n", file_name);
		return -1;
	}
	ef->fd = fd;

	ret = read_elf_info(fd, ef, is_readonly);
	if (ret != 0) {
		SI_LOG_ERR("read_elf_info fail, %s\n", file_name);
		return -1;
	}

	return 0;
}

static void _elf_close_file(elf_file_t *ef)
{
	close(ef->fd);
	munmap((void *)ef->hdr, ef->length);
}

static int read_relocation_file(char *file_name, elf_file_t *ef)
{
	int ret = 0;
	char rel_file_name[PATH_MAX];
	char old_build_id[BUILD_ID_LEN] = {0};

	// save old build id
	memcpy(old_build_id, ef->build_id, BUILD_ID_LEN);
	_elf_close_file(ef);

	SI_LOG_DEBUG("read extern relocations\n");

	memcpy(rel_file_name, file_name, sizeof(rel_file_name));
	strncat(rel_file_name, ".relocation", sizeof(rel_file_name) - strlen(rel_file_name) - 1);

	ret = _elf_read_file(rel_file_name, ef, true);
	if (ret != 0) {
		SI_LOG_ERR("_elf_read_file fail, %s\n", rel_file_name);
		return -1;
	}

	// Compare the value with the build ID in the ELF file, the length of the build ID is 40 characters.
	if (memcmp(ef->build_id, old_build_id, BUILD_ID_LEN) != 0) {
		SI_LOG_ERR("build id mismatch for %s\n", rel_file_name);
		return -1;
	}

	return 0;
}

int elf_read_file(char *file_name, elf_file_t *ef, bool is_readonly)
{
	int ret = 0;

	ret = _elf_read_file(file_name, ef, is_readonly);
	if (ret != 0) {
		SI_LOG_ERR("_elf_read_file fail, %s\n", file_name);
		return -1;
	}

	// check elf arch
	if (ef->hdr->e_machine != LOCAL_RUNNING_ARCH) {
		SI_LOG_ERR("ELF arch is wrong, %s\n", file_name);
		return -1;
	}

	// ELF must pie, we read insn with offset
	if (ef->hdr_Phdr->p_vaddr != 0UL) {
		SI_LOG_ERR("ELF must compile with pie, %s\n", file_name);
		return -1;
	}

	// check elf have relocation
	Elf64_Shdr *sec = elf_find_section_by_name(ef, ".rela.text");
	if ((sec == NULL) && is_readonly) {
		ret = read_relocation_file(file_name, ef);
		if (ret != 0) {
			return 0;
		}
	}

	// ELF must have relocation
	sec = elf_find_section_by_name(ef, ".rela.text");
	if (sec == NULL) {
		SI_LOG_ERR("ELF must have .rela.text, %s\n", file_name);
		return -1;
	}

	ef->file_name = strdup(file_name);
	return 0;
}

void elf_show_dynsym(elf_file_t *ef)
{
	if (ef->dynsym_sec == NULL) {
		SI_LOG_DEBUG(".dynsym not exist\n");
	}

	SI_LOG_DEBUG("  [Nr] Name\n");

	int sym_count = ef->dynsym_sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->dynsym_sec->sh_offset);
	for (int j = 0; j < sym_count; j++) {
		Elf64_Sym *sym = &syms[j];
		char *name = elf_get_dynsym_name(ef, sym);
		SI_LOG_DEBUG("  [%2d] %-32s %016lx\n", j, name, sym->st_value);
	}
}

void elf_show_sections(elf_file_t *ef)
{
	Elf64_Shdr *sec = NULL;
	char *name = NULL;
	Elf64_Shdr *secs = ef->sechdrs;
	int len = ef->hdr->e_shnum;

	SI_LOG_DEBUG("  [Nr] Name                             Type            Address          Offset   Size   ES Flg      Link Info Align\n");

	for (int i = 0; i < len; i++) {
		sec = &secs[i];
		name = elf_get_section_name(ef, sec);
		SI_LOG_DEBUG("  [%2d] %-32s %015x %016lx %08x %06x %02x %08x %4d %4d %5d\n",
			     i, name, sec->sh_type, (unsigned long)sec->sh_addr, (unsigned int)sec->sh_offset, (unsigned int)sec->sh_size,
			     (unsigned int)sec->sh_entsize, (int)sec->sh_flags, sec->sh_link, sec->sh_info, (int)sec->sh_addralign);
	}
}

void elf_show_segments(elf_file_t *ef)
{
	Elf64_Phdr *p = NULL;
	Elf64_Phdr *base = NULL;
	int len = ef->hdr->e_phnum;

	base = (Elf64_Phdr *)((void *)ef->hdr + ef->hdr->e_phoff);

	SI_LOG_DEBUG("  Type     Offset   VirtAddr         PhysAddr         FileSiz  MemSiz   Flg      Align\n");
	for (int i = 0; i < len; i++) {
		p = &base[i];
		SI_LOG_DEBUG("  %08x %08x %016lx %016lx %08x %08x %08x %08x\n",
			     p->p_type, (unsigned int)p->p_offset, p->p_vaddr, p->p_paddr,
			     (unsigned int)p->p_filesz, (unsigned int)p->p_memsz, p->p_flags, (unsigned int)p->p_align);
	}
}