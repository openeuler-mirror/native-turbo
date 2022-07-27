#define _GNU_SOURCE

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

#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough \
	do {        \
	} while (0) /* fallthrough */
#endif

#define _dl_debug_printf printf

typedef void (*main_func)();
main_func g_main = NULL;

/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define __ELF_NATIVE_CLASS 64
#define ElfW(type) _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e, w, t) _ElfW_1(e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

struct elf_info {
	Elf64_Ehdr *hdr;
	Elf64_Shdr *sechdrs;
	Elf64_Shdr *strhdr;
	Elf64_Shdr *symsec;
	char *secstrings;
	char *strtab;
	char *text_vhdr;
	char *rodata_vhdr;
};

/*
 * Generic 64bit nops from GAS:
 *
 * 1: nop
 * 2: osp nop
 * 3: nopl (%eax)
 * 4: nopl 0x00(%eax)
 * 5: nopl 0x00(%eax,%eax,1)
 * 6: osp nopl 0x00(%eax,%eax,1)
 * 7: nopl 0x00000000(%eax)
 * 8: nopl 0x00000000(%eax,%eax,1)
 */
#define BYTES_NOP1 0x90
#define BYTES_NOP2 0x66, BYTES_NOP1
#define BYTES_NOP3 0x0f, 0x1f, 0x00
#define BYTES_NOP4 0x0f, 0x1f, 0x40, 0x00
#define BYTES_NOP5 0x0f, 0x1f, 0x44, 0x00, 0x00
#define BYTES_NOP6 0x66, BYTES_NOP5
#define BYTES_NOP7 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00
#define BYTES_NOP8 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00

#define CALL_INSN_SIZE 5
#define CALL_INSN_OPCODE 0xE8

#define JMP32_INSN_SIZE 5
#define JMP32_INSN_OPCODE 0xE9

#define POKE_MAX_OPCODE_SIZE 10

union text_poke_insn {
	unsigned char text[POKE_MAX_OPCODE_SIZE];
	struct {
		unsigned char opcode;
		int disp;
	} __attribute__((packed));
};

static int text_gen_insn(const unsigned char *loc, const void *dest)
{
	union text_poke_insn *insn;

	// ff 15 00 00 00 00       callq  *0x00(%rip)
	if ((*(unsigned char *)(loc - 2) == 0xff) && (*(unsigned char *)(loc - 1) == 0x15)) {
		insn = (union text_poke_insn *)(loc - 2);
		insn->opcode = CALL_INSN_OPCODE;
		insn->disp = (unsigned long)dest - (unsigned long)(loc - 2 + CALL_INSN_SIZE);
		insn->text[5] = BYTES_NOP1;
		return 0;
	}
}

static int rewrite_section_headers(struct elf_info *info)
{
	unsigned int i;
	Elf64_Ehdr *hdr = info->hdr;
	Elf64_Shdr *sechdrs = info->sechdrs;

	/* This should always be true, but let's be sure. */
	sechdrs[0].sh_addr = 0;

	for (i = 1; i < hdr->e_shnum; i++) {
		Elf64_Shdr *shdr = &sechdrs[i];
		shdr->sh_addr = (size_t)hdr + shdr->sh_offset;
	}

	return 0;
}

static int resolve_symbol(const char *name, Elf64_Addr *st_value)
{
	// TODO
	//dl_lookup_symbol_x(name, match, &ref, match->l_scope, vers, 0, flags | DL_LOOKUP_ADD_DEPENDENCY, NULL);
	char buf[32] = {0};
	for (int i = 0;; i++) {
		if (name[i] == '\0' || name[i] == '@')
			break;
		buf[i] = name[i];
	}
	*st_value = (Elf64_Addr)dlsym(RTLD_DEFAULT, buf);
	_dl_debug_printf("symbol: 0x%016lx %s\n", (long)*st_value, name);
	return 0;
}

static int simplify_symbols(struct elf_info *info)
{
	char *strtab = info->strtab;
	Elf64_Shdr *symsec = info->symsec;
	Elf64_Sym *syms = (void *)symsec->sh_addr;
	unsigned long secbase;
	unsigned int i;
	int ret = 0;

	// .symtab
	for (i = 1; i < symsec->sh_size / sizeof(Elf64_Sym); i++) {
		Elf64_Sym *sym = syms + i;
		const char *name = strtab + sym->st_name;

		switch (sym->st_shndx) {
		case SHN_COMMON:
		case SHN_ABS:
			/* Don't need to do anything */
			break;

		case SHN_UNDEF:
			ret = resolve_symbol(name, &sym->st_value);
			break;

		default:
			if ((ELF64_ST_TYPE(sym->st_info) == STT_SECTION) || (ELF64_ST_TYPE(sym->st_info) == STT_NOTYPE)) {
				break;
			}
			// local ELF FUNC
			if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC) {
				secbase = (unsigned long)info->text_vhdr;
			}
			// TODO: rodata
			// local ELF OBJECT
			if (ELF64_ST_TYPE(sym->st_info) == STT_OBJECT) {
				secbase = (unsigned long)info->rodata_vhdr;
			}
			sym->st_value += secbase;
			_dl_debug_printf("symbol: 0x%016lx %s 0x%x local\n", (long)sym->st_value, name, sym->st_info);

			// for test
			if (strcmp(name, "main") == 0) {
				g_main = (main_func)sym->st_value;
			}

			break;
		}
	}

	return ret;
}

static void relocate_rewrite_value(struct elf_info *info, Elf64_Rela *rel, void *loc)
{
	unsigned long val;

	// GOT data offset to elf hdr
	val = *(int *)loc - rel->r_addend + rel->r_offset;
	val = (unsigned long)info->rodata_vhdr + val;
	val = val - (unsigned long)loc + rel->r_addend;
	memcpy(loc, &val, 4);
}

static int apply_relocate_add(Elf64_Shdr *shdr, struct elf_info *info)
{
	unsigned int i;
	Elf64_Rela *rel_tab = (void *)shdr->sh_addr;
	Elf64_Sym *sym;
	char *loc;
	int ret;

	for (i = 0; i < shdr->sh_size / sizeof(Elf64_Rela); i++) {
		Elf64_Rela *rel = rel_tab + i;
		/* This is where to make the change */
		loc = info->text_vhdr + rel->r_offset;
		sym = (Elf64_Sym *)info->symsec->sh_addr + ELF64_R_SYM(rel->r_info);

		_dl_debug_printf("type %02d st_value %016lx r_addend %lx loc %lx\n", (int)ELF64_R_TYPE(rel->r_info), sym->st_value,
				 rel->r_addend, (unsigned long)loc);

		switch (ELF64_R_TYPE(rel->r_info)) {
		case R_X86_64_NONE:
		case R_X86_64_PLT32:
			break;
		case R_X86_64_GOTPCRELX:
			// ff 15 00 00 00 00       callq  *0x00(%rip)
			ret = text_gen_insn(loc, (const void *)sym->st_value);
			if (ret == 0)
				break;
			// 48 83 3d d2 fe 5f 00    cmpq   $0x0,0x5ffed2(%rip)
			relocate_rewrite_value(info, rel, loc);
			break;
		case R_X86_64_PC32:
			// SHN_COMMON STT_FUNC no need reloc
			if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC)
				break;
			// STT_OBJECT
			// TODO: direct mov, do not use lea
			fallthrough;
		case R_X86_64_GOTPCREL:
		case R_X86_64_REX_GOTPCRELX:
			// sym may not exist, change data offset
			relocate_rewrite_value(info, rel, loc);
			break;
		default:
			_dl_debug_printf("invalid relocation target, type %d, loc 0x%lx\n",
					 (int)ELF64_R_TYPE(rel->r_info), (unsigned long)loc);
			return -1;
		}
	}
	return 0;
}

static int apply_relocations(struct elf_info *info)
{
	Elf64_Shdr *sechdrs = info->sechdrs;
	char *secstrings = info->secstrings;
	unsigned int shnum = info->hdr->e_shnum;
	unsigned int i;
	int err = 0;

	for (i = 1; i < shnum; i++) {
		Elf64_Shdr *shdr = &sechdrs[i];

		/* Not a valid relocation section? */
		if (shdr->sh_info >= shnum)
			continue;

		if (shdr->sh_type == SHT_RELA) {
			const char *name = secstrings + shdr->sh_name;
			if ((strcmp(name, ".rela.text") != 0) && (strcmp(name, ".rela.init") != 0))
				continue;
			_dl_debug_printf("relocation %s\n", name);
			err = apply_relocate_add(shdr, info);
		}
		if (err < 0)
			break;
	}
	return err;
}

static int read_elf_info(int fd, struct elf_info *info)
{
	int ret;
	unsigned int i;
	unsigned int index_str;
	Elf64_Ehdr *hdr = NULL;
	Elf64_Shdr *sechdrs = NULL;
	Elf64_Shdr *strhdr;
	void *buf;

	ret = lseek(fd, 0, SEEK_END);
	buf = mmap(0, ret, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
	_dl_debug_printf("ELF len %d, buf addr 0x%08lx\n", ret, (unsigned long)buf);

	hdr = (Elf64_Ehdr *)buf;
	sechdrs = (Elf64_Shdr *)((char *)hdr + hdr->e_shoff);

	// session header name string table
	strhdr = &sechdrs[hdr->e_shstrndx];
	info->secstrings = (char *)hdr + strhdr->sh_offset;

	// .symtab
	for (i = 1; i < hdr->e_shnum; i++) {
		if (sechdrs[i].sh_type == SHT_SYMTAB) {
			info->symsec = &sechdrs[i];
			index_str = sechdrs[i].sh_link;
			info->strtab = (char *)hdr + sechdrs[index_str].sh_offset;
			break;
		}
	}

	info->hdr = hdr;
	info->sechdrs = sechdrs;
	info->strhdr = strhdr;

	return 0;
}

int main(void)
{
	char *text_layout;
	char *rodata_layout;
	struct elf_info info_buf = {0};
	struct elf_info *info = &info_buf;
	int fd = open("test_rela", O_RDONLY);
	int i;
	Elf64_Phdr *elf_ppnt, *elf_phdata;
	char *load_addr;

	text_layout = (char *)mmap(0, 0x40000000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	rodata_layout = (char *)mmap(0, 0x40000000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	read_elf_info(fd, info);

	// load elf
	load_addr = (void *)info->hdr;
	elf_phdata = (Elf64_Phdr *)(load_addr + info->hdr->e_phoff);
	for (i = 0, elf_ppnt = elf_phdata; i < info->hdr->e_phnum; i++, elf_ppnt++) {
		if (elf_ppnt->p_type != PT_LOAD)
			continue;

		// skip first LOAD segment
		elf_ppnt++;
		// text
		info->text_vhdr = text_layout - elf_ppnt->p_offset;
		memcpy((void *)text_layout, load_addr + elf_ppnt->p_offset, elf_ppnt->p_filesz);
		// rodata
		elf_ppnt++;
		info->rodata_vhdr = rodata_layout - elf_ppnt->p_offset;
		memcpy((void *)rodata_layout, load_addr + elf_ppnt->p_offset, elf_ppnt->p_filesz);
		memset((void *)(rodata_layout + elf_ppnt->p_filesz), 0, elf_ppnt->p_memsz - elf_ppnt->p_filesz);
		// data
		elf_ppnt++;
		char *data_begin = rodata_layout + (elf_ppnt->p_paddr - (elf_ppnt - 1)->p_paddr);
		memcpy(data_begin, load_addr + elf_ppnt->p_offset, elf_ppnt->p_filesz);
		memset(data_begin + elf_ppnt->p_filesz, 0, elf_ppnt->p_memsz - elf_ppnt->p_filesz);

		break;
	}

	rewrite_section_headers(info);
	simplify_symbols(info);
	apply_relocations(info);

	// run
	_dl_debug_printf("text: 0x%016lx  rodata: 0x%016lx \n", (unsigned long)info->text_vhdr, (unsigned long)info->rodata_vhdr);
	_dl_debug_printf("begin run 0x%016lx\n", (unsigned long)g_main);
	g_main();
	_dl_debug_printf("run OK\n");

	return 0;
}
