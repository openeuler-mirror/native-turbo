/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf_link_common.h"
#include "elf_read_elf.h"
#include "si_common.h"
#include "si_debug.h"
#include "si_log.h"

unsigned int elf_align_file(elf_link_t *elf_link, unsigned int align)
{
	elf_link->next_file_offset = ALIGN(elf_link->next_file_offset, align);
	elf_link->next_mem_addr = ALIGN(elf_link->next_mem_addr, align);
	return elf_link->next_file_offset;
}

unsigned int elf_align_file_segment(elf_link_t *elf_link)
{
	return elf_align_file(elf_link, ELF_SEGMENT_ALIGN);
}

// .text offset in PAGE inherit from in ELF
unsigned int elf_align_file_section(elf_link_t *elf_link, Elf64_Shdr *sec, bool is_align_file_offset)
{
	unsigned long old_offset_in_page = sec->sh_addr & (~PAGE_MASK);
	unsigned long cur = elf_link->next_mem_addr & (~PAGE_MASK);
	if (cur <= old_offset_in_page) {
		if (is_align_file_offset) {
			elf_link->next_file_offset = (elf_link->next_file_offset & PAGE_MASK) + old_offset_in_page;
		}
		elf_link->next_mem_addr = (elf_link->next_mem_addr & PAGE_MASK) + old_offset_in_page;
	} else {
		// use next PAGE
		if (is_align_file_offset) {
			elf_link->next_file_offset = ALIGN(elf_link->next_file_offset, (1UL << PAGE_SHIFT));
			elf_link->next_file_offset += old_offset_in_page;
		}
		elf_link->next_mem_addr = ALIGN(elf_link->next_mem_addr, (1UL << PAGE_SHIFT));
		elf_link->next_mem_addr += old_offset_in_page;
	}

	return elf_link->next_file_offset;
}

void *write_elf_file(elf_link_t *elf_link, void *src, unsigned int len)
{
	void *dest = ((void *)elf_link->out_ef.hdr) + elf_link->next_file_offset;
	(void)memcpy(dest, src, len);

	elf_link->next_file_offset += len;
	elf_link->next_mem_addr += len;

	return dest;
}

void *write_elf_file_zero(elf_link_t *elf_link, unsigned int len)
{
	void *dest = ((void *)elf_link->out_ef.hdr) + elf_link->next_file_offset;
	(void)memset(dest, 0, len);

	elf_link->next_file_offset += len;
	elf_link->next_mem_addr += len;

	return dest;
}

void *write_elf_file_section(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, Elf64_Shdr *dst_sec)
{
	// dst_sec is uesd by _get_new_elf_addr, to get new vaddr
	append_sec_mapping(elf_link, ef, sec, dst_sec);

	void *src = ((void *)ef->hdr) + sec->sh_offset;
	unsigned int len = sec->sh_size;

	if (sec->sh_type == SHT_NOBITS) {
		// if .tbss area is empty, get new offset addr will conflict
		// .tbss fill zero
		if (sec->sh_flags & SHF_TLS) {
			dst_sec->sh_type = SHT_PROGBITS;
			return write_elf_file_zero(elf_link, len);
		} else {
			// .bss
			elf_link->next_mem_addr += sec->sh_size;
			return 0;
		}
	}

	return write_elf_file(elf_link, src, len);
}

void elf_modify_file_zero(elf_link_t *elf_link, unsigned long offset, unsigned long len)
{
	void *dest = ((void *)elf_link->out_ef.hdr) + offset;
	(void)memset(dest, 0, len);
}

void elf_modify_section_zero(elf_link_t *elf_link, char *secname)
{
	Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, secname);
	void *dest = ((void *)elf_link->out_ef.hdr) + sec->sh_offset;
	(void)memset(dest, 0, sec->sh_size);
}

int create_elf_file(char *file_name, elf_file_t *elf_file)
{
#define MAX_ELF_FILE_LEN (0x100000 * 512)
	size_t len = MAX_ELF_FILE_LEN;
	int fd = open(file_name, O_CREAT | O_RDWR, 0744);
	size_t ret;

	if (fd == -1) {
		si_panic("open fail %d\n ", errno);
		return -1;
	}

	elf_file->fd = fd;
	elf_file->file_name = strdup(file_name);
	lseek(fd, len - 1, SEEK_SET);
	ret = write(fd, "", 1);
	if (ret == -1UL)
		si_panic("%s write fail\n", __func__);

	elf_file->hdr = mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (elf_file->hdr == MAP_FAILED) {
		si_panic("mmap fail %d\n ", errno);
		close(fd);
		return -1;
	}

	return 0;
	// file need truncate when finish
}

void truncate_elf_file(elf_link_t *elf_link)
{
	elf_file_t *out_ef = &elf_link->out_ef;
	int ret = ftruncate(out_ef->fd, elf_link->next_file_offset);
	if (ret == -1)
		si_panic("%s ftruncate fail\n", __func__);
}
