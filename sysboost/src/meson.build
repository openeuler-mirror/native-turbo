# SPDX-License-Identifier: GPL-2.0

if arch_subdir == 'x86'
    cpu_arch = 'x86_64'
elif arch_subdir == 'arm'
    cpu_arch = 'aarch64'
endif

sources = files([
                  'main.c',
                  'elf_link_elf.c',
                  'elf_read_elf.c',
                  'elf_hugepage.c',
                  'elf_link_common.c',
                  'elf_relocation.c',
                  'elf_relocation_' + cpu_arch + '.c',
                  'elf_check_elf.c',
                  'elf_write_elf.c',
                ])

tools = [
        'static_template',
        'libhook'
]

deps += ['static_si_array', 'static_si_sys']