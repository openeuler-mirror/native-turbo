# SPDX-License-Identifier: GPL-2.0

sources = files('static_template.c')

temp_cflags = ['-O0', '-Wall', '-Wextra', '-Wformat', '-g', '-D_GNU_SOURCE', '-fno-jump-tables', '-Wl,-z,relro,-z,now', '-fpic',
            '-Bsymbolic', '-zcommon-page-size=2097152', '-zmax-page-size=2097152', '-static-pie',
            '-Wno-nonnull', '-Wno-unused-variable', '-Wno-stringop-truncation', '-Wno-unused-result',
            '-O', '-D_FORTIFY_SOURCE=2', '-export-dynamic']

executable('static_template', sources,
        install: true,
        c_args: temp_cflags,
        link_args: temp_cflags + ['-Wl,--emit-relocs', '-ldl'])