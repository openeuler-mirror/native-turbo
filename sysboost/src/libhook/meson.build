# SPDX-License-Identifier: GPL-2.0

sources = files('dlsym_hook.c')

cflags += ['-O2', '-v', '-ldl']

libhook = shared_library('hook', sources,
    c_args: cflags,
    link_args: ldflags)

# Add a custom target for the format rule
format = custom_target('format',
    input: 'dlsym_hook.c',
    output: 'dlsym_hook.c',
    command: ['clang-format', '-i', '@INPUT@'])