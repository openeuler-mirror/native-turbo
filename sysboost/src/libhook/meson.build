# SPDX-License-Identifier: GPL-2.0

sources = files('dlsym_hook.c')

cflags += ['-O2', '-v']
ldflags += ['-ldl']

libhook = shared_library('hook', sources,
    install: true,
    c_args: cflags,
    link_args: ldflags)
