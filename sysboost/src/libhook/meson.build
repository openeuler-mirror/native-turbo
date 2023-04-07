# SPDX-License-Identifier: GPL-2.0

sources = files('dlsym_hook.c')

cflags += ['-v']
ldflags += ['-ldl']
link_libs = si_static_libraries
includes = []
deps += ['static_si_array', 'static_si_sys']

dep_objs = []
foreach dep_name:deps
    if not is_variable(dep_name)
        build = false
        message('Missing dependency "@0@" for app "@1@"'.format(dep_name, src))
        break
    endif
    dep_objs += [get_variable(dep_name)]
    message('"@0@" add depend lib "@1@"'.format(src, dep_name))
endforeach

libhook = shared_library('hook', sources,
    install: true,
    c_args: cflags,
    link_args: ldflags,
    link_whole: link_libs,
    dependencies: dep_objs,
    include_directories: includes)
