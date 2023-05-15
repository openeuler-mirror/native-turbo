# SPDX-License-Identifier: MulanPSL-2.0
sources = files('test_ifunc.c')

cflags += ['-fpic', '-pie', '-pthread', '-ldl', '-static-pie', '-Wl,-z,relro,-z,now']

executable('test_ifunc', sources,
        c_args: cflags,
        link_args: ldflags + cflags,
        link_whole: link_libs,
        build_rpath : './',
        dependencies: ext_deps + dep_objs,
        include_directories: includes)