# SPDX-License-Identifier: MulanPSL-2.0
sources = files('simple_app.c')

cflags += ['-O2', '-fpic', '-pie', '-pthread', '-ldl']

executable('simple_app', sources,
        c_args: cflags,
        link_args: ldflags,
        link_whole: link_libs,
        dependencies: ext_deps + dep_objs,
        include_directories: includes)