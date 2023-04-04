# SPDX-License-Identifier: MulanPSL-2.0

libraries = [
    'sys',
    'array',
    'ring',
    'hashmap'
]

default_cflags = machine_args
if cc.has_argument('-Wno-format-truncation')
    default_cflags += '-Wno-format-truncation'
endif

enabled_libs = [] # used to print summary at the end

foreach l:libraries
    build = true
    reason = '<unknown reason>' # set if build == false to explain why
    name = l
    use_function_versioning = false
    sources = []
    headers = []
    indirect_headers = [] # public headers not directly included by apps
    includes = []
    cflags = default_cflags
    objs = [] # other object files to link against, used e.g. for
              # instruction-set optimized versions of code

    ext_deps = []
    deps = []

    subdir(l)
    if name != l
        warning('Library name, "@0@", and directory name, "@1@", do not match'.format(name, l))
    endif

    static_deps = ext_deps
    foreach d:deps
        if not build
            break
        endif
        static_deps += [get_variable('static_si_' + d)]
    endforeach

    enabled_libs += name
    install_headers(headers)
    install_headers(indirect_headers)

    libname = 'si_' + name
    includes += include_directories(l)

    # first build static lib
    static_lib = static_library(libname,
            sources,
            objects: objs,
            c_args: cflags,
            dependencies: static_deps,
            include_directories: includes,
            install: true)
    static_dep = declare_dependency(
            include_directories: includes,
            dependencies: static_deps)

    si_static_libraries = [static_lib] + si_static_libraries

    set_variable('static_si_' + name, static_dep)
    if debug_mode
        message('lib/@0@: Defining dependency "@1@"'.format(l, name))
    endif
endforeach
