# SPDX-License-Identifier: MulanPSL-2.0

apps = [
        'test_array',
	    'test_hashmap',
        #'test_rela',
]

default_ldflags = []

foreach app:apps
    build = true
    name = app
    sources = []
    includes = []
    cflags = default_cflags
    ldflags = default_ldflags
    objs = []
    ext_deps = []
    deps = []

    subdir(name)

    dep_objs = []
    foreach dep_name:deps
        if not is_variable(dep_name)
            build = false
            message('Missing dependency "@0@" for app "@1@"'.format(dep_name, name))
            break
        endif
        dep_objs += [get_variable(dep_name)]
	message('"@0@" add depend lib "@1@"'.format(name, dep_name))
    endforeach

    if not build
        continue
    endif

    link_libs = []
    link_libs = si_static_libraries

    executable(name + '.out', sources,
            c_args: cflags,
            link_args: ldflags,
            link_whole: link_libs,
            dependencies: ext_deps + dep_objs,
            include_directories: includes)
endforeach
