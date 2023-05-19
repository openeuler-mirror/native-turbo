# SPDX-License-Identifier: MulanPSL-2.0

sysboosts = [
        'src',
        'tests'
]

default_cflags = machine_args

if get_option('buildtype').contains('debug')
	default_cflags += [ '-pedantic', '-DPEDANTIC' ]
else
	default_cflags += [ '-UPEDANTIC' ]
endif

if cc.has_argument('-Wno-format-truncation')
	default_cflags += '-Wno-format-truncation'
endif

default_ldflags = lk_args

foreach src:sysboosts
    build = true
    sources = []
    includes = []
    cflags = default_cflags + ['-Wno-pointer-arith', '-Wno-pedantic']
    ldflags = default_ldflags
    objs = []
    ext_deps = []
    deps = []

    subdir(src)

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

    if not build
        continue
    endif

    link_libs = []

    if get_option('buildtype').contains('debug')
        cflags += ['-Og', '-g', '-rdynamic']
        ldflags += ['-rdynamic']
    else
    	cflags += ['-O2']
    endif

    if src == 'tests'
        foreach tt:tests
            path = join_paths(src, tt)
            subdir(path)
        endforeach
    else
        link_libs = si_static_libraries
        cflags += ['-fpic', '-pie']
        executable('sysboost', sources,
                install: true,
                c_args: cflags,
                link_args: ldflags,
                link_whole: link_libs,
                dependencies: ext_deps + dep_objs,
                include_directories: includes)
        foreach tl:tools
            path = join_paths(src, tl)
            subdir(path)
        endforeach
    endif
endforeach