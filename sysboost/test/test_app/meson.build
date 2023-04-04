# SPDX-License-Identifier: MulanPSL-2.0
sources = files(['common_func.c',
	'test_app.c'])

cflags += ['-O2', '-fpic', '-pthread', '-ldl']
ldflags += ['-pie']

# Add a target for libutil2.so shared library
util1 = shared_library('util1', 'util1.c',
                    dependencies : ext_deps + dep_objs,
                    c_args : cflags,
                    link_args : lk_args,
                    build_rpath : './')

util1_ori = shared_library('util1_ori', 'util1.c',
                        dependencies : ext_deps + dep_objs,
                        c_args : cflags)

# Add a target for libutil2.so shared library
util2 = shared_library('util2', 'util2.c',
                    dependencies : ext_deps + dep_objs,
                    c_args : cflags,
                    link_args : lk_args,
                    build_rpath : './')

# Add dependencies for test_app target
test_app_dep = declare_dependency(link_with: [util1, util2])

executable('test_app', sources,
        c_args: cflags,
        link_args: ldflags,
        link_whole: link_libs,
        dependencies: test_app_dep,
        include_directories: includes)