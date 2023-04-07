# SPDX-License-Identifier: MulanPSL-2.0

project('DFE', 'C',
        version: run_command(find_program('cat', 'more'), files('VERSION'), check: true).stdout().strip(),
        license: 'MulanPSL',
        default_options: [
            'buildtype=release',
            'default_library=static',
            'warning_level=2',
        ],
        meson_version: '>= 0.49.2'
)

# check for developer mode
debug_mode = false
if get_option('debug_mode').auto()
    if meson.version().version_compare('>=0.53') # fs module available
        fs = import('fs')
        debug_mode = fs.is_dir('.git')
    endif
else
    debug_mode = get_option('debug_mode').enabled()
endif
if debug_mode
    message('## Building in Developer Mode ##')
endif

# set up some global vars for compiler, platform, configuration, etc.
cc = meson.get_compiler('c')
si_source_root = meson.current_source_dir()
si_build_root = meson.current_build_dir()
si_static_libraries = []
abi_version_file = files('ABI_VERSION')

if host_machine.cpu_family().startswith('x86')
    arch_subdir = 'x86'
elif host_machine.cpu_family().startswith('arm') or host_machine.cpu_family().startswith('aarch')
    arch_subdir = 'arm'
elif host_machine.cpu_family().startswith('riscv')
    arch_subdir = 'riscv'
endif

machine_args = ['-Wall', '-Werror', '-Wextra', '-Wformat', '-D_GNU_SOURCE',
                '-fno-jump-tables', '-Wl,-z,relro,-z,now', '-Bsymbolic', '-zcommon-page-size=2097152', '-zmax-page-size=2097152']
lk_args = ['-Wl,--emit-relocs', '-Wl,-z,relro,-z,now']

global_inc = include_directories('.',
    'lib/sys/include',
    #'lib/sys/@0@/include'.format(host_machine.system()),
    #'lib/sys/@0@/include'.format(arch_subdir),
)

# build libs
subdir('lib')
subdir('tests')
subdir('sysboost')

# final output, list all the libs and drivers to be built
# this does not affect any part of the build, for information only.
output_message = '\n=================\nLibraries Enabled\n=================\n'
output_message += '\nlibs:\n\t'
output_count = 0
foreach lib:enabled_libs
    output_message += lib + ', '
    output_count += 1
    if output_count == 8
        output_message += '\n\t'
        output_count = 0
    endif
endforeach
message(output_message + '\n')
