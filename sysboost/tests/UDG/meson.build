# SPDX-License-Identifier: GPL-2.0

init_target = custom_target('init', input: ['cell_boot', 'libsm.so'],
                            output: ['cell_boot.elf', 'cell_boot.asm', 'libsm.so.elf', 'libsm.so.asm'],
                            command: [cc.get_id(), '-W', '-a', 'cell_boot', '>', 'cell_boot.elf',
                            '&&', 'objdump', '-d', 'cell_boot', '>', 'cell_boot.asm',
                            '&&', cc.get_id(), '-W', '-a', 'libsm.so', '>', 'libsm.so.elf',
                            '&&', 'objdump', '-d', 'libsm.so', '>', 'libsm.so.asm'])

test_target = custom_target('test', input: ['cell_boot', 'libsm.so', '../../src/binlink'],
                            output: ['all.out.elf', 'all.out.asm'],
                            command: ['../../src/binlink', 'cell_boot', 'libsm.so',
                            '&&', cc.get_id(), '-W', '-a', 'all.out', '>', 'all.out.elf',
                            '&&', 'objdump', '-d', 'all.out', '>', 'all.out.asm'])

gdb_target = custom_target('gdb',
                           input: ['cell_boot', 'libsm.so', '../../src/binlink'],
                           command: ['gdb', '--args', '../../src/binlink', 'cell_boot', 'libsm.so'])

clean_target = clean_files('*.o', '*.ro', '*.old', '*.asm', '*.elf', '*.out', 'test_binlink', 'test_c')
