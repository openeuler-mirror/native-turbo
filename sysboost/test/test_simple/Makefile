# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/

.PHONY: all

all: simple

static_template_debug:
	readelf -W -a $(BUILD_DIR)sysboost/src/static_template/static_template > static_template.elf
	objdump -d $(BUILD_DIR)sysboost/src/static_template/static_template > static_template.asm

simple_app:
	make -C $(ROOT_DIR)
	readelf -W -a $(BUILD_DIR)sysboost/test/test_simple/simple_app > $@.elf
	objdump -d $(BUILD_DIR)sysboost/test/test_simple/simple_app > $@.asm

# simple test with template
simple: static_template_debug simple_app
	clear
	@echo ===rto===
	$(BUILD_DIR)sysboost/sysboost -static $(BUILD_DIR)sysboost/src/static_template/static_template $(BUILD_DIR)sysboost/test/test_simple/simple_app
	readelf -W -a simple_app.rto > simple_app.rto.elf
	objdump -d simple_app.rto > simple_app.rto.asm
	@echo ===run===
	./simple_app.rto

simple-gdb:
	gdb --args $(BUILD_DIR)sysboost/sysboost -static $(BUILD_DIR)sysboost/src/static_template/static_template $(BUILD_DIR)sysboost/test/test_simple/simple_app

# simple test with libc.so
simple2: static_template_debug simple_app
	clear
	$(BUILD_DIR)sysboost/sysboost -static $(BUILD_DIR)sysboost/src/static_template/static_template $(BUILD_DIR)sysboost/test/test_simple/simple_app ../bash/libc.so
	readelf -W -a simple_app.rto > simple_app.rto.elf
	objdump -d simple_app.rto > simple_app.rto.asm

simple2-gdb:
	clear
	gdb --args $(BUILD_DIR)sysboost/sysboost -static $(BUILD_DIR)sysboost/src/static_template/static_template $(BUILD_DIR)sysboost/test/test_simple/simple_app ../bash/libc.so

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space

clean:
	$(RM) *.o *.ro *.old *.so *.asm *.elf *.rto *.out simple_app
