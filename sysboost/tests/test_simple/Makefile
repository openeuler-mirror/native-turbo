# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/sysboost_static_template
SYSBOOST=$(BUILD_DIR)sysboost/sysboost
TEST_APP=$(BUILD_DIR)sysboost/tests/test_simple/simple_app
LIBC=/usr/lib64/libc.so.6
LIBLD=/lib/ld-linux-aarch64.so.1

TEMPLATE_FILE_PUB_PATH=/usr/bin/sysboost_static_template

.PHONY: all

all: simple

static_template_debug:
	readelf -W -a $(TEMPLATE_FILE) > sysboost_static_template.elf
	objdump -d $(TEMPLATE_FILE) > sysboost_static_template.asm

simple_app:
	make -C $(ROOT_DIR)
	readelf -W -a $(TEST_APP) > $@.elf
	objdump -d $(TEST_APP) > $@.asm

# simple test
simple: static_template_debug simple_app
	cp -f $(TEMPLATE_FILE) $(TEMPLATE_FILE_PUB_PATH)
	clear
	@echo ===rto===
	$(SYSBOOST) -static $(TEST_APP) $(LIBC)
	readelf -W -a simple_app.rto > simple_app.rto.elf
	objdump -d simple_app.rto > simple_app.rto.asm
	@echo ===run===
	./simple_app.rto

rto:
	gdb --args $(SYSBOOST) -static $(TEST_APP) $(LIBC)

run:
	gdb --args ./simple_app.rto

aot:
	make -C $(ROOT_DIR)
	$(SYSBOOST) -set $(TEST_APP)
	readelf -W -a $(TEST_APP) > simple_app.elf
	objdump -d $(TEST_APP) > simple_app.asm

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
	readelf -W -a $(LIBC) > libc.so.elf
	objdump -d $(LIBC) > libc.so.asm
	readelf -W -a $(LIBC).relocation > libc.so.r.elf
	objdump -d $(LIBC).relocation > libc.so.r.asm

clean:
	$(RM) *.o *.ro *.old *.so *.asm *.elf *.rto *.out simple_app
