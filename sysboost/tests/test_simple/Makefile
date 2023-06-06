# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
SYSBOOST=$(BUILD_DIR)sysboost/sysboost
TEST_APP=$(BUILD_DIR)sysboost/tests/test_simple/simple_app

TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/sysboost_static_template
TEMPLATE_FILE_PUB_PATH=/usr/lib/relocation/sysboost_static_template.relocation

LIBC=/usr/lib64/libc.so.6
LIBC_R=/usr/lib/relocation$(LIBC).relocation

ARCH=$(shell uname -m)
ifeq ($(ARCH), aarch64)
	LIBLD=/lib/ld-linux-aarch64.so.1
else
	LIBLD=/lib64/ld-linux-x86-64.so.2
endif
LIBLD_R=/usr/lib/relocation$(LIBLD).relocation


.PHONY: all

all: simple

simple_app:
	make -C $(ROOT_DIR)
	readelf -W -a $(TEST_APP) > $@.elf
	objdump -d $(TEST_APP) > $@.asm

# static mode
simple: simple_app
	clear
	@echo ===rto===
	$(SYSBOOST) -static $(TEST_APP) $(LIBC)
	readelf -W -a $(TEST_APP).rto > simple_app.rto.elf
	objdump -d $(TEST_APP).rto > simple_app.rto.asm
	@echo ===run===
	$(TEST_APP).rto

rto:
	gdb --args $(SYSBOOST) -static $(TEST_APP) $(LIBC)

run:
	gdb --args $(TEST_APP).rto

# static-nolibc mode
nolibc: simple_app
	clear
	xz $(TEMPLATE_FILE)
	mv -f $(TEMPLATE_FILE).xz $(TEMPLATE_FILE_PUB_PATH)
	@echo ===rto===
	$(SYSBOOST) -static-nolibc $(TEST_APP)
	readelf -W -a $(TEST_APP).rto > simple_app.rto.elf
	objdump -d $(TEST_APP).rto > simple_app.rto.asm
	@echo ===run===
	$(TEST_APP).rto

aot:
	make -C $(ROOT_DIR)
	$(SYSBOOST) -set $(TEST_APP)
	readelf -W -a $(TEST_APP) > simple_app.elf
	objdump -d $(TEST_APP) > simple_app.asm

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
	readelf -W -a $(LIBC_R) > libc.so.elf
	objdump -d $(LIBC_R) > libc.so.asm
	readelf -W -a $(LIBLD_R) > ld.so.elf
	objdump -d $(LIBLD_R) > ld.so.asm

clean:
	$(RM) *.o *.ro *.old *.so *.asm *.elf *.rto *.out simple_app
