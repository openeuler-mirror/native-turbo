# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/sysboost_static_template
SYSBOOST=$(BUILD_DIR)sysboost/sysboost
TEST_APP=$(BUILD_DIR)sysboost/test/test_simple/simple_app

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

# simple test with template
simple: static_template_debug simple_app
	clear
	@echo ===rto===
	cp -f $(TEMPLATE_FILE) $(TEMPLATE_FILE_PUB_PATH)
	$(SYSBOOST) -static $(TEST_APP)
	readelf -W -a simple_app.rto > simple_app.rto.elf
	objdump -d simple_app.rto > simple_app.rto.asm
	@echo ===run===
	./simple_app.rto

rto:
	gdb --args $(SYSBOOST) -static $(TEST_APP)

# simple test with libc.so
simple2: static_template_debug simple_app
	clear
	cp -f $(TEMPLATE_FILE) $(TEMPLATE_FILE_PUB_PATH)
	$(SYSBOOST) -static $(TEST_APP) ../bash/libc.so
	readelf -W -a simple_app.rto > simple_app.rto.elf
	objdump -d simple_app.rto > simple_app.rto.asm

simple2-gdb:
	clear
	gdb --args $(SYSBOOST) -static $(TEST_APP) ../bash/libc.so

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space

clean:
	$(RM) *.o *.ro *.old *.so *.asm *.elf *.rto *.out simple_app
