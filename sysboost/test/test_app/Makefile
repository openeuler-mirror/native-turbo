# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/static_template
SYSBOOST=$(BUILD_DIR)sysboost/sysboost
TEST_APP=$(BUILD_DIR)sysboost/test/test_app/test_app
LIB1=$(BUILD_DIR)sysboost/test/test_app/libutil1.so
LIB2=$(BUILD_DIR)sysboost/test/test_app/libutil2.so

.PHONY: all

all: test_app

static_template_debug:
	readelf -W -a $(TEMPLATE_FILE) > static_template.elf
	objdump -d $(TEMPLATE_FILE) > static_template.asm

# simple test with template
test_app: static_template_debug
	make -C $(ROOT_DIR)
	readelf -W -a $(TEST_APP) > test_app.elf
	objdump -d $(TEST_APP) > test_app.asm
	readelf -W -a $(LIB1) > libutil1.so.elf
	objdump -d $(LIB1) > libutil1.so.asm
	clear
	@echo ===rto===
	$(SYSBOOST) -static $(TEMPLATE_FILE) $(TEST_APP) $(LIB1) $(LIB2)
	readelf -W -a test_app.rto > test_app.rto.elf
	objdump -d test_app.rto > test_app.rto.asm
	@echo ===run_ori===
	$(TEST_APP)
	@echo ===run===
	./test_app.rto

gdb:
	gdb --args $(SYSBOOST) -static $(TEMPLATE_FILE) $(TEST_APP) $(LIB1) $(LIB2)

gdb2:
	gdb --args ./test_app.rto

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
