# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/sysboost_static_template
SYSBOOST=$(BUILD_DIR)sysboost/sysboost
TEST_APP=$(BUILD_DIR)sysboost/test/test_app/test_app
LIB1=$(BUILD_DIR)sysboost/test/test_app/libutil1.so
LIB2=$(BUILD_DIR)sysboost/test/test_app/libutil2.so
LIBHOOK=$(BUILD_DIR)sysboost/src/libhook/libhook.so


.PHONY: all

all: test-s

static_template_debug:
	readelf -W -a $(TEMPLATE_FILE) > sysboost_static_template.elf
	objdump -d $(TEMPLATE_FILE) > sysboost_static_template.asm

# DYN mod
test-d:
	make -C $(ROOT_DIR)
	readelf -W -a $(TEST_APP) > test_app.elf
	objdump -d $(TEST_APP) > test_app.asm
	readelf -W -a $(LIB1) > libutil1.so.elf
	objdump -d $(LIB1) > libutil1.so.asm
	readelf -W -a $(LIBHOOK) > libhook.so.elf
	objdump -d $(LIBHOOK) > libhook.so.asm
	cp $(LIB1) .
	clear
	@echo ===rto===
	$(SYSBOOST) $(TEST_APP) $(LIB1) $(LIB2) $(LIBHOOK)
	readelf -W -a test_app.rto > test_app.rto.elf
	objdump -d test_app.rto > test_app.rto.asm
	@echo ===run_ori===
	$(TEST_APP) -dlsym
	@echo ===run===
	./test_app.rto -dlsym

rto-d:
	gdb --args $(SYSBOOST) $(TEST_APP) $(LIB1) $(LIB2) $(LIBHOOK)

run-d:
	gdb --args ./test_app.rto -dlsym

# static mod
test-s: static_template_debug
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

rto-s:
	gdb --args $(SYSBOOST) -static $(TEMPLATE_FILE) $(TEST_APP) $(LIB1) $(LIB2)

run:
	gdb --args ./test_app.rto

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
