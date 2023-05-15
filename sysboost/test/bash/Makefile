# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/sysboost_static_template
SYSBOOST=$(BUILD_DIR)sysboost/sysboost
LIBC=libc.so

TEMPLATE_FILE_PUB_PATH=/usr/bin/sysboost_static_template

.PHONY: all

all: bash

static_template_debug:
	readelf -W -a $(TEMPLATE_FILE) > sysboost_static_template.elf
	objdump -d $(TEMPLATE_FILE) > sysboost_static_template.asm

# simple test with template
bash: static_template_debug
	make -C $(ROOT_DIR)
	cp -f $(TEMPLATE_FILE) $(TEMPLATE_FILE_PUB_PATH)
	clear
	@echo ===rto===
	$(SYSBOOST) -static bash libtinfo.so $(LIBC)
	readelf -W -a bash.rto > bash.rto.elf
	objdump -d bash.rto > bash.rto.asm
	@echo ===run===
	./bash.rto -c "echo 1"

rto:
	gdb --args $(SYSBOOST) -static bash libtinfo.so $(LIBC)

run:
	gdb --args ./bash.rto -c "echo 1"

run2:
	gdb --args ./bash.rto

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
	readelf -W -a bash > bash.elf
	objdump -d bash > bash.asm
	readelf -W -a $(LIBC) > libc.so.elf
	objdump -d $(LIBC) > libc.so.asm
