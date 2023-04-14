# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/sysboost_static_template
SYSBOOST=$(BUILD_DIR)sysboost/sysboost

.PHONY: all

all: bash

static_template_debug:
	readelf -W -a $(TEMPLATE_FILE) > sysboost_static_template.elf
	objdump -d $(TEMPLATE_FILE) > sysboost_static_template.asm

# simple test with template
bash: static_template_debug
	make -C $(ROOT_DIR)
	clear
	@echo ===rto===
	$(SYSBOOST) -static $(TEMPLATE_FILE) bash libtinfo.so
	readelf -W -a bash.rto > bash.rto.elf
	objdump -d bash.rto > bash.rto.asm
	@echo ===run===
	./bash.rto -c "echo 1"

rto:
	gdb --args $(SYSBOOST) -static $(TEMPLATE_FILE) bash libtinfo.so

run:
	gdb --args ./bash.rto -c "echo 1"

run2:
	gdb --args ./bash.rto

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
	readelf -W -a bash > bash.elf
	objdump -d bash > bash.asm

install:
	cp ./bash.rto /usr/bin/bash
