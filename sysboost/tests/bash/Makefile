# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/sysboost_static_template
SYSBOOST=$(BUILD_DIR)sysboost/sysboost
LIBC=libc.so
LIBTINFO=/usr/lib64/libtinfo.so.7
BASH=/usr/bin/bash

TEMPLATE_FILE_PUB_PATH=/usr/bin/sysboost_static_template

.PHONY: all

all: bash

bash:
	make -C $(ROOT_DIR)
	cp -f $(TEMPLATE_FILE) $(TEMPLATE_FILE_PUB_PATH)
	clear
	@echo ===rto===
	$(SYSBOOST) -static $(BASH) $(LIBTINFO) $(LIBC)
	readelf -W -a bash.rto > bash.rto.elf
	objdump -d bash.rto > bash.rto.asm
	@echo ===run===
	./bash.rto -c "echo 1"

rto:
	gdb --args $(SYSBOOST) -static $(BASH) $(LIBTINFO) $(LIBC)

bash2:
	readelf -W -a $(TEMPLATE_FILE) > sysboost_static_template.elf
	objdump -d $(TEMPLATE_FILE) > sysboost_static_template.asm
	make -C $(ROOT_DIR)
	cp -f $(TEMPLATE_FILE) $(TEMPLATE_FILE_PUB_PATH)
	clear
	@echo ===rto2===
	$(SYSBOOST) -static $(BASH) $(LIBTINFO)
	readelf -W -a bash.rto > bash.rto.elf
	objdump -d bash.rto > bash.rto.asm
	@echo ===run===
	./bash.rto -c "echo 1"

rto2:
	gdb --args $(SYSBOOST) -static $(BASH) $(LIBTINFO)

run:
	gdb --args ./bash.rto -c "echo 1"

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
	readelf -W -a $(BASH) > bash.elf
	objdump -d $(BASH) > bash.asm
	readelf -W -a $(LIBC) > libc.so.elf
	objdump -d $(LIBC) > libc.so.asm
	readelf -W -a $(LIBTINFO) > libtinfo.so.elf
	objdump -d $(LIBTINFO) > libtinfo.so.asm
