# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
SYSBOOST=$(BUILD_DIR)sysboost/sysboost
BASH=/usr/bin/bash

TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/sysboost_static_template
TEMPLATE_FILE_PUB_PATH=/usr/lib/relocation/sysboost_static_template.relocation

LIBC=/usr/lib64/libc.so.6
LIBC_R=/usr/lib/relocation$(LIBC).relocation

LIBTINFO=/usr/lib64/libtinfo.so.7
LIBTINFO_R=/usr/lib/relocation$(LIBTINFO).relocation


.PHONY: all

all: bash

bash:
	clear
	make -C $(ROOT_DIR)
	xz $(TEMPLATE_FILE)
	mv -f $(TEMPLATE_FILE).xz $(TEMPLATE_FILE_PUB_PATH)
	@echo ===rto===
	$(SYSBOOST) -static $(BASH) $(LIBTINFO) $(LIBC)
	readelf -W -a bash.rto > bash.rto.elf
	objdump -d bash.rto > bash.rto.asm
	@echo ===run===
	./bash.rto -c "echo 1"

rto:
	gdb --args $(SYSBOOST) -static $(BASH) $(LIBTINFO) $(LIBC)

nolibc:
	clear
	readelf -W -a $(TEMPLATE_FILE) > sysboost_static_template.elf
	objdump -d $(TEMPLATE_FILE) > sysboost_static_template.asm
	make -C $(ROOT_DIR)
	xz $(TEMPLATE_FILE)
	mv -f $(TEMPLATE_FILE).xz $(TEMPLATE_FILE_PUB_PATH)
	@echo ===rto2===
	$(SYSBOOST) -static-nolibc $(BASH) $(LIBTINFO)
	readelf -W -a bash.rto > bash.rto.elf
	objdump -d bash.rto > bash.rto.asm
	@echo ===run===
	./bash.rto -c "echo 1"

rto2:
	gdb --args $(SYSBOOST) -static-nolibc $(BASH) $(LIBTINFO)

run:
	gdb --args ./bash.rto -c "echo 1"

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
	readelf -W -a $(BASH) > bash.elf
	objdump -d $(BASH) > bash.asm
	readelf -W -a $(LIBC_R) > libc.so.elf
	objdump -d $(LIBC_R) > libc.so.asm
	readelf -W -a $(LIBTINFO) > libtinfo.so.elf
	objdump -d $(LIBTINFO) > libtinfo.so.asm
