# SPDX-License-Identifier: GPL-2.0
CFLAGS += -O2 -Wall -Werror -Wextra -Wformat -Wpointer-arith -g -D_GNU_SOURCE
CFLAGS += -Wl,-z,relro,-z,now -fpic -pie -fno-plt -Bsymbolic -zcommon-page-size=2097152 -zmax-page-size=2097152
LDLIBS +=

EXTCFLAGS += -Wl,--emit-relocs
#EXTCFLAGS += -Wl,--dynamic-linker=/root/rpmbuild/BUILD/glibc-2.28/build-x86_64-openEuler-linux/elf/ld.so

all: test_rela relocation
%: %.c
	$(CC) $(CFLAGS) -o $@ $^

test_rela: a.o b.o
	$(CC) $(EXTCFLAGS) $(CFLAGS) -o $@ a.o b.o
	$(CC) $(CFLAGS) -o $@.old a.o b.o
	readelf -a test_rela > test_rela.elf
	readelf -a test_rela.old > test_rela.old.elf
	objdump -d test_rela > test_rela.asm
	objdump -d test_rela.old > test_rela.old.asm

relocation:
	gcc -g -o relocation relocation.c -ldl

clean:
	$(RM) test_rela *.o *.ro *.old relocation

prepare_env:
	echo 256 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages

test:
	LD_DEBUG=all ./ld.so ./test_rela

.PHONY: all clean
