# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../../
BUILD_DIR=$(ROOT_DIR)build/
TEMPLATE_FILE=$(BUILD_DIR)sysboost/src/static_template/sysboost_static_template
SYSBOOST=$(BUILD_DIR)sysboost/sysboost
TEST_APP=$(BUILD_DIR)sysboost/test/test_ifunc/test_ifunc

TEMPLATE_FILE_PUB_PATH=/usr/bin/sysboost_static_template

.PHONY: all

all: test_ifunc

test_ifunc:
	make -C $(ROOT_DIR)
	readelf -W -a $(TEST_APP) > $@.elf
	objdump -d $(TEST_APP) > $@.asm

run:
	gdb $(TEST_APP)

clean:
	$(RM) *.o *.ro *.old *.so *.asm *.elf *.rto *.out test_ifunc
