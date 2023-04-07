# SPDX-License-Identifier: MulanPSL-2.0

.PHONY: all init test format clean
all:
	ninja -C build -v

#meson compile -C build

release:
	rm -rf build
	meson build

debug:
	rm -rf build
	meson build --buildtype=debug

test:
	meson test -C build

format:
	meson --internal clangformat ./ ./build

clean:
	ninja -C build clean

static_template_debug:
	readelf -W -a ./build/sysboost/src/static_template/static_template > static_template.elf
	objdump -d ./build/sysboost/src/static_template/static_template > static_template.asm

bash-test: static_template_debug
	clear
	./build/sysboost/sysboost -static ./build/sysboost/src/static_template/static_template bash/bash bash/libtinfo.so
	readelf -W -a bash.rto > bash.rto.elf
	objdump -d bash.rto > bash.rto.asm

bash-gdb:
	gdb --args ./build/sysboost/sysboost -static ./build/sysboost/src/static_template/static_template bash/bash bash/libtinfo.so
