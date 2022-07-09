# SPDX-License-Identifier: MulanPSL-2.0

.PHONY: all init test format clean
all:
	ninja -C build

#meson compile -C build

init:
	meson build

test:
	meson test -C build

format:
	ninja -C build clang-format

clean:
	ninja -C build clean
