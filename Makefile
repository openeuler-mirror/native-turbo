# SPDX-License-Identifier: MulanPSL-2.0

INCLUDE_SRCS += lib/sys/include/si_debug.h
INCLUDE_SRCS += lib/sys/include/si_log.h
INCLUDE_SRCS += lib/sys/include/si_test.h
INCLUDE_SRCS += lib/sys/include/si_common.h
INCLUDE_SRCS += lib/hashmap/si_hashmap.h
INCLUDE_SRCS += lib/array/si_array.h
INCLUDE_SRCS += lib/ring/si_ring_core.h
INCLUDE_SRCS += lib/ring/si_ring.h

STATIC_LIBS += build/lib/libsi_ring.a
STATIC_LIBS += build/lib/libsi_array.a
STATIC_LIBS += build/lib/libsi_hashmap.a
STATIC_LIBS += build/lib/libsi_sys.a


.PHONY: all init test format clean
all:
	ninja -C build -v

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

install:
	cp -f $(INCLUDE_SRCS) /usr/include/
	cp -f $(STATIC_LIBS) /usr/lib64/

