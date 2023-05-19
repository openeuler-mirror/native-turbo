.PHONY: all clean test

SYSBOOSTD=./target/debug/sysboostd
SYSBOOST=../build/sysboost/sysboost
SYSBOOSTD_INSTALL_PATH=/usr/bin/sysboostd
SYSBOOST_INSTALL_PATH=/usr/bin/sysboost

all: sysboostd

sysboostd:
	clear
	cargo build

clean:
	cargo clean

test: sysboostd
	cp -f $(SYSBOOSTD) $(SYSBOOSTD_INSTALL_PATH)
	cp -f $(SYSBOOST) $(SYSBOOST_INSTALL_PATH)
	clear
	cargo test

test-debug:
	cargo test -- --nocapture

format:
	cargo fmt
