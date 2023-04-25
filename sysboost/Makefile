.PHONY: all clean test

all: sysboost

sysboost:
	clear
	cargo build

clean:
	cargo clean

test:
	cargo build
	clear
	@echo ======
	target/debug/sysboost -h
	@echo ======
	target/debug/sysboost -static file1 file2 file3
	@echo ======
	target/debug/sysboost -daemon

format:
	cargo fmt
