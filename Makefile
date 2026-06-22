.DEFAULT_GOAL := help

export CARGO_TOOL_VERSION_dd-rust-license-tool ?= 1.0.6
export CARGO_BIN_DIR := $(shell echo "$${HOME}/.cargo/bin")
DD_RUST_LICENSE_TOOL := $(CARGO_BIN_DIR)/dd-rust-license-tool

.PHONY: help
help:
	@printf "Usage: make <target>\n"
	@printf "  %-20s %s\n" "fmt" "Check Rust formatting"
	@printf "  %-20s %s\n" "clippy" "Run clippy with warnings denied"
	@printf "  %-20s %s\n" "test" "Run the test suite"
	@printf "  %-20s %s\n" "sync-licenses" "Regenerate LICENSE-3rdparty.csv"
	@printf "  %-20s %s\n" "check-licenses" "Verify LICENSE-3rdparty.csv is up to date"

.PHONY: cargo-install-dd-rust-license-tool
cargo-install-dd-rust-license-tool:
	@if [ ! -x "$(DD_RUST_LICENSE_TOOL)" ] || ! "$(DD_RUST_LICENSE_TOOL)" --version 2>/dev/null | grep -q "$(CARGO_TOOL_VERSION_dd-rust-license-tool)"; then \
		echo "[*] Installing dd-rust-license-tool $(CARGO_TOOL_VERSION_dd-rust-license-tool)..."; \
		cargo install "dd-rust-license-tool@$(CARGO_TOOL_VERSION_dd-rust-license-tool)"; \
	fi

.PHONY: fmt
fmt:
	@echo "[*] Checking Rust source code formatting..."
	@cargo fmt -- --check

.PHONY: clippy
clippy:
	@echo "[*] Running clippy..."
	@cargo clippy --all-targets -- -D warnings

.PHONY: test
test:
	@echo "[*] Running tests..."
	@cargo test

.PHONY: sync-licenses
sync-licenses: cargo-install-dd-rust-license-tool
	@echo "[*] Synchronizing third-party license file to current dependencies..."
	@"$(DD_RUST_LICENSE_TOOL)" write

.PHONY: check-licenses
check-licenses: cargo-install-dd-rust-license-tool
	@echo "[*] Checking if third-party license file is up to date..."
	@"$(DD_RUST_LICENSE_TOOL)" check
