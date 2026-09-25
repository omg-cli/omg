# OMG Makefile - Development and Testing Targets

.PHONY: help build release test test-lib check fmt fmt-check clippy clippy-strict clean bench bench-fast bench-hyperfine bench-hyperfine-fast bench-charts docker-debian docker-ubuntu docker-test docker-debian-shell docker-ubuntu-shell install audit dev dev-stop dev-check test-property test-fuzz test-fuzz-quick test-advanced test-security qa coverage tdd ci-workflow-quick ci-local-quick ci-local-full check-shell-syntax debt-check debt-refresh

# Default target - show help
.DEFAULT_GOAL := help

# Display help information
help:
	@echo "OMG Development Makefile"
	@echo "========================"
	@echo ""
	@echo "Building:"
	@echo "  make build           - Development build"
	@echo "  make release         - Optimized release build"
	@echo "  make install         - Install to ~/.local/bin"
	@echo ""
	@echo "Testing:"
	@echo "  make test            - Run all tests"
	@echo "  make test-lib        - Run library tests only"
	@echo "  make tdd             - Watch mode (requires cargo-watch)"
	@echo "  make coverage        - Generate coverage report"
	@echo ""
	@echo "Advanced Testing:"
	@echo "  make test-property   - Run property-based tests"
	@echo "  make test-fuzz       - Run fuzzing tests (5 min)"
	@echo "  make test-fuzz-quick - Run fuzzing tests (1 min)"

	@echo "  make test-advanced   - Run all advanced tests"
	@echo "  make test-security   - Run security-focused tests"
	@echo ""
	@echo "Quality:"
	@echo "  make check           - Fast check without building"
	@echo "  make fmt             - Format code"
	@echo "  make fmt-check       - Check formatting"
	@echo "  make clippy          - Run clippy linter"
	@echo "  make clippy-strict   - Clippy with pedantic+nursery"
	@echo "  make audit           - Security audit dependencies"
	@echo "  make qa              - Run all quality checks"
	@echo "  make ci-local-quick  - Run edit-time CI checks"
	@echo "  make ci-local-full   - Run the full local pre-push gate"
	@echo ""
	@echo "Benchmarking:"
	@echo "  make bench               - Full benchmark suite"
	@echo "  make bench-fast          - Quick benchmark"
	@echo "  make bench-hyperfine     - Hyperfine benchmark"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-test     - Test on Debian+Ubuntu"
	@echo "  make docker-debian   - Test on Debian"
	@echo "  make docker-ubuntu   - Test on Ubuntu"
	@echo ""
	@echo "Development:"
	@echo "  make dev             - Run development build with daemon"
	@echo "  make clean           - Clean build artifacts"

# Quick development target
all: build

# ═══════════════════════════════════════════════════════════════════════════════
# Building
# ═══════════════════════════════════════════════════════════════════════════════

# Development build
build:
	cargo build --features arch

# Release build with optimizations
release:
	cargo build --release --features arch

# Install to ~/.local/bin
install:
	@set -eu; \
	host="$$(rustc --print host-tuple)"; \
	target_dir="$${CARGO_TARGET_DIR:-target}"; \
	cargo build --release --features arch --target "$$host" --target-dir "$$target_dir"; \
	mkdir -p "$$HOME/.local/bin"; \
	cp "$$target_dir/$$host/release/omg" "$$target_dir/$$host/release/omgd" "$$HOME/.local/bin/"
	@echo "✓ Installed omg and omgd to ~/.local/bin"

# ═══════════════════════════════════════════════════════════════════════════════
# Testing
# ═══════════════════════════════════════════════════════════════════════════════

# Run all tests
test:
	cargo test --features arch

# Run library tests only (fast)
test-lib:
	cargo test --lib --features arch

# ═══════════════════════════════════════════════════════════════════════════════
# Advanced Testing
# ═══════════════════════════════════════════════════════════════════════════════

# Run property-based tests
test-property:
	@echo "Running property-based tests..."
	cargo test --test property_tests_v2 --features arch
	@echo "✓ Property tests passed!"

# Run fuzzing tests (5 minutes per target)
test-fuzz:
	@echo "Running fuzzing tests (5 minutes per target)..."
	@command -v cargo-fuzz >/dev/null 2>&1 || (echo "Installing cargo-fuzz..." && cargo +nightly install cargo-fuzz)
	cargo +nightly fuzz run ipc_messages -- -max_total_time=300 -seed=1
	cargo +nightly fuzz run package_names -- -max_total_time=300 -seed=2
	if [ -d fuzz/artifacts ]; then echo "⚠️  Fuzzing found crashes! Check fuzz/artifacts/"; ls -la fuzz/artifacts/; exit 1; else echo "✓ Fuzzing tests passed (no crashes)!"; fi

# Run fuzzing tests (quick mode - 60 seconds per target for CI)
test-fuzz-quick:
	@echo "Running quick fuzzing tests (60s per target)..."
	@command -v cargo-fuzz >/dev/null 2>&1 || (echo "Installing cargo-fuzz..." && cargo +nightly install cargo-fuzz)
	cargo +nightly fuzz run ipc_messages -- -max_total_time=60 -seed=1
	cargo +nightly fuzz run package_names -- -max_total_time=60 -seed=2
	if [ -d fuzz/artifacts ]; then echo "⚠️  Fuzzing found crashes! Check fuzz/artifacts/"; exit 1; else echo "✓ Quick fuzzing tests passed!"; fi

# Run all advanced tests (property + fuzz-quick)
test-advanced: test-property test-fuzz-quick
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  All advanced tests passed! ✓"
	@echo "════════════════════════════════════════════════════════════════"

# Run security-focused tests (fuzzing + property tests for validation)
test-security:
	@echo "Running security-focused tests..."
	@echo "1. Package name security fuzzing..."
	@command -v cargo-fuzz >/dev/null 2>&1 || (echo "Installing cargo-fuzz..." && cargo +nightly install cargo-fuzz)
	cargo +nightly fuzz run package_names -- -max_total_time=180 -seed=42
	@echo "2. IPC message validation fuzzing..."
	cargo +nightly fuzz run ipc_messages -- -max_total_time=180 -seed=43
	@echo "3. Security validation tests..."
	cargo test --test security_audit_tests --features arch
	if [ -d fuzz/artifacts ]; then echo "⚠️  Security issues found! Check fuzz/artifacts/"; exit 1; else echo "✓ Security tests passed!"; fi

# ═══════════════════════════════════════════════════════════════════════════════
# Quality Checks
# ═══════════════════════════════════════════════════════════════════════════════

# Check without building (fast)
check:
	cargo check --features arch

# Format code
fmt:
	cargo fmt

# Check formatting without modifying
fmt-check:
	cargo fmt -- --check

# Run clippy with warnings as errors
clippy:
	cargo clippy --features arch -- -D warnings

# Run clippy with all targets (pedantic+nursery configured in Cargo.toml [lints])
clippy-strict:
	cargo clippy --features arch --all-targets -- -D warnings

# Security audit dependencies
audit:
	cargo audit

# Run all quality checks
qa: fmt-check clippy-strict test-lib
	@echo "✓ All quality checks passed!"

# Clean build artifacts
clean:
	cargo clean

# ═══════════════════════════════════════════════════════════════════════════════
# TDD and Coverage
# ═══════════════════════════════════════════════════════════════════════════════

# Continuous testing (TDD mode)
tdd:
	cargo watch -x test

# Generate coverage report (requires cargo-tarpaulin)
coverage:
	cargo tarpaulin --ignore-config --ignore-tests --out html

# ═══════════════════════════════════════════════════════════════════════════════
# Benchmarking
# ═══════════════════════════════════════════════════════════════════════════════

# Run full benchmark suite (10 iterations, 2 warmup)
bench:
	./benchmark.sh

# Run fast benchmark (5 iterations, 1 warmup)
bench-fast:
	./benchmark.sh --fast

# Run hyperfine benchmark (requires hyperfine: pacman -S hyperfine)
bench-hyperfine:
	./benchmark-hyperfine.sh

# Run hyperfine benchmark in fast mode
bench-hyperfine-fast:
	./benchmark-hyperfine.sh --fast

# Generate benchmark visualization charts
bench-charts:
	python3 scripts/generate-benchmark-chart.py

# ═══════════════════════════════════════════════════════════════════════════════
# Docker Testing (for Debian/Ubuntu support development on Arch)
# ═══════════════════════════════════════════════════════════════════════════════

# Build and test on Debian Bookworm
docker-debian:
	@echo "Building OMG for Debian Bookworm..."
	docker build -f Dockerfile.debian -t omg-debian .
	@echo "Running smoke tests..."
	docker run --rm omg-debian

# Build and test on Ubuntu 24.04
docker-ubuntu:
	@echo "Building OMG for Ubuntu 24.04..."
	docker build -f Dockerfile.ubuntu -t omg-ubuntu .
	@echo "Running smoke tests..."
	docker run --rm omg-ubuntu

# Run both Debian and Ubuntu tests
docker-test: docker-debian docker-ubuntu
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  All Docker tests passed! ✓"
	@echo "════════════════════════════════════════════════════════════════"

# Interactive shell in Debian container (for debugging)
docker-debian-shell:
	docker build -f Dockerfile.debian -t omg-debian .
	docker run --rm -it omg-debian /bin/bash

# Interactive shell in Ubuntu container (for debugging)
docker-ubuntu-shell:
	docker build -f Dockerfile.ubuntu -t omg-ubuntu .
	docker run --rm -it omg-ubuntu /bin/bash

# Unused dependencies; install once with: cargo install cargo-machete
.PHONY: deps-check
deps-check:
	cargo-machete

# ═══════════════════════════════════════════════════════════════════════════════
# Development Workflow
# ═══════════════════════════════════════════════════════════════════════════════

# Run development environment (build + daemon)
dev: build
	@echo "Starting OMG daemon..."
	@pkill omgd 2>/dev/null || true
	./target/debug/omgd &
	@echo "Daemon started. Run 'make dev-stop' to stop."

# Stop development daemon
dev-stop:
	@pkill omgd || echo "No daemon running"

# Full development cycle: format, check, test
dev-check: fmt check test-lib
	@echo "✓ Development checks passed!"

CI_LOCAL_TARGET_DIR ?= $(HOME)/.cache/build-targets/omg-ci-local

ci-local-quick ci-local-full: export CARGO_TARGET_DIR := $(CI_LOCAL_TARGET_DIR)

check-shell-syntax:
	@for script in install.sh benchmark.sh benchmark-hyperfine.sh scripts/*.sh; do \
		bash -n "$$script" || exit $$?; \
	done

# Debt ratchet: fails when per-file debt counts exceed the committed baseline.
debt-check:
	python3 scripts/debt-ratchet.py

# Lower the ratchet floor after a cleanup; refuses to raise any count.
debt-refresh:
	python3 scripts/debt-ratchet.py --refresh

# Hosted prerequisite: no compilation before independent platform jobs.
ci-workflow-quick: check-shell-syntax
	cargo fmt --all -- --check
	python3 -m unittest discover -s scripts -p 'test_*.py'
	python3 tests/test_benchmark_records.py
	python3 tests/test_terminal_update_notice.py

ci-local-quick: ci-workflow-quick
	cargo check --all-targets --no-default-features --features pgp,license --locked
	cargo check --manifest-path fuzz/Cargo.toml --all-targets --locked

ci-local-full: ci-local-quick
	cargo clippy --all-targets --no-default-features --features pgp,license \
		--locked -- -D warnings
	cargo clippy --all-targets --no-default-features --features debian-pure \
		--locked -- -D warnings
	cargo clippy --all-targets --no-default-features --features arch,pgp,license \
		--locked -- -D warnings
	cargo nextest run --lib --no-default-features --features pgp,license \
		--locked --profile ci
	cargo nextest run --no-default-features --features arch,pgp,license \
		--locked --profile ci --no-fail-fast
