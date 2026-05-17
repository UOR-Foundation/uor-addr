# `just vv` is the normative V&V acceptance gate.
# See VERIFICATION.md for the full axis-by-axis mapping.

set shell := ["bash", "-cu"]

default: vv

# ──────────────────────────────────────────────────────────────────────────
# Acceptance gate
# ──────────────────────────────────────────────────────────────────────────

# Full V&V — every axis required for merge. Halts on the first failure.
vv: fmt-check lint test conformance analysis replay doc-check verify

# Fast CI subset — no Lean, no live network. Use when iterating locally.
ci: fmt-check lint test

# ──────────────────────────────────────────────────────────────────────────
# Individual axes
# ──────────────────────────────────────────────────────────────────────────

# Axis 1 — format check.
fmt-check:
	cargo fmt --all -- --check

# Axis 2 — clippy with -D warnings.
lint:
	cargo clippy --workspace --all-targets -- -D warnings

# Axis 3 — workspace unit + integration tests.
test:
	cargo test --workspace

# Axis 4 — conformance suite (release).
conformance:
	cargo test -p uor-addr-1 --release --test conformance

# Axis 5 — analysis suite (release, large samples).
analysis:
	cargo test -p uor-addr-1 --release --test analysis

# Axis 6 — TC-05 replay round-trip via `prism_verify::certify_from_trace`.
replay:
	cargo test -p uor-addr-1 --release --test replay

# Axis 7 — rustdoc with broken-intra-doc-links denied.
doc-check:
	RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc --workspace --no-deps

# Axis 8 — Lean proofs (lake build).
verify:
	cd uor-addr-1-lean && lake build

# Axis 9 — live cross-validation. Gated; opt in via UOR_ADDR_LIVE=1.
cn:
	UOR_ADDR_LIVE=1 cargo test -p uor-addr-1 --release --test cross_validation -- --ignored

# ──────────────────────────────────────────────────────────────────────────
# Build / clean / repl conveniences
# ──────────────────────────────────────────────────────────────────────────

build:
	cargo build --workspace

build-release:
	cargo build --workspace --release

clean:
	cargo clean && cd uor-addr-1-lean && lake clean

doc:
	cargo doc --workspace --no-deps --open

fmt:
	cargo fmt --all
