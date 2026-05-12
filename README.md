# uor-addr-1

> **Reference Rust implementation of UOR-ADDR-1** — chain-agnostic canonical content addressing for agent-produced content.

[![License: CC0-1.0](https://img.shields.io/badge/License-CC0%201.0-lightgrey.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

## What this crate is

UOR-ADDR-1 is a community proposal under the UOR Foundation that specifies how to deterministically compute a content address for any JSON-serializable value, so that two semantically-equal values produce identical addresses regardless of how they were constructed.

The address takes the form `sha256:<64hex>` and is computed as:

```
content_address(value) = "sha256:" + hex(sha256(canonical_bytes(value)))
canonical_bytes(value) = utf8(json_serialize(nfc_recursive(value),
                                             sort_keys=true,
                                             separators=",:",
                                             no_whitespace))
```

The standard lives at: <https://github.com/maurathat/verifiable-agent-settlement-standards>

## Why this crate exists

The UOR Foundation publishes a Rust crate ecosystem (`uor-foundation`, `uor-foundation-sdk`) covering the Prism framework's compile-time type enforcement. Those crates operate on a different primitive — 128-bit FNV-1a fingerprints used for type discrimination.

UOR-ADDR-1 (this crate) is the **application-layer** content-addressing primitive: SHA-256 over JCS-RFC8785 + Unicode NFC canonical bytes. It is the address shape that appears inside derivation certificates, task specifications, and on-chain references in the VTEAI settlement protocol.

Until now, the only canonical reference implementation has been a Python module (`AgentLevy/agentlevy/primitives/canonical.py`) plus the live endpoint `mcp.uor.foundation/tools/encode_address`. This crate is the **Rust reference**.

## Usage

```rust
use uor_addr_1::{content_address, content_address_bytes, to_canonical_bytes};
use serde_json::json;

let v = json!({ "foo": "bar" });

// String form (canonical wire format): "sha256:<64hex>"
let addr: String = content_address(&v);

// Raw 32-byte digest (for signing, hashlock conditions, Merkle leaves)
let bytes: [u8; 32] = content_address_bytes(&v);

// Just the canonical bytes (for cache keys, signing inputs, custom hashing)
let canonical: Vec<u8> = to_canonical_bytes(&v);
```

## Testing

The test suite has three layers:

```bash
# (1) Unit tests — deterministic, offline, run by default
cargo test --lib

# (2) Offline byte-identity tests against harvested fixtures from the
#     UOR Foundation reference endpoint — also offline, also default
cargo test --test cross_validation offline_byte_identity_against_harvested_fixtures

# (3) Live cross-validation against mcp.uor.foundation/mcp — network required,
#     gated behind --ignored so default runs don't hit the network
cargo test --test cross_validation -- --ignored
```

Layer (2) is the load-bearing one: a table of 12 known-good `(input, canonical_form, content_address)` triples harvested from the canonical UOR Foundation reference (`mcp-uor-server` v0.2.1, algorithm `uor-sha256-v1`, canonicalization `jcs-rfc8785+nfc`). The test asserts that this crate produces byte-identical output for every fixture. **No network call** — these are vendored fixtures.

Layer (3) re-verifies the harvested fixtures against the live endpoint over MCP / JSON-RPC / Server-Sent Events. Run this whenever you want to confirm the upstream spec hasn't drifted. The MCP wire-up is implemented in `tests/cross_validation.rs` (see `mcp_session()` and `mcp_encode_address()`).

To re-harvest fixtures (e.g. when adding new test cases), run:

```bash
bash tests/harvest_fixtures.sh
```

This script speaks MCP directly via curl and prints `(address, canonical_form)` pairs ready to paste into the Rust fixture table.

## What this crate does NOT do

- **Sign or verify.** Pair this with Ed25519 (e.g. `ed25519-dalek`). The content address is the message you sign.
- **Implement chain-specific bindings.** Chain bindings consume this crate to compute addresses, then settle them on-chain (Base via Solidity, XRPL via XLS-100 SmartEscrow, etc.).
- **Cover the full RFC 8785 number-formatting edge cases.** The current implementation uses `serde_json`'s default number serialization. Edge cases like `1.0` vs `1` may need explicit handling. Add a test fixture to `tests/cross_validation.rs` if you find a divergence.

## Roadmap

- [x] Wire up `cross_validation.rs` with a real MCP client (`ureq` over JSON-RPC + SSE) — **done 2026-05-12**
- [x] Vendor 12 known-good fixtures from the canonical reference for offline byte-identity testing — **done 2026-05-12**
- [ ] Add PyO3 bindings so the Python AgentLevy implementation can call this crate directly (drop-in replacement for `agentlevy/primitives/canonical.py`)
- [ ] Publish to crates.io as the canonical Rust reference implementation of UOR-ADDR-1
- [ ] Submit to the UOR Foundation as a community-contributed reference alongside `uor-foundation-sdk`
- [ ] Add full RFC 8785 number-formatting compliance (`1.0` → `1`, ECMAScript `Number.toString` shortest-round-trip semantics)
- [ ] Add fixture cases for: deeply nested arrays, large numbers (close to `Number.MAX_SAFE_INTEGER`), strings with surrogate pairs, strings with control characters

## License

CC0 1.0 (public domain dedication). The standard is open by design; the reference implementation matches.
