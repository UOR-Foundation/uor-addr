# uor-addr-1

> Reference Rust implementation of **UOR-ADDR-1** — chain-agnostic
> canonical content addressing for JSON-serializable data.

`uor-addr-1` is a Prism application of the [UOR Foundation](https://github.com/UOR-Foundation)
that derives a 71-byte `sha256:<64hex>` content address from any
JSON-serializable input. Output is byte-identical to the UOR Foundation's
canonical reference at `mcp.uor.foundation/tools/encode_address`.

The pipeline is **JCS-RFC8785 canonicalization + Unicode NFC normalization
+ SHA-256**, exposed through a single function:

```rust
use uor_addr_1::address;

let outcome = address(br#"{"foo": "bar"}"#).unwrap();
assert_eq!(
    outcome.address,
    "sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b"
);
```

## What this crate guarantees

The implementation carries a numbered [conformance contract](https://github.com/UOR-Foundation/uor-addr-1/blob/main/CONFORMANCE.md)
covering structural, deterministic, probabilistic, formal-Lean, and
live-network invariants. Highlights:

- **Determinism (CD-D01).** `address(b)` is a pure function of the
  canonical-form bytes; identical inputs always yield identical κ-labels.
- **Invariance (CD-I01a–d).** Key ordering, whitespace, and Unicode
  normalization form (NFC/NFD/NFKC/NFKD) do not affect the output.
- **Wire format (CL-W01).** The κ-label is exactly 71 ASCII bytes —
  `"sha256:"` followed by 64 lowercase hex digits — proved at the type
  level by a [Lean theorem](https://github.com/UOR-Foundation/uor-addr-1/blob/main/uor-addr-1-lean/UorAddr1/AddressShape.lean).
- **Byte identity (CD-D02).** The 12 reference fixtures harvested from
  the UOR Foundation canonical endpoint reproduce byte-for-byte.
- **Cryptographic precision.** Collision probability bounded by
  SHA-256's standard `2^{-128}` security margin.

See [VERIFICATION.md](https://github.com/UOR-Foundation/uor-addr-1/blob/main/VERIFICATION.md)
for the full V&V gate (`just vv`) and reproduction commands.

## Features

- **`std`** (default) — uses the standard library. Disable for `no_std`
  environments; `alloc` is always required.

## Architecture

The crate is a single
`PrismModel<HostTypes, HostBounds, Hasher, ResolverTuple, TypedCommitment>`
declared over the `uor-prism` standard-library façade (wiki ADR-031),
with `TypedCommitment = EmptyCommitment` per ADR-048. The PrismModel's
`Input` is the typed [`JsonValue`] — a JSON value of bounded depth
and width carried as a structurally-tagged byte serialization. The
ψ-pipeline derives the κ-label through four typed stages
(Nerve → PostnikovTower → HomotopyGroups → KInvariants); JCS-RFC8785
+ Unicode NFC canonicalisation and the canonical hash axis are both
consumed inside the terminal ψ_9 resolver per wiki ADR-046.

For the full architectural specification (substitution axes,
discipline-scope boundaries, algebraic-closure encoding, seal regime),
see [ARCHITECTURE.md](https://github.com/UOR-Foundation/uor-addr-1/blob/main/ARCHITECTURE.md).

## MSRV

Rust 1.83 or later.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

## Authorship

Maintained by [The UOR Foundation](https://uor.foundation), grounded
against the [UOR Foundation wiki specification](https://github.com/UOR-Foundation/UOR-Framework/wiki).
