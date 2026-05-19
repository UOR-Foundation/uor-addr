# Getting started

This walks the three-step path from raw bytes to a κ-label, then shows
how κ-labels compose with the framework's structural guarantees.

## 1. Pick a realization

Each realization handles a specific data format. The choice is fixed
by what your data already is; pick the row that matches the format you
have on the wire.

```rust
use uor_addr::json::address as json_address;
use uor_addr::sexp::address as sexp_address;
use uor_addr::xml::address as xml_address;
use uor_addr::asn1::address as asn1_address;
use uor_addr::ring::address as ring_address;
use uor_addr::codemodule::address as codemodule_address;
```

For schema-typed data (photo metadata, articles, signed-software
attestations) prefer the schema-pinned descendants — they add
admission predicates without changing the κ-label.

```rust
use uor_addr::schema::photo::address as photo_address;
use uor_addr::schema::document::address as document_address;
use uor_addr::schema::codemodule_signed::address as signed_address;
```

See [realizations.md](realizations.md) for the full decision matrix.

## 2. Mint a κ-label

The `address` function takes raw bytes and returns an outcome carrying
the wire-format κ-label plus a `Grounded<AddressLabel>` witness for
downstream verification.

```rust
let outcome = uor_addr::json::address(br#"{"foo": "bar"}"#).unwrap();
println!("{}", outcome.address);
// sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b
```

The κ-label is **deterministic** — feed the same bytes twice, get the
same label. It's also **invariant** under the format's canonical-form
rules:

```rust
// JSON: whitespace, key order, NFC vs NFD all collapse.
let a = uor_addr::json::address(br#"{"a":1,"b":2}"#).unwrap().address;
let b = uor_addr::json::address(br#"{ "b" : 2 , "a" : 1 }"#).unwrap().address;
assert_eq!(a, b);
```

But it **distinguishes** typed values that look similar but mean
different things:

```rust
let int = uor_addr::json::address(b"42").unwrap().address;
let str = uor_addr::json::address(br#""42""#).unwrap().address;
assert_ne!(int, str);
```

## 3. Verify a κ-label without re-hashing

Every `address()` call also emits a `Grounded<AddressLabel>` witness.
Downstream consumers replay it through
`prism_verify::certify_from_trace` to re-derive a
`Certified<GroundingCertificate>` — the verifier sees the trace, not
the original input, and does not invoke SHA-256 again.

```rust
let outcome = uor_addr::json::address(br#"{"foo": "bar"}"#).unwrap();
let grounded = outcome.witness.grounded();
// grounded.output_bytes() == outcome.address.as_bytes()
// The trace replay path is exercised by `tests/replay.rs`.
```

## Where to next?

- Pick the right realization: [realizations.md](realizations.md).
- See the full architectural picture: [../ARCHITECTURE.md](../ARCHITECTURE.md).
- Run every example: `just examples`.
- Reproduce the V&V gate: [../VERIFICATION.md](../VERIFICATION.md).
