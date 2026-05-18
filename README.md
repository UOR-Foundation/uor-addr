# uor-addr

> UOR-ADDR — the typed reference vocabulary for typed content-addressing
> across recursively-grammared formats. A [UOR Foundation](https://uor.foundation)
> standard-library Layer-3 realization grounded against the wiki
> specification at <https://github.com/UOR-Foundation/UOR-Framework/wiki>.

## What this crate is

A single Rust crate shipping UOR-ADDR's **common architectural surface**
plus **multiple concrete realizations** of that surface, each a
`PrismModel<HostTypes, HostBounds, Hasher, ResolverTuple, TypedCommitment>`
whose typed-iso surface derives a 71-byte `sha256:<64hex>` content
address from a typed format-specific value:

```rust
// JSON realization
use uor_addr::json::address as json_address;
let outcome = json_address(br#"{"foo": "bar"}"#).unwrap();
// outcome.address == "sha256:7a38bf81…ee24b"

// S-expression realization (Rivest canonical S-expressions)
use uor_addr::sexp::address as sexp_address;
let outcome = sexp_address(b"(a b c)").unwrap();
// outcome.address == "sha256:cdd489dd…f50e"
```

Every realization shares the same common surface — the
[`AddressInput`] trait, the [`AddressLabel`] output shape, the
`address_inference` verb body composing ψ_1 + ψ_7 + ψ_8 + ψ_9
(ADR-035's canonical k-invariants branch), and the eight-resolver
tuple shape (ADR-036). Only the typed-input shape `V`, the
canonicalization, the parser, and the `HostBounds` profile vary
across realizations.

## Realizations shipped

| Module | Realization | Authoritative source | Conformance fixtures |
|---|---|---|---|
| [`uor_addr::json`](crates/uor-addr/src/json/) | JSON under JCS-RFC8785 + Unicode NFC, σ-projection = SHA-256 | [RFC 8785](https://datatracker.ietf.org/doc/rfc8785/) + [RFC 8259](https://datatracker.ietf.org/doc/rfc8259/) + [UAX #15](https://www.unicode.org/reports/tr15/) + [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | 12-fixture `mcp.uor.foundation/tools/encode_address` baseline + 8-fixture Maura Clark baseline + JCS-RFC8785 published test vectors |
| [`uor_addr::sexp`](crates/uor-addr/src/sexp/) | S-expressions under Rivest 1997 canonical form, σ-projection = SHA-256 | [Rivest 1997 *S-expressions*](https://people.csail.mit.edu/rivest/Sexp.txt) + [RFC 2693 §3](https://datatracker.ietf.org/doc/html/rfc2693#section-3) | 8-fixture Rivest §4.2/§4.3 canonical-form conformance + typed-distinction theorem corpus |
| [`uor_addr::variant::storage`](crates/uor-addr/src/variant/storage.rs) | Cost-model-bearing JSON variant binding `C = AndCommitment<EmptyCommitment, SingletonCommitment<LexicographicLessEqThreshold>>` | [ADR-048](https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-048) + [QS-06](https://github.com/UOR-Foundation/UOR-Framework/wiki/QS-06) + [ADR-047 U6](https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-047) | 5-fixture predicate-evaluation, bandwidth-additivity, and typed-commitment conformance |

See [`STANDARDS.md`](STANDARDS.md) for the complete index of
authoritative source references.

Deferred realizations (per ADR-031's demand-driven clause):
`uor-addr-xml` (XML-C14N), `uor-addr-asn1` (DER), `uor-addr-ring`
(Amendment 43 §2), `uor-addr-codemodule`, schema-pinned descendants
(`uor-addr-photo`, `uor-addr-document`, `uor-addr-codemodule-signed`),
and the `uor-addr-signed` variant.

## The common architectural surface

```rust
pub trait AddressInput: ConstrainedTypeShape + IntoBindingValue + Sized {
    type Registry: ShapeRegistryProvider;
    fn canonicalize_into(parser_emitted: &[u8], out: &mut [u8])
        -> Result<usize, ShapeViolation>;
    fn parse(input: &[u8]) -> Result<Self, ShapeViolation>;
}
```

Every realization implements `AddressInput` on its typed-input shape.
The trait composes three substrate commitments — `ConstrainedTypeShape`
(constraint geometry per ADR-001 + ADR-017), `IntoBindingValue`
(catamorphism's typed-input serialization per ADR-023), and the
`Registry` associated type (ADR-057 application shape registry, emitted
via `register_shape!`).

## The ψ-chain (every realization)

```text
V (typed input — V: AddressInput)
   ↓ ψ_1 Nerve            (Constraints → SimplicialComplex)
   ↓ ψ_7 PostnikovTower   (SimplicialComplex → PostnikovTower)
   ↓ ψ_8 HomotopyGroups   (PostnikovTower → HomotopyGroups)
   ↓ ψ_9 KInvariants      (HomotopyGroups → KInvariants)
AddressLabel — the κ-label (71-byte `sha256:<64hex>`)
```

The verb body composes only ψ-Term variants per ADR-035 — the
`verb_arena_contains_no_sigma_residuals` test pins this from the
implementation side for every realization. The format's
canonicalization lives **inside the ψ_9 resolver body** per ADR-046's
resolver-body iterative-resolution discipline (the
`<V as AddressInput>::canonicalize_into` dispatch). ψ_2..ψ_6 are
off-path with identity-shaped carriers for `ResolverTuple`
completeness.

## File layout

```
crates/uor-addr/
├── Cargo.toml
├── examples/                      — runnable use-case demos
│   ├── address_value.rs           — JSON realization
│   ├── dedupe_cache.rs            — JSON realization
│   ├── typed_distinction.rs       — JSON realization
│   ├── replay_verification.rs     — JSON realization
│   └── sexp_address.rs            — S-expression realization
├── tests/                         — integration + conformance suites
│   ├── analysis.rs
│   ├── byte_identity.rs           — JSON byte-identity baseline (12 fixtures)
│   ├── common_surface.rs          — `AddressInput` trait conformance
│   ├── conformance.rs             — CS / CD / CP / CT / CL JSON suite
│   ├── cross_validation.rs        — live `mcp.uor.foundation` checks
│   ├── replay.rs                  — TC-05 replay round-trip (CL-R)
│   ├── sexp_conformance.rs        — Rivest 1997 conformance (NEW)
│   ├── typed_input.rs             — JSON typed-input bounds
│   └── variant_storage.rs         — ADR-048 cost-model variant (NEW)
└── src/
    ├── lib.rs                     — façade + crate-root re-exports
    ├── common.rs                  — AddressInput trait + architectural surface
    ├── label.rs                   — AddressLabel (shared shape, IRI `/sha256` axis suffix)
    ├── json/                      — JSON realization
    │   ├── mod.rs
    │   ├── model.rs               — AddressModel (prism_model!)
    │   ├── value.rs               — JsonValue + JCS+NFC canonicalizer + register_shape!
    │   ├── verbs.rs               — address_inference (verb!)
    │   ├── resolvers.rs           — eight ψ-stage resolvers (resolver!)
    │   ├── pipeline.rs            — `address(bytes) → AddressOutcome`
    │   └── shapes/
    │       ├── mod.rs             — re-export of prism::crypto::Sha256Hasher
    │       └── bounds.rs          — AddrBounds (HostBounds, ADR-037)
    ├── sexp/                      — S-expression realization
    │   ├── mod.rs
    │   ├── model.rs               — AddressModel (prism_model!)
    │   ├── value.rs               — SExprValue + Rivest canonical-form canonicalizer + register_shape!
    │   ├── verbs.rs               — address_inference (verb!)
    │   ├── resolvers.rs           — eight ψ-stage resolvers (resolver!)
    │   ├── pipeline.rs            — `address(bytes) → AddressOutcome`
    │   └── shapes/
    │       ├── mod.rs
    │       └── bounds.rs          — SExprAddrBounds (HostBounds, ADR-037)
    └── variant/                   — cost-model-bearing variants
        ├── mod.rs
        └── storage.rs             — AddressStorageModel (ADR-048 non-default C)
```

## Build

```bash
cargo build           # rustc >= 1.83; uor-prism = "0.1", uor-foundation = "0.4"
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

`no_std`-compatible: `default-features = false` drops the `std`
feature flag; only `alloc` is required. `#![forbid(unsafe_code)]` —
zero unsafe blocks anywhere in the crate.

## Use-case examples

```bash
# JSON realization
cargo run -p uor-addr --example address_value
cargo run -p uor-addr --example dedupe_cache
cargo run -p uor-addr --example typed_distinction
cargo run -p uor-addr --example replay_verification

# S-expression realization
cargo run -p uor-addr --example sexp_address

# Or run every example in sequence as part of the V&V gate:
just examples
```

## Verification & Validation

The single normative acceptance gate:

```bash
just vv          # full V&V: fmt, lint, tests, conformance, analysis, replay, doc-check, Lean
```

| Doc | Role |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Normative architectural specification — the typed reference vocabulary |
| [STANDARDS.md](STANDARDS.md) | Authoritative source references — RFC, ANSI, NIST, wiki ADR index |
| [CONFORMANCE.md](CONFORMANCE.md) | Conformance contract — invariant IDs (CS / CD / CP / CN / CT / CL) referenced by tests |
| [VERIFICATION.md](VERIFICATION.md) | V&V index — maps `just vv` axes to conformance-class IDs |
| [ANALYSIS.md](ANALYSIS.md) | Derivation of CP sample sizes, χ² thresholds, CT typed-input bounds |
| [uor-addr-lean/](uor-addr-lean/) | Lean 4 library — 14 mechanised theorems against UOR-Framework's `UOR.Enforcement` shapes |

## License

Apache-2.0, matching `uor-foundation`.
