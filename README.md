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

### Format-specific realizations

| Module | Realization | Authoritative source |
|---|---|---|
| [`uor_addr::json`](crates/uor-addr/src/json/) | JSON under JCS-RFC8785 + Unicode NFC | [RFC 8785](https://datatracker.ietf.org/doc/rfc8785/) + [RFC 8259](https://datatracker.ietf.org/doc/rfc8259/) + [UAX #15](https://www.unicode.org/reports/tr15/) + [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) |
| [`uor_addr::sexp`](crates/uor-addr/src/sexp/) | S-expressions under Rivest 1997 canonical form | [Rivest 1997 *S-expressions*](https://people.csail.mit.edu/rivest/Sexp.txt) + [RFC 2693 §3](https://datatracker.ietf.org/doc/html/rfc2693#section-3) |
| [`uor_addr::xml`](crates/uor-addr/src/xml/) | XML under W3C Canonical XML 1.1 (subset) | [W3C XML-C14N 1.1](https://www.w3.org/TR/xml-c14n11/) + [XML 1.0](https://www.w3.org/TR/xml/) |
| [`uor_addr::asn1`](crates/uor-addr/src/asn1/) | ASN.1 under X.690 DER | [ITU-T X.690](https://www.itu.int/rec/T-REC-X.690) + [ITU-T X.680](https://www.itu.int/rec/T-REC-X.680) |
| [`uor_addr::ring`](crates/uor-addr/src/ring/) | Ring elements under Amendment 43 §2 canonical bytes | [UOR-Framework Amendment 43](https://github.com/UOR-Foundation/UOR-Framework/wiki/Amendment-43) |
| [`uor_addr::codemodule`](crates/uor-addr/src/codemodule/) | Code-module AST under CCMAS canonical form | [CCMAS grammar](crates/uor-addr/src/codemodule/mod.rs) + [Rivest 1997](https://people.csail.mit.edu/rivest/Sexp.txt) |

### Schema-pinned descendants

Per UOR's schema-import discipline, well-known kinds and types map to
**existing standards** rather than UOR-native inventions:

| Module | Specializes | Imported standard |
|---|---|---|
| [`uor_addr::schema::photo`](crates/uor-addr/src/schema/photo.rs) | JSON | [schema.org/Photograph](https://schema.org/Photograph) (JSON-LD) |
| [`uor_addr::schema::document`](crates/uor-addr/src/schema/document.rs) | JSON | [schema.org/Article](https://schema.org/Article) + 14 subtypes (JSON-LD) |
| [`uor_addr::schema::codemodule_signed`](crates/uor-addr/src/schema/codemodule_signed.rs) | JSON | [in-toto Statement v1](https://in-toto.io/Statement/v1) (sigstore / SLSA envelope) |

### Cost-model-bearing variants

| Module | `C` binding | Reference |
|---|---|---|
| [`uor_addr::variant::storage`](crates/uor-addr/src/variant/storage.rs) | `AndCommitment<EmptyCommitment, SingletonCommitment<LexicographicLessEqThreshold>>` | [ADR-048](https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-048) + [QS-06](https://github.com/UOR-Foundation/UOR-Framework/wiki/QS-06) |
| [`uor_addr::variant::signed`](crates/uor-addr/src/variant/signed.rs) | `SingletonCommitment<UltrametricCloseTo<2>>` | [ADR-048](https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-048) + [ADR-049](https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-049) |

See [`STANDARDS.md`](STANDARDS.md) for the complete index of
authoritative source references and per-realization conformance
fixture maps.

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

Every shipped realization has a comprehensive runnable example;
`just examples` runs all 16 in sequence as part of the V&V gate:

```bash
# Common architectural surface
cargo run -p uor-addr --example common_surface

# JSON realization (RFC 8785 + RFC 8259 + UAX #15 + FIPS 180-4)
cargo run -p uor-addr --example address_value
cargo run -p uor-addr --example dedupe_cache
cargo run -p uor-addr --example typed_distinction
cargo run -p uor-addr --example replay_verification

# Other format-specific realizations
cargo run -p uor-addr --example sexp_address              # Rivest 1997 canonical S-exprs
cargo run -p uor-addr --example xml_realization           # W3C XML-C14N 1.1 subset
cargo run -p uor-addr --example asn1_realization          # ITU-T X.690 DER
cargo run -p uor-addr --example ring_realization          # Amendment 43 §2
cargo run -p uor-addr --example codemodule_realization    # CCMAS

# Schema-pinned descendants
cargo run -p uor-addr --example photo_schema              # PhotoValue over JSON
cargo run -p uor-addr --example document_schema           # DocumentValue over JSON
cargo run -p uor-addr --example codemodule_signed_schema  # SignedCodeModuleValue over CCMAS

# Cost-model-bearing variants
cargo run -p uor-addr --example storage_variant           # ADR-048 + QS-06
cargo run -p uor-addr --example signed_variant            # ADR-048 + ADR-049

# Cross-realization showcase
cargo run -p uor-addr --example multi_realization

# All in sequence as part of the V&V gate:
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
