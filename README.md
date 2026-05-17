# uor-addr-1

> Pure-Prism JSON content addressing — a [UOR Foundation](https://uor.foundation)
> reference implementation of UOR-ADDR-1, grounded against the wiki
> specification at <https://github.com/UOR-Foundation/UOR-Framework/wiki>.

## What this crate is

A `PrismModel<HostTypes, HostBounds, Hasher, ResolverTuple,
TypedCommitment>` whose typed-iso surface derives a 71-byte
`sha256:<64hex>` content address from any JSON value of bounded
depth and width:

```rust
use uor_addr_1::address;

let outcome = address(br#"{"foo": "bar"}"#).unwrap();
assert_eq!(
    outcome.address,
    "sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b"
);
```

The PrismModel's `Input` is the typed `JsonValue` shape; the host
boundary does only parsing. JCS-RFC8785 + Unicode NFC
canonicalisation and the SHA-256 σ-projection both run **inside**
the ψ-pipeline (the ψ_9 resolver body) per wiki ADR-046. Output is
byte-identical to the UOR Foundation's canonical reference at
`mcp.uor.foundation/tools/encode_address`; 12 reference fixtures
covering scalar / object / array / Unicode-normalisation /
nested-structure cases are pinned in `tests/byte_identity.rs`.

See [`examples/`](examples/) for runnable use-case demonstrations:
dedupe cache keys, signature payloads under structural-equivalence
collapse, replay-verification round-trips.

## Validation & verification against the wiki specification

Every architectural commitment this crate makes is traceable to a wiki
ADR or wiki-defined concept. The crate validates the wiki's Prism
model on the JSON content-addressing problem: each piece below names
the ADR or concept it satisfies, and the test suite pins the
satisfaction at compile/run time.

### Substitution axes (ADR-007, ADR-018, ADR-030)

The wiki's three-position substitution-axis pattern:

| Axis             | Bound declared by | This crate's selection                              |
|------------------|-------------------|-----------------------------------------------------|
| `HostTypes`      | `prism`           | `uor_foundation::DefaultHostTypes`                  |
| `HostBounds`     | `prism`           | [`AddrBounds`][bounds] (24 ADR-037 ceilings)        |
| `AxisTuple` + `Hasher` | `prism`     | [`Sha256Hasher`][hasher] (`impl Hasher<32>`)        |
| `ResolverTuple`  | `prism`           | [`AddressResolverTuple<H>`][resolvers] (ADR-036)    |

[bounds]: crates/uor-addr-1/src/shapes/bounds.rs
[hasher]: crates/uor-addr-1/src/shapes/hasher.rs
[resolvers]: crates/uor-addr-1/src/resolvers.rs

### HostBounds — ADR-037 capacity ceilings

`AddrBounds` declares all 24 ADR-037-migrated capacity constants:
fingerprint width range, trace event-count ceiling, Witt-level
bit-width, the 14 data-shape capacity caps, and the eight per-ψ-stage
resolver output-byte ceilings. `NERVE_SITES_MAX = 71` matches the
`AddressLabel::SITE_COUNT`. Pinned by
`shapes::bounds::tests::psi_stage_output_ceilings_uniform`.

### Hasher — ADR-007 / ADR-010 substitution axis

`Sha256Hasher` is the `prism::crypto::Sha256Hasher` re-export from the
Prism standard-library cryptography sub-crate (wiki ADR-031). It is a
`Hasher<32>` impl satisfying the four ADR-007 trait laws: width-in-budget
(`32 ∈ [FINGERPRINT_MIN_BYTES, FINGERPRINT_MAX_BYTES]`), determinism,
sensitivity, no interior mutability. The body is the
foundation-recommended-secondary algorithm per
`Element::digest_algorithm` (BLAKE3 primary, SHA-256 secondary). This
crate carries no bespoke SHA-256 of its own.

### Verb — ADR-024 (implementation closure) + ADR-035 (canonical k-invariants branch)

The verb body is exactly the wiki's canonical k-invariants branch:

```rust
verb! {
    pub fn address_inference(input: JsonValue) -> AddressLabel {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}
```

ψ_1 → ψ_7 → ψ_8 → ψ_9, the wiki's "maximum-discriminating structural
witness with the minimum number of resolver-bound stages"
(`12-Glossary.md`).

### ψ-residuals discipline — ADR-035 (verb-body discipline)

ADR-035 forbids σ-residuals — `Term::FirstAdmit`,
`Term::AxisInvocation`, byte-comparison `PrimitiveOp`s (`Le`, `Lt`,
`Ge`, `Gt`), and `PrimitiveOp::Concat` — in **verb bodies**. The test
`verbs::tests::verb_arena_contains_no_sigma_residuals` walks the
emitted `Term` arena and asserts none of those variants appear. This
is the load-bearing pure-prism invariant: from outside, `forward()`
is one structural inference per `JsonValue`; the ψ-pipeline maps
the typed JSON-value tagged bytes to the κ-label by structural
transformation, never by search.

### Iterative-resolution discipline — ADR-046 (resolver-body discipline)

ADR-046 records the discipline-scope boundary between ADR-035's
verb-body ψ-residuals discipline and the resolver-body
iterative-resolution discipline. σ-residuals are **admissible** in
resolver bodies; that is exactly where the canonical hash axis is
consumed in this crate. `AddressKInvariantResolver::resolve` invokes
`H::initial().fold_bytes(canonical).finalize()` once per ψ_9
dispatch — one σ-projection, deterministic in the typed input.

### Resolver tuple — ADR-036 (eight resolver categories)

`AddressResolverTuple<H>` declares all eight resolver-trait impls
(the seven non-terminal carriers plus the terminal
`KInvariantResolver`). Each non-terminal resolver threads the
canonical-form bytes forward unchanged through the structural
ψ-functor it realises; the terminal ψ_9 resolver materialises the
71-byte κ-label. The structural geometry (71 isolated vertices, no
higher simplices) flows uniformly through every stage's emitted
carrier.

### Typed-coordinate carriers — ADR-041

Each resolver consumes the wiki-specified typed-coordinate carrier
of its upstream ψ-stage (`SimplicialComplexBytes`,
`ChainComplexBytes`, …, `HomotopyGroupsBytes`) and emits its stage's
carrier. The catamorphism's per-stage type-checking is verified by
the workspace building cleanly — ADR-041 type aliases are pinned at
compile time by the resolver-trait impls.

### Algebraic-closure encoding of `AddressLabel` — ADR-024 (substrate closure) + ADR-026 (prism closure)

`AddressLabel::CONSTRAINTS` declares 71 disjoint
`ConstraintRef::Site` instances — one per wire-format-address byte.
The constraint nerve N(C) is 71 isolated vertices with no higher
simplices:

```
β_0 = 71,    β_k = 0 for k ≥ 1
χ(N(C)) = β_0 − β_1 + … = 71 = SITE_COUNT
```

This satisfies the wiki's canonical closure criterion at the
declaration level. A `const _: () = { … }` block in
`resolvers.rs` asserts the criterion at compile time; the runtime
resolver bodies emit carriers directly without re-validating.

### Seal regime — TC-02 (mechanism sealing) and TC-05 (replay)

`AddressLabel` reaches the typed-iso surface only through
`AddressModel::forward` per constraint TC-02 (no
`Grounded<AddressLabel>` construction outside the foundation
pipeline). The `AddressWitness` newtype carries the
foundation-sealed `Grounded<AddressLabel>` by borrow; downstream
consumers can replay it through `prism-verify` per TC-05 once
`prism` ships, producing a `Certified<GroundingCertificate>` without
re-invoking the deciders.

### SDK macros — ADR-020 (`prism_model!`), ADR-024 (`verb!`), ADR-027 (`output_shape!`), ADR-036 (`resolver!`)

The crate exercises the SDK's four primary macros end-to-end:

- `prism_model!` emits `AddressModel`'s `PrismModel<H, B, A, R>`
  impl with the `FoundationClosed` proof.
- `verb!` emits `address_inference`'s term arena.
- `output_shape!` emits `AddressLabel`'s sealed
  `ConstrainedTypeShape` + `GroundedShape` + `IntoBindingValue`
  impls.
- `resolver!` emits `AddressResolverTuple`'s eight
  `Has<Category>Resolver<H>` impls.

The crate compiles cleanly against `uor-foundation-sdk@=0.4.5` —
which itself validates that the SDK's emission machinery is correct
for the canonical k-invariants branch on a non-cryptographic domain.

## The ψ-chain

```text
JsonValue  (typed JSON value, structurally-tagged bytes)
   ↓ ψ_1 Nerve            (Constraints → SimplicialComplex)
   ↓ ψ_7 PostnikovTower   (SimplicialComplex → PostnikovTower)
   ↓ ψ_8 HomotopyGroups   (PostnikovTower → HomotopyGroups)
   ↓ ψ_9 KInvariants      (HomotopyGroups → KInvariants — JCS+NFC + SHA-256)
AddressLabel — the κ-label (71-byte `sha256:<64hex>`)
```

## File layout

```
crates/uor-addr-1/
├── Cargo.toml
├── examples/           — runnable use-case demos (just examples)
│   ├── address_value.rs
│   ├── dedupe_cache.rs
│   ├── typed_distinction.rs
│   └── replay_verification.rs
└── src/
    ├── lib.rs          — façade
    ├── model.rs        — AddressLabel, AddressModel (prism_model! with EmptyCommitment)
    ├── value.rs        — JsonValue typed input + tagged byte layout + parser + canonicalizer + canonicalize()
    ├── verbs.rs        — address_inference (the ψ-chain verb, verb!)
    ├── resolvers.rs    — eight ψ-stage resolvers (resolver!); ψ_9 owns canonicalization
    ├── pipeline.rs     — public entry point `address(bytes) → AddressOutcome`
    └── shapes/
        ├── mod.rs      — re-export of prism::crypto::Sha256Hasher (ADR-031)
        └── bounds.rs   — AddrBounds (HostBounds, ADR-037) + typed-input bounds
```

## Build

```bash
cargo build           # requires rustc >= 1.83 (uor-foundation@0.4 MSRV)
cargo test            # 75 passing tests + 2 ignored live tests
cargo clippy --all-targets -- -D warnings
```

`no_std`-compatible: `default-features = false` drops the `std`
feature flag; only `alloc` is required.
`#![forbid(unsafe_code)]` — zero unsafe blocks.

## Use-case examples

Four runnable examples cover the load-bearing use cases for
content-addressed JSON. Each panics on a failed invariant, so they
double as small executable conformance demos.

| Example                                                                            | Use case                                                                                                                     |
|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| [`address_value`](crates/uor-addr-1/examples/address_value.rs)                     | Mint a κ-label from raw JSON bytes — the minimal entry point                                                                |
| [`dedupe_cache`](crates/uor-addr-1/examples/dedupe_cache.rs)                       | Three syntactic variants (key order, whitespace, NFC) collapse to one address — a cache key / blob-store dedupe demonstration |
| [`typed_distinction`](crates/uor-addr-1/examples/typed_distinction.rs)             | `42` ≠ `"42"`, `null` ≠ `false`, `{} ≠ []` — typed-input distinction matters for signature payloads                          |
| [`replay_verification`](crates/uor-addr-1/examples/replay_verification.rs)         | TC-05 round-trip: a third party re-derives the κ-label's `Certified<GroundingCertificate>` without invoking the hash axis    |

```bash
cargo run -p uor-addr-1 --example address_value
cargo run -p uor-addr-1 --example dedupe_cache
cargo run -p uor-addr-1 --example typed_distinction
cargo run -p uor-addr-1 --example replay_verification

# Or run all four in sequence as part of the V&V gate:
just examples
```

## Verification & Validation

This crate ships a multi-axis V&V framework. The single normative
acceptance gate is:

```bash
just vv          # full V&V: fmt, lint, tests, conformance, analysis, replay, doc-check, Lean
```

The framework establishes correctness for **arbitrary use cases to
arbitrary precision** across four convergent surfaces — universal
quantification (Lean), cryptographic precision (SHA-256 sensitivity),
statistical precision (calibrated χ² at α = 0.001), and typed-input
structural distinction (`CT-T` case-tag pinning):

| Doc                                     | Role                                                                                                          |
|-----------------------------------------|---------------------------------------------------------------------------------------------------------------|
| [ARCHITECTURE.md](ARCHITECTURE.md)     | Normative pure-prism architectural specification — vocabulary used by the rest of the V&V                    |
| [CONFORMANCE.md](CONFORMANCE.md)       | Conformance contract — 60+ invariant IDs (CS / CD / CP / CN / CT / CL incl. CL-CT, CL-R) referenced by tests |
| [VERIFICATION.md](VERIFICATION.md)     | V&V index — maps `just vv` axes to conformance-class IDs                                                      |
| [ANALYSIS.md](ANALYSIS.md)             | Derivation of CP sample sizes, χ² thresholds, CT typed-input bounds, and "arbitrary precision" framing       |
| [uor-addr-1-lean/](uor-addr-1-lean/)   | Lean 4 library — 14 mechanised theorems against UOR-Framework's `UOR.Enforcement` shapes                      |

Lean proofs pin the universally-quantified claims: the κ-derivation
is a function of the digest (`CL-K01`), distinct digests yield
distinct κ-labels (`CL-K02`), the algebraic-closure
Euler-characteristic identity holds (`CL-A01`), the wire-format
width is structurally 71 bytes (`CL-W01`), hex encoding is injective
on `[0, 16)` (`CL-H01`), JSON cases carry pairwise-distinct
structural tags (`CL-CT01`), the parse-time depth bound is strict
(`CL-CT02`), the cost-model commitment is `EmptyCommitment`
(`CL-CT03`). Statistical axes (CP) cover what no finite proof can —
that the implementation's empirical distribution matches its
theoretical behaviour at 10⁶ samples and α = 10⁻³. Typed-input axes
(CT) pin the structural distinction the `JsonValue` shape buys:
`42` ≠ `"42"`, `null` ≠ `false`, NFC-equivalent strings collapse to
one κ-label, over-deep/over-wide inputs are rejected at parse.

## The architectural shape

Four commitments fix the implementation as a pure-Prism application
of the wiki specification:

1. **The hash function is a `Hasher` impl, not a custom axis.** Per
   ADR-007 the `Hasher` trait is pluggable; the foundation ships no
   concrete impl. `Sha256Hasher` here is the `prism::crypto`
   standard-library re-export (ADR-031).
2. **The canonicalisation step lives inside the typed-iso surface**
   per ADR-046. ψ_9's `AddressKInvariantResolver` decodes the
   structurally-tagged `JsonValue` bytes, applies JCS-RFC8785 +
   Unicode NFC, and feeds the canonical bytes to the hash axis —
   all inside the resolver body. The host boundary only parses raw
   bytes into the typed `JsonValue` (`JsonValue::parse`); it does
   no canonicalisation.
3. **`Term::AxisInvocation` is forbidden in the verb body** per
   ADR-035. The canonical hash axis is consumed inside the ψ_9
   resolver body via `H::initial().fold_bytes(canonical).finalize()`,
   generic over the model's `H: Hasher` selection. One σ-projection
   per `address()` call — deterministic in the typed input, no
   enumeration.
4. **The output shape is algebraic-closure encoded** per ADR-024 /
   ADR-026: 71 disjoint `Site` constraints satisfying
   `χ(N(C)) = 71 = SITE_COUNT`.

## Outstanding reconciliation

The canonical-form bytes this crate hashes (plain UTF-8 JCS-RFC8785
JSON bytes) differ structurally from what `uor-foundation@0.4`'s
`Element::canonical_bytes` docstring specifies — Amendment 43 §2:
`header(k) || le_bytes(x, k+1)`, the byte layout of a ring element
in R_n. Two parties speaking UOR-ADDR-1 (this crate) agree with each
other; a UOR-ADDR-1 party and a foundation-grounded party computing
`Element::digest` over the same JSON value disagree, even when both
name `sha256` as the algorithm.

Closing that gap is a [UOR Foundation](https://uor.foundation)
wiki / foundation decision (publish a canonical JSON-to-R_n ingress
producing Amendment-43-§2 canonical bytes, or document UOR-ADDR-1 as
a foundation-adjacent JSON-domain flavour with its own canonical
form). This crate is byte-identical to the
`mcp.uor.foundation/tools/encode_address` reference across every
input in its domain; the reconciliation is orthogonal to the Prism
grounding.

## License

Apache-2.0, matching `uor-foundation`.
