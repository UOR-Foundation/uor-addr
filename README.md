# uor-addr-1

> Pure-UOR refactor of Maura Clark's [`uor-addr-1`][upstream] proposal —
> JSON content addressing as a Prism application of the UOR Foundation,
> grounded against the wiki specification at
> <https://github.com/UOR-Foundation/UOR-Framework/wiki>.

[upstream]: https://github.com/maurathat/uor-addr-1

## What this crate is

A `PrismModel<HostTypes, HostBounds, Hasher, ResolverTuple>` whose
ψ-pipeline derives a 71-byte `sha256:<64hex>` content address from a
canonical-form (JCS-RFC8785 + Unicode NFC) JSON byte sequence:

```rust
use uor_addr_1::address;

let outcome = address(br#"{"foo": "bar"}"#).unwrap();
assert_eq!(
    outcome.address,
    "sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b"
);
```

The 12 byte-identity fixtures Maura Clark harvested from
`mcp.uor.foundation/tools/encode_address` (mcp-uor-server v0.2.1,
algorithm `uor-sha256-v1`, canonicalisation `jcs-rfc8785+nfc`) are
reproduced verbatim through this pipeline — see
`tests/byte_identity.rs`.

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

`Sha256Hasher` is a `Hasher<32>` impl satisfying the four ADR-007
trait laws: width-in-budget
(`32 ∈ [FINGERPRINT_MIN_BYTES, FINGERPRINT_MAX_BYTES]`), determinism,
sensitivity, no interior mutability. The body is the
foundation-recommended-secondary algorithm per
`Element::digest_algorithm` (BLAKE3 primary, SHA-256 secondary).
Implemented in pure Rust against FIPS-180-4; pinned by
`shapes::hasher::tests::sha256_hasher_*`.

### Verb — ADR-024 (implementation closure) + ADR-035 (canonical k-invariants branch)

The verb body is exactly the wiki's canonical k-invariants branch:

```rust
verb! {
    pub fn address_inference(input: JsonInput) -> AddressLabel {
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
is one structural inference per `JsonInput`; the ψ-pipeline maps
typed canonical-form bytes to the κ-label by structural
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
JsonInput  (canonical-form JCS+NFC bytes)
   ↓ ψ_1 Nerve            (Constraints → SimplicialComplex)
   ↓ ψ_7 PostnikovTower   (SimplicialComplex → PostnikovTower)
   ↓ ψ_8 HomotopyGroups   (PostnikovTower → HomotopyGroups)
   ↓ ψ_9 KInvariants      (HomotopyGroups → KInvariants)
AddressLabel — the κ-label (71-byte `sha256:<64hex>`)
```

## File layout

```
crates/uor-addr-1/
├── Cargo.toml
└── src/
    ├── lib.rs           — façade
    ├── model.rs         — JsonInput, AddressLabel, AddressModel (prism_model!)
    ├── verbs.rs         — address_inference (the ψ-chain verb, verb!)
    ├── resolvers.rs     — eight ψ-stage resolvers (resolver!)
    ├── pipeline.rs      — public entry point `address(bytes) → AddressOutcome`
    ├── shapes/
    │   ├── mod.rs
    │   ├── bounds.rs    — AddrBounds (HostBounds, ADR-037)
    │   └── hasher.rs    — Sha256Hasher (Hasher, ADR-007/ADR-010)
    └── ops/
        ├── mod.rs
        ├── sha256.rs    — pure-Rust FIPS-180-4 SHA-256
        └── canonicalize.rs — JCS+NFC host-boundary transform
```

## Build

```bash
cargo build           # requires rustc >= 1.83 (uor-foundation@0.4.5 MSRV)
cargo test            # 31 tests across lib + integration
cargo clippy --all-targets -- -D warnings
```

`no_std`-compatible: `default-features = false` drops the `std`
feature flag; only `alloc` is required.
`#![forbid(unsafe_code)]` — zero unsafe blocks.

## What changed from the upstream proposal

The earlier `uor-addr-1` framing — `sha256:<64hex>` as a parallel
application-layer primitive distinct from `uor-foundation`'s
internal fingerprints — was a misreading of the foundation surface.
The correct framing, established directly by the wiki:

1. **The hash function is a `Hasher` impl, not a custom axis.** Per
   ADR-007 the `Hasher` trait is pluggable; the foundation ships no
   concrete impl. `Sha256Hasher` here is one valid selection.
2. **The canonicalisation step is a host-boundary transform, not a
   ψ-stage.** `ops::canonicalize::jcs_nfc` runs at the host
   boundary before `JsonInput::new`; it is not part of the
   typed-iso surface.
3. **`Term::AxisInvocation` is forbidden in the verb body** per
   ADR-035. The canonical hash axis is consumed inside the ψ_9
   resolver body via `H::initial().fold_bytes(bytes).finalize()`,
   generic over the model's `H: Hasher` selection. One σ-projection
   per `address()` call — deterministic in the typed input, no
   enumeration.
4. **The output shape is algebraic-closure encoded** per ADR-024 /
   ADR-026: 71 disjoint `Site` constraints satisfying
   `χ(N(C)) = 71 = SITE_COUNT`.

## Outstanding reconciliation

The canonical-form bytes this crate hashes (plain UTF-8 JCS-RFC8785
JSON bytes) differ structurally from what `uor-foundation@0.4.5`'s
`Element::canonical_bytes` docstring specifies — Amendment 43 §2:
`header(k) || le_bytes(x, k+1)`, the byte layout of a ring element
in R_n. Two parties speaking UOR-ADDR-1 (this crate) agree with each
other; a UOR-ADDR-1 party and a foundation-grounded party computing
`Element::digest` over the same JSON value disagree, even when both
name `sha256` as the algorithm.

Closing that gap is an upstream wiki/foundation decision (publish a
canonical JSON-to-R_n ingress producing Amendment-43-§2 canonical
bytes, or document UOR-ADDR-1 as a foundation-adjacent JSON-domain
flavour with its own canonical form). This crate is byte-identical
to Maura's reference; the reconciliation is orthogonal to the prism
grounding.

## License

Apache-2.0, matching `uor-foundation`.
