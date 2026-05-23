# UOR-ADDR — architecture

> Normative architectural specification. The vocabulary defined here is
> referenced by [CONFORMANCE.md](CONFORMANCE.md), [VERIFICATION.md](VERIFICATION.md),
> [ANALYSIS.md](ANALYSIS.md), and [STANDARDS.md](STANDARDS.md). Wiki ADRs
> cited below live at
> <https://github.com/UOR-Foundation/UOR-Framework/wiki>.

This document defines what UOR-ADDR is and what its role is in the
UOR-Framework wiki's conceptual model. The wiki is the normative source;
UOR-ADDR's architecture is determined by the framework's existing
commitments specialized to the typed content-addressing problem.

## What UOR-ADDR is

UOR-ADDR is the framework's **typed reference vocabulary** for typed
content-addressing. It is a body of prism_model declarations realizing
the framework's architecture for the content-addressing problem across
the formats that admit bounded recursive structural typing.

UOR-ADDR is not a separate informatical system at the wiki's conceptual
model layer. It is informatical content *inside* Prism — specifically,
a collection of `PrismModel` declarations whose `Input` types are typed
values of various recursively-grammared formats, whose `Output` type is
the shared κ-label output type `AddressLabel`, whose verb arena is the
common `address_inference` shape composing ψ_1 + ψ_7 + ψ_8 + ψ_9, and
whose typed-iso surface realizes the framework's "context-bijective"
typed-reference property at the standard-library layer.

UOR-ADDR's reach has three concentric layers:

- The **common architectural surface** — declarations that every
  format-specific addressing realization shares (the output shape, the
  verb arena, the resolver-tuple shape, the `AddressInput` trait, the
  cost-model commitment surface, the V&V framing, the TC-05 replay
  discipline, the example shape).

- The **format-specific realizations** — concrete `PrismModel`
  declarations for each format with bounded recursive structural
  typing (JSON under JCS-RFC8785, S-expression under Rivest's
  canonical form, XML under Canonical XML, ASN.1 under DER,
  code-module AST under format-specific canonicalization,
  ring-element under Amendment 43 §2's `Element::canonical_bytes`,
  and any other recursively-grammared format the framework supports).
  Each format-specific realization declares its typed input shape and
  the host-boundary parser that canonicalizes it into an ADR-060
  source-polymorphic carrier; it binds the single shared
  [`AddrBounds`](crates/uor-addr/src/bounds.rs) capacity profile and the
  single shared [`AddressResolverTuple`](crates/uor-addr/src/resolvers.rs)
  ψ-tower; and it ships its conformance corpus against the format's
  reference baselines and its V&V theorem instantiation.

- The **schema-pinned descendants** — concrete `PrismModel`
  declarations specializing a format-specific realization with
  domain-specific structural typing. A schema is a substitution-axis
  per ADR-007/030/052 declaring the typed feature hierarchy's
  domain-specific refinement.

UOR-ADDR's contribution is the realization of these layers across the
framework's supported formats and domain schemas.

## The schema-import discipline

UOR-ADDR follows UOR's substitution-axis discipline (ADR-007 /
ADR-030 / ADR-052) for schema-pinned descendants: **well-known
kinds and types map to existing standards** rather than UOR-native
inventions. The schemas shipped here import from the published
taxonomies that already exist for those types:

- Photo content-addressing imports [schema.org/Photograph](https://schema.org/Photograph).
- Document content-addressing imports [schema.org/Article](https://schema.org/Article) (and its 14 standard subtypes).
- Signed-software-attestation addressing imports
  [in-toto Statement v1](https://in-toto.io/Statement/v1) — the same
  envelope used by sigstore, SLSA, and the broader supply-chain
  ecosystem.

UOR-native primitives are reserved for low-level concerns where no
standard exists or where UOR's typed-iso surface explicitly defines
the canonical bytes: cryptographic primitives (the σ-projection
axis selection per ADR-047), codec layouts ([`crate::ring`]'s
Amendment 43 §2 form), and the [`crate::codemodule`] CCMAS
canonical AST. These are the **only** UOR-defined shapes; everything
else imports.

## What this crate ships

| Module | Layer |
|---|---|
| [`uor_addr::common`](crates/uor-addr/src/common.rs) | Common architectural surface — `AddressInput` trait |
| [`uor_addr::label`](crates/uor-addr/src/label.rs) | Common output shape — `AddressLabel` (71-Site SHA-256 specialization, IRI `…/sha256`) + `KappaLabel` byte carrier |
| [`uor_addr::outcome`](crates/uor-addr/src/outcome.rs) | Shared `AddressOutcome` / `AddressWitness` carriers — one architectural-surface output type re-exported by every realization |
| [`uor_addr::canonical`](crates/uor-addr/src/canonical/) | Prism-native canonical primitives — `nfc` (UAX #15 streaming normalizer, full UCD 15.1.0) + `hex` (lowercase-hex emit). `no_std` + `no_alloc`. |
| [`uor_addr::json`](crates/uor-addr/src/json/) | Format: JSON under JCS-RFC8785 + Unicode NFC |
| [`uor_addr::sexp`](crates/uor-addr/src/sexp/) | Format: S-expressions under Rivest 1997 canonical form |
| [`uor_addr::xml`](crates/uor-addr/src/xml/) | Format: XML under W3C Canonical XML 1.1 (subset) |
| [`uor_addr::asn1`](crates/uor-addr/src/asn1/) | Format: ASN.1 under ITU-T X.690 DER |
| [`uor_addr::ring`](crates/uor-addr/src/ring/) | Format: ring elements under UOR-Framework Amendment 43 §2 |
| [`uor_addr::codemodule`](crates/uor-addr/src/codemodule/) | Format: code-module AST under CCMAS |
| [`uor_addr::schema::photo`](crates/uor-addr/src/schema/photo.rs) | Schema-pinned descendant of `json` — imports [schema.org/Photograph](https://schema.org/Photograph) |
| [`uor_addr::schema::document`](crates/uor-addr/src/schema/document.rs) | Schema-pinned descendant of `json` — imports [schema.org/Article](https://schema.org/Article) |
| [`uor_addr::schema::codemodule_signed`](crates/uor-addr/src/schema/codemodule_signed.rs) | Schema-pinned descendant of `json` — imports [in-toto Statement v1](https://in-toto.io/Statement/v1) |
| [`uor_addr::variant::storage`](crates/uor-addr/src/variant/storage.rs) | Cost-model variant — `AndCommitment<EmptyCommitment, SingletonCommitment<LexicographicLessEqThreshold>>` |
| [`uor_addr::variant::signed`](crates/uor-addr/src/variant/signed.rs) | Cost-model variant — `SingletonCommitment<UltrametricCloseTo<2>>` |

In addition to the Rust crate, two FFI distribution targets ship the
same κ-derivation byte-for-byte to polyglot consumers:

| Crate | Layer |
|---|---|
| [`uor-addr-c`](crates/uor-addr-c/) | **Layer 1 — C ABI.** `extern "C"` exports per realization + `cbindgen`-generated header at [include/uor_addr.h](crates/uor-addr-c/include/uor_addr.h). Builds as `staticlib` / `cdylib` on hosted targets and as a static library on `thumbv7em-none-eabihf` for bare-metal embedded consumption. |
| [`uor-addr-wasm`](crates/uor-addr-wasm/) | **Layer 2b — WASM Component Model.** [wit-bindgen]-driven component declared by [wit/uor-addr.wit](crates/uor-addr-wasm/wit/uor-addr.wit). Builds to `wasm32-wasip2`; the emitted `.wasm` is consumable from JS (`jco transpile`), Python (`wasmtime-py`), Go (`wasmtime-go`), .NET (`Wasmtime.NET`), and any language with a wasm runtime. |

[wit-bindgen]: https://github.com/bytecodealliance/wit-bindgen

The `uor-addr` core is **`no_std` + `no_alloc`** by default (UOR
Foundation tooling contract). All canonicalization paths stream into
caller-provided slices; no allocator is touched. The `alloc` and
`std` features layer ergonomic convenience APIs on top of the
no_alloc core without affecting κ-label byte identity (CB-A03 +
CB-A04 in [CONFORMANCE.md](CONFORMANCE.md)).

See [STANDARDS.md](STANDARDS.md) for the complete index of
authoritative source references for every shipped realization.

## What the wiki's conceptual model says about UOR-ADDR

UOR-ADDR appears inside the wiki's conceptual model at three SD-level
positions, none of them as its own informatical system. Each position
is the framework's existing commitment to typed reference vocabulary
specialized to the content-addressing problem.

### Position at SD1 — Prism Structure

UOR-ADDR is informatical content of the Substrate's *Type Vocabulary*
attribute and the Runtime's *Sealed Type* attribute per SD1's
`exhibits` relations. The `AddressLabel` output type is a
`ConstrainedTypeShape` declared in the substrate's type vocabulary; it
is also a `GroundedShape` that the runtime's pipeline emits as a sealed
value. Format-specific typed input shapes (`JsonValue`, `SExprValue`)
are similarly substrate-vocabulary entries; they are
`ConstrainedTypeShape` impls. ADR-057's bounded recursion is enforced
directly by each format's parser via native stack-safety depth guards
(`MAX_JSON_DEPTH`, `MAX_XML_DEPTH`, `MAX_ASN1_DEPTH`, …), not by a
per-realization shape registry.

UOR-ADDR's existence at SD1 is the framework's commitment that
content-addressing's typed surface lives inside the substrate's
vocabulary — the addressing prism_models compose foundation primitives
through the standard-library Layer-3 sub-crate machinery per ADR-031.
There is no separate addressing substrate; the framework's substrate
vocabulary suffices.

### Position at SD2 — Principal Data Path

Every UOR-ADDR prism_model's `forward(input)` invocation is one
instantiation of SD2's four-stage pipeline: Grounding takes the
format's Host Bytes and yields a Datum of the format's typed input
shape; Compile Unit Construction wraps the Datum in a typed Compile
Unit; Validation confirms structural conformance to the format's typed
input shape's constraint geometry; Pipeline Run executes the
catamorphism over the `address_inference` verb arena, emitting the
κ-label as the Grounded Output plus the Trace.

SD2's cost-model commitments C1–C4 hold for every UOR-ADDR prism_model:

- **C1 (operational cost = declared bandwidth at equality)** — UOR-ADDR
  prism_models bind `C = EmptyCommitment` by default. Cost-model
  variants (`uor-addr-storage`) bind non-default `C` and C1's equality
  reading applies with the K-predicate bandwidth carried by their `C`
  selection.
- **C2 (zero runtime movement)** — every UOR-ADDR prism_model's
  `address_inference` verb arena composes only ψ-Term variants per
  ADR-035; the verb body is ψ-residual-clean per CS-V01 and passes
  the framework's `verb_arena_contains_no_sigma_residuals` test. Under
  ADR-060 canonicalization happens at **carrier production** (the input
  handle's `as_binding_value`) at the host boundary; the only sanctioned
  σ-residual is `AddressKInvariantResolver`'s ψ₉ fold of the carrier
  through `H` per ADR-046's scope.
- **C3 (structural inference)** — every UOR-ADDR `forward(input)`
  invocation is one structural emission of the κ-label; no
  host-side retry loop, no search over the typed-iso surface, no
  iterative refinement.
- **C4 (σ-projection axis qualification)** — every UOR-ADDR
  prism_model's `A` slot binds `prism::crypto::Sha256Hasher`
  (`H::IDENTIFIER = "sha256"`, `H::DIGEST_BYTES = 32`), an
  ADR-047-conforming axis.

### Position at SD3 — Verification

Every UOR-ADDR prism_model's emitted Trace is replayable through
`prism_verify::certify_from_trace`, yielding a `Certified<AddressLabel>`
whose κ-label is byte-identical to the original Grounded Output's
κ-label. The replay path is the anamorphism dual to SD2's catamorphism
per ADR-019.

### Position at SD5 — Distribute And Run

Every UOR-ADDR prism_model's Compiled Executable distributes through
SD5's Publication / Retrieval / Execution / Verification handoff path.

## Relationship to the wiki's three-layer structure

The framework declares a three-layer architecture at ADR-024 + ADR-031:
substrate (the closure-vocabulary layer hosted in `uor-foundation`),
standard library (the Layer-3 sub-crate ecosystem hosted in `prism`),
applications (downstream prism_model declarations consuming the
standard library).

UOR-ADDR sits at the **standard-library layer**. Per ADR-031's
demand-driven clause, the inclusion of UOR-ADDR into the prism standard
library is operational policy of the prism workspace's maintenance —
UOR-ADDR's architectural content does not change under inclusion; the
crate's module path changes from `uor-addr::*` to `prism::addr::*` and
the workspace home moves from the standalone repo to
`github.com/UOR-Foundation/prism`.

## What UOR-ADDR provides

### Common output shape

`AddressLabel` — a `ConstrainedTypeShape` parameterized at the
architectural level on the realization's selected hash axis `H: Hasher`,
realized concretely for `H = Sha256Hasher` (the first-published axis
selection across UOR-ADDR's realizations). The shape's `SITE_COUNT` is
structurally derived:

```text
SITE_COUNT = H::IDENTIFIER.len() + 1 + 2 × H::DIGEST_BYTES
```

For `H = Sha256Hasher` (`IDENTIFIER = "sha256"`, `DIGEST_BYTES = 32`),
the specialization is the **71-Site shape** emitting `sha256:<64hex>`
ASCII bytes. The content-addressed IRI is
`https://uor.foundation/addr/AddressLabel/sha256` — the IRI specializes
per axis (the framework's typed-iso commitment per ADR-001 + ADR-017).

The output space is **π_0-only** by structural property of the
σ-projection + hex-serialization composition; `χ(N(C)) = SITE_COUNT`;
`β_0 = SITE_COUNT`; `β_k = 0` for `k ≥ 1`.

### Common verb arena

```rust
verb! {
    pub fn address_inference(input: V) -> AddressLabel {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}
```

The SDK `verb!` macro emits a concrete declaration per realization
(one `verb!` invocation per format module, with the same body
structure and different input type `V`). The verb arena composes only
ψ-Term variants per ADR-035 — `Term::Nerve`, `Term::PostnikovTower`,
`Term::HomotopyGroups`, `Term::KInvariants` — plus the
`Term::Variable` for the input parameter and the implicit output
binding. The verb body emission contains no σ-residuals per CS-V01.

ψ_2..ψ_6 are off-path on the address-derivation transform per
ADR-036's `ResolverCategory` enumeration. Their resolver impls emit
the identity-shaped carrier; the verb arena does not invoke them.

### Common resolver tuple shape

`AddressResolverTuple<H>` is the **single, shared, format-independent**
resolver-tuple shape, parameterized on the hash axis `H` and bound by
every realization. Because canonicalization happens at carrier
production, no resolver holds format state. It declares the eight
resolver-trait impls per ADR-036's `ResolverCategory` enumeration:

- `AddressNerveResolver<H>` — ψ_1.
- `AddressChainComplexResolver<H>` — ψ_2. Off-path.
- `AddressHomologyGroupResolver<H>` — ψ_3. Off-path.
- `AddressCochainComplexResolver<H>` — ψ_5. Off-path.
- `AddressCohomologyGroupResolver<H>` — ψ_6. Off-path.
- `AddressPostnikovResolver<H>` — ψ_7.
- `AddressHomotopyGroupResolver<H>` — ψ_8.
- `AddressKInvariantResolver<H>` — ψ_9. Body: folds the incoming
  carrier (the canonical-form bytes the input already streamed via
  `as_binding_value`) through `H`'s σ-projection chunk-by-chunk with
  bounded resident memory (sanctioned σ-residual per ADR-046), then
  emits the κ-label as `<H::IDENTIFIER>:<digest_hex>` ASCII as an
  `Inline` `AddressLabel` carrier. It never materializes the carrier and
  imposes no size cap. ψ_1…ψ_8 thread the carrier through unchanged.

### AddressInput trait

```rust
pub trait AddressInput<'a>:
    ConstrainedTypeShape + IntoBindingValue<'a> + PartitionProductFields + Sized
{
}

impl<'a, T> AddressInput<'a> for T where
    T: ConstrainedTypeShape + IntoBindingValue<'a> + PartitionProductFields + Sized
{
}
```

Under ADR-060 `AddressInput` is a **blanket marker trait** composing
three substrate commitments — `ConstrainedTypeShape` for the constraint
geometry, `IntoBindingValue<'a>` whose `as_binding_value` produces the
canonical-form `TermValue` carrier (`Inline` / `Borrowed` / `Stream`),
and `PartitionProductFields` for the nerve resolver's field surface. It
has no `canonicalize_into` method, no `Registry` associated type, and no
`parse` method: each realization's host-boundary parser (its own
`parse`/`address` function) builds the handle and canonicalizes the
bytes *before* the typed-iso surface, and ψ₉ only folds. Every
format-specific typed input handle satisfies the marker automatically.

### Common cost-model commitment surface

The default cost-model commitment is `EmptyCommitment`. Every
format-specific realization that does not declare a non-default `C`
inherits the empty selection. The cost-model-bearing variants
([`uor_addr::variant::storage`] and future siblings) demonstrate the
architectural surface admits non-default
`C: TypedCommitment` parameterizations.

### Common PrismModel form

```rust
prism_model! {
    pub struct AddressModel;
    pub struct AddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        B,
        H,
        AddressResolverTuple<H>,
        C,
    > for AddressModel {
        type Input = V;
        type Output = AddressLabel;
        type Route = AddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            address_inference(input)
        }
    }
}
```

Each format-specific module declares its concrete `prism_model!`
invocation binding `V`, `B`, `H`, and `C` to its selections. The
framework's typed-iso commitment carries through each axis selection.

## V&V framework

UOR-ADDR provides the common V&V framing every realization
instantiates, with eight required axes (rustdoc, clippy, fmt-check,
test, conformance, replay, analysis, cross-validation) and a Lean
theorem corpus.

Format-specific realizations and schema-pinned descendants instantiate
the theorem corpus over their typed input shapes; cost-model-bearing
variants add their cost-model-specific theorems.

## TC-05 replay

UOR-ADDR provides the common TC-05 replay surface every realization
inherits — each `forward(input)` invocation's trace is replayable
through `prism_verify::certify_from_trace`, yielding a
`Certified<AddressLabel>` byte-identical to the original.

## Architectural commitments specialized to UOR-ADDR

Every UOR-ADDR realization upholds the framework commitments
specialized to the content-addressing problem:

- **ADR-001** typed-iso surface — the prism_model's input and output
  types are `ConstrainedTypeShape` impls with content-addressed IRIs
  per ADR-017.
- **ADR-006** bilateral compile-time UORassembly.
- **ADR-008** trace wire format.
- **ADR-017** canonical UOR-address mapping.
- **ADR-019** categorical structure (catamorphism / anamorphism /
  hylomorphism).
- **ADR-024** three-layer closure — UOR-ADDR sits at Layer 3
  (standard library).
- **ADR-031** standard-library Layer-3 sub-crate discipline.
- **ADR-035** resolver-bound ψ-pipeline — every realization composes
  ψ_1 + ψ_7 + ψ_8 + ψ_9 through `address_inference`; ψ_2..ψ_6 are
  off-path.
- **ADR-036** `ResolverCategory` enumeration — eight resolver-trait
  impls per `AddressResolverTuple<H>`.
- **ADR-046** resolver-body discipline scope — canonicalization lives
  inside `AddressKInvariantResolver`'s body.
- **ADR-047** σ-Projection Hardening Principle — every realization's
  selected `H: Hasher` axis satisfies U1–U6.
- **ADR-048** `C: TypedCommitment` cost-model surface.
- **ADR-054** fold-fusion principle.
- **ADR-057** bounded recursive structural typing — enforced by each
  format parser's native stack-safety depth guards (`MAX_JSON_DEPTH`,
  `MAX_XML_DEPTH`, `MAX_ASN1_DEPTH` = 1024; GGUF/ONNX subgraph depth =
  64), not a per-realization shape registry. (sexp / codemodule validate
  iteratively and need no depth guard.)
- **ADR-060** unbounded source-polymorphic carrier — a realization's
  canonical form flows through `run_route` as a `TermValue`
  (`Inline` / `Borrowed` / `Stream`) with no input size ceiling and no
  per-ψ-stage byte-width cap; the single shared `AddrBounds` carries only
  structural-count / trace caps.

## Architectural commitments that UOR-ADDR does not change

UOR-ADDR's existence does not require any wiki architectural
commitment to change. UOR-ADDR adds no new ADR. Its architecture is
the framework's existing commitments specialized to the typed
content-addressing problem.

## Container-format realizations — GGUF and ONNX

Two container-format realizations join the six recursively-grammared
realizations, validating tensor element types against the
`prism::tensor::dtype` alphabet (uor-prism-tensor 0.2.0):

| Module | Format |
|---|---|
| `uor_addr::gguf` | GGUF v3 under a flat Merkle-skeleton canonical form (header, key-sorted metadata KVs, name-sorted tensor info; variable-length leaves replaced by their streamed SHA-256 digest) |
| `uor_addr::onnx` | ONNX IR v13 under a flat Merkle-skeleton canonical form (Kahn-topological node ordering, name-sorted initializers / IO, typed-data→raw_data reduction, inline-recursed subgraphs; variable-length leaves digested) |

### Flat-skeleton design (ADR-060)

Under ADR-060 there is no fixed route-input buffer and no size cap, so
both realizations canonicalize to the **full flat skeleton** rather than
a two-level section commitment. The skeleton is emitted in a fixed total
order — header, then sorted KVs/metadata, then sorted tensors/nodes with
subgraphs recursed inline — and every variable-length leaf (a string, an
array payload, a tensor's data region) is replaced by its streamed
SHA-256 digest (`prism::crypto::Sha256Hasher`'s incremental
`fold_bytes`). The skeleton's size therefore grows only with the KV /
tensor / node **counts**, never with model size, while still binding
every weight byte into the κ-label. The full skeleton flows through the
pipeline as a `TermValue::Borrowed` carrier that ψ₉ folds — there is no
two-level commitment and no count / width cap. GGUF's
`CANONICAL_FORM_VERSION` is **2**. The exact byte layouts are documented
in the [`gguf::value`](crates/uor-addr/src/gguf/value.rs) and
[`onnx::value`](crates/uor-addr/src/onnx/value.rs) module headers.
