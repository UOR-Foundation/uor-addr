//! UOR-ADDR's **common architectural surface** — the declarations every
//! format-specific addressing realization shares (ARCHITECTURE.md
//! "What UOR-ADDR provides" §§ Common output shape, Common verb arena,
//! Common resolver tuple shape, AddressInput trait, Common cost-model
//! commitment surface, Common PrismModel form).
//!
//! UOR-ADDR's reach has three concentric layers per the architecture
//! document:
//!
//! - **Common architectural surface** (this module) — the typed
//!   reference vocabulary every realization shares: the [`AddressInput`]
//!   trait + the [`AddressLabel`] output shape + the
//!   [`AddressResolverTuple`] eight-resolver shape + the
//!   [`address_inference`] verb body. Wiki ADR-001 + ADR-017 + ADR-035
//!   + ADR-036.
//!
//! - **Format-specific realizations** (sibling modules in this crate
//!   for the JSON realization; sibling crates for other formats per
//!   the demand-driven inclusion clause of ADR-031). Each realization
//!   names a typed-input shape `V: AddressInput` plus a `HostBounds`
//!   profile plus the `register_shape!` invocation that publishes the
//!   shape's grammar cases into the foundation's shape-IRI registry per
//!   ADR-057.
//!
//! - **Schema-pinned descendants** (e.g. `uor-addr-photo`,
//!   `uor-addr-document`, `uor-addr-codemodule-signed` — separate
//!   crates per the architecture). Each descendant specializes a
//!   format-specific realization with domain-specific structural
//!   typing (ADR-007 + ADR-030 + ADR-052 substitution-axis selection).
//!
//! ## What the common surface guarantees
//!
//! - **One verb arena across formats.** [`address_inference`] composes
//!   only `Term::Nerve / PostnikovTower / HomotopyGroups / KInvariants`
//!   per the wiki's canonical k-invariants branch (ADR-035). Off-path
//!   `Term::ChainComplex / HomologyGroups / CochainComplex /
//!   CohomologyGroups` are populated for `ResolverTuple` completeness
//!   (ADR-036) but never invoked.
//!
//! - **σ-residual-clean verb body (ADR-035 / CS-V01).** The verb body
//!   emission carries no `FirstAdmit / AxisInvocation / Le / Concat /
//!   Lt / Ge / Gt` operations. ADR-046's resolver-body
//!   iterative-resolution discipline admits the sole σ-projection (the
//!   hash-axis invocation) at the ψ_9 resolver — not in the verb
//!   composition.
//!
//! - **Substitution-axis selection across hash axes (ADR-047).** Every
//!   realization binds a concrete `H: Hasher` axis from
//!   [`prism::crypto`]. The default selection across UOR-ADDR's
//!   first-published realizations is [`prism::crypto::Sha256Hasher`].
//!   The architecture admits any Hardening-Principle-conforming axis
//!   (`Sha512Hasher`, `Blake3Hasher`, …) through the same surface
//!   without modification.
//!
//! - **TC-05 replay surface.** Every realization's `forward(input)`
//!   yields a Trace replayable through `prism_verify::certify_from_trace`,
//!   producing a `Certified<AddressLabel>` byte-identical to the
//!   original Grounded Output. Cross-axis replay fails closed (the
//!   verifier's Hasher Selection out-of-band per TC-05 must match the
//!   Hasher Identifier embedded in the Trace).
//!
//! ## What this module **re-exports**
//!
//! The common surface is a thin layer above the format-specific
//! implementations. For the JSON realization shipped in this crate,
//! the concrete types are declared in [`crate::json::model`],
//! [`crate::json::resolvers`], and [`crate::json::verbs`]; the trait
//! [`AddressInput`] is declared here and implemented in
//! [`crate::json::value`] (`impl AddressInput for JsonValue`).
//!
//! Downstream format crates that consume UOR-ADDR through the
//! standard-library Layer-3 sub-crate machinery (per ADR-031's
//! demand-driven clause) re-export this same surface — the
//! `prism::addr::*` paths under standard-library inclusion mirror
//! `uor_addr::common::*`. UOR-ADDR's architectural content does
//! not change under inclusion.

use prism::pipeline::{
    ConstrainedTypeShape, IntoBindingValue, ShapeRegistryProvider, ShapeViolation,
};

/// **The common input trait — every format-specific UOR-ADDR
/// realization implements this trait on its typed-input shape.**
///
/// `AddressInput` composes three substrate commitments — the
/// `ConstrainedTypeShape` constraint geometry per ADR-001 + ADR-017,
/// the `IntoBindingValue` typed-input serialization per ADR-023, the
/// `Registry` associated type for the application's ADR-057
/// recursive-shape registry — plus two methods supplying the
/// format's canonicalization and parsing.
///
/// The architecture's commitment is: every format with bounded
/// recursive structural typing admits a `V: AddressInput` impl that
/// reuses the common verb arena ([`address_inference`]), the common
/// resolver-tuple shape ([`AddressResolverTuple`]), and the common
/// output shape ([`AddressLabel`]) — wiki ADR-031 "domain-neutral-
/// within-domain realization" applied to content-addressing.
///
/// # Wiki commitments enforced by this trait
///
/// - **ADR-001 + ADR-017 typed-iso surface** — the `Self` carrier is
///   a `ConstrainedTypeShape` with a content-addressed IRI; the
///   realization's κ-label IRI identifies the typed reference
///   unambiguously within the realization's typed environment.
/// - **ADR-023 typed-iso input serialization** — `Self` flows through
///   the catamorphism's binding-table form via `IntoBindingValue`
///   without bypassing the typed-iso surface.
/// - **ADR-057 bounded recursive structural typing** — the `Registry`
///   associated type publishes the realization's registered grammar
///   cases for ψ_1's registry-aware nerve-expansion path
///   (`primitive_simplicial_nerve_betti_in::<Self, Self::Registry>` /
///   `expand_constraints_in::<Self::Registry>`).
/// - **ADR-046 resolver-body discipline scope** — the
///   `canonicalize_into` method body lives **inside the ψ_9 resolver
///   body** (per [`crate::json::resolvers::AddressKInvariantResolver`]'s
///   sanctioned σ-residual scope). The trait method itself names the
///   function pointer the resolver dispatches through; the verb body
///   never invokes `canonicalize_into` directly.
/// - **Format-specific canonicalization byte-output discipline** —
///   `canonicalize_into` writes byte-output-equivalent to the
///   format's canonical-form specification (JCS-RFC8785 + NFC for the
///   JSON realization; XML-C14N for the XML realization; the
///   format's canonical-form for any other realization).
///
/// # Method contract
///
/// - [`parse`](AddressInput::parse) consumes raw bytes, validates
///   every typed-input bound declared in the realization's
///   `HostBounds` profile, and emits a typed `Self`. The parser is
///   the only σ-projection that runs **before** the typed-iso
///   surface; it is a host-boundary helper, not part of the
///   ψ-pipeline transform per wiki ADR-035.
///
/// - [`canonicalize_into`](AddressInput::canonicalize_into) walks the
///   parser-emitted byte sequence (the `IntoBindingValue` form the
///   catamorphism threads through every ψ-stage carrier) and emits
///   the canonical-form byte sequence the σ-projection consumes,
///   into the caller-supplied `out` slice; returns the number of
///   bytes written. Called by [`crate::json::resolvers::AddressKInvariantResolver`]
///   inside its resolver body per ADR-046.
pub trait AddressInput: ConstrainedTypeShape + IntoBindingValue + Sized {
    /// **The realization's application shape-registry**
    /// (ADR-057 + the `register_shape!` SDK macro). Consumed by
    /// `AddressNerveResolver`'s registry-aware nerve-expansion path
    /// (`primitive_simplicial_nerve_betti_in::<Self, Self::Registry>` /
    /// `expand_constraints_in::<Self::Registry>`).
    ///
    /// For format-specific realizations whose typed-input shape carries
    /// `ConstraintRef::Recurse` entries (the partition_coproduct +
    /// recurse-operand grammar), `Registry` is the marker type emitted
    /// by `register_shape!` declaring the realization's registered
    /// grammar cases.
    ///
    /// For realizations whose typed-input shape carries no `Recurse`
    /// entries, `Registry` defaults to
    /// `prism::pipeline::shape_iri_registry::EmptyShapeRegistry`.
    type Registry: ShapeRegistryProvider;

    /// **Format canonicalization** — walks the parser-emitted byte
    /// sequence (the structurally-tagged byte serialization carried
    /// through the catamorphism's binding-table form per ADR-023) and
    /// emits the canonical-form byte sequence the σ-projection
    /// consumes.
    ///
    /// The byte-output discipline is pinned by the format's
    /// canonical-form specification:
    ///
    /// - JSON realization — JCS-RFC8785 §3 + Unicode NFC per
    ///   [`crate::json::value::canonicalize`].
    /// - XML realization — Canonical XML 1.1 / XML-C14N2.
    /// - S-expression realization — the format's canonical form.
    /// - ASN.1 realization — DER (Distinguished Encoding Rules).
    /// - Ring-element realization — Amendment 43 §2's
    ///   `Element::canonical_bytes`.
    /// - Code-module AST realization — the format-specific canonical
    ///   AST serialization.
    ///
    /// # Errors
    ///
    /// Returns a `ShapeViolation` if the parser-emitted bytes are
    /// truncated, carry an unknown structural tag, or violate the
    /// realization's typed-input grammar. Unreachable for
    /// `Self` instances constructed through [`Self::parse`] — the
    /// parser emits well-formed bytes by construction; the guard is
    /// defensive against substrate-corrupted inputs.
    ///
    /// # Buffer sizing
    ///
    /// The `out` slice must be large enough to hold the
    /// canonical-form bytes. For the JSON realization, this is
    /// bounded by [`crate::json::JSON_VALUE_MAX_BYTES`] (JCS+NFC
    /// canonicalization is byte-output-bounded by the input typed
    /// width). The resolver allocates the buffer at the
    /// ψ_9-resolver-body layer per ADR-046.
    fn canonicalize_into(parser_emitted: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation>;

    /// **Format parser** — walks an untyped byte sequence and emits
    /// a typed instance of `Self`. Enforces the realization's
    /// typed-input bounds at the parser layer; the constraint-geometry
    /// typing in `Self::CONSTRAINTS` reaches the same bounds for the
    /// post-typed Datum.
    ///
    /// This is the host-boundary parser per SD2's Grounding stage —
    /// it runs **before** the typed-iso surface, not as part of the
    /// ψ-pipeline transform. The host-boundary externality for
    /// content-addressing is empty (no `PipelineFailure::DidNotAdmit`
    /// admission filter): every well-formed parsed `Self` yields
    /// exactly one κ-label.
    ///
    /// # Errors
    ///
    /// Returns a `ShapeViolation` carrying the violated
    /// typed-input-bound IRI. The IRI's `constraint_iri` field names
    /// the bound (e.g.
    /// `https://uor.foundation/addr/JsonValue/depthBound`,
    /// `https://uor.foundation/addr/JsonValue/stringWidth`, …) so
    /// downstream consumers can surface the specific violation
    /// without parsing the message text.
    fn parse(input: &[u8]) -> Result<Self, ShapeViolation>;
}

/// **The common output shape across realizations** — the κ-label.
///
/// The κ-label's wire-format byte layout follows the architecture
/// document's structural formula:
///
/// ```text
/// SITE_COUNT = H::IDENTIFIER.len() + 1 + 2 × H::DIGEST_BYTES
/// ```
///
/// For UOR-ADDR's first-published realizations (which bind
/// `H = prism::crypto::Sha256Hasher` per ADR-047), the
/// specialization is the **71-Site shape** declared as
/// [`crate::AddressLabel`]:
///
/// - 7 bytes for `H::IDENTIFIER = b"sha256"` + the `:` separator
///   (sites 0..7),
/// - 64 bytes for the lowercase-hex serialization of the σ-projection's
///   32-byte digest (sites 7..71),
/// - total = 71 ASCII bytes — the wire-format `sha256:<64hex>` width.
///
/// The IRI is `https://uor.foundation/addr/AddressLabel`. The shape
/// carries 71 disjoint `ConstraintRef::Site` constraints — one per
/// wire-format byte position. The output space is **π_0-only** by
/// structural property of the σ-projection + hex-serialization
/// composition: `χ(N(C)) = SITE_COUNT`; `β_0 = SITE_COUNT`;
/// `β_k = 0` for `k ≥ 1`. The wiki's iterative-resolution discipline
/// converges in 0 residual rank at ψ_9 because all 71 sites pin
/// simultaneously to the κ-derivation.
///
/// Per the architecture document, alternate-hash-axis specializations
/// (e.g. `AddressLabel<Sha512Hasher>` with `SITE_COUNT = 6 + 1 + 128 =
/// 135`, `AddressLabel<Blake3Hasher>` with the axis's identifier +
/// digest width) are conforming UOR-ADDR realizations against ADR-047's
/// Hardening Principle. The architecture admits the parameterization
/// without modification at the structural surface; each realization
/// publishes its specialization through a distinct shape IRI
/// (e.g. `https://uor.foundation/addr/AddressLabel/sha512`) so that
/// realizations binding different `H` selections produce distinct typed
/// reference vocabularies at the IRI level (the framework's typed-iso
/// commitment per ADR-001 + ADR-017).
///
/// This crate publishes the `Sha256Hasher` specialization as
/// [`crate::AddressLabel`]; downstream realizations binding a
/// different conforming axis declare their own specialization
/// against the same architectural surface.
pub use crate::label::AddressLabel;

/// **The common verb arena across realizations** — the canonical
/// k-invariants branch of the ψ-pipeline (ADR-035).
///
/// ```text
/// V (typed input — V: AddressInput)
///    ↓ ψ_1 Nerve            (Constraints → SimplicialComplex)
///    ↓ ψ_7 PostnikovTower   (SimplicialComplex → PostnikovTower)
///    ↓ ψ_8 HomotopyGroups   (PostnikovTower → HomotopyGroups)
///    ↓ ψ_9 KInvariants      (HomotopyGroups → KInvariants)
/// AddressLabel — the κ-label
/// ```
///
/// The body is the wiki's **canonical k-invariants branch**: the
/// longest discriminating ψ-chain that reaches `KInvariants` through
/// `Nerve → PostnikovTower → HomotopyGroups`. Off-path resolver
/// positions (`ChainComplex`, `HomologyGroups`, `CochainComplex`,
/// `CohomologyGroups`) are populated for `ResolverTuple` completeness
/// (ADR-036) but never appear in the verb's term arena.
///
/// This re-export points to the format-specific verb declared in
/// [`crate::json::verbs`]. For format-specific realizations whose
/// verb body is identical at the term-arena level, the term arena
/// is reused. Each format-specific crate publishing
/// `pub fn address_inference<V: AddressInput>(input: V) -> AddressLabel`
/// emits the same `Term::Nerve / PostnikovTower / HomotopyGroups /
/// KInvariants` chain — only the `V` type and its `Registry`
/// associated type vary across realizations.
pub use crate::json::verbs::address_inference;

/// **The common resolver-tuple shape across realizations** — the
/// eight resolver-trait impls per ADR-036's `ResolverCategory`
/// enumeration.
///
/// Re-exported here as the common architectural surface; the
/// format-specific generic type is declared in [`crate::json::resolvers`].
///
/// - `AddressNerveResolver<H>` — ψ_1. Builds N(C) for the
///   realization's constraint set; for the algebraic-closure
///   shape of [`AddressLabel`], N(C) is 71 isolated vertices.
/// - `AddressChainComplexResolver<H>` — ψ_2. Off-path; threads the
///   carrier identity through.
/// - `AddressHomologyGroupResolver<H>` — ψ_3. Off-path; threads
///   identity.
/// - `AddressCochainComplexResolver<H>` — ψ_5. Off-path; threads
///   identity.
/// - `AddressCohomologyGroupResolver<H>` — ψ_6. Off-path; threads
///   identity.
/// - `AddressPostnikovResolver<H>` — ψ_7. On-path; pass-through to
///   ψ_8.
/// - `AddressHomotopyGroupResolver<H>` — ψ_8. On-path; pass-through
///   to ψ_9.
/// - `AddressKInvariantResolver<H>` — ψ_9. **The only resolver
///   that invokes the format's canonicalization** (via
///   `V::canonicalize_into`, per ADR-046's resolver-body
///   iterative-resolution discipline) and the hash axis (one
///   σ-projection per `forward()` invocation).
///
/// The tuple is parameterized on `H: Hasher` only at the type level;
/// the dispatch to `V::canonicalize_into` lives inside the
/// ψ_9-resolver body by reference to the format-specific module
/// supplying the `AddressInput` impl.
pub use crate::json::resolvers::AddressResolverTuple;

/// **The common cost-model commitment surface across realizations**.
///
/// UOR-ADDR's default cost-model commitment per ADR-048 is
/// `EmptyCommitment` — every format-specific realization that does
/// not declare a non-default `C` inherits the empty selection. The
/// κ-derivation surface carries no auxiliary cost-model dimension
/// beyond the σ-projection itself; one `forward(input)` invocation
/// yields a κ-label unconditionally (C3 structural inference).
///
/// Non-default cost-model variants are part of UOR-ADDR's
/// architectural surface — `uor-addr-storage` binds
/// `C = AndCommitment<EmptyCommitment, PayloadCommitment<K>>` per
/// QS-06, `uor-addr-signed` binds
/// `C = SingletonCommitment<SignatureCommitmentPredicate>`, and
/// further variants land as separate crates following the same
/// discipline.
pub use prism::pipeline::EmptyCommitment;
