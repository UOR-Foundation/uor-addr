//! `uor-addr`'s public entry point — the ψ-pipeline content-address
//! inference over the typed [`JsonValue`] input.
//!
//! 1. The host-boundary parser [`crate::JsonValue::parse`] consumes
//!    raw JSON bytes, builds the structurally-tagged byte form, and
//!    validates every typed-input bound declared in
//!    [`crate::json::shapes::bounds`]. The output is a typed `JsonValue` —
//!    no canonicalisation has happened yet.
//! 2. [`AddressModel`]'s `forward()` (from the foundation `PrismModel`
//!    trait) invokes the ψ-chain verb
//!    ([`crate::json::verbs::address_inference`]) end-to-end via foundation's
//!    catamorphism. The catamorphism dispatches each resolver-bound
//!    ψ-Term through [`crate::json::resolvers::AddressResolverTuple`].
//! 3. The terminal ψ_9 resolver
//!    ([`crate::json::resolvers::AddressKInvariantResolver`]) decodes the
//!    structurally-tagged bytes, performs JCS-RFC8785 + Unicode NFC
//!    canonicalisation **inside the typed-iso surface** per ADR-046's
//!    resolver-body iterative-resolution discipline, projects through
//!    the canonical hash axis (one σ-projection — deterministic, no
//!    enumeration), and structurally κ-derives the 71-byte
//!    wire-format address.
//! 4. [`address`] returns the 71-byte address — well-formed
//!    `JsonValue` always yields exactly one κ-label.
//!
//! Per wiki ADR-039 (verdict realisation), the address-derivation
//! verdict envelope is **total**: every well-formed `JsonValue`
//! produces an `Ok(AddressOutcome)` carrying the κ-label, because the
//! constraint nerve N(C) is non-empty for every input. There is no
//! `PipelineFailure::DidNotAdmit`-style admission filter at the host
//! boundary; the κ-label IS the address. The defensive
//! [`AddressFailure::PipelineFailure`] variant is reserved for
//! substrate-level shape violations that ADR-039 classifies as
//! impossibility certificates — unreachable in normal flow.

use prism::pipeline::{EmptyCommitment, PrismModel};
use prism::vocabulary::DefaultHostTypes;

use crate::json::model::AddressModel;
use crate::json::resolvers::AddressResolverTuple;
use crate::json::shapes::bounds::AddrBounds;
use crate::json::shapes::Sha256Hasher;
use crate::json::value::JsonValue;
use crate::label::KappaLabel;
pub use crate::outcome::{AddressOutcome, AddressWitness};

// Architectural-surface output carrier — declared once in
// [`crate::outcome`] and re-exported here so the historical
// `uor_addr::json::AddressOutcome` import path resolves to the same
// shared type.

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not valid UTF-8 JSON.
    InvalidJson,
    /// The parsed JSON value's structurally-tagged byte serialization
    /// (or one of its sub-bounds — depth, string width, number width,
    /// object key count, array element count) exceeds a typed-input
    /// ceiling declared in [`crate::json::shapes::bounds`].
    TooLarge,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs — the
    /// ψ-pipeline is total over the typed input surface.
    PipelineFailure,
}

/// **uor-addr's public entry point** — one ψ-pipeline content-address
/// inference per JSON input.
///
/// 1. [`JsonValue::parse`] parses `input_bytes` and validates every
///    typed-input bound (depth, per-string/number width, container
///    arity, total serialized size).
/// 2. Invokes [`AddressModel`]'s `forward()` (from the foundation
///    `PrismModel` trait) which always produces a κ-label for
///    well-formed inputs.
/// 3. Returns the [`AddressOutcome`] carrying the κ-label.
///
/// JCS-RFC8785 + Unicode NFC canonicalisation runs **inside** the
/// ψ_9 resolver body — it is part of the typed-iso surface, not a
/// host-boundary preprocessing step.
///
/// # Errors
///
/// - [`AddressFailure::InvalidJson`] — `input_bytes` is not valid UTF-8 JSON.
/// - [`AddressFailure::TooLarge`] — the parsed JSON value exceeds a
///   typed-input ceiling (depth, string/number width, container
///   arity, or total serialized byte width).
/// - [`AddressFailure::PipelineFailure`] — defensive variant for
///   substrate-level shape violations; unreachable in normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    let json_value = JsonValue::parse(input_bytes).map_err(|violation| {
        // The `validUtf8Json` violation is the InvalidJson surface; every
        // other typed-input violation collapses to TooLarge so the public
        // API stays a clean three-state enum.
        if violation.constraint_iri.ends_with("/validUtf8Json") {
            AddressFailure::InvalidJson
        } else {
            AddressFailure::TooLarge
        }
    })?;

    let grounded = <AddressModel as PrismModel<
        DefaultHostTypes,
        AddrBounds,
        Sha256Hasher,
        AddressResolverTuple<Sha256Hasher>,
        EmptyCommitment,
    >>::forward(json_value)
    .map_err(|_| AddressFailure::PipelineFailure)?;

    let address = KappaLabel::from_bytes(grounded.output_bytes())
        .map_err(|_| AddressFailure::PipelineFailure)?;

    Ok(AddressOutcome {
        witness: AddressWitness::new(grounded),
        address,
    })
}
