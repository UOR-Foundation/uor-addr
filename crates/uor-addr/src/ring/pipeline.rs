//! `ring::address` — the ring-element realization's public entry
//! point. Mirrors [`crate::json::pipeline::address`] for
//! `V = RingElement`.
//!
//! 1. The host-boundary parser
//!    [`crate::ring::RingElement::parse`] consumes raw canonical-bytes
//!    bytes (Rivest canonical or token-list sugar), builds the
//!    structurally-tagged byte form, and validates every typed-input
//!    bound declared in [`crate::ring::shapes::bounds`].
//! 2. [`AddressModel`]'s `forward()` invokes the ψ-chain verb
//!    [`crate::ring::address_inference`] end-to-end through
//!    foundation's catamorphism, dispatching each ψ-Term through
//!    [`crate::ring::AddressResolverTuple`].
//! 3. The terminal ψ_9 resolver
//!    ([`crate::ring::AddressKInvariantResolver`]) decodes the
//!    structurally-tagged bytes, performs Amendment 43 §2
//!    canonicalization inside the typed-iso surface per ADR-046's
//!    resolver-body iterative-resolution discipline, and projects
//!    through the canonical hash axis (`H = Sha256Hasher`) to
//!    materialize the 71-byte κ-label.
//! 4. [`address`] returns the κ-label — every well-formed
//!    [`RingElement`] always yields exactly one κ-label.

use prism::pipeline::{EmptyCommitment, PrismModel};
use prism::vocabulary::DefaultHostTypes;

use crate::label::KappaLabel;
pub use crate::outcome::{AddressOutcome, AddressWitness};
use crate::ring::model::AddressModel;
use crate::ring::resolvers::AddressResolverTuple;
use crate::ring::shapes::bounds::RingAddrBounds;
use crate::ring::value::RingElement;

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not a valid Amendment 43 canonical bytes.
    InvalidRingElement,
    /// The parsed value exceeds a typed-input ceiling (depth, atom
    /// width, element count, or total serialized byte width).
    TooLarge,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

/// **uor-addr's ring-element entry point** — one ψ-pipeline
/// content-address inference per ring-element input.
///
/// # Errors
///
/// - [`AddressFailure::InvalidRingElement`] — `input_bytes` is not a valid
///   Amendment 43 canonical bytes.
/// - [`AddressFailure::TooLarge`] — the parsed value exceeds a
///   typed-input ceiling.
/// - [`AddressFailure::PipelineFailure`] — defensive variant for
///   substrate-level shape violations; unreachable in normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    let element = RingElement::parse(input_bytes).map_err(|violation| {
        if violation.constraint_iri.ends_with("/validCanonicalBytes") {
            AddressFailure::InvalidRingElement
        } else {
            AddressFailure::TooLarge
        }
    })?;

    let grounded = <AddressModel as PrismModel<
        DefaultHostTypes,
        RingAddrBounds,
        prism::crypto::Sha256Hasher,
        AddressResolverTuple<prism::crypto::Sha256Hasher>,
        EmptyCommitment,
    >>::forward(element)
    .map_err(|_| AddressFailure::PipelineFailure)?;

    let address = KappaLabel::from_bytes(grounded.output_bytes())
        .map_err(|_| AddressFailure::PipelineFailure)?;

    Ok(AddressOutcome {
        witness: AddressWitness::new(grounded),
        address,
    })
}
