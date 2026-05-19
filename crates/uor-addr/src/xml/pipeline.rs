//! `xml::address` — the XML realization's public entry
//! point. Mirrors [`crate::json::pipeline::address`] for
//! `V = XmlValue`.
//!
//! 1. The host-boundary parser
//!    [`crate::xml::XmlValue::parse`] consumes raw XML
//!    bytes (Rivest canonical or token-list sugar), builds the
//!    structurally-tagged byte form, and validates every typed-input
//!    bound declared in [`crate::xml::shapes::bounds`].
//! 2. [`AddressModel`]'s `forward()` invokes the ψ-chain verb
//!    [`crate::xml::address_inference`] end-to-end through
//!    foundation's catamorphism, dispatching each ψ-Term through
//!    [`crate::xml::AddressResolverTuple`].
//! 3. The terminal ψ_9 resolver
//!    ([`crate::xml::AddressKInvariantResolver`]) decodes the
//!    structurally-tagged bytes, performs W3C XML-C14N 1.1
//!    canonicalization inside the typed-iso surface per ADR-046's
//!    resolver-body iterative-resolution discipline, and projects
//!    through the canonical hash axis (`H = Sha256Hasher`) to
//!    materialize the 71-byte κ-label.
//! 4. [`address`] returns the κ-label — every well-formed
//!    [`XmlValue`] always yields exactly one κ-label.

use prism::pipeline::{EmptyCommitment, PrismModel};
use prism::vocabulary::DefaultHostTypes;

use crate::label::KappaLabel;
pub use crate::outcome::{AddressOutcome, AddressWitness};
use crate::xml::model::AddressModel;
use crate::xml::resolvers::AddressResolverTuple;
use crate::xml::shapes::bounds::XmlAddrBounds;
use crate::xml::value::XmlValue;

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not a valid valid UTF-8 XML.
    InvalidXml,
    /// The parsed value exceeds a typed-input ceiling (depth, atom
    /// width, element count, or total serialized byte width).
    TooLarge,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

/// **uor-addr's XML entry point** — one ψ-pipeline
/// content-address inference per XML input.
///
/// # Errors
///
/// - [`AddressFailure::InvalidXml`] — `input_bytes` is not a valid
///   valid UTF-8 XML.
/// - [`AddressFailure::TooLarge`] — the parsed value exceeds a
///   typed-input ceiling.
/// - [`AddressFailure::PipelineFailure`] — defensive variant for
///   substrate-level shape violations; unreachable in normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    let value = XmlValue::parse(input_bytes).map_err(|violation| {
        if violation.constraint_iri.ends_with("/validXml") {
            AddressFailure::InvalidXml
        } else {
            AddressFailure::TooLarge
        }
    })?;

    let grounded = <AddressModel as PrismModel<
        DefaultHostTypes,
        XmlAddrBounds,
        prism::crypto::Sha256Hasher,
        AddressResolverTuple<prism::crypto::Sha256Hasher>,
        EmptyCommitment,
    >>::forward(value)
    .map_err(|_| AddressFailure::PipelineFailure)?;

    let address = KappaLabel::from_bytes(grounded.output_bytes())
        .map_err(|_| AddressFailure::PipelineFailure)?;

    Ok(AddressOutcome {
        witness: AddressWitness::new(grounded),
        address,
    })
}
