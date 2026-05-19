//! `sexp::address` — the S-expression realization's public entry
//! point. Mirrors [`crate::json::pipeline::address`] for
//! `V = SExprValue`.
//!
//! 1. The host-boundary parser
//!    [`crate::sexp::SExprValue::parse`] consumes raw S-expression
//!    bytes (Rivest canonical or token-list sugar), builds the
//!    structurally-tagged byte form, and validates every typed-input
//!    bound declared in [`crate::sexp::shapes::bounds`].
//! 2. [`AddressModel`]'s `forward()` invokes the ψ-chain verb
//!    [`crate::sexp::address_inference`] end-to-end through
//!    foundation's catamorphism, dispatching each ψ-Term through
//!    [`crate::sexp::AddressResolverTuple`].
//! 3. The terminal ψ_9 resolver
//!    ([`crate::sexp::AddressKInvariantResolver`]) decodes the
//!    structurally-tagged bytes, performs Rivest canonical-form
//!    canonicalization inside the typed-iso surface per ADR-046's
//!    resolver-body iterative-resolution discipline, and projects
//!    through the canonical hash axis (`H = Sha256Hasher`) to
//!    materialize the 71-byte κ-label.
//! 4. [`address`] returns the κ-label — every well-formed
//!    [`SExprValue`] always yields exactly one κ-label.

use prism::pipeline::{EmptyCommitment, PrismModel};
use prism::vocabulary::DefaultHostTypes;

use crate::label::KappaLabel;
pub use crate::outcome::{AddressOutcome, AddressWitness};
use crate::sexp::model::AddressModel;
use crate::sexp::resolvers::AddressResolverTuple;
use crate::sexp::shapes::bounds::SExprAddrBounds;
use crate::sexp::value::SExprValue;

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not a valid UTF-8 S-expression.
    InvalidSExpr,
    /// The parsed value exceeds a typed-input ceiling (depth, atom
    /// width, element count, or total serialized byte width).
    TooLarge,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

/// **uor-addr's S-expression entry point** — one ψ-pipeline
/// content-address inference per S-expression input.
///
/// # Errors
///
/// - [`AddressFailure::InvalidSExpr`] — `input_bytes` is not a valid
///   UTF-8 S-expression.
/// - [`AddressFailure::TooLarge`] — the parsed value exceeds a
///   typed-input ceiling.
/// - [`AddressFailure::PipelineFailure`] — defensive variant for
///   substrate-level shape violations; unreachable in normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    let sexpr = SExprValue::parse(input_bytes).map_err(|violation| {
        if violation.constraint_iri.ends_with("/validUtf8SExpr") {
            AddressFailure::InvalidSExpr
        } else {
            AddressFailure::TooLarge
        }
    })?;

    let grounded = <AddressModel as PrismModel<
        DefaultHostTypes,
        SExprAddrBounds,
        prism::crypto::Sha256Hasher,
        AddressResolverTuple<prism::crypto::Sha256Hasher>,
        EmptyCommitment,
    >>::forward(sexpr)
    .map_err(|_| AddressFailure::PipelineFailure)?;

    let address = KappaLabel::from_bytes(grounded.output_bytes())
        .map_err(|_| AddressFailure::PipelineFailure)?;

    Ok(AddressOutcome {
        witness: AddressWitness::new(grounded),
        address,
    })
}
