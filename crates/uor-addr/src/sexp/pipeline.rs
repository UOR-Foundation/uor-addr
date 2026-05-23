//! `sexp::address` — the S-expression realization's public entry point.
//!
//! 1. [`SExprCanon::validate`] checks the S-expression grammar at the
//!    host boundary (UTF-8, balanced parentheses, single top-level value)
//!    over the borrowed input — no buffer, no caps.
//! 2. [`AddressModel::forward`] runs the shared ψ-tower: the borrowed
//!    [`SExprCanon`] flows in as an ADR-060 `Stream` carrier that emits
//!    Rivest canonical bytes on demand, and ψ₉ folds them chunk-by-chunk
//!    through `H = Sha256Hasher` to mint the κ-label.
//! 3. [`AddressOutcome::from_grounded`] extracts the owned κ-label +
//!    replayable TC-05 witness.

use prism::pipeline::PrismModel;

pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};
use crate::sexp::model::AddressModel;
use crate::sexp::value::{SExprCanon, SExprValue};

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not a valid UTF-8 S-expression.
    InvalidSExpr,
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
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable in
///   normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    SExprCanon::validate(input_bytes).map_err(|_| AddressFailure::InvalidSExpr)?;

    let canon = SExprCanon::new(input_bytes);
    let grounded = AddressModel::forward(SExprValue::new(&canon))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
