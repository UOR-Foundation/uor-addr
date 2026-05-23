//! `codemodule::address` — the code-module AST realization's public
//! entry point.
//!
//! 1. [`SExprCanon::validate`] checks the CCMAS S-expression grammar at
//!    the host boundary over the borrowed input — no buffer, no caps.
//! 2. [`AddressModel::forward`] runs the shared ψ-tower: the borrowed
//!    [`SExprCanon`] flows in as an ADR-060 `Stream` carrier that emits
//!    Rivest canonical bytes on demand (CCMAS canonical form), and ψ₉
//!    folds them through `H = Sha256Hasher` to mint the κ-label.
//! 3. [`AddressOutcome::from_grounded`] extracts the owned κ-label +
//!    replayable TC-05 witness.
//!
//! The entry point is `no_alloc`: CCMAS canonical bytes stream from the
//! borrowed input without materialization.

use prism::pipeline::PrismModel;

use crate::codemodule::model::AddressModel;
use crate::codemodule::value::CodeModuleCarrier;
pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};
use crate::sexp::SExprCanon;

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not a well-formed CCMAS S-expression.
    InvalidAst,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

/// **uor-addr's code-module AST entry point** — one ψ-pipeline
/// content-address inference per CCMAS input.
///
/// # Errors
///
/// - [`AddressFailure::InvalidAst`] — `input_bytes` is not a well-formed
///   CCMAS S-expression.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable in
///   normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    SExprCanon::validate(input_bytes).map_err(|_| AddressFailure::InvalidAst)?;

    let canon = SExprCanon::new(input_bytes);
    let grounded = AddressModel::forward(CodeModuleCarrier::new(&canon))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
