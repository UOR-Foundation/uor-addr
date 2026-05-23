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

pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not a valid UTF-8 S-expression.
    InvalidSExpr,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

use crate::sexp::model::{
    AddressModel, AddressModelBlake3, AddressModelKeccak256, AddressModelSha3_256,
};
use crate::sexp::value::{SExprCanon, SExprValue};
use prism::pipeline::PrismModel;

/// **uor-addr's sexp entry point** (σ-axis `Sha256Hasher`) — one
/// ψ-pipeline content-address inference, yielding a `sha256:<64hex>`
/// κ-label.
///
/// # Errors
///
/// - [`AddressFailure::InvalidSExpr`] — the input is not well-formed.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome<71>, AddressFailure> {
    SExprCanon::validate(input_bytes).map_err(|_| AddressFailure::InvalidSExpr)?;
    let canon = SExprCanon::new(input_bytes);
    let grounded = AddressModel::forward(SExprValue::new(&canon))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::<71>::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}

/// The sexp entry point under σ-axis `Blake3Hasher` — yields a
/// `blake3:<64hex>` κ-label. See [`address`] for the error contract.
///
/// # Errors
///
/// As [`address`].
pub fn address_blake3(input_bytes: &[u8]) -> Result<AddressOutcome<71>, AddressFailure> {
    SExprCanon::validate(input_bytes).map_err(|_| AddressFailure::InvalidSExpr)?;
    let canon = SExprCanon::new(input_bytes);
    let grounded = AddressModelBlake3::forward(SExprValue::new(&canon))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::<71>::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}

/// The sexp entry point under σ-axis `Sha3_256Hasher` — yields a
/// `sha3-256:<64hex>` κ-label. See [`address`] for the error contract.
///
/// # Errors
///
/// As [`address`].
pub fn address_sha3_256(input_bytes: &[u8]) -> Result<AddressOutcome<73>, AddressFailure> {
    SExprCanon::validate(input_bytes).map_err(|_| AddressFailure::InvalidSExpr)?;
    let canon = SExprCanon::new(input_bytes);
    let grounded = AddressModelSha3_256::forward(SExprValue::new(&canon))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::<73>::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}

/// The sexp entry point under σ-axis `Keccak256Hasher` — yields a
/// `keccak256:<64hex>` κ-label. See [`address`] for the error contract.
///
/// # Errors
///
/// As [`address`].
pub fn address_keccak256(input_bytes: &[u8]) -> Result<AddressOutcome<74>, AddressFailure> {
    SExprCanon::validate(input_bytes).map_err(|_| AddressFailure::InvalidSExpr)?;
    let canon = SExprCanon::new(input_bytes);
    let grounded = AddressModelKeccak256::forward(SExprValue::new(&canon))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::<74>::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
