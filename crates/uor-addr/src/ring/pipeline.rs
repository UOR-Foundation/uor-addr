//! `ring::address` — the ring-element realization's public entry point.
//!
//! 1. [`RingElement::parse`] validates the Amendment 43 §2 canonical
//!    bytes at the host boundary.
//! 2. [`AddressModel::forward`] runs the shared ψ-tower: the handle's
//!    canonical bytes flow in as an ADR-060 carrier and ψ₉ folds them
//!    through `H = Sha256Hasher` to mint the κ-label.
//! 3. [`AddressOutcome::from_grounded`] extracts the owned κ-label +
//!    replayable TC-05 witness.

use prism::pipeline::PrismModel;

pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};
use crate::ring::model::AddressModel;
use crate::ring::value::RingElement;

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not valid Amendment 43 canonical bytes (a
    /// canonical ring element is intrinsically ≤ 5 bytes — Witt level
    /// plus its little-endian coefficient — so every malformed or
    /// over-wide input falls here).
    InvalidRingElement,
    /// Defensive: foundation's catamorphism returned a shape violation.
    PipelineFailure,
}

/// **uor-addr's ring-element entry point** — one ψ-pipeline
/// content-address inference per ring-element input.
///
/// # Errors
///
/// - [`AddressFailure::InvalidRingElement`] — not valid canonical bytes.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable in
///   normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    let element =
        RingElement::parse(input_bytes).map_err(|_| AddressFailure::InvalidRingElement)?;

    let grounded = AddressModel::forward(element).map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
