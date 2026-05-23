//! `asn1::address` — the ASN.1 realization's public entry point.
//!
//! 1. [`validate_der`] checks the input is a single well-formed DER value
//!    (X.690 §§ 8 / 10 / 11) at the host boundary — no buffer, no caps.
//! 2. [`AddressModel::forward`] runs the shared ψ-tower: DER is canonical,
//!    so the input bytes flow in directly as an ADR-060 `Borrowed`
//!    carrier and ψ₉ folds them through `H = Sha256Hasher` to mint the
//!    κ-label.
//! 3. [`AddressOutcome::from_grounded`] extracts the owned κ-label +
//!    replayable TC-05 witness.
//!
//! The entry point is `no_alloc`: no transformation buffer is needed
//! because DER is its own canonical form.

use prism::pipeline::PrismModel;

use crate::asn1::model::AddressModel;
use crate::asn1::value::{validate_der, Asn1Carrier};
pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not a single well-formed DER value.
    InvalidDer,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

/// **uor-addr's ASN.1 entry point** — one ψ-pipeline content-address
/// inference per DER input.
///
/// # Errors
///
/// - [`AddressFailure::InvalidDer`] — `input_bytes` is not a single
///   well-formed DER value.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable in
///   normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    validate_der(input_bytes).map_err(|_| AddressFailure::InvalidDer)?;

    let grounded = AddressModel::forward(Asn1Carrier::new(input_bytes))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
