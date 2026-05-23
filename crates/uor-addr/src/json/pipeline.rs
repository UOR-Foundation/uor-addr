//! `json::address` — the JSON realization's public entry point.
//!
//! 1. [`canonicalize`](crate::json::value::canonicalize) parses + emits
//!    the JCS-RFC8785 §3 + Unicode NFC canonical form into an `alloc`
//!    buffer (no width / depth / count caps).
//! 2. `AddressModel::forward` runs the shared ψ-tower: the canonical
//!    bytes flow in as an ADR-060 `Borrowed` carrier and ψ₉ folds them
//!    through `H = Sha256Hasher` to mint the κ-label.
//! 3. [`AddressOutcome::from_grounded`] extracts the owned κ-label +
//!    replayable TC-05 witness.
//!
//! JSON canonicalization requires heap storage (object-key sort scratch +
//! canonical output), so [`address`] is gated behind the `alloc` feature.

pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not valid UTF-8 JSON.
    InvalidJson,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

/// **uor-addr's JSON entry point** — one ψ-pipeline content-address
/// inference per JSON input.
///
/// # Errors
///
/// - [`AddressFailure::InvalidJson`] — `input_bytes` is not valid UTF-8
///   JSON.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable in
///   normal flow.
#[cfg(feature = "alloc")]
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    use prism::pipeline::PrismModel;

    use crate::json::model::AddressModel;
    use crate::json::value::{canonicalize, JsonCarrier};

    let canonical = canonicalize(input_bytes).map_err(|_| AddressFailure::InvalidJson)?;
    let grounded = AddressModel::forward(JsonCarrier::new(&canonical))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
