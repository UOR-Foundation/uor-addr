//! `gguf::address` — the GGUF realization's public entry point.
//!
//! 1. [`canonicalize`](crate::gguf::value::canonicalize) parses the GGUF
//!    v3 file and emits the flat canonical skeleton into an `alloc`
//!    buffer (no count / width caps).
//! 2. `AddressModel::forward` runs the shared ψ-tower: the skeleton
//!    flows in as an ADR-060 `Borrowed` carrier and ψ₉ folds it through
//!    `H = Sha256Hasher` to mint the κ-label.
//! 3. [`AddressOutcome::from_grounded`] extracts the owned κ-label +
//!    replayable TC-05 witness.
//!
//! GGUF canonicalization requires heap storage (entry sort scratch +
//! the skeleton), so [`address`] is gated behind the `alloc` feature.

pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes are not a well-formed GGUF v3 file (bad magic,
    /// unsupported version, truncation, over-rank tensor, over-deep array
    /// nesting, invalid alignment, or an unknown / deprecated tensor
    /// type).
    InvalidGguf,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

/// **uor-addr's GGUF entry point** — one ψ-pipeline content-address
/// inference per GGUF v3 file.
///
/// # Errors
///
/// - [`AddressFailure::InvalidGguf`] — malformed GGUF v3 input.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable in
///   normal flow.
#[cfg(feature = "alloc")]
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    use prism::pipeline::PrismModel;

    use crate::gguf::model::AddressModel;
    use crate::gguf::value::{canonicalize, GgufCarrier};

    let skeleton = canonicalize(input_bytes).map_err(|_| AddressFailure::InvalidGguf)?;
    let grounded = AddressModel::forward(GgufCarrier::new(&skeleton))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
