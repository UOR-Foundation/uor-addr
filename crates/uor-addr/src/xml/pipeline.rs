//! `xml::address` — the XML realization's public entry point.
//!
//! 1. [`canonicalize`](crate::xml::value::canonicalize) parses + emits
//!    the W3C XML-C14N 1.1 (subset) canonical form into an `alloc` buffer
//!    (no width / count caps).
//! 2. `AddressModel::forward` runs the shared ψ-tower: the canonical
//!    bytes flow in as an ADR-060 `Borrowed` carrier and ψ₉ folds them
//!    through `H = Sha256Hasher` to mint the κ-label.
//! 3. [`AddressOutcome::from_grounded`] extracts the owned κ-label +
//!    replayable TC-05 witness.
//!
//! XML canonicalization requires heap storage (attribute sort scratch +
//! canonical output), so [`address`] is gated behind the `alloc` feature.

pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not a well-formed XML document in the
    /// supported canonical-XML subset.
    InvalidXml,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

/// **uor-addr's XML entry point** — one ψ-pipeline content-address
/// inference per XML input.
///
/// # Errors
///
/// - [`AddressFailure::InvalidXml`] — `input_bytes` is not a well-formed
///   document in the supported subset.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable in
///   normal flow.
#[cfg(feature = "alloc")]
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    use prism::pipeline::PrismModel;

    use crate::xml::model::AddressModel;
    use crate::xml::value::{canonicalize, XmlValue};

    let canonical = canonicalize(input_bytes).map_err(|_| AddressFailure::InvalidXml)?;
    let grounded = AddressModel::forward(XmlValue::new(&canonical))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
