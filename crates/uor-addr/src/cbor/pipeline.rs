//! `cbor::address*` — the CBOR realization's public entry points, one per
//! admissible σ-axis ([`crate::hash`]).
//!
//! 1. [`canonicalize`](crate::cbor::value::canonicalize) re-encodes the
//!    input under RFC 8949 §4.2 Deterministic Encoding into an `alloc`
//!    buffer (shortest ints/floats, definite lengths, sorted map keys).
//! 2. The selected axis's `AddressModel*::forward` runs the shared ψ-tower:
//!    the canonical bytes flow in as an ADR-060 `Borrowed` carrier and ψ₉
//!    folds them through the bound `H` to mint the κ-label.
//! 3. [`AddressOutcome::from_grounded`] extracts the owned κ-label +
//!    replayable TC-05 witness.
//!
//! [`address`] selects `H = Sha256Hasher` (the default); [`address_blake3`],
//! [`address_sha3_256`], and [`address_keccak256`] select the other 32-byte
//! axes. CBOR canonicalization requires heap storage (per-map key-sort
//! scratch + canonical output), so the entry points are gated behind the
//! `alloc` feature.

pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};

/// Failure modes from the CBOR entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not exactly one well-formed CBOR data item
    /// (bad/reserved head, non-UTF-8 text string, duplicate map key,
    /// trailing bytes, or over-deep nesting).
    InvalidCbor,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

#[cfg(feature = "alloc")]
use crate::cbor::model::{
    AddressModel, AddressModelBlake3, AddressModelKeccak256, AddressModelSha3_256,
};
#[cfg(feature = "alloc")]
use crate::cbor::value::{canonicalize, CborCarrier};
#[cfg(feature = "alloc")]
use prism::pipeline::PrismModel;

/// **uor-addr's CBOR entry point** (σ-axis `Sha256Hasher`) — one ψ-pipeline
/// content-address inference, yielding a `sha256:<64hex>` κ-label over the
/// RFC 8949 §4.2 canonical form.
///
/// # Errors
///
/// - [`AddressFailure::InvalidCbor`] — input is not one well-formed CBOR item.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable.
#[cfg(feature = "alloc")]
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome<71>, AddressFailure> {
    let canonical = canonicalize(input_bytes).map_err(|_| AddressFailure::InvalidCbor)?;
    let grounded = AddressModel::forward(CborCarrier::new(&canonical))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::<71>::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}

/// The CBOR entry point under σ-axis `Blake3Hasher` — yields a
/// `blake3:<64hex>` κ-label. See [`address`] for the error contract.
///
/// # Errors
///
/// As [`address`].
#[cfg(feature = "alloc")]
pub fn address_blake3(input_bytes: &[u8]) -> Result<AddressOutcome<71>, AddressFailure> {
    let canonical = canonicalize(input_bytes).map_err(|_| AddressFailure::InvalidCbor)?;
    let grounded = AddressModelBlake3::forward(CborCarrier::new(&canonical))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::<71>::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}

/// The CBOR entry point under σ-axis `Sha3_256Hasher` — yields a
/// `sha3-256:<64hex>` κ-label. See [`address`] for the error contract.
///
/// # Errors
///
/// As [`address`].
#[cfg(feature = "alloc")]
pub fn address_sha3_256(input_bytes: &[u8]) -> Result<AddressOutcome<73>, AddressFailure> {
    let canonical = canonicalize(input_bytes).map_err(|_| AddressFailure::InvalidCbor)?;
    let grounded = AddressModelSha3_256::forward(CborCarrier::new(&canonical))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::<73>::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}

/// The CBOR entry point under σ-axis `Keccak256Hasher` — yields a
/// `keccak256:<64hex>` κ-label. See [`address`] for the error contract.
///
/// # Errors
///
/// As [`address`].
#[cfg(feature = "alloc")]
pub fn address_keccak256(input_bytes: &[u8]) -> Result<AddressOutcome<74>, AddressFailure> {
    let canonical = canonicalize(input_bytes).map_err(|_| AddressFailure::InvalidCbor)?;
    let grounded = AddressModelKeccak256::forward(CborCarrier::new(&canonical))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::<74>::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
