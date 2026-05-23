//! `onnx::address` — the ONNX realization's public entry point.
//!
//! 1. [`canonicalize`](crate::onnx::value::canonicalize) parses the ONNX
//!    `ModelProto` and emits the flat canonical skeleton into an `alloc`
//!    buffer (no count / width caps).
//! 2. `AddressModel::forward` runs the shared ψ-tower: the skeleton
//!    flows in as an ADR-060 `Borrowed` carrier and ψ₉ folds it through
//!    `H = Sha256Hasher` to mint the κ-label.
//! 3. [`AddressOutcome::from_grounded`] extracts the owned κ-label +
//!    replayable TC-05 witness.
//!
//! ONNX canonicalization requires heap storage (span sort scratch + the
//! skeleton), so [`address`] is gated behind the `alloc` feature.

pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes are not a well-formed ONNX `ModelProto` (protobuf
    /// decode failure, unsupported IR version, opset below the minimum,
    /// missing graph, a subgraph cycle, an over-deep subgraph nesting, or
    /// an unknown tensor data type).
    InvalidOnnx,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs.
    PipelineFailure,
}

/// **uor-addr's ONNX entry point** — one ψ-pipeline content-address
/// inference per ONNX `ModelProto`.
///
/// # Errors
///
/// - [`AddressFailure::InvalidOnnx`] — malformed ONNX `ModelProto` input.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable in
///   normal flow.
#[cfg(feature = "alloc")]
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    use prism::pipeline::PrismModel;

    use crate::onnx::model::AddressModel;
    use crate::onnx::value::{canonicalize, OnnxCarrier};

    let skeleton = canonicalize(input_bytes).map_err(|_| AddressFailure::InvalidOnnx)?;
    let grounded = AddressModel::forward(OnnxCarrier::new(&skeleton))
        .map_err(|_| AddressFailure::PipelineFailure)?;
    AddressOutcome::from_grounded(&grounded).map_err(|_| AddressFailure::PipelineFailure)
}
