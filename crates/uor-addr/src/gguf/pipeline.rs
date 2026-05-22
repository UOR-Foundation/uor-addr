//! `gguf::address` — the GGUF realization's public entry point. Mirrors
//! [`crate::ring::pipeline::address`] for `V = GgufValue`: parse at the
//! host boundary, run the model's `forward()`, materialize the κ-label.

use prism::pipeline::{EmptyCommitment, PrismModel};
use prism::vocabulary::DefaultHostTypes;

use crate::gguf::model::AddressModel;
use crate::gguf::resolvers::AddressResolverTuple;
use crate::gguf::shapes::bounds::GgufAddrBounds;
use crate::gguf::value::GgufValue;
use crate::label::KappaLabel;
pub use crate::outcome::{AddressOutcome, AddressWitness};

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes are not a well-formed GGUF v3 file (bad magic,
    /// unsupported version, truncation, invalid alignment, or an unknown
    /// / deprecated tensor type).
    InvalidGguf,
    /// A typed-input bound (KV count, tensor count, string width, array
    /// length / depth, tensor-data width, or canonical-form width) was
    /// exceeded under the active [`GgufAddrBounds`] profile.
    TooLarge,
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
/// - [`AddressFailure::TooLarge`] — a typed-input bound was exceeded.
/// - [`AddressFailure::PipelineFailure`] — defensive; unreachable in
///   normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    let value = GgufValue::parse(input_bytes).map_err(|v| {
        // The bound / depth / canonical-width violations map to TooLarge;
        // everything else is a malformed-input rejection.
        let c = v.constraint_iri;
        if c.ends_with("/withinBounds")
            || c.ends_with("/arrayDepthBound")
            || c.ends_with("/canonicalFormWidth")
        {
            AddressFailure::TooLarge
        } else {
            AddressFailure::InvalidGguf
        }
    })?;

    let grounded = <AddressModel as PrismModel<
        DefaultHostTypes,
        GgufAddrBounds,
        prism::crypto::Sha256Hasher,
        AddressResolverTuple<prism::crypto::Sha256Hasher>,
        EmptyCommitment,
    >>::forward(value)
    .map_err(|_| AddressFailure::PipelineFailure)?;

    let address = KappaLabel::from_bytes(grounded.output_bytes())
        .map_err(|_| AddressFailure::PipelineFailure)?;

    Ok(AddressOutcome {
        witness: AddressWitness::new(grounded),
        address,
    })
}
