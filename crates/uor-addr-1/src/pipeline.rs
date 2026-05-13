//! `uor-addr-1`'s public entry point — the ψ-pipeline content-address
//! inference.
//!
//! 1. The host runs the boundary [`crate::ops::canonicalize::jcs_nfc`]
//!    transform on a raw JSON byte sequence to produce canonical-form
//!    bytes.
//! 2. [`AddressModel::forward`] invokes the ψ-chain verb
//!    ([`crate::verbs::address_inference`]) end-to-end via foundation's
//!    catamorphism. The catamorphism dispatches each resolver-bound
//!    ψ-Term through [`crate::resolvers::AddressResolverTuple`].
//! 3. The terminal ψ_9 resolver
//!    ([`crate::resolvers::AddressKInvariantResolver`]) structurally
//!    κ-derives the 71-byte wire-format address from the typed
//!    `JsonInput` via the canonical hash axis (one σ-projection —
//!    deterministic, no enumeration). The κ-label IS the
//!    `sha256:<64hex>` ASCII bytes.
//! 4. [`address`] returns the 71-byte address — well-formed
//!    `JsonInput` always yields exactly one κ-label.
//!
//! Per wiki ADR-039 (verdict realisation), the address-derivation
//! verdict envelope is **total**: every well-formed `JsonInput`
//! produces an `Ok(AddressOutcome)` carrying the κ-label, because the
//! constraint nerve N(C) is non-empty for every input. There is no
//! `PipelineFailure::DidNotAdmit`-style admission filter at the host
//! boundary; the κ-label IS the address. The defensive
//! [`AddressFailure::PipelineFailure`] variant is reserved for
//! substrate-level shape violations that ADR-039 classifies as
//! impossibility certificates — unreachable in normal flow.

extern crate alloc;

use alloc::string::String;

use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

use crate::model::{AddressLabel, AddressModel, JsonInput, ADDRESS_LABEL_BYTES};
use crate::ops::canonicalize::jcs_nfc;
use crate::resolvers::AddressResolverTuple;
use crate::shapes::bounds::AddrBounds;
use crate::shapes::hasher::Sha256Hasher;

/// The result of a successful [`address`] invocation.
///
/// Not `Clone` — the underlying foundation `Grounded<AddressLabel>` is
/// not `Clone`, so cloning the outcome would require either re-running
/// the pipeline (expensive) or losing the witness. Applications that
/// need to share the address out cheaply should extract `.address`
/// (a plain `String`, which is `Clone`) and drop the witness.
#[derive(Debug)]
pub struct AddressOutcome {
    /// Foundation-sealed `Grounded<AddressLabel>`; its `output_bytes()`
    /// are the 71-byte wire-format content address.
    pub witness: AddressWitness,
    /// The ASCII wire-format address, `sha256:<64-lowercase-hex>`.
    pub address: String,
}

/// Newtype around a `Grounded<AddressLabel>` carrying the κ-label.
/// Sealed by foundation; constructible only through the model's
/// `forward()` (constraint TC-02). Inherits the `Grounded` non-`Clone`
/// property — the κ-label is content-addressed, so reuse goes through
/// the borrow `AddressOutcome::witness.grounded()` rather than a
/// shallow copy.
pub struct AddressWitness(uor_foundation::enforcement::Grounded<AddressLabel>);

impl AddressWitness {
    /// Borrow the underlying foundation-sealed `Grounded<AddressLabel>`.
    #[must_use]
    pub fn grounded(&self) -> &uor_foundation::enforcement::Grounded<AddressLabel> {
        &self.0
    }
}

impl core::fmt::Debug for AddressWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AddressWitness").finish_non_exhaustive()
    }
}

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input bytes were not valid UTF-8 JSON.
    InvalidJson,
    /// The canonical-form bytes exceeded [`crate::model::JSON_INPUT_MAX_BYTES`].
    TooLarge,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed inputs — the
    /// ψ-pipeline is total over the typed input surface.
    PipelineFailure,
}

/// **uor-addr-1's public entry point** — one ψ-pipeline content-address
/// inference per JSON input.
///
/// 1. JCS+NFC canonicalises `input_bytes` at the host boundary.
/// 2. Constructs a typed [`JsonInput`].
/// 3. Invokes [`AddressModel::forward`] which always produces a
///    κ-label for well-formed inputs.
/// 4. Returns the [`AddressOutcome`] carrying the κ-label.
///
/// # Errors
///
/// - [`AddressFailure::InvalidJson`] — `input_bytes` is not valid UTF-8 JSON.
/// - [`AddressFailure::TooLarge`] — canonical-form bytes exceed the
///   `JsonInput` cap.
/// - [`AddressFailure::PipelineFailure`] — defensive variant for
///   substrate-level shape violations; unreachable in normal flow.
pub fn address(input_bytes: &[u8]) -> Result<AddressOutcome, AddressFailure> {
    let canonical = jcs_nfc(input_bytes).map_err(|_| AddressFailure::InvalidJson)?;
    let json_input = JsonInput::new(canonical).map_err(|_| AddressFailure::TooLarge)?;

    let grounded = <AddressModel as PrismModel<
        DefaultHostTypes,
        AddrBounds,
        Sha256Hasher,
        AddressResolverTuple<Sha256Hasher>,
    >>::forward(json_input)
    .map_err(|_| AddressFailure::PipelineFailure)?;

    // Read the 71-byte κ-label out of the Grounded value.
    let output = grounded.output_bytes();
    if output.len() != ADDRESS_LABEL_BYTES {
        return Err(AddressFailure::PipelineFailure);
    }
    let mut buf = [0u8; ADDRESS_LABEL_BYTES];
    buf.copy_from_slice(output);
    // ASCII-only by construction.
    let address = core::str::from_utf8(&buf)
        .map_err(|_| AddressFailure::PipelineFailure)?
        .into();

    Ok(AddressOutcome {
        witness: AddressWitness(grounded),
        address,
    })
}
