//! Pipeline-output carrier — the shape every realization's `address()`
//! entry point returns.
//!
//! All UOR-ADDR realizations produce the same output triple: the
//! 71-byte ASCII κ-label ([`crate::KappaLabel`]) plus the
//! foundation-sealed [`prism::seal::Grounded<AddressLabel>`] witness
//! that downstream consumers can replay through
//! `prism_verify::certify_from_trace` without re-hashing.
//!
//! [`AddressOutcome`] and [`AddressWitness`] are declared once here
//! and re-exported by every per-realization `pipeline` module so the
//! existing `uor_addr::<realization>::AddressOutcome` import paths
//! still resolve to the same architectural-surface type. Integrators
//! see one carrier across the API, not six identical copies.

use crate::label::{AddressLabel, KappaLabel};

/// **The result of a successful `address()` invocation** —
/// architectural-surface output carrier shared by every realization.
///
/// `AddressOutcome` is not `Clone` — the underlying
/// `prism::seal::Grounded<AddressLabel>` is not `Clone`, so cloning
/// the outcome would require either re-running the pipeline
/// (expensive) or losing the witness. Applications that need to
/// share the address out cheaply should extract `.address`
/// ([`KappaLabel`] is `Copy`) and drop the witness.
#[derive(Debug)]
pub struct AddressOutcome {
    /// Foundation-sealed `Grounded<AddressLabel>`; its
    /// `output_bytes()` are the 71 ASCII bytes the κ-derivation
    /// emits. Downstream consumers can replay this through
    /// `prism_verify::certify_from_trace` to re-derive the κ-label
    /// without re-running SHA-256.
    pub witness: AddressWitness,
    /// The ASCII wire-format κ-label, `sha256:<64-lowercase-hex>` —
    /// 71 bytes. `Copy + Eq + Hash`, `Deref<Target = str>` for
    /// ergonomic use.
    pub address: KappaLabel,
}

/// Newtype around a foundation-sealed `Grounded<AddressLabel>`.
/// Constructible only through a realization's pipeline `forward()`
/// (TC-02 mechanism sealing). Inherits the `Grounded` non-`Clone`
/// property — the κ-label is content-addressed, so reuse goes
/// through the borrow [`AddressWitness::grounded`] rather than a
/// shallow copy.
pub struct AddressWitness(prism::seal::Grounded<AddressLabel>);

impl AddressWitness {
    /// **Internal constructor** — only the per-realization pipeline
    /// `address()` functions invoke this, after the model's
    /// `forward()` has produced a `Grounded<AddressLabel>`.
    #[doc(hidden)]
    #[must_use]
    pub fn new(grounded: prism::seal::Grounded<AddressLabel>) -> Self {
        Self(grounded)
    }

    /// Borrow the underlying foundation-sealed
    /// `Grounded<AddressLabel>`.
    #[must_use]
    pub fn grounded(&self) -> &prism::seal::Grounded<AddressLabel> {
        &self.0
    }
}

impl core::fmt::Debug for AddressWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AddressWitness").finish_non_exhaustive()
    }
}
