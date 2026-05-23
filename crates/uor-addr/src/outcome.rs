//! Pipeline-output carrier — the shape every realization's `address()`
//! entry point returns.
//!
//! All realizations produce the same triple: the ASCII κ-label
//! ([`crate::KappaLabel`]) plus a replayable TC-05 witness. The κ-label
//! width `N` is the selected σ-axis's [`AddrHash::LABEL_BYTES`](crate::hash::AddrHash::LABEL_BYTES)
//! (71 for sha256 / blake3, 73 for sha3-256, 74 for keccak256), carried in
//! the type. Under ADR-060 the model's `forward()` yields a `Grounded<'a,
//! S, NIN>` whose `'a` borrows the input carrier; [`AddressOutcome`]
//! extracts the **owned** witness data (the κ-label, the replay [`Trace`],
//! and the σ-projection fingerprint) from it so the outcome carries no
//! borrow and the input may be dropped.

use prism::replay::{certify_from_trace, Trace};
use prism::seal::Grounded;

use crate::label::{KappaLabel, LabelDecodeError};

/// Trace event capacity for the address realizations. The κ-derivation's
/// canonical k-invariants branch emits a short, bounded trace; 256 is the
/// foundation's default `Trace` width (`HostBounds::TRACE_MAX_EVENTS`).
pub const ADDRESS_TRACE_EVENTS: usize = 256;

/// **The result of a successful `address()` invocation.** Generic over the
/// κ-label byte width `N` (the selected σ-axis's `LABEL_BYTES`).
#[derive(Debug)]
pub struct AddressOutcome<const N: usize> {
    /// The replayable TC-05 witness (owns its trace + fingerprint).
    pub witness: AddressWitness<N>,
    /// The ASCII wire-format κ-label, `<algorithm>:<lowercase-hex>`.
    pub address: KappaLabel<N>,
}

impl<const N: usize> AddressOutcome<N> {
    /// Extract the owned outcome from a model's `forward()` result. Reads
    /// the κ-label output bytes, replays the derivation into an owned
    /// [`Trace`], and snapshots the σ-projection fingerprint — none of
    /// which borrow the (about-to-be-dropped) input carrier.
    ///
    /// `N` must equal the grounded output shape's `SITE_COUNT` (the κ-label
    /// byte width); the per-axis entry points supply the matching literal.
    ///
    /// # Errors
    ///
    /// [`LabelDecodeError`] if the grounded output is not a well-formed
    /// `N`-byte ASCII κ-label (unreachable for the address realizations'
    /// ψ₉ output; defensive against substrate corruption).
    pub fn from_grounded<S, const NIN: usize>(
        grounded: &Grounded<'_, S, NIN>,
    ) -> Result<Self, LabelDecodeError>
    where
        S: prism::std_types::GroundedShape,
    {
        let address = KappaLabel::<N>::from_bytes(grounded.output_bytes())?;
        let trace: Trace<ADDRESS_TRACE_EVENTS> = grounded.derivation().replay();
        let mut fingerprint = [0u8; 32];
        let fp = grounded.content_fingerprint();
        let fp_bytes = fp.as_bytes();
        let n = fp_bytes.len().min(32);
        fingerprint[..n].copy_from_slice(&fp_bytes[..n]);
        Ok(Self {
            witness: AddressWitness {
                address,
                trace,
                fingerprint,
            },
            address,
        })
    }
}

/// A replayable TC-05 witness. Holds the owned replay [`Trace`], the
/// σ-projection fingerprint, and the κ-label. [`verify`](Self::verify)
/// re-certifies the trace through `prism::replay::certify_from_trace`
/// without re-invoking the σ-axis, and confirms the re-derived
/// fingerprint equals the source's (QS-05 replay equivalence).
pub struct AddressWitness<const N: usize> {
    address: KappaLabel<N>,
    trace: Trace<ADDRESS_TRACE_EVENTS>,
    fingerprint: [u8; 32],
}

impl<const N: usize> AddressWitness<N> {
    /// The κ-label this witness attests.
    #[must_use]
    pub fn kappa_label(&self) -> KappaLabel<N> {
        self.address
    }

    /// The 32-byte σ-projection content fingerprint.
    #[must_use]
    pub fn content_fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Replay the derivation through `certify_from_trace` (no σ-axis
    /// re-invocation) and confirm the re-derived fingerprint matches.
    /// Returns the attested κ-label on success.
    ///
    /// # Errors
    ///
    /// [`VerifyError`] if the trace is malformed or the re-derived
    /// fingerprint diverges from the source (QS-05 violation).
    pub fn verify(&self) -> Result<KappaLabel<N>, VerifyError> {
        let certified = certify_from_trace(&self.trace).map_err(|_| VerifyError::ReplayFailed)?;
        if certified.certificate().content_fingerprint().as_bytes()[..] != self.fingerprint[..] {
            return Err(VerifyError::FingerprintMismatch);
        }
        Ok(self.address)
    }
}

impl<const N: usize> core::fmt::Debug for AddressWitness<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AddressWitness")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// TC-05 replay-verification failures from [`AddressWitness::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// `certify_from_trace` rejected the trace (malformed / out-of-order).
    ReplayFailed,
    /// The re-derived fingerprint diverged from the source (QS-05).
    FingerprintMismatch,
}
