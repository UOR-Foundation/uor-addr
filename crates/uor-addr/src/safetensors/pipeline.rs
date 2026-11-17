//! `safetensors::address` — the safetensors realization's public entry
//! point. [`canonicalize`] parses the file and emits the flat skeleton;
//! the shared ψ-tower folds it through the selected σ-axis to mint the
//! κ-label.

pub use crate::outcome::{AddressOutcome, AddressWitness, VerifyError};

use crate::safetensors::model::{
    AddressModel, AddressModelBlake3, AddressModelKeccak256, AddressModelSha3_256,
    AddressModelSha512,
};
use crate::safetensors::value::{canonicalize, SafetensorsCarrier};
use prism::pipeline::PrismModel;

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// The input is not a well-formed safetensors file: a truncated or
    /// oversized header, a header that is not the format's JSON object,
    /// an unknown dtype, a tensor whose size disagrees with its dtype and
    /// shape, or a buffer with holes, overlaps or bytes no tensor claims.
    /// [`SafetensorsValue::parse`](crate::safetensors::SafetensorsValue::parse)
    /// names the violated rule.
    InvalidSafetensors,
    /// Defensive: a resolver returned a shape violation. Unreachable for
    /// well-formed inputs.
    PipelineFailure,
}

macro_rules! entry_point {
    ($(#[$doc:meta])* $name:ident, $model:ty, $($n:literal),+) => {
        $(#[$doc])*
        ///
        /// # Errors
        ///
        /// - [`AddressFailure::InvalidSafetensors`] — the input is not well-formed.
        /// - [`AddressFailure::PipelineFailure`] — defensive; unreachable.
        pub fn $name(input_bytes: &[u8]) -> Result<AddressOutcome<$($n),+>, AddressFailure> {
            let skeleton = canonicalize(input_bytes).map_err(|_| AddressFailure::InvalidSafetensors)?;
            let grounded = <$model>::forward(SafetensorsCarrier::new(&skeleton))
                .map_err(|_| AddressFailure::PipelineFailure)?;
            AddressOutcome::<$($n),+>::from_grounded(&grounded)
                .map_err(|_| AddressFailure::PipelineFailure)
        }
    };
}

entry_point!(
    /// **uor-addr's safetensors entry point** (σ-axis `Sha256Hasher`),
    /// yielding a `sha256:<64hex>` κ-label.
    address,
    AddressModel,
    71
);
entry_point!(
    /// The safetensors entry point under σ-axis `Blake3Hasher`, yielding a
    /// `blake3:<64hex>` κ-label.
    address_blake3,
    AddressModelBlake3,
    71
);
entry_point!(
    /// The safetensors entry point under σ-axis `Sha3_256Hasher`, yielding
    /// a `sha3-256:<64hex>` κ-label.
    address_sha3_256,
    AddressModelSha3_256,
    73
);
entry_point!(
    /// The safetensors entry point under σ-axis `Keccak256Hasher`, yielding
    /// a `keccak256:<64hex>` κ-label.
    address_keccak256,
    AddressModelKeccak256,
    74
);
entry_point!(
    /// The safetensors entry point under σ-axis `Sha512Hasher`, yielding a
    /// `sha512:<128hex>` κ-label.
    address_sha512,
    AddressModelSha512,
    135,
    64
);
