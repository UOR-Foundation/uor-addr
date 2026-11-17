//! **`uor_addr::safetensors` — the safetensors realization of UOR-ADDR.**
//!
//! Typed content-addressing for safetensors files under a spec-canonical
//! structural form. The default σ-projection is
//! [`prism::crypto::Sha256Hasher`]; [`address_blake3`], [`address_sha3_256`],
//! [`address_keccak256`], and [`address_sha512`] select the other axes
//! ([`crate::hash`]).
//!
//! ## Why a canonical form, and why this one
//!
//! A safetensors file is an 8-byte little-endian header length, a JSON
//! header, and a packed byte buffer. The same tensors can be written with
//! the header keys in any order, with any JSON whitespace or escape
//! spelling, with trailing header padding, and with the buffer in any
//! tensor order. None of that is content, so none of it may move the label.
//!
//! The canonical form is the same shape as the GGUF realization's (ADR-060):
//! a **flat Merkle skeleton** whose size grows with the tensor and metadata
//! counts, never with the model, in which every tensor's data is represented
//! by the SHA-256 of that tensor's own bytes. That leaf choice is what lets a
//! reader holding the skeleton check one tensor from a ranged read of any
//! copy of the file, and it gives a tensor the same leaf here as in a GGUF
//! file that stores the same bytes.
//!
//! ## Leaf axis vs. κ-axis
//!
//! As in [`crate::gguf`], leaves are **SHA-256 by canonical-form definition**
//! ([`CANONICAL_FORM_VERSION`]); the selected κ-axis `H` is applied to the
//! finished skeleton.
//!
//! ## Authoritative sources
//!
//! - safetensors format — <https://github.com/huggingface/safetensors#format>
//! - reference implementation (header validation, `Dtype::bitsize`) —
//!   <https://github.com/huggingface/safetensors/blob/main/safetensors/src/tensor.rs>
//! - JSON — RFC 8259.
//! - SHA-256 σ-projection — NIST FIPS 180-4.
//!
//! See [`value`] for the byte layout and the admission rules.

pub mod dtype;
pub mod model;
pub mod pipeline;
pub mod value;
pub mod verbs;

/// Canonical-form version (see [`value`]).
pub const CANONICAL_FORM_VERSION: u32 = 1;

/// Largest header the realization admits, in bytes: the reference
/// implementation's `MAX_HEADER_SIZE`.
pub const SAFETENSORS_MAX_HEADER_BYTES: u64 = 100_000_000;

/// The skeleton's first four bytes. They differ from the GGUF skeleton's
/// (`GGUF` magic) so the two realizations can never mint one label from
/// two different files.
pub const SAFETENSORS_SKELETON_TAG: [u8; 4] = *b"SAFE";

pub use dtype::SafetensorsDtype;
pub use model::{
    AddressModel, AddressModelBlake3, AddressModelKeccak256, AddressModelSha3_256,
    AddressModelSha512, AddressRoute,
};
pub use pipeline::{address, address_blake3, address_keccak256, address_sha3_256, address_sha512};
pub use pipeline::{AddressFailure, AddressOutcome, AddressWitness, VerifyError};
pub use value::{canonicalize, SafetensorsCarrier, SafetensorsValue};
pub use verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

/// The shared, format-independent ψ-tower.
pub use crate::resolvers::AddressResolverTuple;
