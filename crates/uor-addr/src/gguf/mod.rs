//! **`uor_addr::gguf` — the GGUF v3 realization of UOR-ADDR.**
//!
//! Typed content-addressing for GGUF v3 model files
//! (`GGUF_MAGIC = 0x46554747`, `version = 3`) under a spec-canonical
//! structural form, with the σ-projection bound to
//! [`prism::crypto::Sha256Hasher`].
//!
//! ## Authoritative sources
//!
//! - GGUF v3 binary format — <https://github.com/ggml-org/ggml/blob/master/docs/gguf.md>
//! - Reference C++ header — <https://github.com/ggml-org/ggml/blob/master/include/gguf.h>
//! - Reference Python tooling — <https://github.com/ggml-org/llama.cpp/tree/master/gguf-py>
//! - `ggml_type` enum / `GGML_MAX_DIMS` — <https://github.com/ggml-org/ggml/blob/master/include/ggml.h>
//! - SHA-256 σ-projection — NIST FIPS 180-4.
//!
//! ## Canonical form
//!
//! The GGUF spec defines no canonical form; this realization defines one
//! (canonical form v1 — [`CANONICAL_FORM_VERSION`]). It is a **Merkle
//! skeleton**: a bounded structural form (header, metadata KVs sorted by
//! key bytes, tensor info sorted by name bytes with recomputed canonical
//! offsets) in which every variable-length leaf — tensor data, metadata
//! array payloads, long strings — is represented by its 32-byte streamed
//! SHA-256 digest. Tensor data is streamed through the hash axis at the
//! host boundary (true incremental SHA-256), so arbitrarily large weights
//! bind into the κ-label without flowing through the bounded ψ-pipeline
//! carrier. See [`crate::gguf::value`] for the full byte layout.
//!
//! Two GGUF files that decode to the same logical content (modulo
//! metadata-KV order, tensor order, and tensor-data layout) canonicalize
//! to byte-identical skeletons and therefore to the same κ-label.
//!
//! ## Tensor element types
//!
//! Validated against the [`prism::tensor::dtype`] alphabet via
//! [`dtype::GgmlType`] — a total mapping of the 29 GGUF v3 `ggml_type`
//! IDs to `prism::tensor::dtype` shapes.

pub mod dtype;
pub mod model;
pub mod pipeline;
pub mod shapes;
pub mod value;
pub mod verbs;

/// Canonical-form version (see module docs). Bumped to 2 under ADR-060:
/// the canonical form is now the full flat Merkle skeleton (no two-level
/// commitment), so v2 κ-labels differ from the v1 commitment's.
pub const CANONICAL_FORM_VERSION: u32 = 2;

pub use dtype::GgmlType;
pub use model::{AddressModel, AddressRoute};
#[cfg(feature = "alloc")]
pub use pipeline::address;
pub use pipeline::{AddressFailure, AddressOutcome, AddressWitness, VerifyError};
pub use shapes::bounds::{
    GGUF_DEFAULT_ALIGNMENT, GGUF_HEADER_BYTES, GGUF_MAGIC, GGUF_MAX_DIMS,
    GGUF_METADATA_ARRAY_DEPTH_MAX, GGUF_VERSION_REQUIRED,
};
pub use value::GgufCarrier;
#[cfg(feature = "alloc")]
pub use value::{canonicalize, GgufValue};
pub use verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

/// The shared, format-independent ψ-tower (re-exported for convenience;
/// canonical path is [`crate::resolvers::AddressResolverTuple`]).
pub use crate::resolvers::AddressResolverTuple;
