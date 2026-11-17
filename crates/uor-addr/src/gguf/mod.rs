//! **`uor_addr::gguf` — the GGUF v3 realization of UOR-ADDR.**
//!
//! Typed content-addressing for GGUF v3 model files
//! (`GGUF_MAGIC = 0x46554747`, `version = 3`) under a spec-canonical
//! structural form. The default σ-projection is
//! [`prism::crypto::Blake3Hasher`], the primary `u:digestAlgorithm` of the
//! UOR foundation ontology; [`address_sha256`], [`address_sha3_256`],
//! [`address_keccak256`], and [`address_sha512`] select the other axes
//! ([`crate::hash`]).
//!
//! ## σ-axis vs. the canonical form
//!
//! The leaf commitments inside the skeleton (tensor-data, array-payload,
//! and long-string digests) are **BLAKE3 by canonical-form definition**
//! ([`CANONICAL_FORM_VERSION`] 3) — a fixed part of the serialization,
//! exactly as JCS fixes JSON number formatting independently of the κ-hash.
//! A tensor's leaf is the BLAKE3 of its own bytes: the same 32 bytes as its
//! `blake3:` address anywhere else, and the root of the tree a Bao outboard
//! proves ranges against. The selected κ-axis `H` is applied *on top* of the
//! fixed canonical form: κ = `H(skeleton)`, so [`address`] is BLAKE3 from
//! leaf to label and [`address_sha256`] is `sha256(skeleton-with-blake3-leaves)`.
//! Canonical form 2 (SHA-256 leaves) is uor-addr 0.3.0's; its labels are
//! reproduced with that release.
//!
//! ## Authoritative sources
//!
//! - GGUF v3 binary format — <https://github.com/ggml-org/ggml/blob/master/docs/gguf.md>
//! - Reference C++ header — <https://github.com/ggml-org/ggml/blob/master/include/gguf.h>
//! - Reference Python tooling — <https://github.com/ggml-org/llama.cpp/tree/master/gguf-py>
//! - `ggml_type` enum / `GGML_MAX_DIMS` — <https://github.com/ggml-org/ggml/blob/master/include/ggml.h>
//! - BLAKE3 leaves and default σ-projection — <https://github.com/BLAKE3-team/BLAKE3-specs>.
//!
//! ## Canonical form
//!
//! The GGUF spec defines no canonical form; this realization defines one
//! (canonical form v3 — [`CANONICAL_FORM_VERSION`]). It is the **full
//! flat Merkle skeleton** (ADR-060): a structural form (header, metadata
//! KVs sorted by key bytes, tensor info sorted by name bytes with
//! recomputed canonical offsets) in which every variable-length leaf —
//! tensor data, metadata array payloads, long strings — is represented by
//! its 32-byte streamed BLAKE3 digest. The skeleton's size grows only
//! with the KV / tensor counts (never with model size) and flows through
//! the pipeline as a `Borrowed` carrier that ψ₉ folds; tensor data is
//! streamed through the hash axis at the host boundary (true incremental
//! BLAKE3) with bounded resident memory. There is no two-level
//! commitment and no count / width ceiling. See [`crate::gguf::value`]
//! for the full byte layout.
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
pub const CANONICAL_FORM_VERSION: u32 = 3;

pub use dtype::GgmlType;
pub use model::{
    AddressModel, AddressModelKeccak256, AddressModelSha256, AddressModelSha3_256,
    AddressModelSha512, AddressRoute,
};
#[cfg(feature = "alloc")]
pub use pipeline::{
    address, address as address_blake3, address_keccak256, address_sha256, address_sha3_256,
    address_sha512,
};
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
