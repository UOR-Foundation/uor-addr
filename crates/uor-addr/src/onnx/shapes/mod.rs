//! ONNX realization substitution-axis selections.
//!
//! - [`bounds`] — spec-pinned ONNX constants, the
//!   [`OnnxHostBounds`](bounds::OnnxHostBounds) application-policy bound
//!   trait, and the concrete [`OnnxAddrBounds`](bounds::OnnxAddrBounds)
//!   carrier + encoding profile.
//! - [`recurse`] — documents the depth-bounded subgraph recursion
//!   (ADR-057).
//! - [`Sha256Hasher`] — the canonical `Hasher` axis (re-export).

pub mod bounds;
pub mod recurse;

pub use bounds::{
    OnnxAddrBounds, OnnxHostBounds, ONNX_CANON_BYTES, ONNX_CANON_MAX_BYTES,
    ONNX_IR_VERSION_REQUIRED, ONNX_TENSOR_DATA_TYPE_MAX, ONNX_TENSOR_DATA_TYPE_MIN,
};
/// Canonical `Hasher<32>` selection. Re-exported from the Prism standard
/// library; see wiki ADR-031 / ADR-047.
pub use prism::crypto::Sha256Hasher;
