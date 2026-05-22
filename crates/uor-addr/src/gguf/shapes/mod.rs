//! GGUF realization substitution-axis selections.
//!
//! - [`bounds`] — the spec-pinned GGUF v3 constants, the
//!   [`GgufHostBounds`](bounds::GgufHostBounds) application-policy bound
//!   trait, and the concrete [`GgufAddrBounds`](bounds::GgufAddrBounds)
//!   carrier + encoding profile.
//! - [`recurse`] — documents the depth-bounded ARRAY metadata recursion
//!   (ADR-057).
//! - [`Sha256Hasher`] — the canonical `Hasher` axis (re-export).

pub mod bounds;
pub mod recurse;

pub use bounds::{
    GgufAddrBounds, GgufHostBounds, GGUF_CANON_MAX_BYTES, GGUF_DEFAULT_ALIGNMENT, GGUF_HEADER_BYTES,
    GGUF_MAGIC, GGUF_MAX_DIMS, GGUF_VERSION_REQUIRED,
};
/// Canonical `Hasher<32>` selection. Re-exported from the Prism standard
/// library; see wiki ADR-031 / ADR-047.
pub use prism::crypto::Sha256Hasher;
