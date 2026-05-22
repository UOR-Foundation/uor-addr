//! Bounded recursive structural typing for GGUF metadata (ADR-057).
//!
//! GGUF metadata `ARRAY` values may nest (an array whose element type is
//! itself `ARRAY`). The recursion target is therefore the metadata-value
//! grammar; the descent bound is the application-declared
//! [`GgufHostBounds::GGUF_METADATA_ARRAY_DEPTH_MAX`].
//!
//! Following the proven discipline of the JSON and S-expression
//! realizations (whose typed-input shapes are likewise recursive yet
//! declare `CONSTRAINTS = &[]`), the recursion is enforced **in the
//! parser**: [`crate::gguf::value`]'s `measure_value` descends ARRAY
//! payloads carrying an explicit `depth` counter and rejects any input
//! exceeding `GGUF_METADATA_ARRAY_DEPTH_MAX` with the
//! `…/GgufValue/arrayDepthBound` shape violation. The canonical form of
//! a nested array is the streamed SHA-256 digest of its (already
//! deterministic) wire payload — recursion bottoms out at the digest, so
//! the structural skeleton stays carrier-bounded at every depth.
//!
//! [`GgufHostBounds::GGUF_METADATA_ARRAY_DEPTH_MAX`]: crate::gguf::shapes::bounds::GgufHostBounds::GGUF_METADATA_ARRAY_DEPTH_MAX

use crate::gguf::shapes::bounds::{GgufAddrBounds, GgufHostBounds};

/// The metadata ARRAY descent bound under the bundled encoding profile —
/// the `descent_bound` an `ADR-057` `ConstraintRef::Recurse` would carry
/// for the metadata-value grammar.
pub const METADATA_ARRAY_DESCENT_BOUND: usize =
    <GgufAddrBounds as GgufHostBounds>::GGUF_METADATA_ARRAY_DEPTH_MAX;
