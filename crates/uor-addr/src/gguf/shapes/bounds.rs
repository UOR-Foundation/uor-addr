//! `GgufHostBounds` — the GGUF realization's typed-input bound surface
//! plus the concrete carrier capacity profile (`GgufAddrBounds`).
//!
//! Two layers, per the spec's bounds discipline:
//!
//! - **Spec-pinned constants** (this module, `GGUF_*`) — fixed by the
//!   GGUF v3 specification; no application override.
//! - **Application-policy constants** (the [`GgufHostBounds`] trait) —
//!   the GGUF spec sets no ceiling on KV count, tensor count, string
//!   bytes, or array length (all `uint64`), so every applied bound is
//!   application policy. The crate ships **no** blanket default; the
//!   bundled [`GgufAddrBounds`] is the *encoding profile* the in-crate
//!   pipeline + C / WASM bindings use, calibrated to a TinyLlama-class
//!   reference model and cited inline. Applications requiring different
//!   ceilings declare their own `impl GgufHostBounds`.

use prism::vocabulary::HostBounds;

// ─── Spec-pinned GGUF v3 constants (no application override) ─────────────

/// `GGUF_MAGIC` — ASCII `"GGUF"` little-endian `u32`. Source: `gguf.md`.
pub const GGUF_MAGIC: u32 = 0x4655_4747;

/// The only GGUF version this realization admits. Source: `gguf.md`.
pub const GGUF_VERSION_REQUIRED: u32 = 3;

/// Header byte width: magic(4) + version(4) + tensor_count(8) +
/// kv_count(8). Source: `gguf.md`.
pub const GGUF_HEADER_BYTES: usize = 24;

/// Default tensor-data alignment when `general.alignment` is absent.
/// Overridable via that metadata key (must be a power of two ≥ 8).
/// Source: `gguf.h` `GGUF_DEFAULT_ALIGNMENT`.
pub const GGUF_DEFAULT_ALIGNMENT: u64 = 32;

/// Maximum tensor rank (`GGML_MAX_DIMS`). Source: `ggml.h`.
pub const GGUF_MAX_DIMS: usize = 4;

// ─── Carrier capacity (the structural canonical form fits here) ──────────

/// Byte width of the GGUF **canonical form** — a fixed 96-byte two-level
/// commitment that the ψ-pipeline carries and ψ₉ hashes:
///
/// ```text
/// LE_u32(magic) LE_u32(version) LE_u64(tensor_count) LE_u64(kv_count)
///   LE_u64(alignment) metadata_root[32] tensor_root[32]
/// ```
///
/// The section roots are streamed SHA-256 over the (unbounded) sorted
/// metadata / tensor skeletons at the host boundary, so the canonical
/// form stays a flat 96 bytes regardless of model size — within the
/// foundation pipeline's fixed 4096-byte route-input buffer. This buffer
/// reserves headroom above 96.
pub const GGUF_CANON_MAX_BYTES: usize = 256;

/// Exact byte width of the canonical commitment (see
/// [`GGUF_CANON_MAX_BYTES`]).
pub const GGUF_CANON_BYTES: usize = 4 + 4 + 8 + 8 + 8 + 32 + 32;

// ─── GgufHostBounds — application-policy typed-input bounds ───────────────

/// Application-policy bounds for GGUF typed input. Extends
/// [`HostBounds`] (the framework's 24-constant capacity profile, ADR-037)
/// with GGUF-specific ceilings the GGUF spec leaves open.
///
/// The crate ships no blanket default impl: every constant is policy.
/// Use `tools/calibrate-gguf-bounds.py` to derive the minimum admissible
/// values for a given model corpus.
pub trait GgufHostBounds: HostBounds {
    /// Maximum metadata key-value entry count.
    const GGUF_METADATA_KV_COUNT_MAX: usize;
    /// Maximum tensor count.
    const GGUF_TENSOR_COUNT_MAX: usize;
    /// Maximum metadata-key byte width.
    const GGUF_METADATA_KEY_BYTES_MAX: usize;
    /// Maximum string-value byte width (keys and string values).
    const GGUF_STRING_BYTES_MAX: usize;
    /// Maximum element count of a single metadata ARRAY value.
    const GGUF_METADATA_ARRAY_LEN_MAX: usize;
    /// Maximum nesting depth of ARRAY-of-ARRAY metadata values.
    const GGUF_METADATA_ARRAY_DEPTH_MAX: usize;
    /// Maximum aggregate tensor-data byte width.
    const GGUF_TENSOR_DATA_BYTES_MAX: u64;
}

/// The GGUF realization's concrete capacity profile — both the
/// [`HostBounds`] carrier ceilings and the [`GgufHostBounds`] encoding
/// bounds.
///
/// # Calibration
///
/// The [`GgufHostBounds`] constants are calibrated to admit a
/// TinyLlama-1.1B-class reference model (the smallest reference-quality
/// GGUF in the conformance corpus) with generous headroom:
///
/// - `GGUF_METADATA_KV_COUNT_MAX = 512` — TinyLlama declares ~24 KVs;
///   modern Llama-3 Tekken metadata reaches ~30.
/// - `GGUF_TENSOR_COUNT_MAX = 1024` — TinyLlama has 201 tensors;
///   8B-class models reach ~291.
/// - `GGUF_METADATA_ARRAY_LEN_MAX = 200_000` — covers a 128k-entry
///   tokenizer vocabulary array.
///
/// Applications admitting larger models declare their own
/// `impl GgufHostBounds`. (`tools/calibrate-gguf-bounds.py` reports the
/// minimum bounds for any given input.)
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GgufAddrBounds;

impl HostBounds for GgufAddrBounds {
    const FINGERPRINT_MIN_BYTES: usize = 32;
    const FINGERPRINT_MAX_BYTES: usize = 32;
    const TRACE_MAX_EVENTS: usize = 64;
    const WITT_LEVEL_MAX_BITS: u32 = 32;

    const TERM_VALUE_MAX_BYTES: usize = 4096;
    const AXIS_OUTPUT_BYTES_MAX: usize = 4096;
    const FOLD_UNROLL_THRESHOLD: usize = 8;
    const BETTI_DIMENSION_MAX: usize = 71;
    const NERVE_CONSTRAINTS_MAX: usize = 128;
    const NERVE_SITES_MAX: usize = 71;
    const JACOBIAN_SITES_MAX: usize = 71;
    const RECURSION_TRACE_DEPTH_MAX: usize = 16;
    const OP_CHAIN_DEPTH_MAX: usize = 8;
    const AFFINE_COEFFS_MAX: usize = 80;
    const CONJUNCTION_TERMS_MAX: usize = 128;
    const ROUTE_INPUT_BUFFER_BYTES: usize = 4096;
    const ROUTE_OUTPUT_BUFFER_BYTES: usize = 4096;
    const UNFOLD_ITERATIONS_MAX: usize = 256;

    const NERVE_OUTPUT_BYTES_MAX: usize = 4096;
    const CHAIN_COMPLEX_OUTPUT_BYTES_MAX: usize = 4096;
    const HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX: usize = 4096;
    const COCHAIN_COMPLEX_OUTPUT_BYTES_MAX: usize = 4096;
    const COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX: usize = 4096;
    const POSTNIKOV_TOWER_OUTPUT_BYTES_MAX: usize = 4096;
    const HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX: usize = 4096;
    const K_INVARIANTS_OUTPUT_BYTES_MAX: usize = 4096;
}

impl GgufHostBounds for GgufAddrBounds {
    const GGUF_METADATA_KV_COUNT_MAX: usize = 512;
    const GGUF_TENSOR_COUNT_MAX: usize = 1024;
    const GGUF_METADATA_KEY_BYTES_MAX: usize = 256;
    const GGUF_STRING_BYTES_MAX: usize = 1 << 20; // 1 MiB
    const GGUF_METADATA_ARRAY_LEN_MAX: usize = 200_000;
    const GGUF_METADATA_ARRAY_DEPTH_MAX: usize = 8;
    const GGUF_TENSOR_DATA_BYTES_MAX: u64 = 1 << 40; // 1 TiB
}
