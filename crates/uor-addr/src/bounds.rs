//! `AddrBounds` — the single `HostBounds` capacity profile shared by
//! every UOR-ADDR realization (ADR-037), and the foundation-derived
//! inline-carrier width [`ADDR_INLINE_BYTES`] (ADR-060).
//!
//! ADR-060 removed the fixed per-ψ-stage byte-width ceilings
//! (`TERM_VALUE_MAX_BYTES`, `AXIS_OUTPUT_BYTES_MAX`,
//! `ROUTE_INPUT_BUFFER_BYTES`, …): a realization's canonical form flows
//! through the pipeline as a source-polymorphic [`prism::operation::TermValue`]
//! carrier (`Borrowed` / `Stream`) with no size cap. The remaining
//! `HostBounds` constants are structural-count / catamorphism-trace caps,
//! identical across realizations. Every admissible σ-axis ([`crate::hash`])
//! is a `Hasher<32>`, so the fingerprint width is fixed at 32; the
//! site-count ceilings admit the widest κ-label geometry (keccak256's
//! 74-site shape).

use prism::uor_foundation::pipeline::carrier_inline_bytes;
use prism::vocabulary::HostBounds;

/// The shared capacity profile. Every realization's `PrismModel` binds
/// this `B`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddrBounds;

impl HostBounds for AddrBounds {
    const FINGERPRINT_MIN_BYTES: usize = 32;
    const FINGERPRINT_MAX_BYTES: usize = 32;
    const TRACE_MAX_EVENTS: usize = 256;
    const WITT_LEVEL_MAX_BITS: u32 = 32;

    const FOLD_UNROLL_THRESHOLD: usize = 8;
    const BETTI_DIMENSION_MAX: usize = 74;
    const NERVE_CONSTRAINTS_MAX: usize = 128;
    const NERVE_SITES_MAX: usize = 74;
    const JACOBIAN_SITES_MAX: usize = 74;
    const RECURSION_TRACE_DEPTH_MAX: usize = 16;
    const OP_CHAIN_DEPTH_MAX: usize = 8;
    const AFFINE_COEFFS_MAX: usize = 80;
    const CONJUNCTION_TERMS_MAX: usize = 128;
    const UNFOLD_ITERATIONS_MAX: usize = 256;
}

/// The foundation-derived inline-carrier width for [`AddrBounds`]
/// (ADR-060). For the SHA-256 σ-axis this is the κ-label ASCII width
/// (`sha256:` + 64 hex = 71) rounded up by the hasher-identifier header —
/// large enough for the Inline κ-label ψ₉ emits, and unrelated to input
/// size (large inputs flow as `Borrowed` / `Stream`).
pub const ADDR_INLINE_BYTES: usize = carrier_inline_bytes::<AddrBounds>();
