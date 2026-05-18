//! `RingAddrBounds` — the ring-element realization's `HostBounds`
//! profile (wiki ADR-018 + ADR-037 + ARCHITECTURE.md § `uor-addr-ring`).

use prism::vocabulary::HostBounds;

/// Maximum Witt level admissible per Amendment 43 §2's tower (0..=3,
/// inclusive). The Witt-level byte at canonical-bytes offset 0 must
/// satisfy `witt_level ≤ MAX_WITT_LEVEL`.
pub const MAX_WITT_LEVEL: u8 = 3;

/// Maximum total byte width of a `RingElement`'s structurally-tagged
/// serialization. Sized to match
/// [`RingAddrBounds::TERM_VALUE_MAX_BYTES`] minus the ψ-stage
/// carrier overhead.
pub const RING_VALUE_MAX_BYTES: usize = 3968;

/// The ring realization's capacity profile. Mirrors the shape of
/// [`crate::json::AddrBounds`] / [`crate::sexp::SExprAddrBounds`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RingAddrBounds;

impl HostBounds for RingAddrBounds {
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
