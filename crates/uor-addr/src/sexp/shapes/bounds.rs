//! `SExprAddrBounds` — the S-expression realization's `HostBounds`
//! profile (wiki ADR-018 + ADR-037 + ARCHITECTURE.md
//! "Format-specific realizations" § `uor-addr-sexp`).
//!
//! ADR-037 makes the catamorphism's 24-constant capacity profile
//! `HostBounds`-parametric: per-ψ-stage output ceilings, the route
//! input/output buffer sizes, the nerve/Betti/Jacobian array caps,
//! and the constraint-conjunction/affine-coefficient ceilings.
//!
//! In addition to the 24 ADR-037 constants `HostBounds` requires,
//! this module declares **typed-input bounds** the host-boundary
//! S-expression parser enforces at construction time when building a
//! [`crate::sexp::SExprValue`]. These bounds are not part of the
//! `HostBounds` trait surface; they are application-specific
//! constants the parser consults.

use prism::vocabulary::HostBounds;

// ─── typed-input bounds — SExprValue construction ceilings ───────────

/// Maximum recursion depth a `SExprValue` may carry. Inputs nested
/// deeper than this are rejected at parse time with a depth-bound
/// shape violation.
pub const MAX_SEXPR_DEPTH: usize = 32;

/// Maximum number of UTF-8 bytes any one atom may carry.
pub const MAX_SEXPR_ATOM_BYTES: usize = 1024;

/// Maximum number of elements any one cons-list may carry (counting
/// the chain of cons cells; lists deeper than this are rejected at
/// parse time).
pub const MAX_SEXPR_ELEMENTS: usize = 256;

/// Maximum total byte width of an `SExprValue`'s structurally-tagged
/// serialization. Sized to match
/// [`SExprAddrBounds::TERM_VALUE_MAX_BYTES`] minus the 4-byte length
/// prefix and the geometry-tail header each ψ-stage carrier reserves.
pub const SEXPR_VALUE_MAX_BYTES: usize = 3968;

// ─── HostBounds selection ────────────────────────────────────────────

/// The S-expression realization's capacity profile.
///
/// Mirrors the JSON realization's [`crate::json::AddrBounds`] shape
/// because every shipped UOR-ADDR realization binds
/// `H = prism::crypto::Sha256Hasher` (FINGERPRINT_*_BYTES = 32) and
/// the algebraic-closure shape of [`crate::AddressLabel`] pins the
/// SHA-256 specialization at 71 sites. The per-ψ-stage output
/// ceilings stay uniform (4 KiB) so the structurally-tagged
/// `SExprValue` byte sequence threads through every resolver
/// carrier.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SExprAddrBounds;

impl HostBounds for SExprAddrBounds {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_constants_match_addr_label_width() {
        assert_eq!(<SExprAddrBounds as HostBounds>::NERVE_SITES_MAX, 71);
        assert_eq!(<SExprAddrBounds as HostBounds>::FINGERPRINT_MAX_BYTES, 32);
    }

    const _: () = {
        assert!(MAX_SEXPR_DEPTH >= 4);
        assert!(MAX_SEXPR_ATOM_BYTES >= 64);
        assert!(MAX_SEXPR_ELEMENTS >= 16);
        assert!(SEXPR_VALUE_MAX_BYTES <= <SExprAddrBounds as HostBounds>::TERM_VALUE_MAX_BYTES);
    };
}
