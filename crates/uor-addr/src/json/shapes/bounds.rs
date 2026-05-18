//! `AddrBounds` — `uor-addr`'s `HostBounds` selection
//! (wiki ADR-018, ADR-037).
//!
//! ADR-037 makes the catamorphism's 24-constant capacity profile
//! `HostBounds`-parametric: per-ψ-stage output ceilings, the route
//! input/output buffer sizes, the nerve/Betti/Jacobian array caps,
//! and the constraint-conjunction/affine-coefficient ceilings. This
//! module declares `uor-addr`'s binding ceiling.
//!
//! In addition to the 24 ADR-037 constants `HostBounds` requires,
//! this module declares **typed-input bounds** the host-boundary JSON
//! parser enforces at construction time when building a
//! [`crate::JsonValue`]. These bounds are not part of the
//! `HostBounds` trait surface; they are application-specific
//! constants the parser consults and the cost-model surface
//! references.

use prism::vocabulary::HostBounds;

// ─── typed-input bounds — JsonValue construction ceilings ───────────

/// Maximum recursion depth a `JsonValue` may carry. Inputs nested
/// deeper than this are rejected at parse time with a depth-bound
/// shape violation.
pub const MAX_JSON_DEPTH: usize = 32;

/// Maximum number of UTF-8 bytes any one JSON string value (or object
/// key) may carry. Strings longer than this are rejected at parse
/// time.
pub const MAX_STRING_BYTES: usize = 1024;

/// Maximum number of ASCII digit/sign/period/exponent characters any
/// one JSON number value may carry, after JCS-RFC8785 §3.2.2.3
/// normalization.
pub const MAX_NUMBER_DIGITS: usize = 64;

/// Maximum number of key-value pairs any one JSON object may carry.
pub const MAX_OBJECT_KEYS: usize = 256;

/// Maximum number of elements any one JSON array may carry.
pub const MAX_ARRAY_ELEMENTS: usize = 256;

/// Maximum total byte width of a `JsonValue`'s structurally-tagged
/// serialization (the byte form the typed-iso surface carries
/// through the ψ-pipeline). Sized to match
/// [`AddrBounds::TERM_VALUE_MAX_BYTES`] minus the 4-byte length
/// prefix and the 91-byte geometry-tail header each ψ-stage carrier
/// reserves — see [`crate::json::resolvers`].
pub const JSON_VALUE_MAX_BYTES: usize = 3968;

// ─── HostBounds selection ────────────────────────────────────────────

/// `uor-addr`'s capacity profile.
///
/// - `FINGERPRINT_MIN_BYTES = 32` — matches SHA-256 output width.
/// - `FINGERPRINT_MAX_BYTES = 32` — fixed; one `Hasher` selected via
///   [`crate::json::shapes::Sha256Hasher`] (re-export of
///   `prism::crypto::Sha256Hasher`).
/// - `TRACE_MAX_EVENTS = 64` — one event per ψ-stage transition.
/// - `WITT_LEVEL_MAX_BITS = 32` — the canonical content address is
///   71 ASCII bytes; the algebra is W32-bounded.
/// - `NERVE_SITES_MAX = 71` — the wire-format `AddressLabel` width.
/// - `*_OUTPUT_BYTES_MAX = 4096` — uniform across all ψ-stages; the
///   structurally-tagged `JsonValue` byte sequence is bounded by this.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddrBounds;

impl HostBounds for AddrBounds {
    // uor-addr-specific:
    const FINGERPRINT_MIN_BYTES: usize = 32;
    const FINGERPRINT_MAX_BYTES: usize = 32;
    const TRACE_MAX_EVENTS: usize = 64;
    const WITT_LEVEL_MAX_BITS: u32 = 32;

    // ADR-037 catamorphism ceilings — uniform 4 KiB per ψ-stage so
    // the structurally-tagged `JsonValue` byte sequence (bounded by
    // 4 KiB on the host boundary per `JSON_VALUE_MAX_BYTES`) fits
    // through every resolver carrier.
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

    // ADR-037 per-ψ-stage resolver-output ceilings — uniform 4 KiB.
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
        assert_eq!(<AddrBounds as HostBounds>::FINGERPRINT_MIN_BYTES, 32);
        assert_eq!(<AddrBounds as HostBounds>::FINGERPRINT_MAX_BYTES, 32);
        assert_eq!(<AddrBounds as HostBounds>::TRACE_MAX_EVENTS, 64);
        assert_eq!(<AddrBounds as HostBounds>::WITT_LEVEL_MAX_BITS, 32);
        assert_eq!(<AddrBounds as HostBounds>::NERVE_SITES_MAX, 71);
    }

    #[test]
    fn psi_stage_output_ceilings_uniform() {
        let v = <AddrBounds as HostBounds>::TERM_VALUE_MAX_BYTES;
        assert_eq!(<AddrBounds as HostBounds>::NERVE_OUTPUT_BYTES_MAX, v);
        assert_eq!(
            <AddrBounds as HostBounds>::CHAIN_COMPLEX_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <AddrBounds as HostBounds>::HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <AddrBounds as HostBounds>::COCHAIN_COMPLEX_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <AddrBounds as HostBounds>::COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <AddrBounds as HostBounds>::POSTNIKOV_TOWER_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <AddrBounds as HostBounds>::HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(<AddrBounds as HostBounds>::K_INVARIANTS_OUTPUT_BYTES_MAX, v);
    }

    // Typed-input bound floors are compile-time invariants: the parser
    // and Lean-side `maxJsonDepth` definitions reference these
    // constants, so any tightening below the documented floors is a
    // contract change. Failure surfaces at build time, not at runtime.
    const _: () = {
        assert!(MAX_JSON_DEPTH >= 4);
        assert!(MAX_STRING_BYTES >= 64);
        assert!(MAX_NUMBER_DIGITS >= 16);
        assert!(MAX_OBJECT_KEYS >= 16);
        assert!(MAX_ARRAY_ELEMENTS >= 16);
        assert!(JSON_VALUE_MAX_BYTES <= <AddrBounds as HostBounds>::TERM_VALUE_MAX_BYTES);
    };
}
