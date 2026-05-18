//! `RingElement` — typed ring-element carrier per UOR-Framework
//! Amendment 43 §2's `Element::canonical_bytes` layout.
//!
//! The PrismModel's `Input` for the ring realization is
//! [`RingElement`], a typed carrier whose runtime bytes are
//!
//! ```text
//! tagged_bytes(e) := [witt_level: u8] || [coefficient: u8; witt_level + 1]
//! ```
//!
//! identical to the canonical-bytes layout — the structurally-tagged
//! byte form **is** the canonical form for this realization, so the
//! canonicalizer is the identity function (Amendment 43 pins the
//! canonical bytes at construction, no further canonicalization step
//! is required at ψ_9).
//!
//! # Input parsing
//!
//! [`RingElement::parse`] consumes raw bytes shaped as the canonical
//! Amendment 43 layout. The host-boundary parser validates:
//!
//! - The Witt-level byte is `≤ MAX_WITT_LEVEL` (currently 3 per the
//!   amendment's tower).
//! - The total byte width is exactly `1 + (witt_level + 1)` bytes —
//!   2 bytes for `witt_level = 0`, 5 bytes for `witt_level = 3`.

extern crate alloc;

use alloc::vec::Vec;

use prism::pipeline::{
    register_shape, ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation,
    ViolationKind,
};

use crate::ring::shapes::bounds::{MAX_WITT_LEVEL, RING_VALUE_MAX_BYTES};

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

const INVALID_RING_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/RingElement",
    constraint_iri: "https://uor.foundation/addr/RingElement/validCanonicalBytes",
    property_iri: "https://uor.foundation/addr/inputBytes",
    expected_range: "https://uor.foundation/addr/ValidRingElementBytes",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

const WITT_LEVEL_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/RingElement",
    constraint_iri: "https://uor.foundation/addr/RingElement/wittLevelBound",
    property_iri: "https://uor.foundation/addr/RingElement/wittLevel",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedByte",
    min_count: 0,
    max_count: MAX_WITT_LEVEL as u32,
    kind: ViolationKind::CardinalityViolation,
};

const TOTAL_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/RingElement",
    constraint_iri: "https://uor.foundation/addr/RingElement/serializedWidth",
    property_iri: "https://uor.foundation/addr/RingElement/totalByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: RING_VALUE_MAX_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

// ─── RingElement — the typed input carrier ──────────────────────────────

/// Typed ring-element input shape. Runtime bytes follow Amendment 43
/// §2's canonical-bytes layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingElement {
    pub(crate) bytes: Vec<u8>,
}

impl RingElement {
    /// Construct a `RingElement` from explicit Witt level + coefficient.
    /// Returns `Err(WITT_LEVEL_VIOLATION)` if `witt_level >
    /// MAX_WITT_LEVEL`.
    pub fn from_components(witt_level: u8, coefficient: u64) -> Result<Self, ShapeViolation> {
        if witt_level > MAX_WITT_LEVEL {
            return Err(WITT_LEVEL_VIOLATION);
        }
        let coefficient_bytes = (witt_level + 1) as usize;
        let mut bytes = Vec::with_capacity(1 + coefficient_bytes);
        bytes.push(witt_level);
        let le = coefficient.to_le_bytes();
        bytes.extend_from_slice(&le[..coefficient_bytes]);
        Ok(Self { bytes })
    }

    /// Parse raw canonical-bytes into a typed `RingElement`.
    ///
    /// # Errors
    ///
    /// - `validCanonicalBytes` — input is empty or its width does not
    ///   match `1 + (witt_level + 1)`.
    /// - `wittLevelBound` — the Witt-level byte exceeds
    ///   [`MAX_WITT_LEVEL`].
    /// - `serializedWidth` — the input exceeds
    ///   [`RING_VALUE_MAX_BYTES`].
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        if raw.is_empty() {
            return Err(INVALID_RING_VIOLATION);
        }
        if raw.len() > RING_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        let witt_level = raw[0];
        if witt_level > MAX_WITT_LEVEL {
            return Err(WITT_LEVEL_VIOLATION);
        }
        let expected_len = 1 + (witt_level as usize + 1);
        if raw.len() != expected_len {
            return Err(INVALID_RING_VIOLATION);
        }
        Ok(Self {
            bytes: raw.to_vec(),
        })
    }

    /// Borrow the canonical-bytes byte sequence — the same bytes the
    /// SHA-256 σ-projection hashes inside ψ_9.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The element's Witt level (the first byte of the canonical
    /// layout).
    #[must_use]
    pub fn witt_level(&self) -> u8 {
        self.bytes[0]
    }
}

/// Canonical-bytes accessor. For the ring realization, the
/// structurally-tagged bytes **are** the canonical bytes (Amendment
/// 43 §2 pins them at construction), so the canonicalizer is the
/// identity on well-formed input.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, ShapeViolation> {
    let element = RingElement::parse(raw)?;
    Ok(element.bytes)
}

/// Slice-output canonicalizer — the signature
/// [`crate::common::AddressInput::canonicalize_into`] requires. For
/// ring elements the canonical form is the identity transform on
/// the tagged bytes per Amendment 43 §2.
pub(crate) fn canonicalize_into_slice(
    tagged: &[u8],
    out: &mut [u8],
) -> Result<usize, ShapeViolation> {
    if tagged.len() > out.len() {
        return Err(TOTAL_WIDTH_VIOLATION);
    }
    out[..tagged.len()].copy_from_slice(tagged);
    Ok(tagged.len())
}

// ─── ConstrainedTypeShape + IntoBindingValue + AddressInput ──────────────

impl ConstrainedTypeShape for RingElement {
    const IRI: &'static str = "https://uor.foundation/addr/RingElement";
    const SITE_COUNT: usize = RING_VALUE_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for RingElement {}

impl IntoBindingValue for RingElement {
    const MAX_BYTES: usize = RING_VALUE_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if self.bytes.len() > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

register_shape!(RingElementRegistry, RingElement);

impl crate::common::AddressInput for RingElement {
    type Registry = RingElementRegistry;

    #[inline]
    fn canonicalize_into(parser_emitted: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        canonicalize_into_slice(parser_emitted, out)
    }

    #[inline]
    fn parse(input: &[u8]) -> Result<Self, ShapeViolation> {
        Self::parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_components_round_trip() {
        let e = RingElement::from_components(2, 0x0001_0203).expect("valid");
        // witt_level = 2, coefficient = 4 LE bytes (but Amendment 43
        // pins coefficient_bytes = witt_level + 1 = 3)
        assert_eq!(e.bytes[0], 2);
        assert_eq!(&e.bytes[1..], &[0x03, 0x02, 0x01]);
    }

    #[test]
    fn parse_matches_construction() {
        let constructed = RingElement::from_components(1, 0x0102).expect("valid");
        let parsed = RingElement::parse(&[1, 0x02, 0x01]).expect("valid");
        assert_eq!(constructed, parsed);
    }

    #[test]
    fn rejects_overflow_witt_level() {
        let err = RingElement::from_components(MAX_WITT_LEVEL + 1, 0).expect_err("must reject");
        assert_eq!(err.constraint_iri, WITT_LEVEL_VIOLATION.constraint_iri);
        let err = RingElement::parse(&[MAX_WITT_LEVEL + 1, 0]).expect_err("must reject");
        assert_eq!(err.constraint_iri, WITT_LEVEL_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_truncated_bytes() {
        // witt_level = 2 requires 1 + 3 = 4 bytes total
        let err = RingElement::parse(&[2, 0, 0]).expect_err("must reject");
        assert_eq!(err.constraint_iri, INVALID_RING_VIOLATION.constraint_iri);
    }

    #[test]
    fn canonicalize_is_identity_on_canonical_form() {
        // Amendment 43 §2 pins canonical bytes at construction — the
        // canonicalizer is the identity function.
        let bytes = &[0u8, 0x42];
        let canon = canonicalize(bytes).expect("valid");
        assert_eq!(canon, bytes);
    }
}
