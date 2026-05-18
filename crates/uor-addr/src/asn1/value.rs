//! `Asn1Value` — typed ASN.1 input carrier with DER canonical bytes.
//!
//! The PrismModel's `Input` for the ASN.1 realization is
//! [`Asn1Value`], a typed carrier whose runtime bytes are the
//! DER-encoded byte sequence per ITU-T X.690 §§ 8 / 10 / 11. DER is
//! the canonical form by construction; the ψ_9 canonicalizer is the
//! identity on these bytes.
//!
//! # Supported universal-tag cases
//!
//! - `Boolean` (tag `0x01`) — single content byte: `0x00` (false) or
//!   `0xFF` (true) per X.690 §8.2.2 / §11.1.
//! - `Integer` (tag `0x02`) — minimum-octets two's-complement
//!   big-endian per X.690 §8.3 / §10.2.
//! - `OctetString` (tag `0x04`) — primitive encoding per X.690
//!   §8.7 / §10.2.
//! - `Null` (tag `0x05`) — zero-length content per X.690 §8.8.1.
//! - `Sequence` (tag `0x30`) — DER-encoded child sequence per
//!   X.690 §8.9.
//!
//! # Length encoding
//!
//! Length octets follow X.690 §8.1.3:
//! - Short form for lengths `< 128`: single octet `0x00..0x7F`.
//! - Long form for lengths `>= 128`: `0x8N` byte (N = byte count of
//!   length) followed by N length octets in big-endian.
//!
//! # Input parsing
//!
//! [`Asn1Value::parse`] consumes raw DER bytes. The parser validates
//! the encoding is *valid DER*, not just *valid BER* — long-form
//! lengths under the short-form threshold are rejected (X.690
//! §10.1).

extern crate alloc;

use alloc::vec::Vec;

use prism::pipeline::{
    register_shape, ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation,
    ViolationKind,
};

use crate::asn1::shapes::bounds::{ASN1_VALUE_MAX_BYTES, MAX_ASN1_DEPTH};

// ─── DER tag bytes ──────────────────────────────────────────────────────

pub(crate) const TAG_BOOLEAN: u8 = 0x01;
pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_NULL: u8 = 0x05;
pub(crate) const TAG_SEQUENCE: u8 = 0x30;

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

const INVALID_DER_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/Asn1Value",
    constraint_iri: "https://uor.foundation/addr/Asn1Value/validDer",
    property_iri: "https://uor.foundation/addr/inputBytes",
    expected_range: "https://uor.foundation/addr/ValidDerBytes",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

const DEPTH_BOUND_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/Asn1Value",
    constraint_iri: "https://uor.foundation/addr/Asn1Value/depthBound",
    property_iri: "https://uor.foundation/addr/Asn1Value/depth",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_ASN1_DEPTH as u32,
    kind: ViolationKind::CardinalityViolation,
};

const TOTAL_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/Asn1Value",
    constraint_iri: "https://uor.foundation/addr/Asn1Value/serializedWidth",
    property_iri: "https://uor.foundation/addr/Asn1Value/totalByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: ASN1_VALUE_MAX_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

// ─── Asn1Value — the typed input carrier ────────────────────────────────

/// Typed ASN.1 input shape. Runtime bytes are DER-encoded per X.690.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1Value {
    pub(crate) bytes: Vec<u8>,
}

impl Asn1Value {
    /// Construct from a DER-encoded byte sequence after validating
    /// it is well-formed DER per X.690.
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        if raw.len() > ASN1_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        // Validate the single-TLV structure by walking it.
        let mut pos = 0;
        validate_tlv(raw, &mut pos, 0)?;
        if pos != raw.len() {
            return Err(INVALID_DER_VIOLATION);
        }
        Ok(Self {
            bytes: raw.to_vec(),
        })
    }

    /// Build a Boolean (DER tag `0x01`).
    pub fn boolean(value: bool) -> Self {
        Self {
            bytes: alloc::vec![TAG_BOOLEAN, 1, if value { 0xFF } else { 0x00 }],
        }
    }

    /// Build a Null (DER tag `0x05`).
    pub fn null() -> Self {
        Self {
            bytes: alloc::vec![TAG_NULL, 0],
        }
    }

    /// Build an Integer (DER tag `0x02`) from a signed 64-bit value.
    /// DER §8.3: minimum-octets two's-complement big-endian.
    pub fn integer(value: i64) -> Self {
        // Drop leading 0x00 (positive) / 0xFF (negative) bytes that
        // don't change the sign per X.690 §8.3.2.
        let be = value.to_be_bytes();
        let mut start = 0;
        if value >= 0 {
            while start < 7 && be[start] == 0x00 && (be[start + 1] & 0x80) == 0 {
                start += 1;
            }
        } else {
            while start < 7 && be[start] == 0xFF && (be[start + 1] & 0x80) != 0 {
                start += 1;
            }
        }
        let content = &be[start..];
        let mut out = Vec::with_capacity(2 + content.len());
        out.push(TAG_INTEGER);
        out.extend_from_slice(&encode_length(content.len()));
        out.extend_from_slice(content);
        Self { bytes: out }
    }

    /// Build an OctetString (DER tag `0x04`) from raw bytes.
    pub fn octet_string(bytes: &[u8]) -> Self {
        let mut out = Vec::with_capacity(2 + bytes.len());
        out.push(TAG_OCTET_STRING);
        out.extend_from_slice(&encode_length(bytes.len()));
        out.extend_from_slice(bytes);
        Self { bytes: out }
    }

    /// Build a Sequence (DER tag `0x30`) wrapping the concatenated
    /// DER bytes of the supplied children.
    pub fn sequence(children: &[Asn1Value]) -> Self {
        let total_content: usize = children.iter().map(|c| c.bytes.len()).sum();
        let mut out = Vec::with_capacity(1 + 5 + total_content);
        out.push(TAG_SEQUENCE);
        out.extend_from_slice(&encode_length(total_content));
        for child in children {
            out.extend_from_slice(&child.bytes);
        }
        Self { bytes: out }
    }

    /// Borrow the DER-encoded canonical bytes — these are the bytes
    /// the SHA-256 σ-projection hashes inside ψ_9. DER is the
    /// canonical form per X.690 §10.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// X.690 §8.1.3 length octets — short form for lengths < 128,
/// long form for lengths ≥ 128.
fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        alloc::vec![len as u8]
    } else {
        // Compute minimum-byte-count big-endian length.
        let mut value = len;
        let mut bytes = Vec::new();
        while value > 0 {
            bytes.push((value & 0xFF) as u8);
            value >>= 8;
        }
        bytes.reverse();
        let mut out = Vec::with_capacity(1 + bytes.len());
        out.push(0x80 | (bytes.len() as u8));
        out.extend_from_slice(&bytes);
        out
    }
}

/// Walk a single TLV starting at `*pos` and validate it is well-formed
/// DER. Advances `*pos` past the TLV.
fn validate_tlv(buf: &[u8], pos: &mut usize, depth: usize) -> Result<(), ShapeViolation> {
    if depth > MAX_ASN1_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    if *pos >= buf.len() {
        return Err(INVALID_DER_VIOLATION);
    }
    let tag = buf[*pos];
    *pos += 1;
    let content_len = decode_length(buf, pos)?;
    if *pos + content_len > buf.len() {
        return Err(INVALID_DER_VIOLATION);
    }
    let content_end = *pos + content_len;
    match tag {
        TAG_BOOLEAN => {
            // §8.2.2 + §11.1: content is exactly one byte, 0x00 (false) or 0xFF (true).
            if content_len != 1 {
                return Err(INVALID_DER_VIOLATION);
            }
            let b = buf[*pos];
            if b != 0x00 && b != 0xFF {
                return Err(INVALID_DER_VIOLATION);
            }
            *pos += 1;
        }
        TAG_INTEGER => {
            // §8.3.1: content has at least one octet.
            // §8.3.2: leading two octets must not both be `0x00` or both `0xFF` with the next bit
            // continuing the sign — i.e. minimum-octets encoding.
            if content_len == 0 {
                return Err(INVALID_DER_VIOLATION);
            }
            if content_len >= 2 {
                let b0 = buf[*pos];
                let b1 = buf[*pos + 1];
                if b0 == 0x00 && (b1 & 0x80) == 0 {
                    return Err(INVALID_DER_VIOLATION);
                }
                if b0 == 0xFF && (b1 & 0x80) != 0 {
                    return Err(INVALID_DER_VIOLATION);
                }
            }
            *pos = content_end;
        }
        TAG_OCTET_STRING => {
            *pos = content_end;
        }
        TAG_NULL => {
            // §8.8.1: zero-length content.
            if content_len != 0 {
                return Err(INVALID_DER_VIOLATION);
            }
        }
        TAG_SEQUENCE => {
            // §8.9: walk children.
            while *pos < content_end {
                validate_tlv(buf, pos, depth + 1)?;
            }
            if *pos != content_end {
                return Err(INVALID_DER_VIOLATION);
            }
        }
        _ => return Err(INVALID_DER_VIOLATION),
    }
    Ok(())
}

fn decode_length(buf: &[u8], pos: &mut usize) -> Result<usize, ShapeViolation> {
    if *pos >= buf.len() {
        return Err(INVALID_DER_VIOLATION);
    }
    let first = buf[*pos];
    *pos += 1;
    if first < 0x80 {
        Ok(first as usize)
    } else {
        // X.690 §10.1: DER requires definite-length, short-form when
        // possible. Long-form values < 128 are valid BER but not DER.
        let nbytes = (first & 0x7F) as usize;
        if nbytes == 0 {
            // Indefinite-length (BER only).
            return Err(INVALID_DER_VIOLATION);
        }
        if nbytes > 4 || *pos + nbytes > buf.len() {
            return Err(INVALID_DER_VIOLATION);
        }
        let mut len: usize = 0;
        for _ in 0..nbytes {
            len = (len << 8) | (buf[*pos] as usize);
            *pos += 1;
        }
        if len < 128 {
            // Long-form for a length < 128 is non-canonical per
            // §10.1: reject.
            return Err(INVALID_DER_VIOLATION);
        }
        Ok(len)
    }
}

/// Canonical-bytes accessor. DER is the canonical form per X.690 §10
/// — the canonicalizer is the identity on well-formed input.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, ShapeViolation> {
    let value = Asn1Value::parse(raw)?;
    Ok(value.bytes)
}

/// Slice-output canonicalizer — the signature
/// [`crate::common::AddressInput::canonicalize_into`] requires.
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

impl ConstrainedTypeShape for Asn1Value {
    const IRI: &'static str = "https://uor.foundation/addr/Asn1Value";
    const SITE_COUNT: usize = ASN1_VALUE_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for Asn1Value {}

impl IntoBindingValue for Asn1Value {
    const MAX_BYTES: usize = ASN1_VALUE_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if self.bytes.len() > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

register_shape!(Asn1ValueRegistry, Asn1Value);

impl crate::common::AddressInput for Asn1Value {
    type Registry = Asn1ValueRegistry;

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
    fn boolean_der_encoding_matches_x690_8_2_2() {
        // X.690 §8.2.2 + §11.1: TRUE → 0xFF, FALSE → 0x00, single content byte.
        assert_eq!(Asn1Value::boolean(true).bytes, vec![0x01, 0x01, 0xFF]);
        assert_eq!(Asn1Value::boolean(false).bytes, vec![0x01, 0x01, 0x00]);
    }

    #[test]
    fn null_der_encoding_matches_x690_8_8() {
        assert_eq!(Asn1Value::null().bytes, vec![0x05, 0x00]);
    }

    #[test]
    fn integer_der_encoding_minimum_octets() {
        // 0 → single 0x00
        assert_eq!(Asn1Value::integer(0).bytes, vec![0x02, 0x01, 0x00]);
        // 127 → single 0x7F (high bit clear, no leading 0)
        assert_eq!(Asn1Value::integer(127).bytes, vec![0x02, 0x01, 0x7F]);
        // 128 → 0x00 0x80 (high bit set requires leading 0 to keep sign positive)
        assert_eq!(Asn1Value::integer(128).bytes, vec![0x02, 0x02, 0x00, 0x80]);
        // -1 → 0xFF
        assert_eq!(Asn1Value::integer(-1).bytes, vec![0x02, 0x01, 0xFF]);
        // -128 → 0x80
        assert_eq!(Asn1Value::integer(-128).bytes, vec![0x02, 0x01, 0x80]);
    }

    #[test]
    fn parse_round_trips_well_formed_der() {
        let cases: &[Vec<u8>] = &[
            Asn1Value::boolean(true).bytes,
            Asn1Value::null().bytes,
            Asn1Value::integer(42).bytes,
            Asn1Value::octet_string(b"hello").bytes,
            Asn1Value::sequence(&[Asn1Value::integer(1), Asn1Value::boolean(true)]).bytes,
        ];
        for bytes in cases {
            let parsed = Asn1Value::parse(bytes).expect("valid DER");
            assert_eq!(parsed.bytes, *bytes);
        }
    }

    #[test]
    fn rejects_non_canonical_boolean_byte() {
        // X.690 §11.1 — boolean must be 0x00 or 0xFF, not 0x01.
        let err = Asn1Value::parse(&[0x01, 0x01, 0x01]).expect_err("rejects non-canonical");
        assert_eq!(err.constraint_iri, INVALID_DER_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_non_minimum_integer_encoding() {
        // X.690 §8.3.2 — leading 0x00 with next-byte high bit clear
        // is non-minimal.
        let err = Asn1Value::parse(&[0x02, 0x02, 0x00, 0x01]).expect_err("non-minimal");
        assert_eq!(err.constraint_iri, INVALID_DER_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_long_form_length_under_128() {
        // X.690 §10.1 — long-form for length < 128 is non-canonical.
        let err = Asn1Value::parse(&[0x04, 0x81, 0x05, 0, 0, 0, 0, 0]).expect_err("non-canonical");
        assert_eq!(err.constraint_iri, INVALID_DER_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_indefinite_length() {
        // X.690 §10.1 — indefinite-length is BER only, not DER.
        let err = Asn1Value::parse(&[0x30, 0x80]).expect_err("BER not DER");
        assert_eq!(err.constraint_iri, INVALID_DER_VIOLATION.constraint_iri);
    }
}
