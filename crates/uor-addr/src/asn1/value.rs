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
//
// Universal-class tag numbers per ITU-T X.680 / X.690 §8.6 — §8.21.
// Constructed flag (0x20) included where DER mandates constructed
// encoding (Sequence, Set per §8.9/§8.11).

pub(crate) const TAG_BOOLEAN: u8 = 0x01;
pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_NULL: u8 = 0x05;
pub(crate) const TAG_OID: u8 = 0x06;
pub(crate) const TAG_UTF8_STRING: u8 = 0x0C;
pub(crate) const TAG_PRINTABLE_STRING: u8 = 0x13;
pub(crate) const TAG_IA5_STRING: u8 = 0x16;
pub(crate) const TAG_UTC_TIME: u8 = 0x17;
pub(crate) const TAG_GENERALIZED_TIME: u8 = 0x18;
pub(crate) const TAG_SEQUENCE: u8 = 0x30;
pub(crate) const TAG_SET: u8 = 0x31;

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
        Self::constructed(TAG_SEQUENCE, children)
    }

    /// Build a Set (DER tag `0x31`). DER (X.690 §11.6) requires Set
    /// element ordering by ascending tag value; for SET OF, by
    /// ascending encoded-element byte sequence. The caller supplies
    /// children in any order; this method sorts them per the DER
    /// canonical-encoding rule.
    pub fn set(children: &[Asn1Value]) -> Self {
        let mut sorted: Vec<&Asn1Value> = children.iter().collect();
        sorted.sort_by(|a, b| a.bytes.cmp(&b.bytes));
        let sorted_owned: Vec<Asn1Value> = sorted.into_iter().cloned().collect();
        Self::constructed(TAG_SET, &sorted_owned)
    }

    fn constructed(tag: u8, children: &[Asn1Value]) -> Self {
        let total_content: usize = children.iter().map(|c| c.bytes.len()).sum();
        let mut out = Vec::with_capacity(1 + 5 + total_content);
        out.push(tag);
        out.extend_from_slice(&encode_length(total_content));
        for child in children {
            out.extend_from_slice(&child.bytes);
        }
        Self { bytes: out }
    }

    /// Build a BIT STRING (DER tag `0x03`). X.690 §8.6 / §11.2:
    /// the first content octet encodes the number of unused bits in
    /// the final byte (0..=7). For DER primitive encoding (the only
    /// admissible form), unused bits must be zero.
    pub fn bit_string(bits: &[u8], unused_bits: u8) -> Result<Self, ShapeViolation> {
        if unused_bits > 7 {
            return Err(INVALID_DER_VIOLATION);
        }
        // §11.2 — if the bit string has zero length, unused_bits must be 0.
        if bits.is_empty() && unused_bits != 0 {
            return Err(INVALID_DER_VIOLATION);
        }
        // §11.2.1 — unused trailing bits must be set to zero.
        if !bits.is_empty() && unused_bits > 0 {
            let last = bits[bits.len() - 1];
            let mask = (1u8 << unused_bits) - 1;
            if last & mask != 0 {
                return Err(INVALID_DER_VIOLATION);
            }
        }
        let content_len = 1 + bits.len();
        let mut out = Vec::with_capacity(2 + content_len);
        out.push(TAG_BIT_STRING);
        out.extend_from_slice(&encode_length(content_len));
        out.push(unused_bits);
        out.extend_from_slice(bits);
        Ok(Self { bytes: out })
    }

    /// Build an OBJECT IDENTIFIER (DER tag `0x06`). X.690 §8.19
    /// encoding: first two arc values combine as `40*x1 + x2` into
    /// the first sub-identifier; each subsequent arc value encodes as
    /// base-128 with continuation bit per §8.19.2.
    pub fn object_identifier(arcs: &[u32]) -> Result<Self, ShapeViolation> {
        if arcs.len() < 2 {
            return Err(INVALID_DER_VIOLATION);
        }
        // §8.19.4 — x1 must be 0..=2; if x1 ∈ {0, 1}, x2 must be 0..=39.
        let x1 = arcs[0];
        let x2 = arcs[1];
        if x1 > 2 {
            return Err(INVALID_DER_VIOLATION);
        }
        if x1 < 2 && x2 >= 40 {
            return Err(INVALID_DER_VIOLATION);
        }
        let mut content = Vec::new();
        encode_oid_subid(40 * x1 + x2, &mut content);
        for &arc in &arcs[2..] {
            encode_oid_subid(arc, &mut content);
        }
        let mut out = Vec::with_capacity(2 + content.len());
        out.push(TAG_OID);
        out.extend_from_slice(&encode_length(content.len()));
        out.extend_from_slice(&content);
        Ok(Self { bytes: out })
    }

    /// Build a UTF8String (DER tag `0x0C`). X.690 §8.21 / §8.7 —
    /// primitive encoding of UTF-8 bytes.
    pub fn utf8_string(s: &str) -> Self {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(2 + bytes.len());
        out.push(TAG_UTF8_STRING);
        out.extend_from_slice(&encode_length(bytes.len()));
        out.extend_from_slice(bytes);
        Self { bytes: out }
    }

    /// Build a PrintableString (DER tag `0x13`). X.680 §41.4: admits
    /// `A..Z`, `a..z`, `0..9`, ` `, `'`, `(`, `)`, `+`, `,`, `-`, `.`,
    /// `/`, `:`, `=`, `?`. Caller is responsible for satisfying the
    /// character-set constraint; this constructor accepts any bytes
    /// (the typed-iso parser validates them on input admission).
    pub fn printable_string(s: &str) -> Result<Self, ShapeViolation> {
        for c in s.chars() {
            let ok = c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '\'' | '(' | ')' | '+' | ',' | '-' | '.' | '/' | ':' | '=' | '?'
                );
            if !ok {
                return Err(INVALID_DER_VIOLATION);
            }
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(2 + bytes.len());
        out.push(TAG_PRINTABLE_STRING);
        out.extend_from_slice(&encode_length(bytes.len()));
        out.extend_from_slice(bytes);
        Ok(Self { bytes: out })
    }

    /// Build an IA5String (DER tag `0x16`). X.680 §41.2: admits the
    /// 7-bit ASCII (IA5) character set (0..=127).
    pub fn ia5_string(s: &str) -> Result<Self, ShapeViolation> {
        if !s.is_ascii() {
            return Err(INVALID_DER_VIOLATION);
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(2 + bytes.len());
        out.push(TAG_IA5_STRING);
        out.extend_from_slice(&encode_length(bytes.len()));
        out.extend_from_slice(bytes);
        Ok(Self { bytes: out })
    }

    /// Borrow the DER-encoded canonical bytes — these are the bytes
    /// the SHA-256 σ-projection hashes inside ψ_9. DER is the
    /// canonical form per X.690 §10.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// X.690 §8.19.2 — base-128 encoding of an OID sub-identifier with
/// continuation bit set on all but the last byte.
fn encode_oid_subid(mut value: u32, out: &mut Vec<u8>) {
    if value == 0 {
        out.push(0);
        return;
    }
    let mut buf = [0u8; 5];
    let mut i = 0;
    while value > 0 {
        buf[i] = (value & 0x7F) as u8;
        value >>= 7;
        i += 1;
    }
    // Reverse, set continuation bit on all but the last.
    for j in (1..i).rev() {
        out.push(buf[j] | 0x80);
    }
    out.push(buf[0]);
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
        TAG_BIT_STRING => {
            // §8.6: first content octet is unused-bits count (0..=7).
            // §11.2.1: in DER, trailing unused bits must be zero.
            if content_len == 0 {
                return Err(INVALID_DER_VIOLATION);
            }
            let unused = buf[*pos];
            if unused > 7 {
                return Err(INVALID_DER_VIOLATION);
            }
            // For empty bit-string (content_len == 1), unused must be 0.
            if content_len == 1 && unused != 0 {
                return Err(INVALID_DER_VIOLATION);
            }
            // Trailing-zero requirement.
            if content_len > 1 && unused > 0 {
                let last = buf[content_end - 1];
                let mask = (1u8 << unused) - 1;
                if last & mask != 0 {
                    return Err(INVALID_DER_VIOLATION);
                }
            }
            *pos = content_end;
        }
        TAG_OID => {
            // §8.19: each sub-identifier is base-128 with continuation
            // bit; the last byte of each sub-identifier has bit 7
            // clear. §8.19.4 — no leading 0x80 (non-minimal encoding).
            if content_len == 0 {
                return Err(INVALID_DER_VIOLATION);
            }
            let mut p = *pos;
            while p < content_end {
                let sub_start = p;
                // Read continuation bytes until a byte with bit 7 clear.
                while p < content_end && buf[p] & 0x80 != 0 {
                    p += 1;
                }
                if p >= content_end {
                    // Continuation never terminated.
                    return Err(INVALID_DER_VIOLATION);
                }
                p += 1; // Include the terminator byte.
                        // §8.19.2 — non-minimal encoding: sub-identifier must
                        // not start with 0x80 (would mean an unnecessary
                        // leading zero in the base-128 representation).
                if p - sub_start > 1 && buf[sub_start] == 0x80 {
                    return Err(INVALID_DER_VIOLATION);
                }
            }
            if p != content_end {
                return Err(INVALID_DER_VIOLATION);
            }
            *pos = content_end;
        }
        TAG_UTF8_STRING => {
            // §8.21: content is a UTF-8 byte sequence. Validate UTF-8.
            let bytes = &buf[*pos..content_end];
            core::str::from_utf8(bytes).map_err(|_| INVALID_DER_VIOLATION)?;
            *pos = content_end;
        }
        TAG_PRINTABLE_STRING => {
            // X.680 §41.4: restricted character set.
            for &b in &buf[*pos..content_end] {
                let ok = b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b' ' | b'\''
                            | b'('
                            | b')'
                            | b'+'
                            | b','
                            | b'-'
                            | b'.'
                            | b'/'
                            | b':'
                            | b'='
                            | b'?'
                    );
                if !ok {
                    return Err(INVALID_DER_VIOLATION);
                }
            }
            *pos = content_end;
        }
        TAG_IA5_STRING => {
            // X.680 §41.2: 7-bit ASCII (0..=127).
            for &b in &buf[*pos..content_end] {
                if b > 127 {
                    return Err(INVALID_DER_VIOLATION);
                }
            }
            *pos = content_end;
        }
        TAG_UTC_TIME | TAG_GENERALIZED_TIME => {
            // X.690 §11.7 / §11.8 require canonical date-time
            // string forms — validate ASCII printability; full
            // calendar validation lives downstream of typed admission.
            for &b in &buf[*pos..content_end] {
                if !b.is_ascii() {
                    return Err(INVALID_DER_VIOLATION);
                }
            }
            *pos = content_end;
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
        TAG_SET => {
            // §8.11 + §11.6: walk children + canonical ordering
            // (element bytes in ascending order). For SET OF this is
            // strict; for SET (heterogeneous) tag-value ordering is
            // required. We validate the structural walk; the ordering
            // rule is enforced by the constructor.
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
