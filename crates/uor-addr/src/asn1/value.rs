//! `Asn1Value` — typed ASN.1 input carrier with DER canonical bytes.
//!
//! Runtime bytes are the DER-encoded byte sequence per ITU-T X.690
//! §§ 8 / 10 / 11. DER is the canonical form by construction; the ψ_9
//! canonicalizer is the identity on these bytes.
//!
//! # `no_std` + `no_alloc`
//!
//! [`Asn1Value`] is a fixed-size stack carrier ([`u8; ASN1_VALUE_MAX_BYTES`]
//! plus a `u16` length). All constructors (`boolean`, `integer`,
//! `sequence`, `set`, …) write DER bytes directly into the fixed
//! buffer; no allocator is touched.
//!
//! # Supported universal-tag cases
//!
//! - `Boolean`, `Integer`, `BitString`, `OctetString`, `Null`,
//!   `ObjectIdentifier`, `Utf8String`, `PrintableString`, `IA5String`,
//!   `UTCTime`, `GeneralizedTime`, `Sequence`, `Set`.
//!
//! # Length encoding (X.690 §8.1.3)
//!
//! - Short form for lengths `< 128`: single octet `0x00..0x7F`.
//! - Long form for lengths `>= 128`: `0x8N` byte (`N` = byte count of
//!   length) followed by `N` length octets in big-endian.
//!
//! [`Asn1Value::parse`] validates the encoding is **valid DER**, not
//! just valid BER — long-form lengths under the short-form threshold
//! are rejected (X.690 §10.1).

use prism::pipeline::{
    register_shape, ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation,
    ViolationKind,
};

use crate::asn1::shapes::bounds::{ASN1_VALUE_MAX_BYTES, MAX_ASN1_DEPTH, MAX_ASN1_ELEMENTS};

// ─── DER tag bytes ──────────────────────────────────────────────────────

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

/// Typed ASN.1 input shape. Runtime bytes are DER-encoded per X.690,
/// stored in a fixed-size stack buffer.
#[derive(Clone)]
pub struct Asn1Value {
    pub(crate) bytes: [u8; ASN1_VALUE_MAX_BYTES],
    pub(crate) len: u16,
}

impl core::fmt::Debug for Asn1Value {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Asn1Value")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Asn1Value {
    fn eq(&self, other: &Self) -> bool {
        self.tagged_bytes() == other.tagged_bytes()
    }
}

impl Eq for Asn1Value {}

impl Asn1Value {
    fn empty() -> Self {
        Self {
            bytes: [0u8; ASN1_VALUE_MAX_BYTES],
            len: 0,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ShapeViolation> {
        if bytes.len() > ASN1_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        let mut me = Self::empty();
        me.bytes[..bytes.len()].copy_from_slice(bytes);
        me.len = bytes.len() as u16;
        Ok(me)
    }

    /// Construct from a DER-encoded byte sequence after validating it
    /// is well-formed DER per X.690.
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        if raw.len() > ASN1_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        let mut pos = 0;
        validate_tlv(raw, &mut pos, 0)?;
        if pos != raw.len() {
            return Err(INVALID_DER_VIOLATION);
        }
        Self::from_bytes(raw)
    }

    /// Build a Boolean (DER tag `0x01`).
    pub fn boolean(value: bool) -> Self {
        let bytes = [TAG_BOOLEAN, 1, if value { 0xFF } else { 0x00 }];
        Self::from_bytes(&bytes).expect("3 bytes fits")
    }

    /// Build a Null (DER tag `0x05`).
    pub fn null() -> Self {
        Self::from_bytes(&[TAG_NULL, 0]).expect("2 bytes fits")
    }

    /// Build an Integer (DER tag `0x02`) from a signed 64-bit value.
    /// DER §8.3: minimum-octets two's-complement big-endian.
    pub fn integer(value: i64) -> Self {
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
        let mut buf = [0u8; 16];
        let mut len = 0;
        buf[len] = TAG_INTEGER;
        len += 1;
        len += encode_length_into(content.len(), &mut buf[len..]);
        buf[len..len + content.len()].copy_from_slice(content);
        len += content.len();
        Self::from_bytes(&buf[..len]).expect("integer fits 16 bytes")
    }

    /// Build an OctetString (DER tag `0x04`) from raw bytes.
    pub fn octet_string(bytes: &[u8]) -> Result<Self, ShapeViolation> {
        Self::primitive(TAG_OCTET_STRING, bytes)
    }

    fn primitive(tag: u8, content: &[u8]) -> Result<Self, ShapeViolation> {
        let mut me = Self::empty();
        me.push_byte(tag)?;
        me.push_length(content.len())?;
        me.extend(content)?;
        Ok(me)
    }

    /// Build a Sequence (DER tag `0x30`).
    pub fn sequence(children: &[Asn1Value]) -> Result<Self, ShapeViolation> {
        Self::constructed(TAG_SEQUENCE, children, false)
    }

    /// Build a Set (DER tag `0x31`). DER (X.690 §11.6) requires Set
    /// element ordering by ascending encoded-element byte sequence.
    pub fn set(children: &[Asn1Value]) -> Result<Self, ShapeViolation> {
        Self::constructed(TAG_SET, children, true)
    }

    fn constructed(tag: u8, children: &[Asn1Value], sort: bool) -> Result<Self, ShapeViolation> {
        if children.len() > MAX_ASN1_ELEMENTS {
            return Err(INVALID_DER_VIOLATION);
        }
        let total_content: usize = children.iter().map(|c| c.len as usize).sum();
        let mut me = Self::empty();
        me.push_byte(tag)?;
        me.push_length(total_content)?;
        if sort {
            // Stack-local index array. Sort indices by child byte
            // sequence per X.690 §11.6.
            let mut order = [0u16; MAX_ASN1_ELEMENTS];
            for (i, slot) in order[..children.len()].iter_mut().enumerate() {
                *slot = i as u16;
            }
            insertion_sort_children(&mut order[..children.len()], children);
            for &idx in &order[..children.len()] {
                me.extend(children[idx as usize].tagged_bytes())?;
            }
        } else {
            for child in children {
                me.extend(child.tagged_bytes())?;
            }
        }
        Ok(me)
    }

    /// Build a BIT STRING (DER tag `0x03`). X.690 §8.6 / §11.2.
    pub fn bit_string(bits: &[u8], unused_bits: u8) -> Result<Self, ShapeViolation> {
        if unused_bits > 7 {
            return Err(INVALID_DER_VIOLATION);
        }
        if bits.is_empty() && unused_bits != 0 {
            return Err(INVALID_DER_VIOLATION);
        }
        if !bits.is_empty() && unused_bits > 0 {
            let last = bits[bits.len() - 1];
            let mask = (1u8 << unused_bits) - 1;
            if last & mask != 0 {
                return Err(INVALID_DER_VIOLATION);
            }
        }
        let content_len = 1 + bits.len();
        let mut me = Self::empty();
        me.push_byte(TAG_BIT_STRING)?;
        me.push_length(content_len)?;
        me.push_byte(unused_bits)?;
        me.extend(bits)?;
        Ok(me)
    }

    /// Build an OBJECT IDENTIFIER (DER tag `0x06`). X.690 §8.19.
    pub fn object_identifier(arcs: &[u32]) -> Result<Self, ShapeViolation> {
        if arcs.len() < 2 {
            return Err(INVALID_DER_VIOLATION);
        }
        let x1 = arcs[0];
        let x2 = arcs[1];
        if x1 > 2 {
            return Err(INVALID_DER_VIOLATION);
        }
        if x1 < 2 && x2 >= 40 {
            return Err(INVALID_DER_VIOLATION);
        }
        // Encode into a stack-local content buffer first to compute
        // the length, then write tag + length + content into Self.
        let mut content = [0u8; 256];
        let mut clen = 0usize;
        encode_oid_subid_into(40 * x1 + x2, &mut content, &mut clen)?;
        for &arc in &arcs[2..] {
            encode_oid_subid_into(arc, &mut content, &mut clen)?;
        }
        let mut me = Self::empty();
        me.push_byte(TAG_OID)?;
        me.push_length(clen)?;
        me.extend(&content[..clen])?;
        Ok(me)
    }

    /// Build a UTF8String (DER tag `0x0C`).
    pub fn utf8_string(s: &str) -> Result<Self, ShapeViolation> {
        Self::primitive(TAG_UTF8_STRING, s.as_bytes())
    }

    /// Build a PrintableString (DER tag `0x13`). X.680 §41.4 character set.
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
        Self::primitive(TAG_PRINTABLE_STRING, s.as_bytes())
    }

    /// Build an IA5String (DER tag `0x16`). X.680 §41.2.
    pub fn ia5_string(s: &str) -> Result<Self, ShapeViolation> {
        if !s.is_ascii() {
            return Err(INVALID_DER_VIOLATION);
        }
        Self::primitive(TAG_IA5_STRING, s.as_bytes())
    }

    /// Borrow the DER-encoded canonical bytes — these are the bytes
    /// the SHA-256 σ-projection hashes inside ψ_9. DER is the
    /// canonical form per X.690 §10.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    fn push_byte(&mut self, b: u8) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos >= ASN1_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos] = b;
        self.len += 1;
        Ok(())
    }

    fn extend(&mut self, data: &[u8]) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos + data.len() > ASN1_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos..pos + data.len()].copy_from_slice(data);
        self.len += data.len() as u16;
        Ok(())
    }

    fn push_length(&mut self, len: usize) -> Result<(), ShapeViolation> {
        let mut buf = [0u8; 5];
        let n = encode_length_into(len, &mut buf);
        self.extend(&buf[..n])
    }
}

fn insertion_sort_children(order: &mut [u16], children: &[Asn1Value]) {
    for i in 1..order.len() {
        let mut j = i;
        while j > 0 {
            let a = children[order[j - 1] as usize].tagged_bytes();
            let b = children[order[j] as usize].tagged_bytes();
            if a > b {
                order.swap(j - 1, j);
                j -= 1;
            } else {
                break;
            }
        }
    }
}

/// X.690 §8.19.2 — base-128 encoding of an OID sub-identifier.
fn encode_oid_subid_into(
    mut value: u32,
    out: &mut [u8],
    cursor: &mut usize,
) -> Result<(), ShapeViolation> {
    if value == 0 {
        if *cursor >= out.len() {
            return Err(INVALID_DER_VIOLATION);
        }
        out[*cursor] = 0;
        *cursor += 1;
        return Ok(());
    }
    let mut buf = [0u8; 5];
    let mut i = 0;
    while value > 0 {
        buf[i] = (value & 0x7F) as u8;
        value >>= 7;
        i += 1;
    }
    for j in (1..i).rev() {
        if *cursor >= out.len() {
            return Err(INVALID_DER_VIOLATION);
        }
        out[*cursor] = buf[j] | 0x80;
        *cursor += 1;
    }
    if *cursor >= out.len() {
        return Err(INVALID_DER_VIOLATION);
    }
    out[*cursor] = buf[0];
    *cursor += 1;
    Ok(())
}

/// X.690 §8.1.3 length octets, writing into `out`. Returns bytes written.
fn encode_length_into(len: usize, out: &mut [u8]) -> usize {
    if len < 128 {
        out[0] = len as u8;
        return 1;
    }
    let mut value = len;
    let mut bytes = [0u8; 8];
    let mut count = 0;
    while value > 0 {
        bytes[count] = (value & 0xFF) as u8;
        value >>= 8;
        count += 1;
    }
    out[0] = 0x80 | (count as u8);
    for i in 0..count {
        out[1 + i] = bytes[count - 1 - i];
    }
    1 + count
}

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
            if content_len != 0 {
                return Err(INVALID_DER_VIOLATION);
            }
        }
        TAG_BIT_STRING => {
            if content_len == 0 {
                return Err(INVALID_DER_VIOLATION);
            }
            let unused = buf[*pos];
            if unused > 7 {
                return Err(INVALID_DER_VIOLATION);
            }
            if content_len == 1 && unused != 0 {
                return Err(INVALID_DER_VIOLATION);
            }
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
            if content_len == 0 {
                return Err(INVALID_DER_VIOLATION);
            }
            let mut p = *pos;
            while p < content_end {
                let sub_start = p;
                while p < content_end && buf[p] & 0x80 != 0 {
                    p += 1;
                }
                if p >= content_end {
                    return Err(INVALID_DER_VIOLATION);
                }
                p += 1;
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
            let bytes = &buf[*pos..content_end];
            core::str::from_utf8(bytes).map_err(|_| INVALID_DER_VIOLATION)?;
            *pos = content_end;
        }
        TAG_PRINTABLE_STRING => {
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
            for &b in &buf[*pos..content_end] {
                if b > 127 {
                    return Err(INVALID_DER_VIOLATION);
                }
            }
            *pos = content_end;
        }
        TAG_UTC_TIME | TAG_GENERALIZED_TIME => {
            for &b in &buf[*pos..content_end] {
                if !b.is_ascii() {
                    return Err(INVALID_DER_VIOLATION);
                }
            }
            *pos = content_end;
        }
        TAG_SEQUENCE => {
            while *pos < content_end {
                validate_tlv(buf, pos, depth + 1)?;
            }
            if *pos != content_end {
                return Err(INVALID_DER_VIOLATION);
            }
        }
        TAG_SET => {
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
        let nbytes = (first & 0x7F) as usize;
        if nbytes == 0 {
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
            return Err(INVALID_DER_VIOLATION);
        }
        Ok(len)
    }
}

// ─── Canonical-bytes accessor ───────────────────────────────────────────

/// **Available only under the `alloc` feature.** Canonical-bytes
/// accessor — DER is the canonical form per X.690 §10; the
/// canonicalizer is the identity on well-formed input. The no_alloc
/// equivalent is [`canonicalize_into_slice`].
#[cfg(feature = "alloc")]
pub fn canonicalize(raw: &[u8]) -> Result<alloc::vec::Vec<u8>, ShapeViolation> {
    extern crate alloc;
    let value = Asn1Value::parse(raw)?;
    Ok(value.tagged_bytes().to_vec())
}

/// Slice-output canonicalizer.
pub fn canonicalize_into_slice(tagged: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
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
        let n = self.len as usize;
        if n > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..n].copy_from_slice(&self.bytes[..n]);
        Ok(n)
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
        assert_eq!(Asn1Value::boolean(true).tagged_bytes(), &[0x01, 0x01, 0xFF]);
        assert_eq!(
            Asn1Value::boolean(false).tagged_bytes(),
            &[0x01, 0x01, 0x00]
        );
    }

    #[test]
    fn null_der_encoding_matches_x690_8_8() {
        assert_eq!(Asn1Value::null().tagged_bytes(), &[0x05, 0x00]);
    }

    #[test]
    fn integer_der_encoding_minimum_octets() {
        assert_eq!(Asn1Value::integer(0).tagged_bytes(), &[0x02, 0x01, 0x00]);
        assert_eq!(Asn1Value::integer(127).tagged_bytes(), &[0x02, 0x01, 0x7F]);
        assert_eq!(
            Asn1Value::integer(128).tagged_bytes(),
            &[0x02, 0x02, 0x00, 0x80]
        );
        assert_eq!(Asn1Value::integer(-1).tagged_bytes(), &[0x02, 0x01, 0xFF]);
        assert_eq!(Asn1Value::integer(-128).tagged_bytes(), &[0x02, 0x01, 0x80]);
    }

    #[test]
    fn parse_round_trips_well_formed_der() {
        let cases: &[Asn1Value] = &[
            Asn1Value::boolean(true),
            Asn1Value::null(),
            Asn1Value::integer(42),
            Asn1Value::octet_string(b"hello").unwrap(),
            Asn1Value::sequence(&[Asn1Value::integer(1), Asn1Value::boolean(true)]).unwrap(),
        ];
        for v in cases {
            let parsed = Asn1Value::parse(v.tagged_bytes()).expect("valid DER");
            assert_eq!(parsed.tagged_bytes(), v.tagged_bytes());
        }
    }

    #[test]
    fn rejects_non_canonical_boolean_byte() {
        let err = Asn1Value::parse(&[0x01, 0x01, 0x01]).expect_err("rejects non-canonical");
        assert_eq!(err.constraint_iri, INVALID_DER_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_non_minimum_integer_encoding() {
        let err = Asn1Value::parse(&[0x02, 0x02, 0x00, 0x01]).expect_err("non-minimal");
        assert_eq!(err.constraint_iri, INVALID_DER_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_long_form_length_under_128() {
        let err = Asn1Value::parse(&[0x04, 0x81, 0x05, 0, 0, 0, 0, 0]).expect_err("non-canonical");
        assert_eq!(err.constraint_iri, INVALID_DER_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_indefinite_length() {
        let err = Asn1Value::parse(&[0x30, 0x80]).expect_err("BER not DER");
        assert_eq!(err.constraint_iri, INVALID_DER_VIOLATION.constraint_iri);
    }
}
