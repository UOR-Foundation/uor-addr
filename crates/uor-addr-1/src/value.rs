//! `JsonValue` — the typed JSON-value carrier (wiki ADR-023, ADR-027).
//!
//! The PrismModel's `Input` is no longer an opaque byte buffer. It is
//! [`JsonValue`], a typed carrier whose runtime bytes are a
//! structurally-tagged serialization of an RFC 8259 JSON value of
//! bounded depth and width. The six JSON cases — object, array,
//! string, number, boolean, null — each map to a known tag in the
//! byte layout; recursive children live inside the same flat buffer.
//!
//! The host-boundary parser ([`JsonValue::parse`]) is the **only**
//! σ-projection that runs before construction. It validates that the
//! parsed value satisfies the typed-input bounds declared in
//! [`crate::shapes::bounds`] (depth ≤ `MAX_JSON_DEPTH`, per-string
//! width ≤ `MAX_STRING_BYTES`, etc.); failure surfaces as a
//! [`prism::pipeline::ShapeViolation`] with a constraint IRI keyed to
//! the violated bound.
//!
//! Canonicalization happens **inside the typed-iso surface** — the
//! ψ_9 resolver invokes the canonicalizer over the tagged bytes,
//! producing JCS-RFC8785 + Unicode NFC canonical-form bytes that feed
//! the canonical hash axis. The host boundary performs no
//! canonicalization. Callers that need the canonical bytes outside
//! the κ-derivation can reach them via [`canonicalize`], which
//! routes through the same typed-iso path used by ψ_9 — no
//! parallel implementation is carried in the crate.
//!
//! # Tagged byte layout
//!
//! ```text
//! JsonValue ::= Tag(1 byte) Payload
//!   Tag = 0x00 Null         — no payload
//!   Tag = 0x01 BoolFalse    — no payload
//!   Tag = 0x02 BoolTrue     — no payload
//!   Tag = 0x03 Number       — u16 BE length || N bytes (ASCII)
//!   Tag = 0x04 String       — u16 BE length || N bytes (UTF-8, pre-NFC)
//!   Tag = 0x05 Array        — u16 BE count  || count × JsonValue
//!   Tag = 0x06 Object       — u16 BE count  || count × (u16 BE keylen || keybytes || JsonValue)
//! ```
//!
//! All multi-byte length / count fields are big-endian. Total
//! serialization size is bounded by
//! [`crate::shapes::bounds::JSON_VALUE_MAX_BYTES`].

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use unicode_normalization::UnicodeNormalization;

use prism::pipeline::{
    ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation, ViolationKind,
};

use crate::shapes::bounds::{
    JSON_VALUE_MAX_BYTES, MAX_ARRAY_ELEMENTS, MAX_JSON_DEPTH, MAX_NUMBER_DIGITS, MAX_OBJECT_KEYS,
    MAX_STRING_BYTES,
};

// ─── Tag byte constants ─────────────────────────────────────────────────

pub(crate) const TAG_NULL: u8 = 0x00;
pub(crate) const TAG_FALSE: u8 = 0x01;
pub(crate) const TAG_TRUE: u8 = 0x02;
pub(crate) const TAG_NUMBER: u8 = 0x03;
pub(crate) const TAG_STRING: u8 = 0x04;
pub(crate) const TAG_ARRAY: u8 = 0x05;
pub(crate) const TAG_OBJECT: u8 = 0x06;

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

const INVALID_JSON_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/validUtf8Json",
    property_iri: "https://uor.foundation/addr/inputBytes",
    expected_range: "https://uor.foundation/addr/ValidUtf8Json",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

const DEPTH_BOUND_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/depthBound",
    property_iri: "https://uor.foundation/addr/JsonValue/depth",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_JSON_DEPTH as u32,
    kind: ViolationKind::CardinalityViolation,
};

const STRING_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/stringWidth",
    property_iri: "https://uor.foundation/addr/JsonValue/stringByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_STRING_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const NUMBER_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/numberWidth",
    property_iri: "https://uor.foundation/addr/JsonValue/numberDigitCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_NUMBER_DIGITS as u32,
    kind: ViolationKind::CardinalityViolation,
};

const OBJECT_KEYS_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/objectKeysBound",
    property_iri: "https://uor.foundation/addr/JsonValue/objectKeyCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_OBJECT_KEYS as u32,
    kind: ViolationKind::CardinalityViolation,
};

const ARRAY_ELEMENTS_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/arrayElementsBound",
    property_iri: "https://uor.foundation/addr/JsonValue/arrayElementCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_ARRAY_ELEMENTS as u32,
    kind: ViolationKind::CardinalityViolation,
};

const TOTAL_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/serializedWidth",
    property_iri: "https://uor.foundation/addr/JsonValue/totalByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: JSON_VALUE_MAX_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const CORRUPT_TAGGED_BYTES: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/wellFormedTaggedBytes",
    property_iri: "https://uor.foundation/addr/JsonValue/taggedBytes",
    expected_range: "https://uor.foundation/addr/WellFormedTaggedJsonValue",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

// ─── JsonValue — the typed input carrier ────────────────────────────────

/// Typed JSON-value input shape. Runtime bytes are the
/// structurally-tagged serialization documented in the module
/// header. Construction goes through [`JsonValue::parse`] which
/// validates every typed-input bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonValue {
    /// Structurally-tagged byte serialization. Length ≤
    /// [`JSON_VALUE_MAX_BYTES`]; well-formed per the module header's
    /// grammar.
    pub(crate) bytes: Vec<u8>,
}

impl JsonValue {
    /// Parse raw JSON bytes into a typed `JsonValue`.
    ///
    /// # Errors
    ///
    /// - `validUtf8Json` — input is not valid UTF-8 JSON.
    /// - `depthBound` — nesting depth exceeds [`MAX_JSON_DEPTH`].
    /// - `stringWidth` — a string value or object key exceeds
    ///   [`MAX_STRING_BYTES`] UTF-8 bytes.
    /// - `numberWidth` — a number's canonical text exceeds
    ///   [`MAX_NUMBER_DIGITS`] characters.
    /// - `objectKeysBound` — an object has more than
    ///   [`MAX_OBJECT_KEYS`] keys.
    /// - `arrayElementsBound` — an array has more than
    ///   [`MAX_ARRAY_ELEMENTS`] elements.
    /// - `serializedWidth` — the tagged byte serialization exceeds
    ///   [`JSON_VALUE_MAX_BYTES`].
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| INVALID_JSON_VIOLATION)?;
        let mut bytes = Vec::new();
        write_tagged(&value, 0, &mut bytes)?;
        if bytes.len() > JSON_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        Ok(Self { bytes })
    }

    /// Borrow the structurally-tagged byte serialization. This is
    /// the runtime form the ψ-pipeline carries through every
    /// resolver carrier; it is **not** the canonical-form bytes the
    /// SHA-256 axis hashes. ψ_9 derives the canonical bytes from
    /// these via the same code path [`canonicalize`] exposes.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Parse raw JSON bytes and emit the JCS-RFC8785 + Unicode NFC
/// canonical-form bytes — the same bytes ψ_9 hashes inside the
/// typed-iso surface. This routes through [`JsonValue::parse`] and
/// the in-surface canonicalizer; **no parallel canonicalization
/// implementation is carried in the crate**.
///
/// Use this when you need the canonical bytes themselves (e.g.,
/// signing the canonical bytes directly, hashing under a different
/// `HashAxis` instance off the ψ-pipeline). Most callers should
/// prefer [`crate::address`] which goes end-to-end through the
/// PrismModel and produces a sealed `Grounded<AddressLabel>`.
///
/// # Errors
///
/// Surfaces any [`ShapeViolation`] [`JsonValue::parse`] would emit
/// for the same input. The canonicalizer is total over well-formed
/// parsed values; the defensive `CORRUPT_TAGGED_BYTES` arm cannot
/// be reached on a freshly-parsed `JsonValue`.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, ShapeViolation> {
    let value = JsonValue::parse(raw)?;
    let mut canonical = Vec::with_capacity(value.bytes.len());
    canonicalize_into(&value.bytes, &mut canonical)?;
    Ok(canonical)
}

// ─── Tagged-format writer (raw JSON value → tagged bytes) ───────────────

fn write_tagged(
    value: &serde_json::Value,
    depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), ShapeViolation> {
    if depth > MAX_JSON_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    match value {
        serde_json::Value::Null => {
            out.push(TAG_NULL);
        }
        serde_json::Value::Bool(false) => {
            out.push(TAG_FALSE);
        }
        serde_json::Value::Bool(true) => {
            out.push(TAG_TRUE);
        }
        serde_json::Value::Number(n) => {
            let text = n.to_string();
            let bytes = text.as_bytes();
            if bytes.len() > MAX_NUMBER_DIGITS {
                return Err(NUMBER_WIDTH_VIOLATION);
            }
            out.push(TAG_NUMBER);
            put_u16(out, bytes.len() as u16);
            out.extend_from_slice(bytes);
        }
        serde_json::Value::String(s) => {
            let bytes = s.as_bytes();
            if bytes.len() > MAX_STRING_BYTES {
                return Err(STRING_WIDTH_VIOLATION);
            }
            out.push(TAG_STRING);
            put_u16(out, bytes.len() as u16);
            out.extend_from_slice(bytes);
        }
        serde_json::Value::Array(elements) => {
            if elements.len() > MAX_ARRAY_ELEMENTS {
                return Err(ARRAY_ELEMENTS_VIOLATION);
            }
            out.push(TAG_ARRAY);
            put_u16(out, elements.len() as u16);
            for child in elements {
                write_tagged(child, depth + 1, out)?;
            }
        }
        serde_json::Value::Object(map) => {
            if map.len() > MAX_OBJECT_KEYS {
                return Err(OBJECT_KEYS_VIOLATION);
            }
            out.push(TAG_OBJECT);
            put_u16(out, map.len() as u16);
            // Preserve the entry order from serde_json's default
            // Map (which is alphabetical under serde_json's default
            // feature set). Order does not affect canonical bytes —
            // the ψ_9 canonicalizer re-sorts keys per JCS §3.2.3.
            for (key, child) in map {
                let key_bytes = key.as_bytes();
                if key_bytes.len() > MAX_STRING_BYTES {
                    return Err(STRING_WIDTH_VIOLATION);
                }
                put_u16(out, key_bytes.len() as u16);
                out.extend_from_slice(key_bytes);
                write_tagged(child, depth + 1, out)?;
            }
        }
    }
    Ok(())
}

#[inline]
fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

// ─── Tagged-format reader (tagged bytes → canonical JCS+NFC bytes) ──────

/// Decode tagged bytes and emit the JCS-RFC8785 + Unicode NFC
/// canonical-form bytes the SHA-256 axis hashes. This is the
/// load-bearing σ-projection the ψ_9 resolver performs, admitted by
/// the resolver-body iterative-resolution discipline (wiki
/// ADR-046).
///
/// # Errors
///
/// Returns [`CORRUPT_TAGGED_BYTES`] if the tagged buffer is
/// truncated or carries an unknown tag. This is unreachable for
/// `JsonValue` instances constructed through [`JsonValue::parse`]
/// — the parser emits well-formed bytes by construction; the
/// guard is defensive against substrate-corrupted inputs.
pub(crate) fn canonicalize_into(tagged: &[u8], out: &mut Vec<u8>) -> Result<(), ShapeViolation> {
    let value = read_tagged(tagged, &mut 0)?;
    let nfc_value = nfc_recursive(&value);
    out.clear();
    out.extend_from_slice(
        &serde_json::to_vec(&nfc_value).expect("nfc-normalised serde_json::Value re-serialises"),
    );
    Ok(())
}

fn read_tagged(buf: &[u8], pos: &mut usize) -> Result<serde_json::Value, ShapeViolation> {
    let tag = take_byte(buf, pos)?;
    match tag {
        TAG_NULL => Ok(serde_json::Value::Null),
        TAG_FALSE => Ok(serde_json::Value::Bool(false)),
        TAG_TRUE => Ok(serde_json::Value::Bool(true)),
        TAG_NUMBER => {
            let len = take_u16(buf, pos)? as usize;
            let bytes = take_slice(buf, pos, len)?;
            let text = core::str::from_utf8(bytes).map_err(|_| CORRUPT_TAGGED_BYTES)?;
            let n: serde_json::Number = text.parse().map_err(|_| CORRUPT_TAGGED_BYTES)?;
            Ok(serde_json::Value::Number(n))
        }
        TAG_STRING => {
            let len = take_u16(buf, pos)? as usize;
            let bytes = take_slice(buf, pos, len)?;
            let text = core::str::from_utf8(bytes).map_err(|_| CORRUPT_TAGGED_BYTES)?;
            Ok(serde_json::Value::String(text.into()))
        }
        TAG_ARRAY => {
            let count = take_u16(buf, pos)? as usize;
            let mut elements = Vec::with_capacity(count);
            for _ in 0..count {
                elements.push(read_tagged(buf, pos)?);
            }
            Ok(serde_json::Value::Array(elements))
        }
        TAG_OBJECT => {
            let count = take_u16(buf, pos)? as usize;
            // Use BTreeMap to ensure JCS §3.2.3 key ordering is the
            // serialization order serde_json::Map sees once we
            // hand it back — `serde_json::Map`'s default
            // preserve_order-disabled behaviour ranks by
            // alphabetical key order, which is what BTreeMap
            // iteration yields for UTF-8 byte-ordered strings.
            let mut entries: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for _ in 0..count {
                let key_len = take_u16(buf, pos)? as usize;
                let key_bytes = take_slice(buf, pos, key_len)?;
                let key = core::str::from_utf8(key_bytes)
                    .map_err(|_| CORRUPT_TAGGED_BYTES)?
                    .to_string();
                let child = read_tagged(buf, pos)?;
                entries.insert(key, child);
            }
            let mut map = serde_json::Map::with_capacity(entries.len());
            for (k, v) in entries {
                map.insert(k, v);
            }
            Ok(serde_json::Value::Object(map))
        }
        _ => Err(CORRUPT_TAGGED_BYTES),
    }
}

#[inline]
fn take_byte(buf: &[u8], pos: &mut usize) -> Result<u8, ShapeViolation> {
    if *pos >= buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let b = buf[*pos];
    *pos += 1;
    Ok(b)
}

#[inline]
fn take_u16(buf: &[u8], pos: &mut usize) -> Result<u16, ShapeViolation> {
    if *pos + 2 > buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let hi = buf[*pos];
    let lo = buf[*pos + 1];
    *pos += 2;
    Ok(u16::from_be_bytes([hi, lo]))
}

#[inline]
fn take_slice<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], ShapeViolation> {
    if *pos + len > buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let s = &buf[*pos..*pos + len];
    *pos += len;
    Ok(s)
}

fn nfc_recursive(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(s.nfc().collect::<String>()),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(nfc_recursive).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut new_obj = serde_json::Map::new();
            for (k, v) in obj {
                let nfc_k: String = k.nfc().collect();
                new_obj.insert(nfc_k, nfc_recursive(v));
            }
            serde_json::Value::Object(new_obj)
        }
        other => other.clone(),
    }
}

// ─── ConstrainedTypeShape + IntoBindingValue impls ──────────────────────

impl ConstrainedTypeShape for JsonValue {
    const IRI: &'static str = "https://uor.foundation/addr/JsonValue";
    /// One Site per tagged-byte position; per-byte sites carry the
    /// structurally-tagged JSON value's parse-tree encoding through
    /// the ψ-pipeline.
    const SITE_COUNT: usize = JSON_VALUE_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for JsonValue {}

impl IntoBindingValue for JsonValue {
    const MAX_BYTES: usize = JSON_VALUE_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if self.bytes.len() > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_object() {
        let v = JsonValue::parse(br#"{"foo":"bar"}"#).expect("valid");
        // Tag byte for object, then count=1, then key/value entry.
        assert_eq!(v.bytes[0], TAG_OBJECT);
    }

    #[test]
    fn rejects_invalid_json() {
        let err = JsonValue::parse(b"not json").expect_err("must reject");
        assert_eq!(err.shape_iri, INVALID_JSON_VIOLATION.shape_iri);
    }

    #[test]
    fn rejects_overdeep_recursion() {
        let mut s = String::new();
        for _ in 0..(MAX_JSON_DEPTH + 2) {
            s.push('[');
        }
        for _ in 0..(MAX_JSON_DEPTH + 2) {
            s.push(']');
        }
        let err = JsonValue::parse(s.as_bytes()).expect_err("must reject");
        assert_eq!(err.constraint_iri, DEPTH_BOUND_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_oversize_string() {
        let big: String = "a".repeat(MAX_STRING_BYTES + 1);
        let raw = format!("\"{big}\"");
        let err = JsonValue::parse(raw.as_bytes()).expect_err("must reject");
        assert_eq!(err.constraint_iri, STRING_WIDTH_VIOLATION.constraint_iri);
    }

    /// Inline expected canonical-form bytes — each pair pins the
    /// in-surface canonicalizer against the JCS-RFC8785 + NFC
    /// reference output for a small, exhaustive structural sample.
    /// Larger byte-identity coverage lives in
    /// `tests/byte_identity.rs` against the 12 published fixtures.
    const CANONICAL_FIXTURES: &[(&[u8], &[u8])] = &[
        (br#"{"foo":"bar"}"#, br#"{"foo":"bar"}"#),
        (br#"{"b": 1, "a": 2}"#, br#"{"a":2,"b":1}"#),
        (
            br#"{"nested": {"deep": {"value": "found"}}}"#,
            br#"{"nested":{"deep":{"value":"found"}}}"#,
        ),
        (
            br#"{"int": 42, "bool": true, "null_val": null}"#,
            br#"{"bool":true,"int":42,"null_val":null}"#,
        ),
        (b"[1, 2, 3]", b"[1,2,3]"),
        (br#"["a", "b", "c"]"#, br#"["a","b","c"]"#),
    ];

    #[test]
    fn canonicalizer_matches_reference_for_inline_fixtures() {
        for (raw, expected) in CANONICAL_FIXTURES {
            let canon = canonicalize(raw).expect("valid");
            assert_eq!(canon, *expected, "raw={raw:?}");
        }
    }

    #[test]
    fn canonicalizer_collapses_unicode_decomposed_to_composed() {
        let decomposed = "{\"name\": \"cafe\u{0301}\"}".as_bytes();
        let composed = "{\"name\":\"caf\u{00E9}\"}".as_bytes();
        assert_eq!(
            canonicalize(decomposed).expect("valid"),
            canonicalize(composed).expect("valid")
        );
    }

    #[test]
    fn canonicalize_is_idempotent_on_its_own_output() {
        for (raw, _expected) in CANONICAL_FIXTURES {
            let once = canonicalize(raw).expect("valid");
            let twice = canonicalize(&once).expect("re-canonicalises");
            assert_eq!(once, twice, "idempotence broken for {raw:?}");
        }
    }
}
